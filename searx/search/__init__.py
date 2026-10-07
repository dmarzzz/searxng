# SPDX-License-Identifier: AGPL-3.0-or-later
# pylint: disable=missing-module-docstring, too-few-public-methods

__all__ = ["SearchWithPlugins"]

import typing as t

import threading
import time
from timeit import default_timer
from uuid import uuid4

from flask import copy_current_request_context

from searx import logger
from searx import settings
import searx.answerers
import searx.plugins
from searx.engines import load_engines
from searx.external_bang import get_bang_url
from searx.metrics import initialize as initialize_metrics, counter_inc
from searx.network import circuits
from searx.network import (
    initialize as initialize_network,
    check_network_configuration,
    get_network,
    set_isolation_for_thread,
    release_isolation,
)
from searx.results import ResultContainer
from searx.search.processors import PROCESSORS
from searx.search.processors.abstract import RequestParams
from searx.search import shadenet

if t.TYPE_CHECKING:
    from .models import SearchQuery
    from searx.search.processors.abstract import EngineProcessor
    from searx.extended_types import SXNG_Request

logger = logger.getChild('search')


def initialize(
    settings_engines: list[dict[str, t.Any]] = None,  # pyright: ignore[reportArgumentType]
    check_network: bool = False,
    enable_metrics: bool = True,
):
    settings_engines = settings_engines or settings['engines']
    load_engines(settings_engines)
    initialize_network(settings_engines, settings['outgoing'])
    _start_circuit_pool()
    if check_network:
        check_network_configuration()
    initialize_metrics([engine['name'] for engine in settings_engines], enable_metrics)
    PROCESSORS.init(settings_engines)


class Search:
    """Search information container"""

    def __init__(self, search_query: "SearchQuery"):
        """Initialize the Search"""
        # init vars
        super().__init__()
        self.search_query: "SearchQuery" = search_query
        self.result_container: ResultContainer = ResultContainer()
        self.start_time: float | None = None
        self.actual_timeout: float | None = None
        self._deadline_reached: bool = False

    def search_external_bang(self) -> bool:
        """Check if there is a external bang.  If yes, update
        self.result_container and return True."""
        if self.search_query.external_bang:
            self.result_container.redirect_url = get_bang_url(self.search_query)

            # This means there was a valid bang and the rest of the search does
            # not need to be continued
            if isinstance(self.result_container.redirect_url, str):
                return True
        return False

    def search_answerers(self):

        results = searx.answerers.STORAGE.ask(self.search_query.query)
        self.result_container.extend(None, results)  # pyright: ignore[reportArgumentType]
        return bool(results)

    # do search-request
    def _get_requests(self) -> tuple[list[tuple[str, str, RequestParams]], float]:
        # init vars
        requests: list[tuple[str, str, RequestParams]] = []

        # max of all selected engine timeout
        default_timeout = 0

        # shaded: at most N ShadeNet engines per search, the healthiest first
        shadenet_candidates = [
            (ref.name, PROCESSORS[ref.name])
            for ref in self.search_query.engineref_list
            if ref.name in PROCESSORS and shadenet.is_shadenet(ref.name)
        ]
        shadenet_allowed = shadenet.allowed_engines(shadenet_candidates)

        # start search-request for all selected engines
        for engineref in self.search_query.engineref_list:
            processor = PROCESSORS.get(engineref.name)
            if not processor:
                # engine does not exists; not yet or the 'init' method of the
                # engine has been failed and the engine has not been registered.
                continue

            network = get_network(engineref.name)
            route = network.route if network else None
            self.result_container.note_engine(engineref.name, 'sent', route=route)

            if route == 'shadenet' and self._shadenet_skip(engineref.name, processor, shadenet_allowed):
                continue

            # stop the request now if the engine is suspend
            if processor.extend_container_if_suspended(self.result_container):
                continue

            # set default request parameters
            request_params = processor.get_params(self.search_query, engineref.category)
            if request_params is None:
                self.result_container.note_engine(engineref.name, 'unsupported')
                continue

            counter_inc('engine', engineref.name, 'search', 'count', 'sent')

            # append request to list
            requests.append((engineref.name, self.search_query.query, request_params))

            # update default_timeout
            default_timeout = max(default_timeout, processor.engine.timeout)

        # adjust timeout
        max_request_timeout = settings['outgoing']['max_request_timeout']
        actual_timeout = default_timeout
        query_timeout = self.search_query.timeout_limit

        if max_request_timeout is None and query_timeout is None:
            # No max, no user query: default_timeout
            pass
        elif max_request_timeout is None and query_timeout is not None:
            # No max, but user query: From user query except if above default
            actual_timeout = min(default_timeout, query_timeout)
        elif max_request_timeout is not None and query_timeout is None:
            # Max, no user query: Default except if above max
            actual_timeout = min(default_timeout, max_request_timeout)
        elif max_request_timeout is not None and query_timeout is not None:
            # Max & user query: From user query except if above max
            actual_timeout = min(query_timeout, max_request_timeout)

        logger.debug(
            "actual_timeout={0} (default_timeout={1}, ?timeout_limit={2}, max_request_timeout={3})".format(
                actual_timeout, default_timeout, query_timeout, max_request_timeout
            )
        )

        # shaded: skip the ShadeNet engines when their tunnels cannot open in time
        shadenet_requests = [r for r in requests if shadenet.is_shadenet(r[0])]
        if shadenet_requests:
            plan = shadenet.plan(len(shadenet_requests))
            if not shadenet.fits(plan, actual_timeout):
                for engine_name, _, _ in shadenet_requests:
                    self.result_container.note_engine(
                        engine_name, 'budget', retry_in=plan.get('completesInSeconds') if plan else None
                    )
                requests = [r for r in requests if not shadenet.is_shadenet(r[0])]

        return requests, actual_timeout

    def _shadenet_skip(self, engine_name: str, processor: "EngineProcessor", allowed: set[str]) -> bool:
        """shaded: True when a ShadeNet engine sits this search out (cap or pacing)."""
        if engine_name not in allowed:
            self.result_container.note_engine(engine_name, 'capped')
            return True
        if not processor.suspended_status.is_suspended and shadenet.paced(engine_name):
            self.result_container.note_engine(engine_name, 'paced')
            return True
        return False

    def search_multiple_requests(self, requests: list[tuple[str, str, RequestParams]]):
        # pylint: disable=protected-access
        # shaded: a pre-built circuit's key doubles as the search id (unique, used once)
        pooled = circuits.take() if settings['outgoing'].get('isolate') else None
        search_id = pooled or str(uuid4())
        self.result_container.circuit = 'pooled' if pooled else 'inline'
        isolate = bool(settings['outgoing'].get('isolate'))

        for engine_name, query, request_params in requests:
            _search = copy_current_request_context(
                _isolated(PROCESSORS[engine_name].search, f'{search_id}:{engine_name}' if isolate else None)
            )
            th = threading.Thread(  # pylint: disable=invalid-name
                target=_search,
                args=(query, request_params, self.result_container, self.start_time, self.actual_timeout),
                name=search_id,
            )
            th._timeout = False
            th._engine_name = engine_name
            th.start()

        threads = [th for th in threading.enumerate() if th.name == search_id]
        deadline = settings['search'].get('deadline')
        if deadline is not None:
            self._wait_for_deadline(threads, float(deadline))

        for th in threads:  # pylint: disable=invalid-name
            remaining_time = max(0.0, self.actual_timeout - (default_timer() - self.start_time))
            if deadline is not None and getattr(self, '_deadline_reached', False):
                remaining_time = 0.0
            th.join(remaining_time)
            if th.is_alive():
                th._timeout = True
                self.result_container.add_unresponsive_engine(th._engine_name, 'timeout')
                late = deadline is not None and getattr(self, '_deadline_reached', False)
                self.result_container.note_engine(th._engine_name, 'late' if late else 'timeout')
                PROCESSORS[th._engine_name].logger.error('engine timeout')

    def _wait_for_deadline(self, threads: list[threading.Thread], deadline: float):
        """shaded: wait until every engine is done, or until ``deadline`` seconds
        have passed and at least ``search.deadline_min_answered`` engines answered
        with results; never longer than the upstream timeout."""
        min_answered = int(settings['search'].get('deadline_min_answered', 1))
        self._deadline_reached = False
        while True:
            elapsed = default_timer() - self.start_time
            if not any(th.is_alive() for th in threads) or elapsed >= self.actual_timeout:
                return
            if elapsed >= deadline:
                answered = sum(1 for e in self.result_container.coverage.values() if e.get('status') == 'ok')
                if answered >= min_answered:
                    self._deadline_reached = True
                    return
            time.sleep(0.05)

    def search_standard(self):
        """
        Update self.result_container, self.actual_timeout
        """
        requests, self.actual_timeout = self._get_requests()

        # send all search-request
        if requests:
            self.search_multiple_requests(requests)

        # return results, suggestions, answers and infoboxes
        return True

    # do search-request
    def search(self) -> ResultContainer:
        self.start_time = default_timer()
        if not self.search_external_bang():
            if not self.search_answerers():
                self.search_standard()
        return self.result_container


def _start_circuit_pool():
    """shaded: pre-build isolated Tor circuits when the default route is an
    isolated Tor proxy (outgoing.circuit_pool.size > 0)."""
    pool = settings['outgoing'].get('circuit_pool') or {}
    network = get_network()
    if not pool.get('size') or network is None or network.route != 'tor' or not network.isolate:
        return
    proxies = network.proxies
    proxy_url = proxies if isinstance(proxies, str) else next(iter(proxies.values()), None)
    if isinstance(proxy_url, list):
        proxy_url = proxy_url[0]
    if proxy_url:
        circuits.start(proxy_url, int(pool['size']), int(pool.get('builders', 4)))


def _isolated(search_function: t.Callable[..., t.Any], isolation: str | None) -> t.Callable[..., t.Any]:
    """shaded: run an engine's search on its own circuit / tunnel, then close it."""

    def run(*args: t.Any):
        set_isolation_for_thread(isolation)
        try:
            return search_function(*args)
        finally:
            set_isolation_for_thread(None)
            if isolation is not None:
                release_isolation(isolation)

    return run


class SearchWithPlugins(Search):
    """Inherit from the Search class, add calls to the plugins."""

    def __init__(self, search_query: "SearchQuery", request: "SXNG_Request", user_plugins: list[str]):
        super().__init__(search_query)
        self.user_plugins = user_plugins
        self.result_container.on_result = self._on_result
        # pylint: disable=line-too-long
        # get the "real" request to use it outside the Flask context.
        # see
        # * https://github.com/pallets/flask/blob/d01d26e5210e3ee4cbbdef12f05c886e08e92852/src/flask/globals.py#L55
        # * https://github.com/pallets/werkzeug/blob/3c5d3c9bd0d9ce64590f0af8997a38f3823b368d/src/werkzeug/local.py#L548-L559
        # * https://werkzeug.palletsprojects.com/en/2.0.x/local/#werkzeug.local.LocalProxy._get_current_object
        # pylint: enable=line-too-long
        self.request = request._get_current_object()

    def _on_result(self, result):
        return searx.plugins.STORAGE.on_result(self.request, self, result)

    def search(self) -> ResultContainer:

        if searx.plugins.STORAGE.pre_search(self.request, self):
            super().search()

        searx.plugins.STORAGE.post_search(self.request, self)
        self.result_container.close()

        return self.result_container

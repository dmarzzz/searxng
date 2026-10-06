# SPDX-License-Identifier: AGPL-3.0-or-later
# pylint: disable=missing-module-docstring,missing-class-docstring,protected-access
"""Tests for the shaded-searxng patches: routes, isolation, backoff, ShadeNet budget, coverage."""

import copy
import threading
import time
from unittest.mock import patch

import searx
import searx.network
from searx.network.network import Network, NoRouteError, _isolated_proxy_url
from searx.results import ResultContainer
from searx.search import shadenet, _isolated
from searx.search.processors.abstract import SuspendedStatus
from tests import SearxTestCase

TOR = "socks5h://127.0.0.1:9250"
SHADENET = "http://shadenet:token@127.0.0.1:8118"


class TestRoutes(SearxTestCase):

    def test_route_resolution(self):
        self.assertEqual(Network().route, "direct")
        self.assertIsNone(Network(require_route=True).route)
        self.assertEqual(Network(require_route=True, route="direct").route, "direct")
        self.assertEqual(Network(proxies=TOR, using_tor_proxy=True).route, "tor")
        self.assertEqual(Network(proxies=TOR).route, "proxy")
        self.assertEqual(
            Network(proxies=SHADENET, route="shadenet", require_route=True).route,
            "shadenet",
        )

    def test_route_misconfiguration(self):
        with self.assertRaises(ValueError):
            Network(route="carrier-pigeon")
        with self.assertRaises(ValueError):
            Network(route="shadenet")  # a proxied route without a proxy
        with self.assertRaises(ValueError):
            Network(route="direct", proxies=TOR)

    async def test_no_route_fails_closed(self):
        network = Network(require_route=True)
        with self.assertRaises(NoRouteError):
            await network.get_client()
        with self.assertRaises(NoRouteError):
            await network.request("GET", "https://example.com/")


class TestIsolation(SearxTestCase):

    def test_isolated_proxy_url(self):
        a = _isolated_proxy_url(TOR, "search-1:google")
        b = _isolated_proxy_url(TOR, "search-2:google")
        self.assertTrue(a.startswith("socks5h://sx"))
        self.assertTrue(a.endswith(":x@127.0.0.1:9250"))
        self.assertNotEqual(a, b)
        self.assertEqual(a, _isolated_proxy_url(TOR, "search-1:google"))
        # an HTTP CONNECT proxy keeps its credentials; isolation is a new client
        self.assertEqual(_isolated_proxy_url(SHADENET, "search-1:google"), SHADENET)

    async def test_one_client_per_isolation(self):
        network = Network(proxies=TOR, isolate=True)
        c1 = await network.get_client(isolation="s1:e")
        c2 = await network.get_client(isolation="s2:e")
        c3 = await network.get_client(isolation="s1:e")
        self.assertIsNot(c1, c2)
        self.assertIs(c1, c3)
        await network.release("s1:e")
        self.assertTrue(c1.is_closed)
        self.assertNotIn("s1:e", network._iso_keys)
        self.assertFalse(c2.is_closed)
        await network.aclose()

    async def test_query_mode_one_circuit(self):
        network = Network(proxies=TOR, isolate=True)  # True == 'query'
        self.assertEqual(network.isolate, "query")
        a = await network.get_client(isolation="sid1:arxiv")
        b = await network.get_client(isolation="sid1:bing")
        c = await network.get_client(isolation="sid2:arxiv")
        self.assertIsNot(a, b)  # own client (own ShadeNet tunnel) per engine
        keys = {iso: network._iso_keys[iso][0] for iso in ("sid1:arxiv", "sid1:bing", "sid2:arxiv")}
        self.assertEqual(keys["sid1:arxiv"][3], keys["sid1:bing"][3])  # same SOCKS user: one circuit
        self.assertNotEqual(keys["sid1:arxiv"][3], keys["sid2:arxiv"][3])
        self.assertIsNot(a, c)
        await network.aclose()

    async def test_engine_mode(self):
        network = Network(proxies=TOR, isolate="engine")
        await network.get_client(isolation="sid1:arxiv")
        await network.get_client(isolation="sid1:bing")
        self.assertNotEqual(network._iso_keys["sid1:arxiv"][0][3], network._iso_keys["sid1:bing"][0][3])
        with self.assertRaises(ValueError):
            Network(proxies=TOR, isolate="circuit")
        await network.aclose()

    async def test_isolation_off(self):
        network = Network(proxies=TOR, isolate=False)
        c1 = await network.get_client(isolation="s1:e")
        c2 = await network.get_client(isolation="s2:e")
        self.assertIs(c1, c2)
        await network.aclose()

    def test_thread_wrapper(self):
        seen = []

        def search(*_):
            seen.append(searx.network.THREADLOCAL.__dict__.get("isolation"))

        with patch("searx.search.release_isolation") as release:
            _isolated(search, "sid:engine")()
            release.assert_called_once_with("sid:engine")
        self.assertEqual(seen, ["sid:engine"])
        self.assertIsNone(searx.network.THREADLOCAL.__dict__.get("isolation"))


class TestBackoff(SearxTestCase):

    def setUp(self):
        super().setUp()
        previous = copy.deepcopy(searx.settings["search"])
        self.addCleanup(lambda: searx.settings.__setitem__("search", previous))
        searx.settings["search"]["suspend_backoff"] = {
            "enabled": True,
            "base": 30,
            "factor": 4,
            "max": 3600,
            "probe_timeout": 60,
        }

    def test_exponential_with_cap(self):
        status = SuspendedStatus()
        clock = [1000.0]
        with patch("searx.search.processors.abstract.default_timer", lambda: clock[0]):
            lengths = []
            for _ in range(6):
                status.suspend(None, "boom")
                lengths.append(status.suspend_end_time - clock[0])
        self.assertEqual(lengths, [30, 120, 480, 1920, 3600, 3600])

    def test_error_class_time_is_capped(self):
        status = SuspendedStatus()
        with patch("searx.search.processors.abstract.default_timer", lambda: 0.0):
            status.suspend(1296000, "cloudflare captcha")  # upstream default: 15 days
        self.assertEqual(status.suspend_end_time, 30)

    def test_half_open_single_probe(self):
        status = SuspendedStatus()
        clock = [0.0]
        with patch("searx.search.processors.abstract.default_timer", lambda: clock[0]):
            status.suspend(None, "boom")
            self.assertTrue(status.should_skip())  # suspended
            clock[0] = 31
            self.assertFalse(status.should_skip())  # this search is the probe
            self.assertTrue(status.should_skip())  # others wait for it
            clock[0] = 31 + 61
            self.assertFalse(status.should_skip())  # probe lost: try again
            status.resume()
            self.assertFalse(status.should_skip())
            self.assertFalse(status.should_skip())

    def test_disabled_is_upstream(self):
        searx.settings["search"]["suspend_backoff"]["enabled"] = False
        status = SuspendedStatus()
        with patch("searx.search.processors.abstract.default_timer", lambda: 0.0):
            status.suspend(86400, "denied")
            self.assertEqual(status.suspend_end_time, 86400)


class FakeProcessor:
    def __init__(self, errors=0, suspended=False):
        self.suspended_status = SuspendedStatus()
        self.suspended_status.continuous_errors = errors
        if suspended:
            self.suspended_status.suspend_end_time = float("inf")


class TestShadenetBudget(SearxTestCase):

    def test_allowed_healthiest_first(self):
        candidates = [
            ("google", FakeProcessor(errors=2)),
            ("brave", FakeProcessor(errors=0)),
            ("duckduckgo", FakeProcessor(errors=0, suspended=True)),
        ]
        with patch("searx.search.shadenet.max_engines_per_query", return_value=1):
            self.assertEqual(shadenet.allowed_engines(candidates), {"brave"})
        with patch("searx.search.shadenet.max_engines_per_query", return_value=5):
            self.assertEqual(shadenet.allowed_engines(candidates), {"brave", "google"})

    def test_fits(self):
        self.assertTrue(shadenet.fits(None, 5))  # unknown: send, the route fails closed
        self.assertTrue(shadenet.fits({"fitsNow": True, "completesInSeconds": 0}, 5))
        self.assertTrue(shadenet.fits({"fitsNow": False, "completesInSeconds": 3}, 5))
        self.assertFalse(shadenet.fits({"fitsNow": False, "completesInSeconds": 40}, 5))

    def test_plan_unconfigured(self):
        self.assertIsNone(shadenet.plan(1))


class TestCoverage(SearxTestCase):

    def test_coverage_block(self):
        rc = ResultContainer()
        rc.note_engine("arxiv", "sent", route="tor")
        rc.note_engine("arxiv", "ok", results=10, seconds=1.2)
        rc.note_engine("google", "sent", route="shadenet")
        rc.note_engine("brave", "sent", route="shadenet")
        rc.note_engine("brave", "capped")
        rc.note_engine("mojeek", "sent", route="tor")
        rc.note_engine("mojeek", "error", error="SearxEngineCaptchaException")
        coverage = rc.get_coverage()
        self.assertEqual(
            coverage["engines"]["arxiv"],
            {"route": "tor", "status": "ok", "results": 10, "seconds": 1.2},
        )
        self.assertEqual(coverage["engines"]["google"]["status"], "timeout")  # still running at return
        self.assertEqual(coverage["engines"]["brave"]["status"], "capped")
        self.assertEqual(coverage["routes_used"], ["tor"])
        self.assertEqual(coverage["answered"], 1)
        self.assertEqual(coverage["queried"], 3)


class TestSharedRouteHealth(SearxTestCase):

    def test_shadenet_own_health(self):
        from searx.search.processors import (
            abstract,
        )  # pylint: disable=import-outside-toplevel

        shared = Network(proxies=SHADENET, route="shadenet")
        tor = Network(proxies=TOR, using_tor_proxy=True)
        networks = {
            "google": shared,
            "brave": shared,
            "google images": tor,
            "google news": tor,
        }

        class Proc(abstract.EngineProcessor):
            engine_type = "online"

            def search(self, *args, **kwargs):  # pragma: no cover
                pass

        with (
            patch.object(abstract, "get_network", lambda name: networks[name]),
            patch.dict(
                abstract.engines,
                {n: type("E", (), {"name": n, "logger": None}) for n in networks},
            ),
        ):
            procs = {n: Proc(type("E", (), {"name": n})) for n in networks}
        self.assertIsNot(procs["google"].suspended_status, procs["brave"].suspended_status)
        # upstream behavior kept elsewhere: engines on one (non-ShadeNet) network share health
        self.assertIs(
            procs["google images"].suspended_status,
            procs["google news"].suspended_status,
        )


class TestTransportErrorsDoNotSuspend(SearxTestCase):

    def _processor(self, network):
        from searx.search.processors import (
            online,
        )  # pylint: disable=import-outside-toplevel

        engine = type(
            "E",
            (),
            {
                "name": "arxiv",
                "timeout": 6,
                "logger": __import__("logging").getLogger("t"),
            },
        )
        with (
            patch.object(online.searx.network, "get_network", lambda name=None: network),
            patch("searx.search.processors.abstract.get_network", lambda name: network),
            patch.dict("searx.search.processors.abstract.engines", {"arxiv": engine}),
        ):
            proc = online.OnlineProcessor(engine)
        proc.init_network_in_thread = lambda *a: None
        # SUSPENDED_STATUS is keyed by id(network); ids are reused across tests
        proc.suspended_status = SuspendedStatus()
        return proc, online

    def _run(self, network, exc):
        proc, online = self._processor(network)
        proc._search_basic = lambda q, p: (_ for _ in ()).throw(exc)
        rc = ResultContainer()
        with (
            patch.object(online.searx.network, "get_network", lambda name=None: network),
            patch.dict(
                "searx.engines.engines",
                {"arxiv": type("E", (), {"display_error_messages": True})},
            ),
            patch("searx.search.processors.abstract.counter_inc"),
            patch("searx.search.processors.abstract.count_exception"),
            patch("searx.search.processors.abstract.count_error"),
        ):
            proc.search("q", {}, rc, 0, 6)
        return proc.suspended_status.continuous_errors

    def test_isolated_proxy_route(self):
        from curl_cffi.requests.exceptions import (
            Timeout,
            ProxyError,
        )  # pylint: disable=import-outside-toplevel
        from searx.exceptions import (
            SearxEngineCaptchaException,
        )  # pylint: disable=import-outside-toplevel

        isolated = Network(proxies=TOR, using_tor_proxy=True, isolate=True)
        self.assertEqual(self._run(isolated, Timeout("t")), 0)
        self.assertEqual(self._run(isolated, ProxyError("p")), 0)
        self.assertEqual(self._run(isolated, SearxEngineCaptchaException()), 1)  # engine-level: suspend

    def test_unisolated_keeps_upstream(self):
        from curl_cffi.requests.exceptions import (
            Timeout,
        )  # pylint: disable=import-outside-toplevel

        plain = Network(proxies=TOR, using_tor_proxy=True, isolate=False)
        self.assertEqual(self._run(plain, Timeout("t")), 1)


class TestDeadline(SearxTestCase):

    def _search(self, timeout=5.0):
        from searx.search import Search  # pylint: disable=import-outside-toplevel

        search = Search.__new__(Search)
        search.result_container = ResultContainer()
        search.start_time = __import__('timeit').default_timer()
        search.actual_timeout = timeout
        search._deadline_reached = False
        return search

    def _threads(self, *durations):
        threads = [threading.Thread(target=time.sleep, args=(d,)) for d in durations]
        for th in threads:
            th.start()
        return threads

    def setUp(self):
        super().setUp()
        previous = copy.deepcopy(searx.settings['search'])
        self.addCleanup(lambda: searx.settings.__setitem__('search', previous))
        searx.settings['search']['deadline_min_answered'] = 1

    def test_returns_at_deadline_once_answered(self):
        search = self._search()
        search.result_container.note_engine('bing', 'ok', results=10)
        threads = self._threads(0.05, 3.0)
        t0 = time.monotonic()
        search._wait_for_deadline(threads, 0.3)
        self.assertLess(time.monotonic() - t0, 1.0)
        self.assertTrue(search._deadline_reached)

    def test_keeps_waiting_without_answers(self):
        search = self._search(timeout=0.8)
        threads = self._threads(3.0)
        t0 = time.monotonic()
        search._wait_for_deadline(threads, 0.2)
        self.assertGreaterEqual(time.monotonic() - t0, 0.7)  # waited for the upstream timeout
        self.assertFalse(search._deadline_reached)

    def test_all_done_before_deadline(self):
        search = self._search()
        threads = self._threads(0.05)
        t0 = time.monotonic()
        search._wait_for_deadline(threads, 2.0)
        self.assertLess(time.monotonic() - t0, 0.5)
        self.assertFalse(search._deadline_reached)


class TestFreshCircuit(TestTransportErrorsDoNotSuspend):

    def setUp(self):
        super().setUp()
        previous = copy.deepcopy(searx.settings['outgoing'])
        self.addCleanup(lambda: searx.settings.__setitem__('outgoing', previous))
        searx.settings['outgoing']['fresh_circuit_retries'] = 1

    def test_retry_on_fresh_circuit(self):
        from searx.exceptions import SearxEngineTooManyRequestsException  # pylint: disable=import-outside-toplevel

        network = Network(proxies=TOR, using_tor_proxy=True, isolate=True)
        proc, online = self._processor(network)
        seen = []

        def basic(q, p):
            seen.append(searx.network.THREADLOCAL.__dict__.get('isolation'))
            if len(seen) == 1:
                raise SearxEngineTooManyRequestsException()
            return None  # accepted, no results to merge

        proc._search_basic = basic
        rc = ResultContainer()
        searx.network.set_isolation_for_thread('sid:arxiv')
        self.addCleanup(searx.network.set_isolation_for_thread, None)
        with (
            patch.object(online.searx.network, 'get_network', lambda name=None: network),
            patch.dict('searx.engines.engines', {'arxiv': type('E', (), {'display_error_messages': True})}),
            patch('searx.search.processors.abstract.counter_inc'),
            patch('searx.search.processors.abstract.histogram_observe'),
            patch.object(online, 'release_isolation') as release,
        ):
            proc.search('q', {}, rc, __import__('timeit').default_timer(), 6)
        self.assertEqual(seen, ['sid:arxiv', 'sid~1:arxiv'])
        release.assert_called_once_with('sid~1:arxiv')
        self.assertEqual(rc.coverage['arxiv']['fresh_circuits'], 1)
        self.assertEqual(rc.coverage['arxiv']['status'], 'sent')  # no error recorded
        self.assertEqual(proc.suspended_status.continuous_errors, 0)

    def test_no_retry_off_tor(self):
        from searx.exceptions import SearxEngineTooManyRequestsException  # pylint: disable=import-outside-toplevel

        network = Network(proxies=SHADENET, route='shadenet', isolate=True)
        calls = []

        def basic(q, p):
            calls.append(1)
            raise SearxEngineTooManyRequestsException()

        self.assertEqual(self._run_with(network, basic), 1)
        self.assertEqual(len(calls), 1)

    def _run_with(self, network, basic):
        proc, online = self._processor(network)
        proc._search_basic = basic
        rc = ResultContainer()
        searx.network.set_isolation_for_thread('sid:arxiv')
        self.addCleanup(searx.network.set_isolation_for_thread, None)
        with (
            patch.object(online.searx.network, 'get_network', lambda name=None: network),
            patch.dict('searx.engines.engines', {'arxiv': type('E', (), {'display_error_messages': True})}),
            patch('searx.search.processors.abstract.counter_inc'),
            patch('searx.search.processors.abstract.count_exception'),
            patch('searx.search.processors.abstract.count_error'),
        ):
            proc.search('q', {}, rc, __import__('timeit').default_timer(), 6)
        return proc.suspended_status.continuous_errors


class TestImpersonateOverride(TestTransportErrorsDoNotSuspend):

    def test_engine_setting_wins(self):
        network = Network(proxies=TOR, using_tor_proxy=True, isolate=True)
        proc, online = self._processor(network)
        proc.engine.impersonate = 'tor145'
        params = {
            'headers': {},
            'cookies': {},
            'auth': None,
            'impersonate': 'chrome99_android',
            'method': 'GET',
            'url': 'https://example.org/',
        }
        response = type('R', (), {'history': []})()
        with patch.object(online.searx.network, 'get', return_value=response) as get:
            proc._send_http_request(params)
        self.assertEqual(get.call_args.kwargs['impersonate'], 'tor145')


class TestHackernewsAlgolia(SearxTestCase):

    def test_algolia_direct_mode(self):
        from searx.engines import hackernews  # pylint: disable=import-outside-toplevel

        with (
            patch.object(hackernews, 'algolia_app_id', 'UJ5WYC0L7X'),
            patch.object(hackernews, 'algolia_search_key', 'public-search-key'),
        ):
            params = hackernews.request('tor', {'pageno': 1, 'time_range': None, 'headers': {}})
        self.assertTrue(params['url'].startswith('https://uj5wyc0l7x-dsn.algolia.net/1/indexes/Item_dev?'))
        self.assertEqual(params['headers']['X-Algolia-Application-Id'], 'UJ5WYC0L7X')
        self.assertEqual(params['headers']['X-Algolia-API-Key'], 'public-search-key')

    def test_default_mode_unchanged(self):
        from searx.engines import hackernews  # pylint: disable=import-outside-toplevel

        params = hackernews.request('tor', {'pageno': 1, 'time_range': None, 'headers': {}})
        self.assertTrue(params['url'].startswith('https://hn.algolia.com/api/v1/search?'))

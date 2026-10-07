# SPDX-License-Identifier: AGPL-3.0-or-later
# pylint: disable=global-statement
# pylint: disable=missing-module-docstring, missing-class-docstring

__all__ = ["get_network"]

import typing as t
from collections.abc import Generator


import atexit
import asyncio
import hashlib
import time
import ipaddress
from itertools import cycle
from urllib.parse import urlsplit, urlunsplit

from curl_cffi import CurlHttpVersion
from curl_cffi.requests.exceptions import (
    ConnectionError as CurlConnectionError,
    ProxyError,
    RequestException,
)

from searx import logger, sxng_debug
from searx.extended_types import SXNG_Response
from .client import DEFAULT_IMPERSONATE, AsyncClient, new_client, get_loop
from .raise_for_httperror import raise_for_httperror

logger = logger.getChild('network')
DEFAULT_NAME = '__DEFAULT__'
NETWORKS: dict[str, "Network"] = {}
# requests compatibility when reading proxy settings from settings.yml
PROXY_PATTERN_MAPPING = {
    'http': 'http://',
    'https': 'https://',
    'socks4': 'socks4://',
    'socks5': 'socks5://',
    'socks5h': 'socks5h://',
    'http:': 'http://',
    'https:': 'https://',
    'socks4:': 'socks4://',
    'socks5:': 'socks5://',
    'socks5h:': 'socks5h://',
}

ADDRESS_MAPPING = {'ipv4': '0.0.0.0', 'ipv6': '::'}

ROUTES = ('tor', 'shadenet', 'proxy', 'direct')
"""shaded: the egress route of a network.  ``tor`` and ``shadenet`` are proxied
routes, ``proxy`` is any other proxy, ``direct`` is the open internet and must be
chosen explicitly when ``outgoing.require_route`` is set."""


class NoRouteError(ProxyError):
    """shaded: a request on a network that has no permitted route.  Raised instead
    of silently sending the request without a proxy."""


def _isolated_proxy_url(proxy_url: str, isolation: str) -> str:
    """shaded: put a per-isolation SOCKS username on a SOCKS proxy URL.

    Tor's ``IsolateSOCKSAuth`` (on by default) never shares a circuit between
    streams with different SOCKS credentials.  Non-SOCKS proxy URLs are returned
    unchanged: they get a new client (and so a new CONNECT tunnel) per isolation
    id instead."""
    parts = urlsplit(proxy_url)
    if not parts.scheme.startswith('socks'):
        return proxy_url
    user = 'sx' + hashlib.sha256(isolation.encode()).hexdigest()[:24]
    host = parts.hostname or ''
    if ':' in host:
        host = f'[{host}]'
    netloc = f'{user}:x@{host}' + (f':{parts.port}' if parts.port else '')
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


@t.final
class Network:  # pylint: disable=too-many-instance-attributes, too-many-public-methods

    __slots__ = (
        'enable_http',
        'verify',
        'enable_http2',
        'enable_http3',
        'max_connections',
        'local_addresses',
        'proxies',
        'using_tor_proxy',
        'max_redirects',
        'retries',
        'retry_on_http_error',
        'route',
        'isolate',
        'warm',
        'warm_stats',
        '_warm_pool',
        '_warm_in_flight',
        '_warm_used',
        '_local_addresses_cycle',
        '_proxies_cycle',
        '_clients',
        '_iso_keys',
        '_logger',
    )

    _TOR_CHECK_RESULT = {}
    _CLIENT_KWARGS = ('verify', 'max_redirects', 'impersonate', 'curl_options', 'enable_http3')

    def __init__(
        # pylint: disable=too-many-arguments, too-many-positional-arguments
        self,
        enable_http: bool = True,
        verify: bool = True,
        enable_http2: bool = False,
        enable_http3: bool = False,
        max_connections: int = None,  # pyright: ignore[reportArgumentType]
        proxies: str | dict[str, str] | None = None,
        using_tor_proxy: bool = False,
        local_addresses: str | list[str] | None = None,
        retries: int = 0,
        retry_on_http_error: bool = False,
        max_redirects: int = 30,
        logger_name: str = None,  # pyright: ignore[reportArgumentType]
        route: str | None = None,
        require_route: bool = False,
        isolate: bool | str = False,
        warm: dict[str, t.Any] | None = None,
    ):

        self.enable_http = enable_http
        self.verify = verify
        self.enable_http2 = enable_http2
        self.enable_http3 = enable_http3
        self.max_connections = max_connections
        self.proxies = proxies
        self.using_tor_proxy = using_tor_proxy
        self.local_addresses = local_addresses
        self.retries = retries
        self.retry_on_http_error = retry_on_http_error
        self.max_redirects = max_redirects
        self._local_addresses_cycle = self.get_ipaddress_cycle()
        self._proxies_cycle = self.get_proxy_cycles()
        self._clients = {}
        self._iso_keys: dict[str, list[tuple[t.Any, ...]]] = {}
        self._logger = logger.getChild(logger_name) if logger_name else logger
        self.route = self.resolve_route(route, require_route)
        if isolate not in (False, True, 'query', 'engine'):
            raise ValueError("isolate has to be false, true / 'query' or 'engine'")
        self.isolate = 'query' if isolate is True else isolate
        self.warm = warm or None
        self.warm_stats = {'built': 0, 'failed': 0, 'used': 0, 'expired': 0, 'skipped_budget': 0}
        self._warm_pool: list[tuple[float, tuple[t.Any, ...], AsyncClient]] = []
        self._warm_in_flight = 0
        self._warm_used: set[str] = set()
        self.check_parameters()

    def resolve_route(self, route: str | None, require_route: bool) -> str | None:
        """shaded: the network's route, or ``None`` when it may not send anything."""
        if route is not None and route not in ROUTES:
            raise ValueError(f'route has to be one of {ROUTES}, not {route!r}')
        if route == 'direct':
            if self.proxies:
                raise ValueError('route: direct with proxies set')
            return 'direct'
        if not self.proxies:
            if route is not None:
                raise ValueError(f'route: {route} without proxies')
            return None if require_route else 'direct'
        return route or ('tor' if self.using_tor_proxy else 'proxy')

    def check_parameters(self):
        for address in self.iter_ipaddresses():
            if '/' in address:
                ipaddress.ip_network(address, False)
            else:
                ipaddress.ip_address(address)

        if self.proxies is not None and not isinstance(self.proxies, (str, dict)):
            raise ValueError('proxies type has to be str, dict or None')

    def iter_ipaddresses(self) -> Generator[str]:
        local_addresses = self.local_addresses
        if not local_addresses:
            return
        if isinstance(local_addresses, str):
            local_addresses = [local_addresses]
        yield from local_addresses

    def get_ipaddress_cycle(self):
        while True:
            count = 0
            for address in self.iter_ipaddresses():
                if '/' in address:
                    for a in ipaddress.ip_network(address, False).hosts():
                        yield str(a)
                        count += 1
                else:
                    a = ipaddress.ip_address(address)
                    yield str(a)
                    count += 1
            if count == 0:
                yield None

    def iter_proxies(self) -> Generator[tuple[str, list[str]]]:
        if not self.proxies:
            return
        if isinstance(self.proxies, str):
            yield 'all://', [self.proxies]
        else:
            for pattern, proxy_url in self.proxies.items():
                pattern: str = PROXY_PATTERN_MAPPING.get(pattern, pattern)
                if isinstance(proxy_url, str):
                    proxy_url = [proxy_url]
                yield pattern, proxy_url

    def get_proxy_cycles(self) -> Generator[tuple[tuple[str, str], ...], str, str]:  # not sure type is correct
        proxy_settings: dict[str, t.Any] = {}
        for pattern, proxy_urls in self.iter_proxies():
            proxy_settings[pattern] = cycle(proxy_urls)
        while True:
            # pylint: disable=stop-iteration-return
            yield tuple((pattern, next(proxy_url_cycle)) for pattern, proxy_url_cycle in proxy_settings.items())

    _HTTP_VERSION = {
        int(CurlHttpVersion.V1_0): "HTTP/1.0",
        int(CurlHttpVersion.V1_1): "HTTP/1.1",
        int(CurlHttpVersion.V2_0): "HTTP/2",
        int(CurlHttpVersion.V2TLS): "HTTP/2",
        int(CurlHttpVersion.V2_PRIOR_KNOWLEDGE): "HTTP/2",
        int(CurlHttpVersion.V3): "HTTP/3",
        int(CurlHttpVersion.V3ONLY): "HTTP/3",
    }

    async def log_response(self, response: SXNG_Response):
        request = response.request
        http_version = self._HTTP_VERSION.get(response.http_version, str(response.http_version))
        status = f"{response.status_code} {response.reason}"
        response_line = f"{http_version} {status}"
        content_type = response.headers.get("Content-Type")
        content_type = f' ({content_type})' if content_type else ''
        method = request.method if request else "?"
        url = request.url if request else response.url
        self._logger.debug(f'HTTP Request: {method} {url} "{response_line}"{content_type}')

    @staticmethod
    async def check_tor_proxy(client: AsyncClient, proxies) -> bool:
        if proxies in Network._TOR_CHECK_RESULT:
            return Network._TOR_CHECK_RESULT[proxies]

        if not proxies or not all(url.startswith('socks5h://') for _, url in proxies):
            Network._TOR_CHECK_RESULT[proxies] = False
            return False

        response = await client.get("https://check.torproject.org/api/ip", timeout=60)
        result = bool(response.json()["IsTor"])
        Network._TOR_CHECK_RESULT[proxies] = result
        return result

    async def get_client(
        self,
        verify: bool | None = None,
        max_redirects: int | None = None,
        impersonate: str | None = None,
        curl_options: dict[int, t.Any] | None = None,
        enable_http3: bool | None = None,
        isolation: str | None = None,
    ) -> AsyncClient:
        if self.route is None:
            raise NoRouteError('Network configuration problem: no route (outgoing.require_route)')
        if not (self.isolate and self.proxies):
            isolation = None
        verify = self.verify if verify is None else verify
        max_redirects = self.max_redirects if max_redirects is None else max_redirects
        impersonate = impersonate or DEFAULT_IMPERSONATE
        enable_http3 = self.enable_http3 if enable_http3 is None else enable_http3
        local_address = next(self._local_addresses_cycle)
        proxies = next(self._proxies_cycle)  # is a tuple so it can be part of the key
        tor_check_key = proxies
        if isolation is not None:
            # isolation ids are "<search id>:<engine>"; in "query" mode the engines of
            # one search share a Tor circuit (one SOCKS username per search) but still
            # get their own client, so their own ShadeNet tunnel
            circuit = isolation if self.isolate == 'engine' else isolation.split(':', 1)[0]
            proxies = tuple((pattern, _isolated_proxy_url(url, circuit)) for pattern, url in proxies)
        curl_key = tuple(sorted((int(k), v) for k, v in (curl_options or {}).items()))
        key = (verify, max_redirects, local_address, proxies, impersonate, curl_key, enable_http3, isolation)
        if isolation is not None and self.warm and key not in self._clients:
            warm_client = self._take_warm(key[:-1])
            if warm_client is not None:
                self._clients[key] = warm_client
                self._iso_keys.setdefault(isolation, []).append(key)
                self._warm_used.add(isolation)
                return warm_client
        if key not in self._clients or self._clients[key].is_closed:
            client = new_client(
                self.enable_http,
                verify,
                self.enable_http2,
                enable_http3,
                self.max_connections,
                dict(proxies),
                local_address,
                max_redirects,
                impersonate=impersonate,
                curl_options=curl_options,
            )
            if self.using_tor_proxy and not await self.check_tor_proxy(client, tor_check_key):
                await client.aclose()
                raise ProxyError('Network configuration problem: not using Tor')
            self._clients[key] = client
            if isolation is not None:
                self._iso_keys.setdefault(isolation, []).append(key)
        return self._clients[key]

    # -- shaded: warm tunnels --------------------------------------------------
    #
    # ``warm: {size, url, max_age, reserve, impersonate}`` keeps ``size`` clients
    # whose connection through the proxy is already open: each was used for one
    # GET of ``url`` (a page without any query) and is then handed to exactly
    # one search, so connection reuse across searches stays off.  On a ShadeNet
    # route a client is only warmed while the proxy's plan shows more than
    # ``reserve`` tunnels left this epoch.

    def _take_warm(self, key_base: tuple[t.Any, ...]) -> AsyncClient | None:
        max_age = float(self.warm.get('max_age', 40)) if self.warm else 0
        now = time.monotonic()
        for i, (built_at, warm_key, client) in enumerate(self._warm_pool):
            if warm_key == key_base and now - built_at < max_age and not client.is_closed:
                del self._warm_pool[i]
                self.warm_stats['used'] += 1
                return client
        return None

    def warm_used(self, isolation: str) -> bool:
        """True once, when the search with this isolation id ran on a warm client."""
        if isolation in self._warm_used:
            self._warm_used.discard(isolation)
            return True
        return False

    async def _warm_one(self, url: str, impersonate: str):
        self._warm_in_flight += 1
        client = None
        try:
            local_address = next(self._local_addresses_cycle)
            proxies = next(self._proxies_cycle)
            key_base = (self.verify, self.max_redirects, local_address, proxies, impersonate, (), self.enable_http3)
            client = new_client(
                self.enable_http,
                self.verify,
                self.enable_http2,
                self.enable_http3,
                self.max_connections,
                dict(proxies),
                local_address,
                self.max_redirects,
                impersonate=impersonate,
            )
            response = await client.get(url, timeout=30)
            if 200 <= response.status_code < 400:
                self._warm_pool.append((time.monotonic(), key_base, client))
                self.warm_stats['built'] += 1
                client = None
            else:
                self.warm_stats['failed'] += 1
        except RequestException:
            self.warm_stats['failed'] += 1
        finally:
            self._warm_in_flight -= 1
            if client is not None:
                await client.aclose()

    async def warm_loop(self):
        """Keep the warm pool full (runs on the network loop)."""
        from searx.search import shadenet  # pylint: disable=import-outside-toplevel, cyclic-import

        size = int(self.warm.get('size', 2))
        url = self.warm['url']
        max_age = float(self.warm.get('max_age', 40))
        reserve = int(self.warm.get('reserve', 4))
        impersonate = self.warm.get('impersonate') or DEFAULT_IMPERSONATE
        loop = asyncio.get_running_loop()
        while True:
            now = time.monotonic()
            for item in [i for i in self._warm_pool if now - i[0] >= max_age]:
                self._warm_pool.remove(item)
                self.warm_stats['expired'] += 1
                await item[2].aclose()
            missing = size - len(self._warm_pool) - self._warm_in_flight
            if missing > 0:
                plan = await loop.run_in_executor(None, shadenet.plan, 1) if self.route == 'shadenet' else None
                if plan is not None and int(plan.get('availableNow', 0)) <= reserve:
                    self.warm_stats['skipped_budget'] += 1
                else:
                    for _ in range(missing):
                        asyncio.ensure_future(self._warm_one(url, impersonate))
            await asyncio.sleep(1)

    async def release(self, isolation: str):
        """shaded: close the clients of one isolation id (connection reuse OFF)."""
        for key in self._iso_keys.pop(isolation, []):
            client = self._clients.pop(key, None)
            if client is not None:
                try:
                    await client.aclose()
                except RequestException:
                    pass

    async def aclose(self):
        async def close_client(client):
            try:
                await client.aclose()
            except RequestException:
                pass

        await asyncio.gather(*[close_client(client) for client in self._clients.values()], return_exceptions=False)

    @staticmethod
    def extract_kwargs_clients(kwargs: dict[str, t.Any]) -> dict[str, t.Any]:
        return {key: kwargs.pop(key) for key in Network._CLIENT_KWARGS if key in kwargs}

    @staticmethod
    def extract_do_raise_for_httperror(kwargs: dict[str, t.Any]):
        do_raise_for_httperror = True
        if 'raise_for_httperror' in kwargs:
            do_raise_for_httperror = kwargs['raise_for_httperror']
            del kwargs['raise_for_httperror']
        return do_raise_for_httperror

    def patch_response(self, response: SXNG_Response, do_raise_for_httperror: bool) -> SXNG_Response:
        if do_raise_for_httperror:
            try:
                raise_for_httperror(response)
            except:
                method = response.request.method if response.request else "?"
                url = response.request.url if response.request else response.url
                self._logger.warning(f"HTTP Request failed: {method} {url}")
                raise
        return response

    def is_valid_response(self, response: SXNG_Response):
        # pylint: disable=too-many-boolean-expressions
        if (
            (self.retry_on_http_error is True and 400 <= response.status_code <= 599)
            or (isinstance(self.retry_on_http_error, list) and response.status_code in self.retry_on_http_error)
            or (isinstance(self.retry_on_http_error, int) and response.status_code == self.retry_on_http_error)
        ):
            return False
        return True

    async def call_client(self, stream: bool, method: str, url: str, **kwargs: t.Any) -> SXNG_Response:
        retries = self.retries
        was_disconnected = False
        do_raise_for_httperror = Network.extract_do_raise_for_httperror(kwargs)
        kwargs_clients = Network.extract_kwargs_clients(kwargs)
        isolation = kwargs.pop('isolation', None)
        while retries >= 0:  # pragma: no cover
            client = await self.get_client(isolation=isolation, **kwargs_clients)
            try:
                method = method.upper()
                if stream:
                    return client.stream(method, url, **kwargs)

                response = await client.request(method, url, **kwargs)
                if sxng_debug:
                    await self.log_response(response)
                if self.is_valid_response(response) or retries <= 0:
                    return self.patch_response(response, do_raise_for_httperror)
                await client.aclose()
            except CurlConnectionError as e:
                if not was_disconnected:
                    # the server has closed the connection:
                    # try again without decreasing the retries variable & with a new HTTP client
                    was_disconnected = True
                    await client.aclose()
                    self._logger.warning('ConnectionError: the server has disconnected, retrying')
                    continue
                if retries <= 0:
                    raise e
            except RequestException as e:
                if retries <= 0:
                    raise e
            retries -= 1

    async def request(self, method: str, url: str, **kwargs: t.Any) -> SXNG_Response:
        return await self.call_client(False, method, url, **kwargs)

    async def stream(self, method: str, url: str, **kwargs):
        return await self.call_client(True, method, url, **kwargs)

    @classmethod
    async def aclose_all(cls):
        await asyncio.gather(*[network.aclose() for network in NETWORKS.values()], return_exceptions=False)


def get_network(name: str | None = None) -> "Network":
    return NETWORKS.get(name or DEFAULT_NAME)  # pyright: ignore[reportReturnType]


def _start_warm_loops():
    """shaded: start the warm-tunnel loop of every network that asks for one."""
    loop = get_loop()
    if not loop:
        return
    for network in {id(n): n for n in NETWORKS.values()}.values():
        if network.warm and network.route is not None:
            asyncio.run_coroutine_threadsafe(network.warm_loop(), loop)


def release_isolation(isolation: str):
    """shaded: close every client opened for ``isolation`` (does not wait)."""
    loop = get_loop()
    if not loop:
        return
    for network in {id(n): n for n in NETWORKS.values()}.values():
        if isolation in network._iso_keys:  # pylint: disable=protected-access
            asyncio.run_coroutine_threadsafe(network.release(isolation), loop)


def check_network_configuration():
    async def check():
        exception_count = 0
        for network in NETWORKS.values():
            if network.using_tor_proxy and network.route is not None:
                try:
                    await network.get_client()
                except Exception:  # pylint: disable=broad-except
                    network._logger.exception('Error')  # pylint: disable=protected-access
                    exception_count += 1
        return exception_count

    future = asyncio.run_coroutine_threadsafe(check(), get_loop())
    exception_count = future.result()
    if exception_count > 0:
        raise RuntimeError("Invalid network configuration")


def initialize(
    settings_engines: list[dict[str, t.Any]] = None,  # pyright: ignore[reportArgumentType]
    settings_outgoing: dict[str, t.Any] = None,  # pyright: ignore[reportArgumentType]
) -> None:
    # pylint: disable=import-outside-toplevel)
    from searx.engines import engines
    from searx import settings

    # pylint: enable=import-outside-toplevel)

    settings_engines = settings_engines or settings['engines']
    settings_outgoing = settings_outgoing or settings['outgoing']

    default_params: dict[str, t.Any] = {
        'enable_http': False,
        'verify': settings_outgoing['verify'],
        'enable_http2': settings_outgoing['enable_http2'],
        'enable_http3': False,
        'max_connections': settings_outgoing['pool_connections'],
        'local_addresses': settings_outgoing['source_ips'],
        'using_tor_proxy': settings_outgoing['using_tor_proxy'],
        'proxies': settings_outgoing['proxies'],
        'max_redirects': settings_outgoing['max_redirects'],
        'retries': settings_outgoing['retries'],
        'retry_on_http_error': False,
        'require_route': settings_outgoing.get('require_route', False),
        'isolate': settings_outgoing.get('isolate', False),
        'warm': None,
    }

    def new_network(params: dict[str, t.Any], logger_name: str | None = None):
        nonlocal default_params
        result = {}
        result.update(default_params)  # pyright: ignore[reportUnknownMemberType]
        result.update(params)  # pyright: ignore[reportUnknownMemberType]
        if logger_name:
            result['logger_name'] = logger_name
        return Network(**result)  # type: ignore

    def iter_networks():
        nonlocal settings_engines
        for engine_spec in settings_engines:
            engine_name = engine_spec['name']
            engine = engines.get(engine_name)
            if engine is None:
                continue
            network = getattr(engine, 'network', None)
            yield engine_name, engine, network

    if NETWORKS:
        done()
    NETWORKS.clear()
    NETWORKS[DEFAULT_NAME] = new_network({}, logger_name='default')
    NETWORKS['ipv4'] = new_network({'local_addresses': '0.0.0.0'}, logger_name='ipv4')
    NETWORKS['ipv6'] = new_network({'local_addresses': '::'}, logger_name='ipv6')

    # define networks from outgoing.networks
    for network_name, network in settings_outgoing['networks'].items():
        NETWORKS[network_name] = new_network(network, logger_name=network_name)

    # define networks from engines.[i].network (except references)
    for engine_name, engine, network in iter_networks():
        if network is None:
            network = {}
            for attribute_name, attribute_value in default_params.items():
                if hasattr(engine, attribute_name):
                    network[attribute_name] = getattr(engine, attribute_name)
                else:
                    network[attribute_name] = attribute_value
            # shaded: an engine's class default (False) must not switch off the
            # global outgoing.using_tor_proxy (it would also mislabel the route)
            network['using_tor_proxy'] = default_params['using_tor_proxy'] or getattr(engine, 'using_tor_proxy', False)
            NETWORKS[engine_name] = new_network(network, logger_name=engine_name)
        elif isinstance(network, dict):
            NETWORKS[engine_name] = new_network(network, logger_name=engine_name)

    # define networks from engines.[i].network (references)
    for engine_name, engine, network in iter_networks():
        if isinstance(network, str):
            NETWORKS[engine_name] = NETWORKS[network]

    _start_warm_loops()

    # the /image_proxy endpoint has a dedicated network.
    # same parameters than the default network, but HTTP/2 is disabled.
    # It decreases the CPU load average, and the total time is more or less the same
    if 'image_proxy' not in NETWORKS:
        image_proxy_params = default_params.copy()
        image_proxy_params['enable_http2'] = False
        NETWORKS['image_proxy'] = new_network(image_proxy_params, logger_name='image_proxy')


@atexit.register
def done():
    """Close all HTTP client

    Note: since Network.aclose has to be async, it is not possible to call this method on Network.__del__
    So Network.aclose is called here using atexit.register
    """
    try:
        loop = get_loop()
        if loop:
            future = asyncio.run_coroutine_threadsafe(Network.aclose_all(), loop)
            # wait 3 seconds to close the HTTP clients
            future.result(3)
    finally:
        NETWORKS.clear()


NETWORKS[DEFAULT_NAME] = Network()

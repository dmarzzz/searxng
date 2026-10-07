# SPDX-License-Identifier: AGPL-3.0-or-later
"""shaded: spend ShadeNet tunnels deliberately.

A ShadeNet seat opens a fixed number of tunnels per epoch (``limit`` proofs times
the tickets in a session book).  Engines whose network has ``route: shadenet``
are the scarce ones, so a search sends at most
``outgoing.shadenet.max_engines_per_query`` of them, the healthiest first, and
asks the local ``shadenet proxy`` whether the batch can open before the search
times out (``GET /_shadenet/plan?count=N``, ADR 0013 of shade-tree-node).

If the plan endpoint does not answer, the engines are sent anyway: a proxy that
is down makes them fail (the network has no other route), it never makes them go
direct.
"""

from __future__ import annotations

__all__ = ["is_shadenet", "allowed_engines", "plan"]

import typing as t

import json
import threading
import urllib.request
from timeit import default_timer

from searx import get_setting, logger
from searx.network import get_network

if t.TYPE_CHECKING:
    from searx.search.processors.abstract import EngineProcessor

logger = logger.getChild("shadenet")

_PLAN_CACHE_SECONDS = 1.0
_plan_lock = threading.Lock()
_plan_cache: dict[int, tuple[float, dict[str, t.Any] | None]] = {}


def is_shadenet(engine_name: str) -> bool:
    network = get_network(engine_name)
    return network is not None and network.route == "shadenet"


def max_engines_per_query() -> int:
    return int(get_setting("outgoing.shadenet.max_engines_per_query", 1))


def allowed_engines(candidates: list[tuple[str, "EngineProcessor"]]) -> set[str]:
    """The ShadeNet engines this search may use: not suspended, fewest continuous
    errors first, then settings order."""
    healthy = [
        (processor.suspended_status.continuous_errors, index, name)
        for index, (name, processor) in enumerate(candidates)
        if not processor.suspended_status.is_suspended
    ]
    healthy.sort()
    return {name for _, _, name in healthy[: max_engines_per_query()]}


_pace_lock = threading.Lock()
_last_sent: dict[str, float] = {}


def paced(engine_name: str) -> bool:
    """True when ``engine_name`` was sent less than ``outgoing.shadenet.min_interval``
    seconds ago; otherwise record this send and return False.

    The proxy does not say which canopy node a tunnel used, and a session book
    sends all its tickets to one node, so this paces per engine; with the proxy's
    rotation across nodes that bounds each node's rate too."""
    min_interval = float(get_setting("outgoing.shadenet.min_interval", 0) or 0)
    if min_interval <= 0:
        return False
    now = default_timer()
    with _pace_lock:
        if now - _last_sent.get(engine_name, float("-inf")) < min_interval:
            return True
        _last_sent[engine_name] = now
        return False


def _token() -> str | None:
    token_file = get_setting("outgoing.shadenet.token_file", None)
    if not token_file:
        return None
    try:
        with open(token_file, encoding="utf-8") as f:
            return f.read().strip()
    except OSError as e:
        logger.warning("cannot read outgoing.shadenet.token_file: %s", e)
        return None


def plan(count: int, timeout: float = 1.0) -> dict[str, t.Any] | None:
    """``GET /_shadenet/plan?count=N`` on the local proxy, cached for a second.
    Returns ``None`` when the proxy is not configured or does not answer."""
    base_url = get_setting("outgoing.shadenet.url", None)
    if not base_url or count <= 0:
        return None
    now = default_timer()
    with _plan_lock:
        cached = _plan_cache.get(count)
        if cached and now - cached[0] < _PLAN_CACHE_SECONDS:
            return cached[1]
    request = urllib.request.Request(f"{base_url.rstrip('/')}/_shadenet/plan?count={count}")
    token = _token()
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    # the proxy is on loopback: never route this call through an environment proxy
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    result: dict[str, t.Any] | None
    try:
        with opener.open(request, timeout=timeout) as response:
            result = json.loads(response.read())
    except (OSError, ValueError) as e:
        logger.warning("shadenet plan unavailable: %s", e)
        result = None
    with _plan_lock:
        _plan_cache[count] = (now, result)
    return result


def fits(plan_result: dict[str, t.Any] | None, timeout: float) -> bool:
    """True when a batch can open before ``timeout`` seconds (or nothing is known)."""
    if plan_result is None:
        return True
    if plan_result.get("fitsNow"):
        return True
    return float(plan_result.get("completesInSeconds", 0)) < timeout

# SPDX-License-Identifier: AGPL-3.0-or-later
"""shaded: a pool of pre-built, isolated Tor circuits.

With ``outgoing.isolate`` every search gets its own SOCKS username and so its
own Tor circuit.  Building that circuit inside the search costs seconds of the
engines' timeout.  This pool builds circuits ahead of time: a worker picks a
fresh random key, sends one small request with the SOCKS username derived from
it (:py:func:`searx.network.network._isolated_proxy_url`), and queues the key.
A search takes a key from the pool and uses it as its isolation id, so its
engines start on a circuit Tor has already built; every key is handed out once.

Tor keeps reusing a circuit for one SOCKS username until it is
``MaxCircuitDirtiness`` (10 minutes by default) old, counted from its first
stream, so keys older than ``max_age`` are dropped.
"""

from __future__ import annotations

__all__ = ["CircuitPool", "take", "start"]

import queue
import threading
import time
import uuid

from curl_cffi import requests as curl_requests

from searx import logger
from .network import _isolated_proxy_url

logger = logger.getChild('circuits')

WARM_URL = 'https://check.torproject.org/api/ip'


class CircuitPool:
    """Keeps up to ``size`` warmed circuit keys, built by ``builders`` threads."""

    def __init__(self, proxy_url: str, size: int = 12, builders: int = 4, max_age: float = 480.0):
        self.proxy_url = proxy_url
        self.size = size
        self.max_age = max_age
        self._keys: queue.Queue[tuple[float, str]] = queue.Queue()
        self._stop = threading.Event()
        self.built = 0
        self.failed = 0
        self.taken = 0
        self.misses = 0
        self._threads = [
            threading.Thread(target=self._build_loop, name=f'circuit-pool-{i}', daemon=True) for i in range(builders)
        ]

    def start(self):
        for th in self._threads:
            th.start()

    def stop(self):
        self._stop.set()

    def warm(self, key: str) -> bool:
        proxy = _isolated_proxy_url(self.proxy_url, key)
        try:
            response = curl_requests.get(WARM_URL, proxy=proxy, timeout=30, impersonate='chrome')
            return response.status_code == 200
        except Exception:  # pylint: disable=broad-except
            return False

    def _build_loop(self):
        while not self._stop.is_set():
            if self._keys.qsize() >= self.size:
                self._stop.wait(0.5)
                continue
            key = uuid.uuid4().hex
            if self.warm(key):
                self._keys.put((time.monotonic(), key))
                self.built += 1
            else:
                self.failed += 1
                self._stop.wait(1.0)

    def take(self) -> str | None:
        """A warmed key, or ``None`` when the pool is empty (build one inline)."""
        while True:
            try:
                built_at, key = self._keys.get_nowait()
            except queue.Empty:
                self.misses += 1
                return None
            if time.monotonic() - built_at < self.max_age:
                self.taken += 1
                return key

    def stats(self) -> dict[str, int]:
        return {
            'ready': self._keys.qsize(),
            'built': self.built,
            'failed': self.failed,
            'taken': self.taken,
            'misses': self.misses,
        }


POOL: CircuitPool | None = None


def start(proxy_url: str, size: int, builders: int = 4):
    """Start the process-wide pool (idempotent)."""
    global POOL  # pylint: disable=global-statement
    if POOL is None and size > 0:
        POOL = CircuitPool(proxy_url, size=size, builders=builders)
        POOL.start()
        logger.info('circuit pool: %i circuits, %i builders', size, builders)


def take() -> str | None:
    return POOL.take() if POOL is not None else None

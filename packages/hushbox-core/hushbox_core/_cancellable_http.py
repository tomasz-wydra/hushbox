# SPDX-License-Identifier: Apache-2.0
"""Cancellable HTTP for the relay poller thread, without abandoning requests.

The API stays synchronous for :class:`~hushbox_core.relay_auth.RelaySession`.
Internally each request runs on its own short-lived event loop with
``httpx.AsyncClient``, so another thread can cancel the wait on the socket and
the socket is closed by the thread that owns it. We never close a synchronous
HTTP client from a foreign thread, and we never "cancel" by merely giving up
on a future while the request keeps running.
"""
from __future__ import annotations

import asyncio
import threading

import httpx

from .errors import RelayRequestStopped


class CancellableRelayHTTP:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stopping = False
        self._active: dict[asyncio.Task, asyncio.AbstractEventLoop] = {}

    @property
    def stopping(self) -> bool:
        with self._lock:
            return self._stopping

    def cancel_pending(self) -> None:
        """Cancel running requests and refuse new ones. Non-blocking (safe to
        call from a GUI thread); each request is cancelled at most once."""
        with self._lock:
            if self._stopping:
                return
            self._stopping = True
            for task, loop in self._active.items():
                loop.call_soon_threadsafe(task.cancel)

    def request(
        self, method: str, url: str, *, timeout: float,
        allow_shutdown: bool = False, **kwargs,
    ) -> httpx.Response:
        """Send one request with an overall deadline of ``timeout`` seconds.

        :param allow_shutdown: run even after :meth:`cancel_pending` and do not
            register for cancellation (used for the best-effort logout).
        :raises RelayRequestStopped: cancelled by :meth:`cancel_pending`.
        :raises httpx.TimeoutException: the overall deadline passed.
        """
        try:
            return asyncio.run(self._request(
                method, url, timeout=timeout, allow_shutdown=allow_shutdown, **kwargs,
            ))
        except asyncio.CancelledError:
            raise RelayRequestStopped from None
        except TimeoutError:
            raise httpx.TimeoutException("relay request deadline") from None

    async def _request(
        self, method: str, url: str, *, timeout: float,
        allow_shutdown: bool, **kwargs,
    ) -> httpx.Response:
        task = asyncio.current_task()
        assert task is not None
        with self._lock:
            if self._stopping and not allow_shutdown:
                raise RelayRequestStopped
            if not allow_shutdown:
                self._active[task] = asyncio.get_running_loop()
        try:
            # Deadline for the whole request, not only for each read. TLS
            # verification stays at the httpx default; redirects are never
            # followed, so a token cannot be forwarded to another origin.
            async with asyncio.timeout(timeout):
                async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
                    return await client.request(method, url, **kwargs)
        finally:
            with self._lock:
                self._active.pop(task, None)

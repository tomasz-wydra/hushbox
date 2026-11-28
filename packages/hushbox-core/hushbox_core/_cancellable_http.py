# SPDX-License-Identifier: Apache-2.0
"""Cancellable HTTP for the relay poller thread, without abandoning requests.

The API stays synchronous for :class:`~hushbox_core.relay_auth.RelaySession`.
Internally one background thread per instance runs an event loop that owns a
single ``httpx.AsyncClient``, so consecutive requests (login, long poll, ACK,
next poll, logout) reuse a kept-alive connection instead of a new TCP and TLS
handshake each time.

Cancellation is unchanged in spirit: another thread cancels the *task* on the
loop that owns the socket, and the caller waits until that task has really
finished. We never close an HTTP client from a foreign thread, and we never
"cancel" by merely giving up on a future while the request keeps running.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import threading

import httpx

from .errors import RelayRequestStopped

# Extra time a caller waits beyond the request deadline before giving up on a
# loop that does not answer (should never happen; prevents a hung caller).
_RESULT_GRACE = 5.0
_SHUTDOWN_TIMEOUT = 2.0


class CancellableRelayHTTP:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stopping = False
        self._closed = False
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._client: httpx.AsyncClient | None = None   # touched only on the loop
        self._active: set[asyncio.Task] = set()

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
            self._cancel_active_locked()

    def close(self) -> None:
        """Cancel everything, close the connection pool and stop the loop
        thread. Idempotent. Blocks for at most about two seconds."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._stopping = True
            self._cancel_active_locked()
            loop, thread = self._loop, self._thread
        if loop is None or thread is None:
            return
        try:
            asyncio.run_coroutine_threadsafe(self._shutdown(), loop).result(
                _SHUTDOWN_TIMEOUT
            )
        except Exception:  # noqa: BLE001 - shutdown is best effort
            pass
        loop.call_soon_threadsafe(loop.stop)
        if thread is not threading.current_thread():
            thread.join(_SHUTDOWN_TIMEOUT)

    def request(
        self, method: str, url: str, *, timeout: float,
        allow_shutdown: bool = False, **kwargs,
    ) -> httpx.Response:
        """Send one request with an overall deadline of ``timeout`` seconds.

        :param allow_shutdown: run even after :meth:`cancel_pending` and do not
            register for cancellation (used for the best-effort logout). Never
            runs after :meth:`close`.
        :raises RelayRequestStopped: cancelled by :meth:`cancel_pending` or
            :meth:`close`.
        :raises httpx.TimeoutException: the overall deadline passed.
        """
        with self._lock:
            if self._closed or (self._stopping and not allow_shutdown):
                raise RelayRequestStopped
            loop = self._ensure_loop_locked()
            future = asyncio.run_coroutine_threadsafe(
                self._request(method, url, timeout=timeout,
                              allow_shutdown=allow_shutdown, **kwargs),
                loop,
            )
        try:
            return future.result(timeout + _RESULT_GRACE)
        except (asyncio.CancelledError, concurrent.futures.CancelledError):
            raise RelayRequestStopped from None
        except (TimeoutError, concurrent.futures.TimeoutError):
            future.cancel()
            raise httpx.TimeoutException("relay request deadline") from None

    # ── internals ────────────────────────────────────────────────
    def _cancel_active_locked(self) -> None:
        if self._loop is not None:
            for task in self._active:
                self._loop.call_soon_threadsafe(task.cancel)

    def _ensure_loop_locked(self) -> asyncio.AbstractEventLoop:
        if self._loop is None:
            loop = asyncio.new_event_loop()
            thread = threading.Thread(
                target=self._run_loop, args=(loop,), daemon=True, name="RelayHTTP",
            )
            thread.start()
            self._loop, self._thread = loop, thread
        return self._loop

    @staticmethod
    def _run_loop(loop: asyncio.AbstractEventLoop) -> None:
        asyncio.set_event_loop(loop)
        try:
            loop.run_forever()
        finally:
            loop.close()

    def _get_client(self) -> httpx.AsyncClient:
        # Called only on the loop thread. TLS verification stays at the httpx
        # default; redirects are never followed, so a token cannot be
        # forwarded to another origin.
        if self._client is None:
            self._client = httpx.AsyncClient(follow_redirects=False)
        return self._client

    async def _request(
        self, method: str, url: str, *, timeout: float,
        allow_shutdown: bool, **kwargs,
    ) -> httpx.Response:
        task = asyncio.current_task()
        assert task is not None
        with self._lock:
            if self._closed or (self._stopping and not allow_shutdown):
                raise RelayRequestStopped
            if not allow_shutdown:
                self._active.add(task)
        try:
            # Deadline for the whole request, not only for each read.
            async with asyncio.timeout(timeout):
                # Non-streaming: the body is read here, on the loop, and the
                # connection is back in the pool before the caller sees it.
                return await self._get_client().request(
                    method, url, timeout=timeout, **kwargs,
                )
        finally:
            with self._lock:
                self._active.discard(task)

    async def _shutdown(self) -> None:
        current = asyncio.current_task()
        tasks = [t for t in asyncio.all_tasks() if t is not current]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if self._client is not None:
            await self._client.aclose()
            self._client = None

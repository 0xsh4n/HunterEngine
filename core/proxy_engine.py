"""
Embedded mitmproxy integration.

Runs mitmproxy in-process as a transparent intercepting proxy.
All browser and HTTP client traffic routes through it for logging,
modification, and passive analysis.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

logger = logging.getLogger("hunterengine.proxy")


@dataclass
class ProxyRequest:
    """Captured request record."""
    id: int
    timestamp: float
    method: str
    url: str
    headers: dict[str, str]
    body: Optional[bytes]
    host: str
    path: str
    query: str


@dataclass
class ProxyResponse:
    """Captured response record."""
    request_id: int
    timestamp: float
    status_code: int
    headers: dict[str, str]
    body: bytes
    content_type: str


@dataclass
class ProxyConfig:
    listen_host: str = "127.0.0.1"
    listen_port: int = 8080
    auto_port: bool = True
    upstream_proxy: str = ""
    log_requests: bool = True
    max_history: int = 10000
    intercept_mode: bool = False


class ProxyEngine:
    """
    In-process mitmproxy providing Burp-equivalent capabilities:

    - Full request/response logging (History)
    - Request interception and modification (Intercept)
    - Response pattern scanning (passive Scanner)
    - Request replay with modifications (Repeater)
    """

    def __init__(self, config: Optional[ProxyConfig] = None) -> None:
        self.config = config or ProxyConfig()
        self._request_counter = 0
        self._history: deque[tuple[ProxyRequest, Optional[ProxyResponse]]] = deque(
            maxlen=self.config.max_history
        )
        self._request_hooks: list[Callable] = []
        self._response_hooks: list[Callable] = []
        self._running = False
        self._master: Any = None

    # ── Hook registration ─────────────────────────────────────────────────

    def on_request(self, callback: Callable[[ProxyRequest], Optional[dict]]) -> None:
        """
        Register a request hook.
        Callback receives a ProxyRequest and can return a dict of modifications:
            {"headers": {...}, "body": b"...", "url": "..."}
        """
        self._request_hooks.append(callback)

    def on_response(self, callback: Callable[[ProxyRequest, ProxyResponse], None]) -> None:
        """Register a response hook for passive analysis."""
        self._response_hooks.append(callback)

    # ── Lifecycle ─────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start the mitmproxy instance in a background thread."""
        try:
            from mitmproxy import options
        except ImportError:
            logger.warning("mitmproxy not installed — proxy features disabled")
            return

        if not is_port_available(self.config.listen_host, self.config.listen_port):
            if self.config.auto_port:
                new_port = find_available_port(self.config.listen_host, self.config.listen_port + 1)
                logger.warning(
                    "Proxy port %s:%s is in use; switching to %s",
                    self.config.listen_host,
                    self.config.listen_port,
                    new_port,
                )
                self.config.listen_port = new_port
            else:
                logger.warning(
                    "Proxy port %s:%s is in use — proxy features disabled",
                    self.config.listen_host,
                    self.config.listen_port,
                )
                return

        self._running = True
        logger.info(
            f"Proxy engine starting on {self.config.listen_host}:{self.config.listen_port}"
        )

        opts = options.Options(
            listen_host=self.config.listen_host,
            listen_port=self.config.listen_port,
        )
        if self.config.upstream_proxy:
            opts.update(mode=[f"upstream:{self.config.upstream_proxy}"])

        # Start in background thread to not block asyncio
        loop = asyncio.get_event_loop()
        loop.run_in_executor(None, self._run_proxy, opts)

    def _run_proxy(self, opts) -> None:
        """Run mitmproxy (blocking — call from executor)."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            from mitmproxy.tools.dump import DumpMaster

            m = DumpMaster(opts, loop=loop, with_termlog=False, with_dumper=False)
            m.addons.add(self._make_addon())
            self._master = m
            loop.run_until_complete(m.run())
        except BaseException as e:
            self._running = False
            _remove_mitmproxy_log_handlers()
            if isinstance(e, SystemExit):
                logger.error("Proxy failed to start and exited during mitmproxy startup")
            else:
                logger.error(f"Proxy failed to start: {e}")
        finally:
            _remove_mitmproxy_log_handlers()
            if not loop.is_closed():
                loop.close()

    def _make_addon(self):
        """Create mitmproxy addon that bridges to our hook system."""
        engine = self

        class HunterAddon:
            def request(self, flow):
                req = ProxyRequest(
                    id=engine._next_id(),
                    timestamp=time.time(),
                    method=flow.request.method,
                    url=flow.request.url,
                    headers=dict(flow.request.headers),
                    body=flow.request.content,
                    host=flow.request.host,
                    path=flow.request.path,
                    query=flow.request.query or "",
                )
                # Run request hooks
                for hook in engine._request_hooks:
                    try:
                        mods = hook(req)
                        if mods:
                            if "headers" in mods:
                                flow.request.headers.update(mods["headers"])
                            if "body" in mods:
                                flow.request.content = mods["body"]
                            if "url" in mods:
                                flow.request.url = mods["url"]
                    except Exception as e:
                        logger.error(f"Request hook error: {e}")

                flow._hunter_request = req

            def response(self, flow):
                req = getattr(flow, "_hunter_request", None)
                if not req:
                    return

                resp = ProxyResponse(
                    request_id=req.id,
                    timestamp=time.time(),
                    status_code=flow.response.status_code,
                    headers=dict(flow.response.headers),
                    body=flow.response.content or b"",
                    content_type=flow.response.headers.get("content-type", ""),
                )

                engine._history.append((req, resp))

                for hook in engine._response_hooks:
                    try:
                        hook(req, resp)
                    except Exception as e:
                        logger.error(f"Response hook error: {e}")

        return HunterAddon()

    async def stop(self) -> None:
        if self._master:
            try:
                loop = getattr(self._master, "event_loop", None)
                if loop is not None and not loop.is_closed():
                    self._master.shutdown()
            except RuntimeError as e:
                logger.debug(f"Proxy shutdown skipped: {e}")
            finally:
                _remove_mitmproxy_log_handlers()
        self._running = False

    # ── History & Replay ──────────────────────────────────────────────────

    def get_history(
        self,
        host_filter: Optional[str] = None,
        method_filter: Optional[str] = None,
        status_filter: Optional[int] = None,
        limit: int = 100,
    ) -> list[tuple[ProxyRequest, Optional[ProxyResponse]]]:
        """Query proxy history with optional filters."""
        results = []
        for req, resp in reversed(self._history):
            if host_filter and host_filter not in req.host:
                continue
            if method_filter and req.method != method_filter.upper():
                continue
            if status_filter and resp and resp.status_code != status_filter:
                continue
            results.append((req, resp))
            if len(results) >= limit:
                break
        return results

    async def replay(
        self,
        request: ProxyRequest,
        modifications: Optional[dict] = None,
    ) -> Optional[ProxyResponse]:
        """
        Replay a captured request with optional modifications.
        Equivalent to Burp Repeater.
        """
        import httpx

        headers = dict(request.headers)
        body = request.body
        url = request.url
        method = request.method

        if modifications:
            headers.update(modifications.get("headers", {}))
            body = modifications.get("body", body)
            url = modifications.get("url", url)
            method = modifications.get("method", method)

        async with httpx.AsyncClient(verify=False) as client:
            resp = await client.request(
                method=method,
                url=url,
                headers=headers,
                content=body,
            )

        return ProxyResponse(
            request_id=request.id,
            timestamp=time.time(),
            status_code=resp.status_code,
            headers=dict(resp.headers),
            body=resp.content,
            content_type=resp.headers.get("content-type", ""),
        )

    def _next_id(self) -> int:
        self._request_counter += 1
        return self._request_counter

    @property
    def is_running(self) -> bool:
        return self._running


def is_port_available(host: str, port: int) -> bool:
    """Return True when host:port can be bound."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError:
            return False
        return True


def find_available_port(host: str, start_port: int, max_tries: int = 100) -> int:
    """Find the first bindable TCP port at or above start_port."""
    for port in range(start_port, start_port + max_tries):
        if is_port_available(host, port):
            return port
    raise RuntimeError(f"No available proxy port found after {start_port + max_tries - 1}")


def _remove_mitmproxy_log_handlers() -> None:
    """Detach mitmproxy's transient logging handlers after embedded shutdown/failure."""
    for log in [logging.getLogger(), logging.getLogger("mitmproxy")]:
        for handler in list(log.handlers):
            module = handler.__class__.__module__
            if module.startswith("mitmproxy."):
                log.removeHandler(handler)

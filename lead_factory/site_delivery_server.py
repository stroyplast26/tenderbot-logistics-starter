"""Explicit stdlib HTTP server wrapper for the website-delivery boundary."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Type

from .site_delivery_runtime import SiteDeliveryEndpoint, json_response


SITE_DELIVERY_PATH = "/v1/site-deliveries"


def build_http_handler(endpoint: SiteDeliveryEndpoint) -> Type[BaseHTTPRequestHandler]:
    """Build a handler that exposes one POST-only endpoint and no request logs."""

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *_args: object) -> None:
            # Request paths and headers can contain personal or secret data.
            return

        def do_POST(self) -> None:  # noqa: N802
            if self.path != SITE_DELIVERY_PATH:
                self._send(404, b'{"accepted":false,"reason":"not_found"}')
                return
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._send(400, b'{"accepted":false,"reason":"length"}')
                return
            if length < 1 or length > 128 * 1024:
                self._send(413, b'{"accepted":false,"reason":"body"}')
                return
            body = self.rfile.read(length)
            result = endpoint.handle(dict(self.headers.items()), body)
            self._send(result.status_code, json_response(result))

        def _send(self, status: int, payload: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    return Handler


def create_server(
    endpoint: SiteDeliveryEndpoint, *, host: str = "127.0.0.1", port: int = 8088
) -> ThreadingHTTPServer:
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("site delivery port is invalid")
    return ThreadingHTTPServer((host, port), build_http_handler(endpoint))


__all__ = ["SITE_DELIVERY_PATH", "build_http_handler", "create_server"]

"""ASGI middleware enforcing a hard 512 KB request body limit.

Rejects bodies over the limit BEFORE the application buffers them,
returning a structured RFC 7807-style 413 response.

Two enforcement layers:
1. Content-Length header check — immediate rejection on first message.
2. Byte-counting during receive — catches chunked/streaming uploads.
"""
from __future__ import annotations

import json
from typing import Any, Awaitable, Callable

MAX_BYTES: int = 512 * 1024  # 512 KB

_413_BODY = json.dumps({
    "type": "https://pipelineshield.internal/errors/payload-too-large",
    "title": "Payload Too Large",
    "status": 413,
    "detail": (
        "The request body exceeds the 512 KB limit (524,288 bytes). "
        "Reduce the payload to at or below 512 KB."
    ),
    "constraint": "max_bytes=524288",
}).encode()


class BodySizeLimitMiddleware:
    """ASGI middleware that enforces a maximum request body size.

    Usage::

        app.add_middleware(BodySizeLimitMiddleware, max_bytes=524288)
    """

    def __init__(
        self,
        app: Callable[..., Awaitable[None]],
        max_bytes: int = MAX_BYTES,
    ) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method: str = scope.get("method", "")
        if method not in ("POST", "PUT", "PATCH"):
            await self.app(scope, receive, send)
            return

        # Layer 1: Content-Length header check (fast path)
        headers: dict[bytes, bytes] = {
            k.lower(): v for k, v in scope.get("headers", [])
        }
        cl_header = headers.get(b"content-length")
        if cl_header:
            try:
                if int(cl_header) > self.max_bytes:
                    await self._send_413(send)
                    return
            except ValueError:
                pass

        # Layer 2: Buffer the full body, counting bytes
        body_parts: list[bytes] = []
        total = 0
        while True:
            message = await receive()
            chunk = message.get("body", b"")
            total += len(chunk)
            if total > self.max_bytes:
                await self._send_413(send)
                return
            body_parts.append(chunk)
            if not message.get("more_body", False):
                break

        full_body = b"".join(body_parts)

        # Re-inject the buffered body for the application
        body_sent = False

        async def _cached_receive() -> dict[str, Any]:
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {"type": "http.request", "body": full_body, "more_body": False}
            return {"type": "http.disconnect"}

        await self.app(scope, _cached_receive, send)

    @staticmethod
    async def _send_413(
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(_413_BODY)).encode()),
            ],
        })
        await send({
            "type": "http.response.body",
            "body": _413_BODY,
            "more_body": False,
        })

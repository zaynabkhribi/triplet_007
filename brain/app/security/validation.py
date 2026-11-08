from datetime import UTC, datetime

from fastapi import HTTPException
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send


def require_reasonable_timestamp(timestamp: datetime, maximum_age_seconds: int) -> None:
    age = (datetime.now(UTC) - timestamp).total_seconds()
    if age < -30 or age > maximum_age_seconds:
        raise HTTPException(422, "event timestamp is outside the accepted window")


class RequestLimitMiddleware:
    def __init__(self, app: ASGIApp, limit: int) -> None:
        self.app, self.limit = app, limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return
        headers = dict(scope["headers"])
        if headers.get(b"content-type", b"").split(b";")[0].strip() != b"application/json":
            await JSONResponse({"detail": "application/json required"}, 415)(scope, receive, send)
            return
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > self.limit:
                await JSONResponse({"detail": "request too large"}, 413)(scope, receive, send)
                return
            if not message.get("more_body", False):
                break

        async def buffered_receive() -> dict:
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, buffered_receive, send)

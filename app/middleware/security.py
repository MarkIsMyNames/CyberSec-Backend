from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.config import config

TIME_FOR_ENFORCED_HTTP: bytes = ("max-age=%d; includeSubDomains" % config["server"]["time_for_enforced_http"]).encode()
BLOCK_FRAMING: bytes = config["server"]["block_framing"].encode()
BLOCK_CONTENT_SNIFFING: bytes = config["server"]["block_content_sniffing"].encode()
ALLOWED_CONTENT_SOURCES: bytes = config["server"]["allowed_content_sources"].encode()
REFERRER_EXPOSURE: bytes = config["server"]["referrer_exposure"].encode()


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = dict(message.get("headers", []))
                headers[b"strict-transport-security"] = TIME_FOR_ENFORCED_HTTP
                headers[b"x-frame-options"] = BLOCK_FRAMING
                headers[b"x-content-type-options"] = BLOCK_CONTENT_SNIFFING
                headers[b"content-security-policy"] = ALLOWED_CONTENT_SOURCES
                headers[b"referrer-policy"] = REFERRER_EXPOSURE
                headers.pop(b"server", None)
                message = {**message, "headers": list(headers.items())}
            await send(message)

        await self._app(scope, receive, send_with_headers)

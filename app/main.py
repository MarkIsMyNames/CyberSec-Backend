from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from http import HTTPStatus

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded

from app.api import auth, groups, keys, messages
from app.auth.rate_limit import limiter
from app.database import init_db
from app.logger import logger
from app.middleware.security import SecurityHeadersMiddleware
from app.vault import load_secrets


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    load_secrets()
    init_db()
    yield


fastapi = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
fastapi.state.limiter = limiter

fastapi.include_router(auth.router, prefix="/api/v1/auth")
fastapi.include_router(keys.router, prefix="/api/v1/keys")
fastapi.include_router(messages.router, prefix="/api/v1/messages")
fastapi.include_router(groups.router, prefix="/api/v1/groups")


@fastapi.get("/health", status_code=HTTPStatus.OK)
async def health() -> dict[str, str]:
    return {"status": "ok"}


@fastapi.exception_handler(RateLimitExceeded)
async def rate_limit_exceeded_handler(
    request: Request, exc: RateLimitExceeded
) -> JSONResponse:
    logger.warning(
        "rate limit exceeded key=%s path=%s detail=%s",
        request.state.view_rate_limit,
        request.url.path,
        exc.detail,
    )
    return JSONResponse(
        {"error": "Rate limit exceeded: %s" % exc.detail},
        status_code=HTTPStatus.TOO_MANY_REQUESTS,
    )


application = SecurityHeadersMiddleware(fastapi)

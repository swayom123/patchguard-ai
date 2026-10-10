from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from hmac import compare_digest

from fastapi import FastAPI
from starlette.middleware.base import RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from patchguard.apps.api.routes import router
from patchguard.core.config import Settings, get_settings
from patchguard.core.logging import configure_logging
from patchguard.storage.database import create_database_engine, create_session_factory


def create_app(settings: Settings | None = None) -> FastAPI:
    active_settings = settings or get_settings()
    configure_logging(level=active_settings.log_level, json_output=active_settings.log_json)
    engine = create_database_engine(active_settings.database_url)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        engine.dispose()

    production = active_settings.environment.casefold() == "production"
    application = FastAPI(
        title="PatchGuard AI",
        description="Defensive vulnerability discovery and patch verification platform",
        version="0.1.0",
        lifespan=lifespan,
        docs_url=None if production else "/docs",
        redoc_url=None if production else "/redoc",
        openapi_url=None if production else "/openapi.json",
    )
    application.state.settings = active_settings
    application.state.engine = engine
    application.state.session_factory = create_session_factory(engine)
    application.include_router(router)

    @application.middleware("http")
    async def authenticate_api(request: Request, call_next: RequestResponseEndpoint) -> Response:
        configured_token = active_settings.api_auth_token
        if configured_token is None or request.url.path == "/health":
            return await call_next(request)
        authorization = request.headers.get("authorization", "")
        scheme, separator, supplied_token = authorization.partition(" ")
        expected_token = configured_token.get_secret_value()
        if (
            not separator
            or scheme.casefold() != "bearer"
            or not compare_digest(supplied_token.strip().encode(), expected_token.encode())
        ):
            return JSONResponse(
                {"detail": "authentication required"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
        return await call_next(request)

    return application


app = create_app()

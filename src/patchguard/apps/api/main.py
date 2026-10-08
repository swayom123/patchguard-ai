from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

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

    application = FastAPI(
        title="PatchGuard AI",
        description="Defensive vulnerability discovery and patch verification platform",
        version="0.1.0",
        lifespan=lifespan,
    )
    application.state.settings = active_settings
    application.state.engine = engine
    application.state.session_factory = create_session_factory(engine)
    application.include_router(router)

    return application


app = create_app()

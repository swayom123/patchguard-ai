from collections.abc import AsyncGenerator

from fastapi import Request
from sqlalchemy.orm import Session

from patchguard.core.config import Settings


async def get_session(request: Request) -> AsyncGenerator[Session, None]:
    with request.app.state.session_factory() as session:
        yield session


async def get_app_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings

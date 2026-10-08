from patchguard.core.config import Settings
from patchguard.models.providers import (
    DisabledModelProvider,
    ModelProvider,
    OpenAICompatibleProvider,
)


def build_model_provider(settings: Settings) -> ModelProvider:
    if settings.model_base_url and settings.model_api_key and settings.model_name:
        return OpenAICompatibleProvider(
            base_url=settings.model_base_url,
            api_key=settings.model_api_key.get_secret_value(),
            model_name=settings.model_name,
        )
    return DisabledModelProvider()

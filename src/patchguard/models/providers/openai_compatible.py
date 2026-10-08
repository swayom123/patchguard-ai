"""Minimal OpenAI-compatible structured-output adapter, opt-in by configuration."""

import json
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from patchguard.domain.analysis import ModelAssessment
from patchguard.models.providers.base import ModelProvider, ModelUnavailableError


class OpenAICompatibleProvider(ModelProvider):
    name = "openai-compatible"

    def __init__(self, *, base_url: str, api_key: str, model_name: str) -> None:
        if urlparse(base_url).scheme not in {"https", "http"}:
            raise ValueError("model base URL must use http or https")
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self.model_name = model_name

    def complete(self, *, system_instruction: str, repository_context: str) -> ModelAssessment:
        body = json.dumps(
            {
                "model": self.model_name,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": system_instruction},
                    {"role": "user", "content": repository_context},
                ],
            }
        ).encode()
        request = Request(  # noqa: S310 - scheme is restricted during construction
            f"{self._base_url}/chat/completions",
            data=body,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=30) as response:  # noqa: S310 - scheme validated above
                payload = json.loads(response.read())
            return ModelAssessment.model_validate_json(payload["choices"][0]["message"]["content"])
        except (KeyError, TypeError, ValueError, URLError, OSError) as exc:
            raise ModelUnavailableError(
                "configured model provider did not return a valid assessment"
            ) from exc

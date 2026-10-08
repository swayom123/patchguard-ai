"""No provider receives filesystem or tool access through this interface."""

from abc import ABC, abstractmethod

from patchguard.domain.analysis import ModelAssessment


class ModelUnavailableError(RuntimeError):
    """Raised when analysis cannot safely reach a configured model provider."""


class ModelProvider(ABC):
    name: str
    model_name: str | None

    @abstractmethod
    def complete(self, *, system_instruction: str, repository_context: str) -> ModelAssessment:
        """Return validated structured output from data-only context."""


class DisabledModelProvider(ModelProvider):
    name = "disabled"
    model_name = None

    def complete(self, *, system_instruction: str, repository_context: str) -> ModelAssessment:
        del system_instruction, repository_context
        raise ModelUnavailableError("no model provider is configured")

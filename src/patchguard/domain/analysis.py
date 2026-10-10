from pydantic import BaseModel, ConfigDict, Field

from patchguard.domain.enums import AssessmentClassification, Confidence, Severity


class ModelAssessment(BaseModel):
    classification: AssessmentClassification
    severity: Severity
    confidence: Confidence
    evidence_strength: Confidence
    root_cause: str = Field(min_length=1, max_length=4_000)
    reasoning_summary: str = Field(min_length=1, max_length=4_000)
    affected_components: list[str] = Field(default_factory=list, max_length=50)
    recommended_fix: str = Field(min_length=1, max_length=4_000)


class ModelPatchProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    diff: str = Field(min_length=1, max_length=30_000)
    reason: str = Field(min_length=1, max_length=4_000)

"""Harmless Phase 1 metadata-inspection fixture.

Intentionally vulnerable examples belong to a later scanner-validation phase.
"""

from fastapi import FastAPI

app = FastAPI()


def service_status() -> str:
    return "ok"


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": service_status()}

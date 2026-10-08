"""INTENTIONALLY VULNERABLE local-only PatchGuard scanner fixture.

Never deploy or execute this application. It contains no real credentials.
"""

import pickle
import subprocess
from pathlib import Path
from typing import Any

from fastapi import FastAPI

app = FastAPI(debug=True)
DEMO_SECRET = "demo-only-not-a-real-secret"


def unsafe_command(command: str) -> None:
    subprocess.run(command, shell=True, check=True)


def unsafe_query(cursor: Any, user_id: str) -> Any:
    return cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")


def unsafe_deserialize(data: bytes) -> object:
    return pickle.loads(data)


def unsafe_file(base: Path, requested: str) -> str:
    return (base / requested).read_text(encoding="utf-8")

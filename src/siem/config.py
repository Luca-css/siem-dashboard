"""Runtime settings, read from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    db_path: str = "siem.db"
    rules_dir: str = "rules"
    host: str = "127.0.0.1"
    port: int = 8000

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            db_path=os.environ.get("SIEM_DB_PATH", cls.db_path),
            rules_dir=os.environ.get("SIEM_RULES_DIR", cls.rules_dir),
            host=os.environ.get("SIEM_HOST", cls.host),
            port=int(os.environ.get("SIEM_PORT", cls.port)),
        )

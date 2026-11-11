"""``python -m siem`` / ``siem``: run the API server with uvicorn."""

from __future__ import annotations

import logging

import uvicorn

from siem.api import create_app
from siem.config import Settings


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = Settings.from_env()
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()

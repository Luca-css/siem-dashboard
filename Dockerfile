FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Unprivileged user; the SQLite database lives in /app/data (a volume).
RUN useradd --create-home --uid 10001 siem \
    && mkdir -p /app/data \
    && chown siem:siem /app/data

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install .

COPY rules ./rules
COPY scripts ./scripts

USER siem

ENV SIEM_DB_PATH=/app/data/siem.db \
    SIEM_RULES_DIR=/app/rules \
    SIEM_HOST=0.0.0.0 \
    SIEM_PORT=8000

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"

CMD ["python", "-m", "siem"]

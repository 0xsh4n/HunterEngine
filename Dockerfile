# HunterEngine — app container only. Run Ollama on the host (or another machine).
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    OLLAMA_BASE_URL=http://host.docker.internal:11434 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates git \
        libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
        libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 \
        libgbm1 libasound2 libpango-1.0-0 libcairo2 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt pyproject.toml README.md LICENSE setup.cfg ./
COPY main.py ./
COPY core ./core
COPY crawl ./crawl
COPY detection ./detection
COPY recon ./recon
COPY ai ./ai
COPY reporting ./reporting
COPY memory ./memory
COPY confidence ./confidence
COPY proxy ./proxy
COPY knowledge ./knowledge
COPY config ./config
COPY dashboard ./dashboard
COPY tests ./tests

RUN pip install --upgrade pip \
    && pip install -r requirements.txt \
    && pip install -e . \
    && playwright install chromium \
    && (playwright install-deps chromium || true)

RUN mkdir -p /app/data/reports /app/data/screenshots /app/data/checkpoints \
        /app/data/domain_profiles /app/data/knowledge

EXPOSE 8787 8080

CMD ["python", "main.py", "dashboard", "--host", "0.0.0.0", "--port", "8787"]

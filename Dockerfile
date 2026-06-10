FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HONEYPOT_WEB_HOST=0.0.0.0 \
    HONEYPOT_HOST=0.0.0.0

WORKDIR /app

RUN addgroup --system honeypot && adduser --system --ingroup honeypot honeypot

COPY pyproject.toml README.md config.yaml ./
COPY honeypot_orchestrator ./honeypot_orchestrator

RUN pip install --no-cache-dir .

RUN mkdir -p /app/logs && chown -R honeypot:honeypot /app

# Run as root to allow writing to namespaced /proc/sys/net/ipv4/* settings
# USER honeypot

EXPOSE 8000 80 8080 21 22 23 53 139 389 445 636 1433 3389 1445

VOLUME ["/app/logs"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3).read()"

CMD ["python", "-m", "honeypot_orchestrator.cli", "--config", "config.yaml"]

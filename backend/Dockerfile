FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HONEYPOT_WEB_HOST=0.0.0.0 \
    HONEYPOT_HOST=0.0.0.0

WORKDIR /app

RUN apt-get update && apt-get install -y iptables libnetfilter-queue-dev python3-dev gcc libpcap-dev && rm -rf /var/lib/apt/lists/*

RUN addgroup --system honeypot && adduser --system --ingroup honeypot honeypot

COPY . .

RUN pip install --no-cache-dir -r requirements.txt

RUN mkdir -p /app/logs && chown -R honeypot:honeypot /app

# Run as root to allow writing to namespaced /proc/sys/net/ipv4/* settings
# USER honeypot

EXPOSE 8000 80 8080 21 22 23 53 135 139 389 445 636 1433 3389 1445 2222 2223 2121 2323 1053 5355/udp 137/udp

VOLUME ["/app/logs"]

CMD ["python", "-m", "cli", "--config", "config.yaml"]

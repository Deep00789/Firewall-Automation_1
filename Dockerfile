# Sophos Firewall Automation Portal
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/data \
    HOST=0.0.0.0 \
    PORT=5555

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as an unprivileged user (UID 1000). The data folder must be writable by this UID.
RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin app \
    && mkdir -p /data \
    && chown -R app:app /data
USER app

VOLUME ["/data"]
EXPOSE 5555

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import os,urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",\"5555\")}/login', timeout=4)" || exit 1

CMD ["gunicorn", "-c", "gunicorn.conf.py", "app:app"]

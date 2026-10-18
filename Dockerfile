# Sophos Firewall Automation Portal (Linux container)
FROM python:3.13-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DEFAULT_TIMEOUT=120 \
    DATA_DIR=/app/data \
    HOST=0.0.0.0 \
    PORT=5555

# nmap is used by the Live Hosts tool (ping + SYN port check; the container runs as root)
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN python -m pip install --no-cache-dir --upgrade pip setuptools wheel \
    && python -m pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Application port
EXPOSE 5555

# Start Python application
CMD ["python", "app.py"]

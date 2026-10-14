FROM python:3.12-slim-bookworm

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DEFAULT_TIMEOUT=120

# Install Python dependencies
COPY requirements.txt .

RUN python -m pip install --no-cache-dir \
    -r requirements.txt

# Copy application source code
COPY . .

# Application port
EXPOSE 5555

# Start Python application
CMD ["python", "app.py"]

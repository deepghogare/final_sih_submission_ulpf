# ==============================================================================
# Universal Log Pre-processing Framework (ULPF)
# Production Container Image (Python 3.12)
# ==============================================================================

FROM python:3.12-slim-bookworm

# Metadata labels
LABEL maintainer="NTRO / SIH 2026 Problem 26156"
LABEL description="Universal Log Pre-processing Framework (ULPF) Container"
LABEL version="1.0.0"

# Set operational environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    ULPF_OUTPUT_DIR=/app/output \
    ULPF_FAILED_DIR=/app/failed_events \
    ULPF_LOG_LEVEL=INFO

# Install system dependencies (curl for container health checks)
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Create dedicated non-root service account
RUN groupadd -g 10001 ulpf && \
    useradd -u 10001 -g ulpf -s /bin/bash -m ulpf

WORKDIR /app

# Install Python dependencies first for Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source tree
COPY . .

# Ensure required runtime directories exist with correct permissions
RUN mkdir -p /app/output /app/failed_events /app/plugins /app/configs && \
    chown -R ulpf:ulpf /app

# Switch to non-root user for security
USER ulpf

# Expose Web API / Dashboard (8000) and Syslog streaming listeners (5140/UDP, 5141/TCP)
EXPOSE 8000 5140/udp 5141/tcp

# Persistent volumes for output standardized events and dead-letter queue
VOLUME ["/app/output", "/app/failed_events"]

# Container healthcheck using built-in readiness endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Default command: start FastAPI REST API and SIEM operations dashboard
CMD ["python", "-m", "app.main", "serve", "--host", "0.0.0.0", "--port", "8000"]

# ══════════════════════════════════════════════════════════════════════════════
# SentinelAI Core Audit Engine — Enterprise Production Dockerfile
# AICPA SOC 2 Type 2 & ISO 27001 Compliant Container
# ══════════════════════════════════════════════════════════════════════════════

FROM python:3.12-slim AS runner

# Hardened environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8090 \
    PYTHONPATH=/app/engine:/app

# Install system dependencies (curl for healthcheck fallback)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged security user (AICPA SOC 2 CC6.1 Principle of Least Privilege)
RUN groupadd -g 10001 sentinel && \
    useradd -u 10001 -g sentinel -s /bin/bash -m sentinel

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy backend engine codebase
COPY engine /app/engine

# Change ownership to non-root user
RUN chown -R sentinel:sentinel /app

USER sentinel

EXPOSE 8090

# Container Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:${PORT}/health || exit 1

CMD ["python", "engine/server.py"]

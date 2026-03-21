# Copyright (c) 2026 Gregory Donarum. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0 — see LICENSE file.

FROM python:3.11-slim

# Security hardening
RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid appgroup --no-create-home --shell /sbin/nologin appuser

WORKDIR /app

# Install dependencies as root, then drop privileges
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY app.py .
COPY prompts/ prompts/
COPY sample_data/ sample_data/
COPY static/ static/

# Lock down permissions
RUN chown -R appuser:appgroup /app && \
    chmod -R 550 /app

USER appuser

EXPOSE 5000

# ANTHROPIC_API_KEY must be provided at runtime — never baked into the image
ENV FLASK_ENV=production

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/')" || exit 1

CMD ["python", "app.py"]

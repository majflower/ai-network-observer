# Multi-stage Dockerfile for AI Network Observer
FROM python:3.11-slim as base

# Metadata
LABEL maintainer="security@example.com"
LABEL description="AI-Driven Network Observability Agent"
LABEL version="1.0.0"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    libssl-dev \
    tcpdump \
    iproute2 \
    net-tools \
    build-essential \
    python3-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Note: eBPF/BCC support is optional
# If you need eBPF, build from a distro with BCC packages (Ubuntu 22.04+)
# or compile BCC from source

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash observer

# Set working directory
WORKDIR /app

# Copy requirements first (for layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY config/ ./config/
COPY examples/ ./examples/

# Create directories for logs and output
RUN mkdir -p /var/log/network_observer /app/output && \
    chown -R observer:observer /var/log/network_observer /app/output

# Copy entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Switch to non-root user (but note: packet capture needs root)
# In production, use --cap-add=NET_ADMIN instead
# USER maj

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV OUTPUT_DIR=/app/output
ENV LOG_DIR=/var/log/network_observer

# Expose port for potential web UI
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Entrypoint
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# Default command
CMD ["--help"]

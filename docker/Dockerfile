# Multi-stage build for AuthTest

# Build stage
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies (including SQLCipher for sqlcipher3)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    libsqlcipher-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml README.md ./
COPY authtest/ authtest/

# Install dependencies
RUN pip install --no-cache-dir build && \
    pip install --no-cache-dir .

# Runtime stage
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies for WeasyPrint and SQLCipher
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-xlib-2.0-0 \
    libffi8 \
    shared-mime-info \
    libsqlcipher1 \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/authtest /usr/local/bin/authtest

# Copy application
COPY authtest/ authtest/

# Create non-root user
RUN useradd --create-home --shell /bin/bash authtest
USER authtest

# Create data directory
RUN mkdir -p /home/authtest/.authtest

# Expose port
EXPOSE 8443

# Default command
CMD ["authtest", "serve", "--host", "0.0.0.0", "--port", "8443"]

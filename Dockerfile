# PSI-Storm Dockerfile
# Private Set Intersection using OpenSSL
#
# Usage:
#   Build:    docker build -t psi-storm .
#   Run:      docker run -v $(pwd):/data psi-storm step1 --config /data/secret-config.ini
#
# The container expects files to be mounted at /data:
#   - Config file (e.g., secret-config.ini)
#   - Input files referenced in config
#   - Output files will be written to /data
#
# Examples:
#   # Run step1
#   docker run -v $(pwd):/data psi-storm step1 --config /data/secret-config.ini
#
#   # Run step2
#   docker run -v $(pwd):/data psi-storm step2 --config /data/secret-config.ini
#
#   # Run compare
#   docker run -v $(pwd):/data psi-storm compare --config /data/secret-config.ini
#
#   # Run tests
#   docker run -v $(pwd):/data --entrypoint /app/tests/test_psi psi-storm

# Build stage
FROM debian:bookworm-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    g++ \
    make \
    libssl-dev \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy source files
COPY psi.cpp Makefile hash_to_curve_p256.cc hash_to_curve_p256.h ./
COPY tests/ tests/

# Build the application
RUN make build

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash psi

# Create data directory for volume mount
RUN mkdir -p /data && chown psi:psi /data

# Copy binaries from builder
COPY --from=builder /build/psi /usr/local/bin/
COPY --from=builder /build/psi /app/psi
COPY --from=builder /build/tests/test_psi /app/tests/
COPY --from=builder /build/tests/benchmark.sh /app/tests/

# Copy example config
COPY secret-config.ini /app/secret-config.ini.example

# Set ownership
RUN chown -R psi:psi /app

# Switch to non-root user
USER psi

# Working directory is /data where files are mounted
WORKDIR /data

# Volume for input/output files
VOLUME ["/data"]

# Default command
ENTRYPOINT ["psi"]
CMD ["--help"]

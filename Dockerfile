# -------- Stage 1: build --------
FROM ubuntu:22.04 AS builder

# Avoid interactive prompts during apt install
ENV DEBIAN_FRONTEND=noninteractive

# Install compiler and libmicrohttpd development files
RUN apt-get update && apt-get install -y \
    gcc \
    make \
    libmicrohttpd-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory inside container
WORKDIR /app

# Copy source code into container
COPY tcp_http_bridge.c .

# Compile the program
RUN gcc tcp_http_bridge.c -o tcp_http_bridge -lmicrohttpd


# -------- Stage 2: runtime --------
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install only runtime dependency (no compiler)
RUN apt-get update && apt-get install -y \
    libmicrohttpd12 \
    && rm -rf /var/lib/apt/lists/*

# Working directory
WORKDIR /app

# Copy compiled binary from builder stage
COPY --from=builder /app/tcp_http_bridge .

# Expose HTTP port of the bridge
EXPOSE 8080

# Run the bridge
ENTRYPOINT ["./tcp_http_bridge"]
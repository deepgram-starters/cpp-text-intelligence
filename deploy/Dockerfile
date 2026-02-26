# ==============================================================================
# C++ Text Intelligence - Production Dockerfile
#
# Multi-stage build:
#   1. Build custom Caddy with rate limiting
#   2. Build frontend
#   3. Build C++ binary
#   4. Run with Caddy reverse proxy
# ==============================================================================

# Stage 1: Build custom Caddy with rate limiting
FROM caddy:2-builder AS caddy-build

RUN xcaddy build \
    --with github.com/mholt/caddy-ratelimit

# Stage 2: Build frontend
FROM node:24-alpine AS frontend-build

RUN corepack enable && corepack prepare pnpm@10.0.0 --activate
WORKDIR /build/frontend
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY frontend/ ./
RUN pnpm build

# Stage 3: Build C++ binary
FROM alpine:3.20 AS cpp-build

RUN apk add --no-cache \
    build-base \
    cmake \
    git \
    curl-dev \
    openssl-dev \
    linux-headers \
    pkgconfig

# Install vcpkg
ENV VCPKG_ROOT=/opt/vcpkg
RUN git clone https://github.com/microsoft/vcpkg.git $VCPKG_ROOT && \
    $VCPKG_ROOT/bootstrap-vcpkg.sh -disableMetrics

WORKDIR /build
COPY vcpkg.json CMakeLists.txt ./
COPY src/ ./src/
COPY deepgram.toml ./

RUN cmake -B build -S . \
    -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake \
    -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build

# Stage 4: Production image with Caddy
FROM alpine:3.20

# Install runtime dependencies
RUN apk add --no-cache ca-certificates libcurl libstdc++ libgcc

# Copy custom Caddy with rate limiting
COPY --from=caddy-build /usr/bin/caddy /usr/bin/caddy

WORKDIR /app

# Copy C++ binary
COPY --from=cpp-build /build/build/cpp-text-intelligence ./cpp-text-intelligence
COPY --from=cpp-build /build/deepgram.toml ./deepgram.toml

# Copy built frontend
COPY --from=frontend-build /build/frontend/dist ./frontend/dist

# Copy Caddy configuration and start script
COPY deploy/Caddyfile /etc/caddy/Caddyfile
COPY deploy/start.sh ./start.sh
RUN chmod +x ./start.sh

# Set environment variables
ENV BACKEND_PORT=8081
ENV PORT=8081
ENV HOST=0.0.0.0
ENV BACKEND_CMD="./cpp-text-intelligence"

EXPOSE 8080

CMD ["./start.sh"]

# syntax=docker/dockerfile:1.7

# ==============================================================================
# Stage 1: Builder — Deterministic Dependency Installation & Crypto Self-Test
# ==============================================================================
FROM node:22-alpine AS builder

WORKDIR /build

# Copy only lockfile and manifest first to maximize Docker layer cache hits
COPY package.json package-lock.json ./

# Install production-only dependencies deterministically from package-lock.json
RUN npm ci --omit=dev --ignore-scripts && \
    npm cache clean --force

# Copy runtime application source and static UI assets
COPY src/ ./src/
COPY public/ ./public/

# Build-time Zero-Trust Gate: Verify PQC (ML-DSA / ML-KEM / SLH-DSA) & Merkle chain
# conformance before allowing the production stage to assemble
RUN node src/cli.js selftest

# ==============================================================================
# Stage 2: Production — Minimal, Read-Only-Ready, Non-Root Runtime
# ==============================================================================
FROM node:22-alpine AS production

# Install dumb-init for proper PID 1 signal forwarding (SIGTERM/SIGINT) and zombie reaping,
# apply OS security patches, and strip npm/corepack from the runtime image to reduce
# attack surface and eliminate package-manager CVEs.
RUN apk update && \
    apk upgrade --no-cache && \
    apk add --no-cache dumb-init && \
    rm -rf /var/cache/apk/* \
           /usr/local/lib/node_modules/npm \
           /usr/local/bin/npm \
           /usr/local/bin/npx \
           /usr/local/bin/corepack

# Lock environment to production and bind to 0.0.0.0 for container ingress
ENV NODE_ENV=production \
    VERIX_HOST=0.0.0.0 \
    VERIX_PORT=4317 \
    VERIX_DATA_DIR=/var/lib/verix

WORKDIR /app

# Prepare isolated, non-root-owned mount point for state while keeping /app owned by root:root
# Defense in Depth: Even if an orchestrator omits --read-only, UID 1000 (node) cannot modify
# /app or any source/dependency files at the Linux kernel DAC permission layer.
RUN mkdir -p /var/lib/verix && \
    chown -R node:node /var/lib/verix && \
    chmod 0700 /var/lib/verix

VOLUME ["/var/lib/verix"]

# Copy runtime artifacts owned by root:root (readable by node, non-writable by node)
COPY --from=builder /build/package.json ./package.json
COPY --from=builder /build/node_modules ./node_modules
COPY --from=builder /build/src ./src
COPY --from=builder /build/public ./public

# Strip all write permissions from /app so runtime code is immutable at the filesystem level
RUN chmod -R a-w /app

# Enforce Principle of Least Privilege: drop root (UID 0) for unprivileged node user (UID 1000)
USER node

EXPOSE 4317

# Zero-dependency health check (avoids installing curl/wget in production image)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:' + (process.env.VERIX_PORT || 4317) + '/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"]

# Run dumb-init as PID 1 to forward SIGTERM/SIGINT directly to the Node.js process
ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "src/cli.js", "serve"]

# TrojanHorse.js Enterprise - Production Dockerfile
# Multi-stage build for optimized production deployment

# ===== BUILD STAGE =====
FROM node:18-alpine AS builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    git \
    curl

# Copy package files
COPY package*.json ./
COPY tsconfig*.json ./
COPY rollup.config*.js ./
COPY .eslintrc.json ./

# Install dependencies
RUN npm ci --only=production --ignore-scripts

# Copy source code
COPY src/ ./src/
COPY bin/ ./bin/
COPY server/ ./server/
COPY k8s/ ./k8s/

# Build the application
RUN npm run build:enterprise

# ===== PRODUCTION STAGE =====
FROM node:18-alpine AS production

# Create non-root user for security
RUN addgroup -g 1001 -S trojanhorse && \
    adduser -S trojanhorse -u 1001 -G trojanhorse

# Set working directory
WORKDIR /app

# Install production dependencies only
RUN apk add --no-cache \
    dumb-init \
    curl \
    ca-certificates \
    tzdata

# Copy package files and install production dependencies
COPY package*.json ./
RUN npm ci --only=production --ignore-scripts && \
    npm cache clean --force

# Copy built application from builder stage
COPY --from=builder /app/dist ./dist/
COPY --from=builder /app/bin ./bin/
COPY --from=builder /app/server ./server/

# Copy configuration files
COPY k8s/configmap.yaml ./config/
COPY examples/ ./examples/

# Create necessary directories
RUN mkdir -p /app/logs /app/data /app/models && \
    chown -R trojanhorse:trojanhorse /app

# Set security configurations
RUN chmod +x /app/bin/trojanhorse-cli.js && \
    chmod 755 /app/dist && \
    chmod 644 /app/dist/*

# Switch to non-root user
USER trojanhorse

# Expose ports
EXPOSE 3000 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:3000/api/health || exit 1

# Set environment variables
ENV NODE_ENV=production \
    LOG_LEVEL=info \
    ENABLE_METRICS=true \
    SECURITY_MODE=enhanced

# Use dumb-init for proper signal handling
ENTRYPOINT ["dumb-init", "--"]

# Default command
CMD ["node", "dist/enterprise/TrojanHorseEnterprise.js"]

# ===== DEVELOPMENT STAGE =====
FROM node:18-alpine AS development

WORKDIR /app

# Install all dependencies (including dev dependencies)
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    git \
    curl

# Copy package files
COPY package*.json ./
RUN npm install

# Copy source code
COPY . .

# Expose ports for development
EXPOSE 3000 8080 9229

# Development health check
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:3000/api/health || exit 1

# Set development environment
ENV NODE_ENV=development \
    LOG_LEVEL=debug \
    ENABLE_DEBUG=true

# Development command with nodemon
CMD ["npm", "run", "dev:enterprise"]

# ===== LABELS FOR METADATA =====
LABEL maintainer="TrojanHorse.js Team" \
      version="1.0.0" \
      description="Enterprise threat intelligence platform" \
      org.opencontainers.image.title="TrojanHorse.js Enterprise" \
      org.opencontainers.image.description="Production-ready threat intelligence platform" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.vendor="TrojanHorse.js" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/sc4rfurry/TrojanHorse.js" 
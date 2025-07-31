# Docker Deployment

Complete guide for deploying TrojanHorse.js in containerized environments using Docker.

## Overview

TrojanHorse.js provides production-ready Docker images for various deployment scenarios, from development to enterprise-scale deployments.

```mermaid
graph TB
    A[Source Code] --> B[Multi-stage Build]
    B --> C[Base Images]
    
    C --> D1[Alpine Linux]
    C --> D2[Ubuntu LTS]
    C --> D3[Distroless]
    
    D1 --> E1[Development Image]
    D2 --> E2[Production Image]
    D3 --> E3[Security-hardened Image]
    
    E1 --> F[Docker Registry]
    E2 --> F
    E3 --> F
    
    F --> G[Deployment]
```

## Docker Images

### Available Images

| Image | Base | Size | Use Case |
|-------|------|------|----------|
| `trojanhorse/core:latest` | Alpine Linux | ~150MB | Development, testing |
| `trojanhorse/production:latest` | Ubuntu LTS | ~200MB | Production deployments |
| `trojanhorse/enterprise:latest` | Ubuntu LTS | ~250MB | Enterprise features |
| `trojanhorse/minimal:latest` | Distroless | ~80MB | Security-critical environments |

### Quick Start

```bash
# Pull and run the latest image
docker pull trojanhorse/core:latest

# Run with basic configuration
docker run -d \
  --name trojanhorse \
  -p 3000:3000 \
  -e TROJANHORSE_MODE=production \
  trojanhorse/core:latest

# Run with custom configuration
docker run -d \
  --name trojanhorse \
  -p 3000:3000 \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/data:/app/data \
  trojanhorse/core:latest
```

## Building Custom Images

### Multi-stage Dockerfile

```dockerfile
# Stage 1: Dependencies and build
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies
RUN npm ci --only=production && \
    npm cache clean --force

# Copy source code
COPY src/ ./src/
COPY rollup.config.js ./

# Build application
RUN npm run build:all

# Stage 2: Production image
FROM node:20-alpine AS production

# Create non-root user
RUN addgroup -g 1001 -S trojanhorse && \
    adduser -S trojanhorse -u 1001

# Set working directory
WORKDIR /app

# Copy built application
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./

# Copy configuration templates
COPY docker/config/ ./config/
COPY docker/scripts/ ./scripts/

# Set permissions
RUN chown -R trojanhorse:trojanhorse /app

# Switch to non-root user
USER trojanhorse

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node scripts/healthcheck.js

# Expose ports
EXPOSE 3000 9090

# Default command
CMD ["node", "dist/index.js"]
```

### Enterprise Dockerfile

```dockerfile
FROM ubuntu:22.04 AS enterprise

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    gnupg \
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs

# Install security tools
RUN apt-get update && apt-get install -y \
    clamav \
    fail2ban \
    logrotate \
    && rm -rf /var/lib/apt/lists/*

# Create application user
RUN groupadd -r trojanhorse && \
    useradd -r -g trojanhorse -s /bin/false trojanhorse

WORKDIR /app

# Copy application
COPY --chown=trojanhorse:trojanhorse dist/ ./dist/
COPY --chown=trojanhorse:trojanhorse node_modules/ ./node_modules/
COPY --chown=trojanhorse:trojanhorse package.json ./

# Copy enterprise configurations
COPY --chown=trojanhorse:trojanhorse docker/enterprise/ ./enterprise/

# Security hardening
RUN chmod -R 755 /app && \
    chmod -R 644 /app/dist && \
    chmod +x /app/dist/index.js

USER trojanhorse

EXPOSE 3000 8080 9090

CMD ["node", "dist/index.js", "--mode=enterprise"]
```

## Docker Compose Configurations

### Development Setup

```yaml
# docker-compose.dev.yml
version: '3.8'

services:
  trojanhorse:
    build:
      context: .
      dockerfile: Dockerfile
      target: development
    ports:
      - "3000:3000"
      - "9090:9090"
    environment:
      - NODE_ENV=development
      - TROJANHORSE_MODE=development
      - LOG_LEVEL=debug
    volumes:
      - ./src:/app/src
      - ./config:/app/config
      - ./data:/app/data
    depends_on:
      - redis
      - mongodb
    networks:
      - trojanhorse-dev

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    networks:
      - trojanhorse-dev

  mongodb:
    image: mongo:7
    ports:
      - "27017:27017"
    environment:
      - MONGO_INITDB_ROOT_USERNAME=admin
      - MONGO_INITDB_ROOT_PASSWORD=password
    volumes:
      - mongodb_data:/data/db
    networks:
      - trojanhorse-dev

volumes:
  redis_data:
  mongodb_data:

networks:
  trojanhorse-dev:
    driver: bridge
```

### Production Setup

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  trojanhorse:
    image: trojanhorse/production:latest
    restart: unless-stopped
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - TROJANHORSE_MODE=production
      - REDIS_URL=redis://redis:6379
      - MONGODB_URL=mongodb://mongodb:27017/trojanhorse
    volumes:
      - ./config/production:/app/config:ro
      - logs:/app/logs
      - data:/app/data
    depends_on:
      - redis
      - mongodb
      - nginx
    networks:
      - trojanhorse-prod
    deploy:
      replicas: 2
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '1'
          memory: 1G

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/ssl:/etc/nginx/ssl:ro
    depends_on:
      - trojanhorse
    networks:
      - trojanhorse-prod

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    networks:
      - trojanhorse-prod
    deploy:
      resources:
        limits:
          memory: 512M

  mongodb:
    image: mongo:7
    restart: unless-stopped
    environment:
      - MONGO_INITDB_ROOT_USERNAME_FILE=/run/secrets/mongo_root_username
      - MONGO_INITDB_ROOT_PASSWORD_FILE=/run/secrets/mongo_root_password
    volumes:
      - mongodb_data:/data/db
      - ./mongodb/mongod.conf:/etc/mongod.conf:ro
    secrets:
      - mongo_root_username
      - mongo_root_password
    networks:
      - trojanhorse-prod

secrets:
  mongo_root_username:
    external: true
  mongo_root_password:
    external: true

volumes:
  redis_data:
  mongodb_data:
  logs:
  data:

networks:
  trojanhorse-prod:
    driver: overlay
    encrypted: true
```

### Enterprise Cluster Setup

```yaml
# docker-compose.enterprise.yml
version: '3.8'

services:
  trojanhorse-api:
    image: trojanhorse/enterprise:latest
    restart: unless-stopped
    environment:
      - TROJANHORSE_MODE=api
      - CLUSTER_ROLE=api
    volumes:
      - ./config/enterprise:/app/config:ro
    networks:
      - trojanhorse-enterprise
    deploy:
      replicas: 3
      placement:
        constraints:
          - node.labels.type == api

  trojanhorse-worker:
    image: trojanhorse/enterprise:latest
    restart: unless-stopped
    environment:
      - TROJANHORSE_MODE=worker
      - CLUSTER_ROLE=worker
    volumes:
      - ./config/enterprise:/app/config:ro
    networks:
      - trojanhorse-enterprise
    deploy:
      replicas: 5
      placement:
        constraints:
          - node.labels.type == worker

  trojanhorse-coordinator:
    image: trojanhorse/enterprise:latest
    restart: unless-stopped
    environment:
      - TROJANHORSE_MODE=coordinator
      - CLUSTER_ROLE=coordinator
    volumes:
      - ./config/enterprise:/app/config:ro
    networks:
      - trojanhorse-enterprise
    deploy:
      replicas: 1
      placement:
        constraints:
          - node.labels.type == coordinator

  load-balancer:
    image: haproxy:2.8
    ports:
      - "80:80"
      - "443:443"
      - "8404:8404"
    volumes:
      - ./haproxy/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro
    networks:
      - trojanhorse-enterprise
    deploy:
      replicas: 2
      placement:
        constraints:
          - node.labels.type == lb

networks:
  trojanhorse-enterprise:
    driver: overlay
    encrypted: true
```

## Configuration Management

### Environment Variables

```bash
# Core configuration
TROJANHORSE_MODE=production
NODE_ENV=production
LOG_LEVEL=info

# Database connections
REDIS_URL=redis://redis:6379/0
MONGODB_URL=mongodb://mongodb:27017/trojanhorse
POSTGRES_URL=postgresql://user:pass@postgres:5432/trojanhorse

# Security
JWT_SECRET_FILE=/run/secrets/jwt_secret
API_KEY_ENCRYPTION_KEY_FILE=/run/secrets/api_encryption_key
SESSION_SECRET_FILE=/run/secrets/session_secret

# External APIs
URLHAUS_API_KEY_FILE=/run/secrets/urlhaus_key
VIRUSTOTAL_API_KEY_FILE=/run/secrets/virustotal_key
ALIENVAULT_API_KEY_FILE=/run/secrets/alienvault_key

# Performance
MAX_WORKERS=4
CACHE_TTL=3600
REQUEST_TIMEOUT=30000

# Monitoring
PROMETHEUS_ENABLED=true
PROMETHEUS_PORT=9090
HEALTH_CHECK_ENABLED=true
```

### Configuration Files

```yaml
# config/docker.yml
server:
  host: 0.0.0.0
  port: 3000
  
database:
  redis:
    url: ${REDIS_URL}
    maxConnections: 10
  
  mongodb:
    url: ${MONGODB_URL}
    options:
      maxPoolSize: 20
      serverSelectionTimeoutMS: 5000

security:
  encryption:
    keyFile: ${API_KEY_ENCRYPTION_KEY_FILE}
  
  authentication:
    jwtSecret: ${JWT_SECRET_FILE}
    sessionSecret: ${SESSION_SECRET_FILE}

feeds:
  urlhaus:
    apiKey: ${URLHAUS_API_KEY_FILE}
    enabled: true
  
  virustotal:
    apiKey: ${VIRUSTOTAL_API_KEY_FILE}
    enabled: true

monitoring:
  prometheus:
    enabled: ${PROMETHEUS_ENABLED}
    port: ${PROMETHEUS_PORT}
  
  health:
    enabled: ${HEALTH_CHECK_ENABLED}
    interval: 30000
```

## Security Best Practices

### Container Security

```dockerfile
# Security-hardened Dockerfile
FROM node:20-alpine AS security-hardened

# Install security updates
RUN apk update && apk upgrade && \
    apk add --no-cache dumb-init && \
    rm -rf /var/cache/apk/*

# Create non-root user with no shell
RUN addgroup -g 1001 -S trojanhorse && \
    adduser -S trojanhorse -u 1001 -G trojanhorse -s /sbin/nologin

# Set up application directory
WORKDIR /app

# Copy application with proper ownership
COPY --chown=trojanhorse:trojanhorse dist/ ./dist/
COPY --chown=trojanhorse:trojanhorse node_modules/ ./node_modules/

# Remove unnecessary packages and files
RUN apk del curl wget && \
    rm -rf /tmp/* /var/tmp/* && \
    find /app -name "*.md" -delete && \
    find /app -name "test*" -delete

# Set strict permissions
RUN chmod -R 755 /app && \
    chmod -R 644 /app/dist && \
    chmod +x /app/dist/index.js

# Switch to non-root user
USER trojanhorse

# Use dumb-init for proper signal handling
ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "dist/index.js"]
```

### Secret Management

```yaml
# docker-compose.secrets.yml
version: '3.8'

services:
  trojanhorse:
    image: trojanhorse/production:latest
    secrets:
      - jwt_secret
      - api_encryption_key
      - urlhaus_api_key
      - virustotal_api_key
    environment:
      - JWT_SECRET_FILE=/run/secrets/jwt_secret
      - API_KEY_ENCRYPTION_KEY_FILE=/run/secrets/api_encryption_key
      - URLHAUS_API_KEY_FILE=/run/secrets/urlhaus_api_key
      - VIRUSTOTAL_API_KEY_FILE=/run/secrets/virustotal_api_key

secrets:
  jwt_secret:
    external: true
  api_encryption_key:
    external: true
  urlhaus_api_key:
    external: true
  virustotal_api_key:
    external: true
```

```bash
# Create Docker secrets
echo "your-jwt-secret" | docker secret create jwt_secret -
echo "your-encryption-key" | docker secret create api_encryption_key -
echo "your-urlhaus-key" | docker secret create urlhaus_api_key -
echo "your-virustotal-key" | docker secret create virustotal_api_key -
```

## Monitoring and Logging

### Container Monitoring

```yaml
# docker-compose.monitoring.yml
version: '3.8'

services:
  trojanhorse:
    image: trojanhorse/production:latest
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    labels:
      - "prometheus.io/scrape=true"
      - "prometheus.io/port=9090"
      - "prometheus.io/path=/metrics"

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3001:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/dashboards:/etc/grafana/provisioning/dashboards
      - ./grafana/datasources:/etc/grafana/provisioning/datasources

volumes:
  prometheus_data:
  grafana_data:
```

### Health Checks

```javascript
// scripts/healthcheck.js
const http = require('http');

const options = {
  hostname: 'localhost',
  port: 3000,
  path: '/health',
  timeout: 2000
};

const request = http.request(options, (res) => {
  if (res.statusCode === 200) {
    process.exit(0);
  } else {
    process.exit(1);
  }
});

request.on('error', () => {
  process.exit(1);
});

request.on('timeout', () => {
  request.abort();
  process.exit(1);
});

request.end();
```

## Deployment Strategies

### Rolling Updates

```bash
#!/bin/bash
# rolling-update.sh

SERVICE_NAME="trojanhorse_trojanhorse"
NEW_IMAGE="trojanhorse/production:latest"

echo "Starting rolling update..."

# Pull new image
docker pull $NEW_IMAGE

# Update service with rolling update
docker service update \
  --image $NEW_IMAGE \
  --update-parallelism 1 \
  --update-delay 30s \
  --update-failure-action rollback \
  --rollback-parallelism 1 \
  --rollback-delay 10s \
  $SERVICE_NAME

echo "Rolling update completed"

# Monitor deployment
docker service ps $SERVICE_NAME
```

### Blue-Green Deployment

```bash
#!/bin/bash
# blue-green-deploy.sh

CURRENT_ENV=$(docker service ls --filter name=trojanhorse --format "{{.Name}}" | grep -o "blue\|green")
NEW_ENV="blue"

if [ "$CURRENT_ENV" = "blue" ]; then
  NEW_ENV="green"
fi

echo "Deploying to $NEW_ENV environment..."

# Deploy to new environment
docker stack deploy -c docker-compose.$NEW_ENV.yml trojanhorse-$NEW_ENV

# Wait for health check
sleep 30

# Switch traffic
docker service update \
  --publish-add 80:3000 \
  --publish-rm 80:3000 \
  trojanhorse-$NEW_ENV_trojanhorse

# Remove old environment
docker stack rm trojanhorse-$CURRENT_ENV

echo "Blue-green deployment completed"
```

## Troubleshooting

### Common Issues

**Container Won't Start**
```bash
# Check container logs
docker logs trojanhorse

# Check container configuration
docker inspect trojanhorse

# Verify environment variables
docker exec trojanhorse env
```

**Memory Issues**
```bash
# Monitor memory usage
docker stats trojanhorse

# Increase memory limits
docker update --memory 2g trojanhorse
```

**Network Connectivity**
```bash
# Test network connectivity
docker exec trojanhorse ping redis
docker exec trojanhorse telnet mongodb 27017
```

**Performance Issues**
```bash
# Profile application
docker exec trojanhorse node --prof dist/index.js

# Monitor resource usage
docker exec trojanhorse top
docker exec trojanhorse iostat
```

---

**Next Steps**: Explore [Kubernetes Deployment](kubernetes.md) for container orchestration or check [Production Deployment](production.md) for additional deployment strategies.
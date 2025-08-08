# ZTF-JS Deployment Guide

This guide covers deploying the Zero Trust Framework in various environments, from development to production.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Development Setup](#development-setup)
3. [Production Deployment](#production-deployment)
4. [Docker Deployment](#docker-deployment)
5. [Kubernetes Deployment](#kubernetes-deployment)
6. [Cloud Deployment](#cloud-deployment)
7. [Security Best Practices](#security-best-practices)
8. [Monitoring & Maintenance](#monitoring--maintenance)

## Prerequisites

### System Requirements

- **Node.js**: Version 16.0.0 or higher
- **MongoDB**: Version 4.4 or higher
- **Redis**: Version 6.0 or higher
- **Memory**: Minimum 2GB RAM (4GB recommended for production)
- **Storage**: Minimum 10GB available space

### Required Software

```bash
# Install Node.js (using nvm recommended)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
nvm install 16
nvm use 16

# Install MongoDB
# Ubuntu/Debian
sudo apt-get install mongodb

# macOS
brew install mongodb-community

# Install Redis
# Ubuntu/Debian
sudo apt-get install redis-server

# macOS
brew install redis
```

## Development Setup

### 1. Clone and Install

```bash
git clone https://github.com/your-username/ztf-js.git
cd ztf-js
npm install
```

### 2. Environment Configuration

Create a `.env` file in the root directory:

```bash
# Database Configuration
MONGO_URI=mongodb://localhost:27017/ztf-dev
REDIS_URL=redis://localhost:6379

# Security Configuration
JWT_SECRET=your-super-secret-key-change-in-production
JWT_EXPIRY=24h
REFRESH_TOKEN_EXPIRY=7d

# Environment
NODE_ENV=development
DEBUG=true

# MFA Configuration
MFA_ENABLED=true
MFA_ISSUER=ZTF-JS Dev

# Monitoring
MONITORING_ENABLED=true
LOG_LEVEL=debug
ALERT_EMAIL=admin@yourcompany.com

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX=100

# Dashboard
DASHBOARD_ENABLED=true
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=admin123
```

### 3. Start Services

```bash
# Start MongoDB
sudo systemctl start mongodb
# or
mongod --dbpath /data/db

# Start Redis
sudo systemctl start redis-server
# or
redis-server

# Start the application
npm run dev
```

### 4. Verify Installation

```bash
# Check health endpoint
curl http://localhost:3000/health

# Access dashboard
open http://localhost:3000/admin/security
```

## Production Deployment

### 1. Environment Setup

Create production environment variables:

```bash
# Production .env
NODE_ENV=production
MONGO_URI=mongodb://your-mongo-host:27017/ztf-prod
REDIS_URL=redis://your-redis-host:6379
JWT_SECRET=your-very-long-and-secure-production-secret-key
MFA_ENABLED=true
MONITORING_ENABLED=true
LOG_LEVEL=info
ALERT_EMAIL=security@yourcompany.com
RATE_LIMIT_MAX=50
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=secure-production-password
```

### 2. Process Manager Setup

Install and configure PM2:

```bash
npm install -g pm2

# Create ecosystem file
cat > ecosystem.config.js << EOF
module.exports = {
  apps: [{
    name: 'ztf-js',
    script: 'src/index.js',
    instances: 'max',
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'production',
      PORT: 3000
    },
    env_production: {
      NODE_ENV: 'production',
      PORT: 3000
    },
    error_file: './logs/err.log',
    out_file: './logs/out.log',
    log_file: './logs/combined.log',
    time: true,
    max_memory_restart: '1G',
    node_args: '--max-old-space-size=1024'
  }]
};
EOF

# Start application
pm2 start ecosystem.config.js --env production

# Save PM2 configuration
pm2 save
pm2 startup
```

### 3. Reverse Proxy Setup (Nginx)

```nginx
# /etc/nginx/sites-available/ztf-js
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /path/to/your/certificate.crt;
    ssl_certificate_key /path/to/your/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://localhost:3000;
    }
}
```

### 4. SSL Certificate Setup

```bash
# Using Let's Encrypt
sudo apt-get install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com

# Auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

## Docker Deployment

### 1. Dockerfile

```dockerfile
FROM node:16-alpine

# Install dependencies
RUN apk add --no-cache python3 make g++

# Create app directory
WORKDIR /usr/src/app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy source code
COPY . .

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nodejs -u 1001

# Change ownership
RUN chown -R nodejs:nodejs /usr/src/app
USER nodejs

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

# Start application
CMD ["npm", "start"]
```

### 2. Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - MONGO_URI=mongodb://mongo:27017/ztf-prod
      - REDIS_URL=redis://redis:6379
      - JWT_SECRET=${JWT_SECRET}
    depends_on:
      - mongo
      - redis
    restart: unless-stopped
    networks:
      - ztf-network

  mongo:
    image: mongo:5.0
    ports:
      - "27017:27017"
    environment:
      - MONGO_INITDB_ROOT_USERNAME=admin
      - MONGO_INITDB_ROOT_PASSWORD=${MONGO_PASSWORD}
    volumes:
      - mongo_data:/data/db
    restart: unless-stopped
    networks:
      - ztf-network

  redis:
    image: redis:6-alpine
    ports:
      - "6379:6379"
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    restart: unless-stopped
    networks:
      - ztf-network

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - app
    restart: unless-stopped
    networks:
      - ztf-network

volumes:
  mongo_data:
  redis_data:

networks:
  ztf-network:
    driver: bridge
```

### 3. Deploy with Docker

```bash
# Build and start
docker-compose up -d

# View logs
docker-compose logs -f app

# Scale application
docker-compose up -d --scale app=3
```

## Kubernetes Deployment

### 1. Namespace

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: ztf-js
```

### 2. ConfigMap

```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ztf-config
  namespace: ztf-js
data:
  NODE_ENV: "production"
  MONGO_URI: "mongodb://mongo-service:27017/ztf-prod"
  REDIS_URL: "redis://redis-service:6379"
  MFA_ENABLED: "true"
  MONITORING_ENABLED: "true"
  LOG_LEVEL: "info"
```

### 3. Secret

```yaml
# secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: ztf-secrets
  namespace: ztf-js
type: Opaque
data:
  JWT_SECRET: <base64-encoded-secret>
  MONGO_PASSWORD: <base64-encoded-password>
  REDIS_PASSWORD: <base64-encoded-password>
```

### 4. Deployment

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ztf-app
  namespace: ztf-js
spec:
  replicas: 3
  selector:
    matchLabels:
      app: ztf-app
  template:
    metadata:
      labels:
        app: ztf-app
    spec:
      containers:
      - name: ztf-app
        image: your-registry/ztf-js:latest
        ports:
        - containerPort: 3000
        envFrom:
        - configMapRef:
            name: ztf-config
        - secretRef:
            name: ztf-secrets
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
```

### 5. Service

```yaml
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: ztf-service
  namespace: ztf-js
spec:
  selector:
    app: ztf-app
  ports:
  - protocol: TCP
    port: 80
    targetPort: 3000
  type: ClusterIP
```

### 6. Ingress

```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ztf-ingress
  namespace: ztf-js
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - your-domain.com
    secretName: ztf-tls
  rules:
  - host: your-domain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: ztf-service
            port:
              number: 80
```

## Cloud Deployment

### AWS Deployment

#### 1. ECS with Fargate

```yaml
# task-definition.json
{
  "family": "ztf-js",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::account:role/ecsTaskExecutionRole",
  "containerDefinitions": [
    {
      "name": "ztf-app",
      "image": "your-account.dkr.ecr.region.amazonaws.com/ztf-js:latest",
      "portMappings": [
        {
          "containerPort": 3000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "NODE_ENV",
          "value": "production"
        }
      ],
      "secrets": [
        {
          "name": "JWT_SECRET",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:ztf-jwt-secret"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/ztf-js",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

#### 2. Application Load Balancer

```bash
# Create ALB
aws elbv2 create-load-balancer \
  --name ztf-alb \
  --subnets subnet-12345678 subnet-87654321 \
  --security-groups sg-12345678

# Create target group
aws elbv2 create-target-group \
  --name ztf-tg \
  --protocol HTTP \
  --port 3000 \
  --vpc-id vpc-12345678 \
  --health-check-path /health
```

### Google Cloud Platform

#### 1. Cloud Run

```bash
# Deploy to Cloud Run
gcloud run deploy ztf-js \
  --image gcr.io/your-project/ztf-js \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars NODE_ENV=production \
  --set-env-vars MONGO_URI=$MONGO_URI \
  --set-env-vars REDIS_URL=$REDIS_URL
```

#### 2. Cloud Build

```yaml
# cloudbuild.yaml
steps:
- name: 'gcr.io/cloud-builders/docker'
  args: ['build', '-t', 'gcr.io/$PROJECT_ID/ztf-js:$COMMIT_SHA', '.']
- name: 'gcr.io/cloud-builders/docker'
  args: ['push', 'gcr.io/$PROJECT_ID/ztf-js:$COMMIT_SHA']
- name: 'gcr.io/cloud-builders/gcloud'
  args:
  - 'run'
  - 'deploy'
  - 'ztf-js'
  - '--image'
  - 'gcr.io/$PROJECT_ID/ztf-js:$COMMIT_SHA'
  - '--region'
  - 'us-central1'
  - '--platform'
  - 'managed'
```

## Security Best Practices

### 1. Environment Variables

- Never commit secrets to version control
- Use secret management services (AWS Secrets Manager, GCP Secret Manager)
- Rotate secrets regularly
- Use different secrets for different environments

### 2. Network Security

- Use VPCs and security groups
- Implement network segmentation
- Use private subnets for databases
- Enable VPC Flow Logs

### 3. Application Security

- Enable HTTPS everywhere
- Implement proper CORS policies
- Use security headers
- Regular security updates
- Input validation and sanitization

### 4. Database Security

- Use strong authentication
- Enable encryption at rest
- Regular backups
- Network access controls
- Audit logging

### 5. Monitoring and Alerting

```bash
# Set up monitoring
npm install -g pm2
pm2 install pm2-logrotate
pm2 set pm2-logrotate:max_size 10M
pm2 set pm2-logrotate:retain 7

# Set up alerts
pm2 install pm2-server-monit
```

## Monitoring & Maintenance

### 1. Health Checks

```bash
# Create health check script
cat > health-check.sh << 'EOF'
#!/bin/bash
HEALTH_URL="http://localhost:3000/health"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" $HEALTH_URL)

if [ $RESPONSE -eq 200 ]; then
    echo "Health check passed"
    exit 0
else
    echo "Health check failed: $RESPONSE"
    exit 1
fi
EOF

chmod +x health-check.sh

# Add to crontab
crontab -e
# Add: */5 * * * * /path/to/health-check.sh
```

### 2. Log Management

```bash
# Set up log rotation
cat > /etc/logrotate.d/ztf-js << EOF
/var/log/ztf-js/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 644 nodejs nodejs
    postrotate
        pm2 reloadLogs
    endscript
}
EOF
```

### 3. Backup Strategy

```bash
# MongoDB backup script
cat > backup-mongo.sh << 'EOF'
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups/mongodb"
mkdir -p $BACKUP_DIR

mongodump --uri="mongodb://localhost:27017/ztf-prod" \
  --out="$BACKUP_DIR/backup_$DATE"

# Compress backup
tar -czf "$BACKUP_DIR/backup_$DATE.tar.gz" -C "$BACKUP_DIR" "backup_$DATE"
rm -rf "$BACKUP_DIR/backup_$DATE"

# Keep only last 7 days
find $BACKUP_DIR -name "backup_*.tar.gz" -mtime +7 -delete
EOF

chmod +x backup-mongo.sh

# Add to crontab
crontab -e
# Add: 0 2 * * * /path/to/backup-mongo.sh
```

### 4. Performance Monitoring

```bash
# Install monitoring tools
npm install -g clinic
npm install -g 0x

# Profile application
clinic doctor -- node src/index.js
clinic flame -- node src/index.js
```

### 5. Updates and Maintenance

```bash
# Update dependencies
npm audit
npm update

# Update Docker images
docker-compose pull
docker-compose up -d

# Kubernetes rolling update
kubectl set image deployment/ztf-app ztf-app=your-registry/ztf-js:new-version
```

## Troubleshooting

### Common Issues

1. **MongoDB Connection Issues**
   ```bash
   # Check MongoDB status
   sudo systemctl status mongodb
   
   # Check connection
   mongo --eval "db.runCommand('ping')"
   ```

2. **Redis Connection Issues**
   ```bash
   # Check Redis status
   sudo systemctl status redis-server
   
   # Test connection
   redis-cli ping
   ```

3. **Memory Issues**
   ```bash
   # Check memory usage
   free -h
   
   # Check Node.js memory
   node --max-old-space-size=2048 src/index.js
   ```

4. **Performance Issues**
   ```bash
   # Check CPU usage
   top
   
   # Check disk I/O
   iostat -x 1
   ```

### Log Analysis

```bash
# View application logs
pm2 logs ztf-js

# View system logs
journalctl -u ztf-js -f

# Search for errors
grep -i error /var/log/ztf-js/*.log
```

This deployment guide provides comprehensive instructions for deploying the ZTF-JS framework in various environments. Always test deployments in a staging environment before applying to production.

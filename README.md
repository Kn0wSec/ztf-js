# ZTF-JS: Zero Trust Framework for MERN Stack

A lightweight, comprehensive zero trust architecture framework designed specifically for MERN stack applications. This framework implements the core principles of zero trust security to protect your applications from threats.

## 🛡️ Zero Trust Principles Implemented

- **Never Trust, Always Verify**: Every request is authenticated and authorized
- **Least Privilege Access**: Users get minimal required permissions
- **Micro-segmentation**: Granular access control at the API level
- **Continuous Monitoring**: Real-time threat detection and response
- **Device Trust**: Device fingerprinting and verification
- **Network Security**: Advanced rate limiting and DDoS protection

## ✨ Features

### 🔐 Authentication & Authorization
- Multi-factor authentication (MFA) with TOTP
- JWT-based session management
- Role-based access control (RBAC)
- Permission-based authorization
- Session management with Redis

### 🛡️ Security Features
- Device fingerprinting and verification
- Geographic location tracking
- Behavioral analysis
- Rate limiting and DDoS protection
- Input validation and sanitization
- SQL injection prevention
- XSS protection

### 📊 Monitoring & Analytics
- Real-time security event logging
- Threat detection and alerting
- Audit trails
- Performance monitoring
- Security metrics dashboard

### 🔧 Framework Support
- **Current**: Express.js, MongoDB
- **Planned**: Next.js, Nest.js

## 🚀 Quick Start

### Installation

```bash
npm install ztf-js
```

### Basic Setup

```javascript
const { ZeroTrustFramework } = require('ztf-js');

const ztf = new ZeroTrustFramework({
  mongoUri: 'mongodb://localhost:27017/ztf-app',
  redisUrl: 'redis://localhost:6379',
  jwtSecret: 'your-super-secret-key',
  environment: 'development'
});

// Initialize the framework
await ztf.initialize();

// Use with Express
app.use(ztf.middleware());
```

### Advanced Configuration

```javascript
const ztf = new ZeroTrustFramework({
  // Database configuration
  mongoUri: process.env.MONGO_URI,
  redisUrl: process.env.REDIS_URL,
  
  // Security settings
  jwtSecret: process.env.JWT_SECRET,
  jwtExpiry: '24h',
  refreshTokenExpiry: '7d',
  
  // Rate limiting
  rateLimit: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
  },
  
  // MFA settings
  mfa: {
    enabled: true,
    issuer: 'Your App Name',
    algorithm: 'sha1'
  },
  
  // Monitoring
  monitoring: {
    enabled: true,
    logLevel: 'info',
    alertEmail: 'admin@yourcompany.com'
  }
});
```

## 📚 API Reference

### Authentication

```javascript
// Register a new user
const user = await ztf.auth.register({
  email: 'user@example.com',
  password: 'securePassword123',
  firstName: 'John',
  lastName: 'Doe'
});

// Login
const session = await ztf.auth.login({
  email: 'user@example.com',
  password: 'securePassword123',
  deviceInfo: req.headers['user-agent']
});

// Enable MFA
const mfaSecret = await ztf.auth.enableMFA(userId);

// Verify MFA
const isValid = await ztf.auth.verifyMFA(userId, token);
```

### Authorization

```javascript
// Create a role
const role = await ztf.auth.createRole({
  name: 'admin',
  permissions: ['read:users', 'write:users', 'delete:users']
});

// Assign role to user
await ztf.auth.assignRole(userId, roleId);

// Check permissions
const hasPermission = await ztf.auth.hasPermission(userId, 'read:users');
```

### Device Management

```javascript
// Register device
const device = await ztf.devices.register({
  userId: userId,
  deviceId: deviceFingerprint,
  userAgent: req.headers['user-agent'],
  ipAddress: req.ip,
  location: geoLocation
});

// Verify device
const isTrusted = await ztf.devices.verify(userId, deviceId);
```

### Monitoring

```javascript
// Log security event
await ztf.monitoring.logEvent({
  type: 'login_attempt',
  userId: userId,
  ipAddress: req.ip,
  userAgent: req.headers['user-agent'],
  success: true,
  metadata: { location: geoLocation }
});

// Get security metrics
const metrics = await ztf.monitoring.getMetrics({
  timeframe: '24h',
  userId: userId
});
```

## 🔧 Middleware Usage

### Express.js Integration

```javascript
const express = require('express');
const { ZeroTrustFramework } = require('ztf-js');

const app = express();
const ztf = new ZeroTrustFramework(config);

// Initialize framework
await ztf.initialize();

// Apply zero trust middleware
app.use(ztf.middleware());

// Protected routes
app.get('/api/users', 
  ztf.auth.requireAuth(),
  ztf.auth.requirePermission('read:users'),
  (req, res) => {
    // Your route logic
  }
);

// Admin routes with role-based access
app.post('/api/admin/users',
  ztf.auth.requireRole('admin'),
  (req, res) => {
    // Admin logic
  }
);
```

## 🛠️ Configuration Options

### Environment Variables

```bash
# Database
MONGO_URI=mongodb://localhost:27017/ztf-app
REDIS_URL=redis://localhost:6379

# Security
JWT_SECRET=your-super-secret-key
JWT_EXPIRY=24h
REFRESH_TOKEN_EXPIRY=7d

# MFA
MFA_ENABLED=true
MFA_ISSUER=Your App Name

# Monitoring
MONITORING_ENABLED=true
ALERT_EMAIL=admin@yourcompany.com

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX=100
```

## 📊 Dashboard

The framework includes a built-in security dashboard for monitoring:

```javascript
// Enable dashboard
app.use('/admin/security', ztf.dashboard.middleware());
```

Access the dashboard at `/admin/security` to view:
- Real-time security events
- User activity logs
- Device trust status
- Threat alerts
- Performance metrics

## 🧪 Testing

```bash
# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Run specific test suite
npm test -- --grep "authentication"
```

## 📈 Performance

The framework is designed for high performance:
- Redis caching for session management
- Optimized database queries
- Minimal overhead on requests
- Efficient device fingerprinting
- Scalable architecture

## 🔒 Security Best Practices

1. **Always use HTTPS in production**
2. **Rotate JWT secrets regularly**
3. **Enable MFA for all users**
4. **Monitor and log all security events**
5. **Regular security audits**
6. **Keep dependencies updated**

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details

## 🆘 Support

- Documentation: [docs.ztf-js.com](https://docs.ztf-js.com)
- Issues: [GitHub Issues](https://github.com/your-username/ztf-js/issues)
- Discussions: [GitHub Discussions](https://github.com/your-username/ztf-js/discussions)

## 🔮 Roadmap

- [ ] Next.js integration
- [ ] Nest.js integration
- [ ] GraphQL support
- [ ] WebSocket security
- [ ] Advanced threat detection
- [ ] Machine learning-based anomaly detection
- [ ] Kubernetes deployment support
- [ ] Multi-tenant support

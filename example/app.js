const express = require('express');
const { ZeroTrustFramework } = require('../src/index');

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize Zero Trust Framework
const ztf = new ZeroTrustFramework({
  mongoUri: process.env.MONGO_URI || 'mongodb://localhost:27017/ztf-example',
  redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
  jwtSecret: process.env.JWT_SECRET || 'your-super-secret-key-change-in-production',
  environment: process.env.NODE_ENV || 'development',
  mfa: {
    enabled: true,
    issuer: 'ZTF Example App'
  },
  monitoring: {
    enabled: true,
    logLevel: 'info'
  }
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Apply Zero Trust middleware
app.use(ztf.middleware());

// Enable dashboard
app.use('/admin/security', ztf.dashboard.middleware());

// Authentication routes
app.post('/auth/register', async (req, res) => {
  try {
    const result = await ztf.auth.register({
      email: req.body.email,
      password: req.body.password,
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });
    
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const result = await ztf.auth.login({
      email: req.body.email,
      password: req.body.password,
      deviceInfo: req.deviceInfo,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });
    
    res.json(result);
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
});

app.post('/auth/mfa/verify', async (req, res) => {
  try {
    const result = await ztf.auth.verifyMFA(
      req.body.userId,
      req.body.token
    );
    
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/auth/logout', ztf.auth.requireAuth(), async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const result = await ztf.auth.logout(token);
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Protected routes
app.get('/api/profile', ztf.auth.requireAuth(), (req, res) => {
  res.json({
    message: 'Profile accessed successfully',
    user: req.user
  });
});

app.get('/api/admin/users', 
  ztf.auth.requireAuth(),
  ztf.auth.requirePermission('read:users'),
  async (req, res) => {
    try {
      // This would typically fetch users from your database
      res.json({
        message: 'Users list accessed successfully',
        users: []
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

app.post('/api/admin/users',
  ztf.auth.requireAuth(),
  ztf.auth.requireRole('admin'),
  async (req, res) => {
    try {
      // This would typically create a user
      res.json({
        message: 'User created successfully'
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

// Device management routes
app.get('/api/devices', ztf.auth.requireAuth(), async (req, res) => {
  try {
    const devices = await ztf.devices.getUserDevices(req.user.userId);
    res.json({ devices });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/devices/trust/:deviceId', ztf.auth.requireAuth(), async (req, res) => {
  try {
    const result = await ztf.devices.trustDevice(req.user.userId, req.params.deviceId);
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.delete('/api/devices/:deviceId', ztf.auth.requireAuth(), async (req, res) => {
  try {
    const result = await ztf.devices.removeDevice(req.user.userId, req.params.deviceId);
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// MFA routes
app.post('/auth/mfa/enable', ztf.auth.requireAuth(), async (req, res) => {
  try {
    const result = await ztf.auth.enableMFA(req.user.userId);
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/auth/mfa/disable', ztf.auth.requireAuth(), async (req, res) => {
  try {
    const result = await ztf.auth.disableMFA(req.user.userId, req.body.token);
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Health check
app.get('/health', async (req, res) => {
  try {
    const status = ztf.getStatus();
    res.json({
      status: 'healthy',
      framework: status,
      timestamp: new Date()
    });
  } catch (error) {
    res.status(500).json({
      status: 'unhealthy',
      error: error.message
    });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Error:', error);
  res.status(500).json({
    error: 'Internal server error',
    message: error.message
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not found',
    message: 'The requested resource was not found'
  });
});

// Initialize and start server
async function startServer() {
  try {
    // Initialize Zero Trust Framework
    await ztf.initialize();
    
    // Start server
    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`📊 Dashboard available at http://localhost:${PORT}/admin/security`);
      console.log(`🔍 Health check at http://localhost:${PORT}/health`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully...');
  await ztf.shutdown();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('SIGINT received, shutting down gracefully...');
  await ztf.shutdown();
  process.exit(0);
});

// Start the server
startServer();

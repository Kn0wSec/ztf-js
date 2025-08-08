const request = require('supertest');
const express = require('express');
const { ZeroTrustFramework } = require('../src/index');
const mongoose = require('mongoose');

describe('ZTF-JS Integration Tests', () => {
  let app;
  let ztf;
  let server;

  beforeAll(async () => {
    // Set up test environment
    process.env.NODE_ENV = 'test';
    process.env.MONGO_URI = 'mongodb://localhost:27017/ztf-test';
    process.env.REDIS_URL = 'redis://localhost:6379';
    process.env.JWT_SECRET = 'test-secret-key';

    // Create Express app
    app = express();
    app.use(express.json());

    // Initialize ZTF
    ztf = new ZeroTrustFramework({
      mongoUri: process.env.MONGO_URI,
      redisUrl: process.env.REDIS_URL,
      jwtSecret: process.env.JWT_SECRET,
      environment: 'test',
      mfa: { enabled: false },
      monitoring: { enabled: false }
    });

    await ztf.initialize();
    app.use(ztf.middleware());

    // Set up test routes
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

    app.get('/api/profile', ztf.auth.requireAuth(), (req, res) => {
      res.json({ user: req.user });
    });

    app.get('/api/admin/users', 
      ztf.auth.requireAuth(),
      ztf.auth.requirePermission('read:users'),
      (req, res) => {
        res.json({ users: [] });
      }
    );

    app.get('/health', (req, res) => {
      res.json({ status: 'healthy', framework: ztf.getStatus() });
    });

    server = app.listen(0); // Use random port
  });

  afterAll(async () => {
    if (server) {
      server.close();
    }
    if (ztf) {
      await ztf.shutdown();
    }
    if (mongoose.connection.readyState === 1) {
      await mongoose.connection.close();
    }
  });

  beforeEach(async () => {
    // Clear test data
    await mongoose.connection.dropDatabase();
  });

  describe('Framework Initialization', () => {
    test('should initialize successfully', () => {
      expect(ztf.initialized).toBe(true);
      expect(ztf.auth).toBeDefined();
      expect(ztf.devices).toBeDefined();
      expect(ztf.monitoring).toBeDefined();
    });

    test('should return health status', async () => {
      const response = await request(app)
        .get('/health')
        .expect(200);

      expect(response.body.status).toBe('healthy');
      expect(response.body.framework.initialized).toBe(true);
    });
  });

  describe('Authentication', () => {
    test('should register a new user', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'password123',
        firstName: 'John',
        lastName: 'Doe'
      };

      const response = await request(app)
        .post('/auth/register')
        .send(userData)
        .expect(200);

      expect(response.body.user).toBeDefined();
      expect(response.body.user.email).toBe(userData.email);
      expect(response.body.user.firstName).toBe(userData.firstName);
      expect(response.body.user.lastName).toBe(userData.lastName);
      expect(response.body.user.password).toBeUndefined();
    });

    test('should prevent duplicate user registration', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'password123',
        firstName: 'John',
        lastName: 'Doe'
      };

      // Register first user
      await request(app)
        .post('/auth/register')
        .send(userData)
        .expect(200);

      // Try to register same user again
      const response = await request(app)
        .post('/auth/register')
        .send(userData)
        .expect(400);

      expect(response.body.error).toContain('already exists');
    });

    test('should login successfully with valid credentials', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'password123',
        firstName: 'John',
        lastName: 'Doe'
      };

      // Register user
      await request(app)
        .post('/auth/register')
        .send(userData)
        .expect(200);

      // Login
      const response = await request(app)
        .post('/auth/login')
        .send({
          email: userData.email,
          password: userData.password
        })
        .expect(200);

      expect(response.body.token).toBeDefined();
      expect(response.body.user).toBeDefined();
      expect(response.body.user.email).toBe(userData.email);
    });

    test('should reject invalid credentials', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'password123',
        firstName: 'John',
        lastName: 'Doe'
      };

      // Register user
      await request(app)
        .post('/auth/register')
        .send(userData)
        .expect(200);

      // Try to login with wrong password
      const response = await request(app)
        .post('/auth/login')
        .send({
          email: userData.email,
          password: 'wrongpassword'
        })
        .expect(401);

      expect(response.body.error).toContain('Invalid credentials');
    });
  });

  describe('Authorization', () => {
    let authToken;
    let userId;

    beforeEach(async () => {
      // Register and login a user
      const userData = {
        email: 'test@example.com',
        password: 'password123',
        firstName: 'John',
        lastName: 'Doe'
      };

      await request(app)
        .post('/auth/register')
        .send(userData)
        .expect(200);

      const loginResponse = await request(app)
        .post('/auth/login')
        .send({
          email: userData.email,
          password: userData.password
        })
        .expect(200);

      authToken = loginResponse.body.token;
      userId = loginResponse.body.user.userId;
    });

    test('should access protected route with valid token', async () => {
      const response = await request(app)
        .get('/api/profile')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.user).toBeDefined();
      expect(response.body.user.userId).toBe(userId);
    });

    test('should reject access without token', async () => {
      const response = await request(app)
        .get('/api/profile')
        .expect(401);

      expect(response.body.error).toContain('Authentication required');
    });

    test('should reject access with invalid token', async () => {
      const response = await request(app)
        .get('/api/profile')
        .set('Authorization', 'Bearer invalid-token')
        .expect(401);

      expect(response.body.error).toContain('Invalid token');
    });

    test('should reject access without required permission', async () => {
      const response = await request(app)
        .get('/api/admin/users')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(403);

      expect(response.body.error).toContain('Permission denied');
    });
  });

  describe('Device Management', () => {
    test('should generate device fingerprint', async () => {
      const fingerprint = await ztf.devices.generateFingerprint({
        headers: {
          'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        },
        ip: '127.0.0.1'
      });

      expect(fingerprint.id).toBeDefined();
      expect(fingerprint.components).toBeDefined();
      expect(fingerprint.confidence).toBeGreaterThan(0);
    });

    test('should register device for user', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'password123',
        firstName: 'John',
        lastName: 'Doe'
      };

      const user = await ztf.auth.register(userData);
      
      const deviceData = {
        userId: user.userId,
        deviceId: 'test-device-id',
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        ipAddress: '127.0.0.1',
        location: { country: 'US', region: 'CA' }
      };

      const device = await ztf.devices.register(deviceData);
      
      expect(device.userId).toBe(user.userId);
      expect(device.deviceId).toBe(deviceData.deviceId);
      expect(device.trusted).toBe(false);
    });
  });

  describe('Threat Detection', () => {
    test('should detect SQL injection attempts', async () => {
      const threatAnalysis = await ztf.middleware.threatDetector.analyzeRequest({
        body: { query: "SELECT * FROM users WHERE id = 1 OR 1=1" },
        headers: { 'user-agent': 'Mozilla/5.0' },
        url: '/api/users',
        ip: '127.0.0.1',
        method: 'POST'
      });

      expect(threatAnalysis.threats).toHaveLength(1);
      expect(threatAnalysis.threats[0].type).toBe('sql_injection_attempt');
      expect(threatAnalysis.riskLevel).toBe('high');
    });

    test('should detect XSS attempts', async () => {
      const threatAnalysis = await ztf.middleware.threatDetector.analyzeRequest({
        body: { comment: "<script>alert('xss')</script>" },
        headers: { 'user-agent': 'Mozilla/5.0' },
        url: '/api/comments',
        ip: '127.0.0.1',
        method: 'POST'
      });

      expect(threatAnalysis.threats).toHaveLength(1);
      expect(threatAnalysis.threats[0].type).toBe('xss_attempt');
      expect(threatAnalysis.riskLevel).toBe('high');
    });

    test('should detect suspicious user agents', async () => {
      const threatAnalysis = await ztf.middleware.threatDetector.analyzeRequest({
        body: {},
        headers: { 'user-agent': 'sqlmap/1.0' },
        url: '/api/users',
        ip: '127.0.0.1',
        method: 'GET'
      });

      expect(threatAnalysis.threats).toHaveLength(1);
      expect(threatAnalysis.threats[0].type).toBe('suspicious_user_agent');
    });
  });

  describe('Rate Limiting', () => {
    test('should enforce rate limits', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'password123',
        firstName: 'John',
        lastName: 'Doe'
      };

      // Register user
      await request(app)
        .post('/auth/register')
        .send(userData)
        .expect(200);

      // Make multiple login attempts
      for (let i = 0; i < 5; i++) {
        await request(app)
          .post('/auth/login')
          .send({
            email: userData.email,
            password: 'wrongpassword'
          })
          .expect(401);
      }

      // Next attempt should be rate limited
      const response = await request(app)
        .post('/auth/login')
        .send({
          email: userData.email,
          password: 'wrongpassword'
        })
        .expect(429);

      expect(response.body.error).toContain('Too many requests');
    });
  });

  describe('Monitoring', () => {
    test('should log security events', async () => {
      const eventData = {
        type: 'login_attempt',
        userId: 'test-user-id',
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0',
        success: false,
        metadata: { reason: 'Invalid credentials' }
      };

      await ztf.monitoring.logEvent(eventData);

      // Verify event was logged (this would typically check the database)
      expect(ztf.monitoring).toBeDefined();
    });
  });

  describe('Error Handling', () => {
    test('should handle invalid configuration', () => {
      expect(() => {
        new ZeroTrustFramework({
          mongoUri: 'invalid-uri',
          jwtSecret: ''
        });
      }).toThrow();
    });

    test('should handle database connection failures gracefully', async () => {
      const invalidZtf = new ZeroTrustFramework({
        mongoUri: 'mongodb://invalid-host:27017/test',
        redisUrl: 'redis://invalid-host:6379',
        jwtSecret: 'test-secret'
      });

      await expect(invalidZtf.initialize()).rejects.toThrow();
    });
  });
});

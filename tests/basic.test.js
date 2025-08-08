const { ZeroTrustFramework } = require('../src/index');
const mongoose = require('mongoose');

describe('Zero Trust Framework', () => {
  let ztf;

  beforeAll(async () => {
    // Connect to test database
    await mongoose.connect('mongodb://localhost:27017/ztf-test', {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
  });

  afterAll(async () => {
    // Clean up
    await mongoose.connection.dropDatabase();
    await mongoose.connection.close();
  });

  beforeEach(async () => {
    // Create new framework instance for each test
    ztf = new ZeroTrustFramework({
      mongoUri: 'mongodb://localhost:27017/ztf-test',
      redisUrl: 'redis://localhost:6379',
      jwtSecret: 'test-secret',
      environment: 'test'
    });
  });

  afterEach(async () => {
    // Clean up after each test
    if (ztf.initialized) {
      await ztf.shutdown();
    }
  });

  describe('Initialization', () => {
    test('should initialize successfully with valid config', async () => {
      await expect(ztf.initialize()).resolves.not.toThrow();
      expect(ztf.initialized).toBe(true);
    });

    test('should fail initialization with invalid MongoDB URI', async () => {
      const invalidZtf = new ZeroTrustFramework({
        mongoUri: 'invalid-uri',
        redisUrl: 'redis://localhost:6379',
        jwtSecret: 'test-secret'
      });

      await expect(invalidZtf.initialize()).rejects.toThrow();
    });

    test('should not initialize twice', async () => {
      await ztf.initialize();
      await expect(ztf.initialize()).rejects.toThrow('ZeroTrustFramework is already initialized');
    });
  });

  describe('Authentication', () => {
    beforeEach(async () => {
      await ztf.initialize();
    });

    test('should register a new user successfully', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'SecurePass123!',
        firstName: 'John',
        lastName: 'Doe',
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0 (Test Browser)'
      };

      const result = await ztf.auth.register(userData);
      
      expect(result.user).toBeDefined();
      expect(result.user.email).toBe(userData.email);
      expect(result.user.firstName).toBe(userData.firstName);
      expect(result.user.lastName).toBe(userData.lastName);
    });

    test('should fail registration with invalid email', async () => {
      const userData = {
        email: 'invalid-email',
        password: 'SecurePass123!',
        firstName: 'John',
        lastName: 'Doe'
      };

      await expect(ztf.auth.register(userData)).rejects.toThrow('Invalid email format');
    });

    test('should fail registration with weak password', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'weak',
        firstName: 'John',
        lastName: 'Doe'
      };

      await expect(ztf.auth.register(userData)).rejects.toThrow('Password must be at least 8 characters long');
    });

    test('should login successfully with valid credentials', async () => {
      // First register a user
      const userData = {
        email: 'test@example.com',
        password: 'SecurePass123!',
        firstName: 'John',
        lastName: 'Doe',
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0 (Test Browser)'
      };
      await ztf.auth.register(userData);

      // Then login
      const loginResult = await ztf.auth.login({
        email: 'test@example.com',
        password: 'SecurePass123!',
        deviceInfo: { userAgent: 'Mozilla/5.0 (Test Browser)' },
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0 (Test Browser)'
      });

      expect(loginResult.user).toBeDefined();
      expect(loginResult.session).toBeDefined();
      expect(loginResult.session.token).toBeDefined();
    });

    test('should fail login with invalid credentials', async () => {
      await expect(ztf.auth.login({
        email: 'test@example.com',
        password: 'wrongpassword',
        deviceInfo: { userAgent: 'Mozilla/5.0 (Test Browser)' },
        ipAddress: '127.0.0.1',
        userAgent: 'Mozilla/5.0 (Test Browser)'
      })).rejects.toThrow('Invalid credentials');
    });
  });

  describe('Device Management', () => {
    beforeEach(async () => {
      await ztf.initialize();
    });

    test('should generate device fingerprint', () => {
      const userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';
      const ipAddress = '192.168.1.1';
      const additionalData = {
        screenResolution: '1920x1080',
        timezone: 'America/New_York'
      };

      const result = ztf.devices.generateDeviceFingerprint(userAgent, ipAddress, additionalData);
      
      expect(result.fingerprint).toBeDefined();
      expect(result.deviceInfo).toBeDefined();
      expect(result.deviceInfo.userAgent).toBe(userAgent);
      expect(result.deviceInfo.ipAddress).toBe(ipAddress);
    });

    test('should register a new device', async () => {
      const userId = '507f1f77bcf86cd799439011'; // Mock ObjectId
      const deviceInfo = {
        userAgent: 'Mozilla/5.0 (Test Browser)',
        screenResolution: '1920x1080'
      };
      const ipAddress = '192.168.1.1';
      const userAgent = 'Mozilla/5.0 (Test Browser)';

      const device = await ztf.devices.registerDevice(userId, deviceInfo, ipAddress, userAgent);
      
      expect(device).toBeDefined();
      expect(device.userId.toString()).toBe(userId);
      expect(device.isTrusted).toBe(false);
    });
  });

  describe('Monitoring', () => {
    beforeEach(async () => {
      await ztf.initialize();
    });

    test('should log security events', async () => {
      const eventData = {
        type: 'test_event',
        level: 'info',
        message: 'Test security event',
        userId: '507f1f77bcf86cd799439011',
        ipAddress: '192.168.1.1'
      };

      const event = await ztf.monitoring.logEvent(eventData);
      
      expect(event).toBeDefined();
      expect(event.type).toBe(eventData.type);
      expect(event.message).toBe(eventData.message);
    });

    test('should get metrics', async () => {
      const metrics = await ztf.monitoring.getMetrics('24h');
      
      expect(metrics).toBeDefined();
      expect(metrics.timeframe).toBe('24h');
      expect(metrics.totalEvents).toBeDefined();
    });
  });

  describe('Middleware', () => {
    beforeEach(async () => {
      await ztf.initialize();
    });

    test('should create middleware stack', () => {
      const middleware = ztf.middleware();
      
      expect(Array.isArray(middleware)).toBe(true);
      expect(middleware.length).toBeGreaterThan(0);
    });

    test('should create authentication middleware', () => {
      const authMiddleware = ztf.auth.requireAuth();
      
      expect(typeof authMiddleware).toBe('function');
    });

    test('should create permission middleware', () => {
      const permissionMiddleware = ztf.auth.requirePermission('read:users');
      
      expect(typeof permissionMiddleware).toBe('function');
    });

    test('should create role middleware', () => {
      const roleMiddleware = ztf.auth.requireRole('admin');
      
      expect(typeof roleMiddleware).toBe('function');
    });
  });

  describe('Framework Status', () => {
    beforeEach(async () => {
      await ztf.initialize();
    });

    test('should return framework status', () => {
      const status = ztf.getStatus();
      
      expect(status).toBeDefined();
      expect(status.initialized).toBe(true);
      expect(status.config).toBeDefined();
      expect(status.components).toBeDefined();
    });

    test('should perform health check', async () => {
      const health = await ztf.healthCheck();
      
      expect(health).toBeDefined();
      expect(health.status).toBeDefined();
      expect(health.components).toBeDefined();
    });
  });

  describe('Shutdown', () => {
    beforeEach(async () => {
      await ztf.initialize();
    });

    test('should shutdown gracefully', async () => {
      await expect(ztf.shutdown()).resolves.not.toThrow();
      expect(ztf.initialized).toBe(false);
    });
  });
});

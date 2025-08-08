const mongoose = require('mongoose');
const Redis = require('ioredis');
const AuthManager = require('../auth/AuthManager');
const DeviceManager = require('../devices/DeviceManager');
const MonitoringManager = require('../monitoring/MonitoringManager');
const SecurityMiddleware = require('../middleware/SecurityMiddleware');
const Dashboard = require('../dashboard/Dashboard');
const Utils = require('../utils/Utils');

class ZeroTrustFramework {
  constructor(config = {}) {
    this.config = this.validateConfig(config);
    this.initialized = false;
    this.redis = null;
    this.monitoring = null;
    this.auth = null;
    this.devices = null;
    this.middleware = null;
    this.dashboard = null;
  }

  validateConfig(config) {
    const defaultConfig = {
      mongoUri: process.env.MONGO_URI || 'mongodb://localhost:27017/ztf-app',
      redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
      jwtSecret: process.env.JWT_SECRET || 'default-secret-change-in-production',
      jwtExpiry: process.env.JWT_EXPIRY || '24h',
      refreshTokenExpiry: process.env.REFRESH_TOKEN_EXPIRY || '7d',
      environment: process.env.NODE_ENV || 'development',
      rateLimit: {
        windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
        max: parseInt(process.env.RATE_LIMIT_MAX) || 100
      },
      mfa: {
        enabled: process.env.MFA_ENABLED === 'true',
        issuer: process.env.MFA_ISSUER || 'ZTF-JS',
        algorithm: 'sha1'
      },
      monitoring: {
        enabled: process.env.MONITORING_ENABLED !== 'false',
        logLevel: process.env.LOG_LEVEL || 'info',
        alertEmail: process.env.ALERT_EMAIL
      },
      security: {
        bcryptRounds: 12,
        sessionTimeout: 30 * 60 * 1000, // 30 minutes
        maxLoginAttempts: 5,
        lockoutDuration: 15 * 60 * 1000 // 15 minutes
      }
    };

    return { ...defaultConfig, ...config };
  }

  async initialize() {
    if (this.initialized) {
      throw new Error('ZeroTrustFramework is already initialized');
    }

    try {
      // Connect to MongoDB
      await this.connectMongoDB();
      
      // Connect to Redis
      await this.connectRedis();
      
      // Initialize components
      await this.initializeComponents();
      
      // Set up monitoring
      await this.setupMonitoring();
      
      this.initialized = true;
      
      this.monitoring.logEvent({
        type: 'framework_initialized',
        level: 'info',
        message: 'Zero Trust Framework initialized successfully'
      });
      
      console.log('✅ Zero Trust Framework initialized successfully');
    } catch (error) {
      console.error('❌ Failed to initialize Zero Trust Framework:', error);
      throw error;
    }
  }

  async connectMongoDB() {
    try {
      await mongoose.connect(this.config.mongoUri, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        maxPoolSize: 10,
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 45000,
      });
      
      console.log('📦 Connected to MongoDB');
    } catch (error) {
      console.error('❌ MongoDB connection failed:', error);
      throw error;
    }
  }

  async connectRedis() {
    try {
      this.redis = new Redis(this.config.redisUrl, {
        retryDelayOnFailover: 100,
        enableReadyCheck: false,
        maxRetriesPerRequest: null,
        lazyConnect: true
      });

      await this.redis.connect();
      console.log('🔴 Connected to Redis');
    } catch (error) {
      console.error('❌ Redis connection failed:', error);
      throw error;
    }
  }

  async initializeComponents() {
    // Initialize monitoring first
    this.monitoring = new MonitoringManager(this.config.monitoring, this.redis);
    
    // Initialize auth manager
    this.auth = new AuthManager(this.config, this.redis, this.monitoring);
    
    // Initialize device manager
    this.devices = new DeviceManager(this.config, this.redis, this.monitoring);
    
    // Initialize security middleware
    this.middleware = new SecurityMiddleware(this.config, this.auth, this.devices, this.monitoring);
    
    // Initialize dashboard
    this.dashboard = new Dashboard(this.config, this.auth, this.devices, this.monitoring);
  }

  async setupMonitoring() {
    // Set up periodic health checks
    setInterval(async () => {
      try {
        await this.healthCheck();
      } catch (error) {
        this.monitoring.logEvent({
          type: 'health_check_failed',
          level: 'error',
          message: error.message
        });
      }
    }, 5 * 60 * 1000); // Every 5 minutes
  }

  async healthCheck() {
    const health = {
      timestamp: new Date(),
      status: 'healthy',
      components: {}
    };

    // Check MongoDB
    try {
      await mongoose.connection.db.admin().ping();
      health.components.mongodb = 'healthy';
    } catch (error) {
      health.components.mongodb = 'unhealthy';
      health.status = 'degraded';
    }

    // Check Redis
    try {
      await this.redis.ping();
      health.components.redis = 'healthy';
    } catch (error) {
      health.components.redis = 'unhealthy';
      health.status = 'degraded';
    }

    // Store health status
    await this.redis.set('ztf:health', JSON.stringify(health), 'EX', 300);

    return health;
  }

  // Main middleware function
  middleware() {
    if (!this.initialized) {
      throw new Error('ZeroTrustFramework must be initialized before using middleware');
    }
    return this.middleware.createMiddleware();
  }

  // Get framework status
  getStatus() {
    return {
      initialized: this.initialized,
      config: {
        environment: this.config.environment,
        mfa: this.config.mfa.enabled,
        monitoring: this.config.monitoring.enabled
      },
      components: {
        auth: !!this.auth,
        devices: !!this.devices,
        monitoring: !!this.monitoring,
        middleware: !!this.middleware,
        dashboard: !!this.dashboard
      }
    };
  }

  // Graceful shutdown
  async shutdown() {
    try {
      console.log('🔄 Shutting down Zero Trust Framework...');
      
      // Close Redis connection
      if (this.redis) {
        await this.redis.quit();
      }
      
      // Close MongoDB connection
      if (mongoose.connection.readyState === 1) {
        await mongoose.connection.close();
      }
      
      this.initialized = false;
      console.log('✅ Zero Trust Framework shutdown complete');
    } catch (error) {
      console.error('❌ Error during shutdown:', error);
      throw error;
    }
  }
}

module.exports = ZeroTrustFramework;

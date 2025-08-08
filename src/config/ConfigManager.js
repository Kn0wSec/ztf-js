const path = require('path');
const fs = require('fs');

class ConfigManager {
  constructor() {
    this.config = {};
    this.environment = process.env.NODE_ENV || 'development';
  }

  load(configPath = null) {
    // Load environment variables
    require('dotenv').config();

    // Load config file if provided
    if (configPath && fs.existsSync(configPath)) {
      const fileConfig = require(path.resolve(configPath));
      this.config = { ...this.config, ...fileConfig };
    }

    // Set default configuration
    this.config = this.validateConfig({
      ...this.getDefaultConfig(),
      ...this.config
    });

    return this.config;
  }

  getDefaultConfig() {
    return {
      // Database configuration
      database: {
        mongo: {
          uri: process.env.MONGO_URI || 'mongodb://localhost:27017/ztf-app',
          options: {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            maxPoolSize: 10,
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
          }
        },
        redis: {
          url: process.env.REDIS_URL || 'redis://localhost:6379',
          options: {
            retryDelayOnFailover: 100,
            enableReadyCheck: false,
            maxRetriesPerRequest: null,
            lazyConnect: true
          }
        }
      },

      // Security configuration
      security: {
        jwt: {
          secret: process.env.JWT_SECRET || 'default-secret-change-in-production',
          expiry: process.env.JWT_EXPIRY || '24h',
          refreshExpiry: process.env.REFRESH_TOKEN_EXPIRY || '7d',
          algorithm: 'HS256'
        },
        bcrypt: {
          rounds: parseInt(process.env.BCRYPT_ROUNDS) || 12
        },
        session: {
          timeout: parseInt(process.env.SESSION_TIMEOUT) || 30 * 60 * 1000, // 30 minutes
          maxLoginAttempts: parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5,
          lockoutDuration: parseInt(process.env.LOCKOUT_DURATION) || 15 * 60 * 1000 // 15 minutes
        },
        cors: {
          origin: process.env.CORS_ORIGIN || '*',
          credentials: true,
          methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
          allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
        }
      },

      // Rate limiting
      rateLimit: {
        windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
        max: parseInt(process.env.RATE_LIMIT_MAX) || 100,
        message: 'Too many requests from this IP, please try again later.',
        standardHeaders: true,
        legacyHeaders: false
      },

      // MFA configuration
      mfa: {
        enabled: process.env.MFA_ENABLED === 'true',
        issuer: process.env.MFA_ISSUER || 'ZTF-JS',
        algorithm: 'sha1',
        digits: 6,
        period: 30,
        window: 1
      },

      // Monitoring configuration
      monitoring: {
        enabled: process.env.MONITORING_ENABLED !== 'false',
        logLevel: process.env.LOG_LEVEL || 'info',
        alertEmail: process.env.ALERT_EMAIL,
        retention: {
          events: parseInt(process.env.EVENT_RETENTION_DAYS) || 90,
          logs: parseInt(process.env.LOG_RETENTION_DAYS) || 30
        },
        alerts: {
          failedLoginThreshold: parseInt(process.env.FAILED_LOGIN_THRESHOLD) || 10,
          suspiciousActivityThreshold: parseInt(process.env.SUSPICIOUS_ACTIVITY_THRESHOLD) || 5
        }
      },

      // Device management
      devices: {
        fingerprinting: {
          enabled: true,
          algorithms: ['canvas', 'webgl', 'audio', 'fonts', 'plugins']
        },
        trust: {
          autoTrust: false,
          requireVerification: true,
          maxDevices: parseInt(process.env.MAX_DEVICES_PER_USER) || 5
        }
      },

      // Dashboard configuration
      dashboard: {
        enabled: process.env.DASHBOARD_ENABLED !== 'false',
        path: process.env.DASHBOARD_PATH || '/admin/security',
        auth: {
          username: process.env.DASHBOARD_USERNAME || 'admin',
          password: process.env.DASHBOARD_PASSWORD || 'admin'
        }
      },

      // Email configuration
      email: {
        enabled: process.env.EMAIL_ENABLED === 'true',
        provider: process.env.EMAIL_PROVIDER || 'smtp',
        smtp: {
          host: process.env.SMTP_HOST,
          port: parseInt(process.env.SMTP_PORT) || 587,
          secure: process.env.SMTP_SECURE === 'true',
          auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS
          }
        },
        from: process.env.EMAIL_FROM || 'noreply@ztf-js.com'
      },

      // Environment
      environment: this.environment,
      debug: process.env.DEBUG === 'true' || this.environment === 'development'
    };
  }

  validateConfig(config) {
    const requiredFields = [
      'database.mongo.uri',
      'security.jwt.secret',
      'database.redis.url'
    ];

    for (const field of requiredFields) {
      const value = this.getNestedValue(config, field);
      if (!value) {
        throw new Error(`Missing required configuration field: ${field}`);
      }
    }

    // Validate JWT secret in production
    if (config.environment === 'production' && 
        config.security.jwt.secret === 'default-secret-change-in-production') {
      throw new Error('JWT_SECRET must be set in production environment');
    }

    // Validate email configuration if enabled
    if (config.email.enabled) {
      if (!config.email.smtp.host || !config.email.smtp.auth.user || !config.email.smtp.auth.pass) {
        throw new Error('Email configuration incomplete when email is enabled');
      }
    }

    return config;
  }

  getNestedValue(obj, path) {
    return path.split('.').reduce((current, key) => current && current[key], obj);
  }

  get(key, defaultValue = null) {
    return this.getNestedValue(this.config, key) || defaultValue;
  }

  set(key, value) {
    const keys = key.split('.');
    const lastKey = keys.pop();
    const target = keys.reduce((obj, k) => obj[k] = obj[k] || {}, this.config);
    target[lastKey] = value;
  }

  isDevelopment() {
    return this.environment === 'development';
  }

  isProduction() {
    return this.environment === 'production';
  }

  isTest() {
    return this.environment === 'test';
  }

  getEnvironment() {
    return this.environment;
  }
}

module.exports = ConfigManager;

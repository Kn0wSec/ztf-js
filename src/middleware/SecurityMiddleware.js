const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const { body, validationResult } = require('express-validator');

class SecurityMiddleware {
  constructor(config, auth, devices, monitoring) {
    this.config = config;
    this.auth = auth;
    this.devices = devices;
    this.monitoring = monitoring;
  }

  // Create the main security middleware stack
  createMiddleware() {
    return [
      this.basicSecurity(),
      this.rateLimiting(),
      this.requestLogging(),
      this.deviceFingerprinting(),
      this.threatDetection(),
      this.responseSecurity()
    ];
  }

  // Basic security headers and protections
  basicSecurity() {
    return [
      helmet({
        contentSecurityPolicy: {
          directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"]
          }
        },
        hsts: {
          maxAge: 31536000,
          includeSubDomains: true,
          preload: true
        },
        noSniff: true,
        referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
      }),
      cors({
        origin: this.config.cors?.origins || ['http://localhost:3000'],
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
      })
    ];
  }

  // Rate limiting middleware
  rateLimiting() {
    const globalLimiter = rateLimit({
      windowMs: this.config.rateLimit.windowMs,
      max: this.config.rateLimit.max,
      message: {
        error: 'Too many requests from this IP, please try again later.',
        retryAfter: Math.ceil(this.config.rateLimit.windowMs / 1000)
      },
      standardHeaders: true,
      legacyHeaders: false,
      handler: (req, res) => {
        this.monitoring.logEvent({
          type: 'rate_limit_exceeded',
          level: 'warning',
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'],
          message: 'Rate limit exceeded'
        });
        res.status(429).json({
          error: 'Too many requests from this IP, please try again later.',
          retryAfter: Math.ceil(this.config.rateLimit.windowMs / 1000)
        });
      }
    });

    const authLimiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 5, // 5 attempts per window
      message: {
        error: 'Too many authentication attempts, please try again later.',
        retryAfter: 900
      },
      standardHeaders: true,
      legacyHeaders: false,
      skipSuccessfulRequests: true,
      handler: (req, res) => {
        this.monitoring.logEvent({
          type: 'auth_rate_limit_exceeded',
          level: 'warning',
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'],
          message: 'Authentication rate limit exceeded'
        });
        res.status(429).json({
          error: 'Too many authentication attempts, please try again later.',
          retryAfter: 900
        });
      }
    });

    return (req, res, next) => {
      // Apply auth limiter to auth routes
      if (req.path.startsWith('/auth') || req.path.startsWith('/login')) {
        return authLimiter(req, res, next);
      }
      // Apply global limiter to all other routes
      return globalLimiter(req, res, next);
    };
  }

  // Request logging middleware
  requestLogging() {
    return (req, res, next) => {
      const startTime = Date.now();
      
      // Capture request details
      const requestInfo = {
        method: req.method,
        path: req.path,
        query: req.query,
        headers: this.sanitizeHeaders(req.headers),
        body: this.sanitizeBody(req.body),
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      };

      // Log request
      this.monitoring.logEvent({
        type: 'request_received',
        level: 'info',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        message: `${req.method} ${req.path}`,
        metadata: {
          requestInfo: requestInfo
        }
      });

      // Capture response
      const originalSend = res.send;
      res.send = function(data) {
        const responseTime = Date.now() - startTime;
        
        // Log response
        this.monitoring.logEvent({
          type: 'request_completed',
          level: 'info',
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'],
          message: `${req.method} ${req.path} - ${res.statusCode}`,
          metadata: {
            responseTime: responseTime,
            statusCode: res.statusCode,
            responseSize: data ? data.length : 0
          }
        });

        originalSend.call(this, data);
      }.bind(this);

      next();
    };
  }

  // Device fingerprinting middleware
  deviceFingerprinting() {
    return (req, res, next) => {
      try {
        // Extract device information from request
        const deviceInfo = {
          userAgent: req.headers['user-agent'],
          ipAddress: req.ip,
          acceptLanguage: req.headers['accept-language'],
          acceptEncoding: req.headers['accept-encoding'],
          screenResolution: req.headers['x-screen-resolution'],
          timezone: req.headers['x-timezone'],
          language: req.headers['accept-language']?.split(',')[0] || 'en'
        };

        // Generate device fingerprint
        const { fingerprint, deviceInfo: parsedDeviceInfo } = this.devices.generateDeviceFingerprint(
          deviceInfo.userAgent,
          deviceInfo.ipAddress,
          deviceInfo
        );

        // Attach to request
        req.deviceFingerprint = fingerprint;
        req.deviceInfo = parsedDeviceInfo;

        next();
      } catch (error) {
        console.error('Device fingerprinting failed:', error);
        next();
      }
    };
  }

  // Threat detection middleware
  threatDetection() {
    return async (req, res, next) => {
      try {
        const threats = [];

        // Check for suspicious patterns
        if (this.isSuspiciousRequest(req)) {
          threats.push('suspicious_request_pattern');
        }

        // Check for known malicious IPs
        if (await this.isMaliciousIP(req.ip)) {
          threats.push('malicious_ip');
        }

        // Check for unusual user agent
        if (this.isUnusualUserAgent(req.headers['user-agent'])) {
          threats.push('unusual_user_agent');
        }

        // Check for suspicious headers
        if (this.hasSuspiciousHeaders(req.headers)) {
          threats.push('suspicious_headers');
        }

        // If threats detected, log and potentially block
        if (threats.length > 0) {
          await this.monitoring.logEvent({
            type: 'threat_detected',
            level: 'warning',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            message: `Threats detected: ${threats.join(', ')}`,
            flags: threats,
            riskScore: threats.length * 25 // 25 points per threat
          });

          // Block if high risk
          if (threats.length >= 3) {
            return res.status(403).json({
              error: 'Request blocked due to security concerns'
            });
          }
        }

        next();
      } catch (error) {
        console.error('Threat detection failed:', error);
        next();
      }
    };
  }

  // Response security middleware
  responseSecurity() {
    return (req, res, next) => {
      // Add security headers
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('X-XSS-Protection', '1; mode=block');
      res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
      
      // Remove sensitive headers
      res.removeHeader('X-Powered-By');
      res.removeHeader('Server');

      next();
    };
  }

  // Authentication middleware
  requireAuth() {
    return async (req, res, next) => {
      try {
        const token = req.headers.authorization?.replace('Bearer ', '');
        if (!token) {
          return res.status(401).json({ error: 'Authentication required' });
        }

        const session = await this.auth.verifyToken(token);
        req.user = session;

        // Verify device if user is authenticated
        if (req.deviceFingerprint) {
          const deviceVerification = await this.devices.verifyDevice(
            session.userId,
            req.deviceFingerprint,
            req.ip,
            req.headers['user-agent']
          );

          if (!deviceVerification.isTrusted) {
            req.deviceVerification = deviceVerification;
          }
        }

        next();
      } catch (error) {
        return res.status(401).json({ error: 'Invalid token' });
      }
    };
  }

  // Permission middleware
  requirePermission(permission) {
    return async (req, res, next) => {
      try {
        if (!req.user) {
          return res.status(401).json({ error: 'Authentication required' });
        }

        const hasPermission = await this.auth.hasPermission(req.user.userId, permission);
        if (!hasPermission) {
          return res.status(403).json({ error: 'Insufficient permissions' });
        }

        next();
      } catch (error) {
        return res.status(500).json({ error: 'Permission check failed' });
      }
    };
  }

  // Role middleware
  requireRole(roleName) {
    return async (req, res, next) => {
      try {
        if (!req.user) {
          return res.status(401).json({ error: 'Authentication required' });
        }

        if (!req.user.roles.includes(roleName)) {
          return res.status(403).json({ error: 'Insufficient role' });
        }

        next();
      } catch (error) {
        return res.status(500).json({ error: 'Role check failed' });
      }
    };
  }

  // Input validation middleware
  validateInput(validationRules) {
    return [
      ...validationRules,
      (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
          return res.status(400).json({
            error: 'Validation failed',
            details: errors.array()
          });
        }
        next();
      }
    ];
  }

  // Common validation rules
  getValidationRules() {
    return {
      email: body('email').isEmail().normalizeEmail(),
      password: body('password').isLength({ min: 8 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/),
      mfaToken: body('token').isLength({ min: 6, max: 6 }).isNumeric(),
      userId: body('userId').isMongoId(),
      deviceId: body('deviceId').isString().isLength({ min: 32, max: 64 })
    };
  }

  // Helper methods
  sanitizeHeaders(headers) {
    const sanitized = {};
    const sensitiveHeaders = ['authorization', 'cookie', 'x-api-key'];
    
    Object.keys(headers).forEach(key => {
      if (!sensitiveHeaders.includes(key.toLowerCase())) {
        sanitized[key] = headers[key];
      }
    });
    
    return sanitized;
  }

  sanitizeBody(body) {
    if (!body) return null;
    
    const sanitized = { ...body };
    const sensitiveFields = ['password', 'token', 'secret', 'key'];
    
    sensitiveFields.forEach(field => {
      if (sanitized[field]) {
        sanitized[field] = '[REDACTED]';
      }
    });
    
    return sanitized;
  }

  isSuspiciousRequest(req) {
    // Check for SQL injection patterns
    const sqlPatterns = [
      /(\b(union|select|insert|update|delete|drop|create|alter)\b)/i,
      /(\b(or|and)\b\s+\d+\s*=\s*\d+)/i,
      /(\b(union|select|insert|update|delete|drop|create|alter)\b.*\b(union|select|insert|update|delete|drop|create|alter)\b)/i
    ];

    const requestString = JSON.stringify({
      path: req.path,
      query: req.query,
      body: req.body
    });

    return sqlPatterns.some(pattern => pattern.test(requestString));
  }

  async isMaliciousIP(ipAddress) {
    // This would typically check against threat intelligence feeds
    // For now, return false as a placeholder
    return false;
  }

  isUnusualUserAgent(userAgent) {
    if (!userAgent) return true;
    
    const suspiciousPatterns = [
      /bot|crawler|spider/i,
      /curl|wget|python|java/i,
      /^$/ // Empty user agent
    ];

    return suspiciousPatterns.some(pattern => pattern.test(userAgent));
  }

  hasSuspiciousHeaders(headers) {
    const suspiciousHeaders = [
      'x-forwarded-for',
      'x-real-ip',
      'x-client-ip',
      'cf-connecting-ip'
    ];

    return suspiciousHeaders.some(header => headers[header]);
  }
}

module.exports = SecurityMiddleware;

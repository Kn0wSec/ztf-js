const winston = require('winston');
const SecurityEvent = require('../models/SecurityEvent');
const Utils = require('../utils/Utils');

class MonitoringManager {
  constructor(config, redis) {
    this.config = config;
    this.redis = redis;
    this.logger = this.setupLogger();
    this.threatPatterns = this.initializeThreatPatterns();
  }

  setupLogger() {
    const logFormat = winston.format.combine(
      winston.format.timestamp(),
      winston.format.errors({ stack: true }),
      winston.format.json()
    );

    return winston.createLogger({
      level: this.config.logLevel || 'info',
      format: logFormat,
      transports: [
        new winston.transports.File({ 
          filename: 'logs/security.log',
          maxsize: 5242880, // 5MB
          maxFiles: 5
        }),
        new winston.transports.File({ 
          filename: 'logs/error.log', 
          level: 'error',
          maxsize: 5242880,
          maxFiles: 5
        }),
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
          )
        })
      ]
    });
  }

  initializeThreatPatterns() {
    return {
      bruteForce: {
        maxAttempts: 5,
        timeWindow: 15 * 60 * 1000, // 15 minutes
        threshold: 3
      },
      suspiciousIPs: new Set(),
      unusualLocations: new Set(),
      rapidRequests: {
        maxRequests: 100,
        timeWindow: 60 * 1000, // 1 minute
        threshold: 50
      }
    };
  }

  // Log security event
  async logEvent(eventData) {
    try {
      const event = {
        type: eventData.type,
        level: eventData.level || 'info',
        timestamp: new Date(),
        userId: eventData.userId || null,
        ipAddress: eventData.ipAddress || null,
        userAgent: eventData.userAgent || null,
        sessionId: eventData.sessionId || null,
        deviceId: eventData.deviceId || null,
        message: eventData.message || '',
        metadata: eventData.metadata || {},
        riskScore: eventData.riskScore || 0,
        flags: eventData.flags || []
      };

      // Save to database
      const securityEvent = new SecurityEvent(event);
      await securityEvent.save();

      // Log to file
      this.logger.log(event.level, event.message, {
        eventType: event.type,
        userId: event.userId,
        ipAddress: event.ipAddress,
        riskScore: event.riskScore
      });

      // Store in Redis for real-time monitoring
      await this.storeEventInRedis(event);

      // Check for threats
      await this.analyzeThreat(event);

      // Send alerts if necessary
      if (event.level === 'error' || event.riskScore > 70) {
        await this.sendAlert(event);
      }

      return event;
    } catch (error) {
      console.error('Failed to log security event:', error);
      // Fallback logging
      this.logger.error('Event logging failed', { error: error.message, originalEvent: eventData });
    }
  }

  // Store event in Redis for real-time monitoring
  async storeEventInRedis(event) {
    try {
      const eventKey = `event:${event.timestamp.getTime()}:${event.type}`;
      await this.redis.setex(eventKey, 3600, JSON.stringify(event)); // Store for 1 hour

      // Update counters
      const counterKey = `counter:${event.type}:${new Date().toISOString().slice(0, 13)}`; // Hourly
      await this.redis.incr(counterKey);
      await this.redis.expire(counterKey, 86400); // Expire after 24 hours

      // Update user activity
      if (event.userId) {
        const userActivityKey = `user_activity:${event.userId}`;
        await this.redis.lpush(userActivityKey, JSON.stringify(event));
        await this.redis.ltrim(userActivityKey, 0, 99); // Keep last 100 events
        await this.redis.expire(userActivityKey, 86400);
      }

      // Update IP activity
      if (event.ipAddress) {
        const ipActivityKey = `ip_activity:${event.ipAddress}`;
        await this.redis.lpush(ipActivityKey, JSON.stringify(event));
        await this.redis.ltrim(ipActivityKey, 0, 99);
        await this.redis.expire(ipActivityKey, 86400);
      }
    } catch (error) {
      console.error('Failed to store event in Redis:', error);
    }
  }

  // Analyze event for threats
  async analyzeThreat(event) {
    try {
      let threatDetected = false;
      const threats = [];

      // Check for brute force attacks
      if (event.type === 'login_failed' && event.userId) {
        const bruteForceThreat = await this.detectBruteForce(event);
        if (bruteForceThreat) {
          threats.push(bruteForceThreat);
          threatDetected = true;
        }
      }

      // Check for suspicious IP activity
      if (event.ipAddress) {
        const suspiciousIPThreat = await this.detectSuspiciousIP(event);
        if (suspiciousIPThreat) {
          threats.push(suspiciousIPThreat);
          threatDetected = true;
        }
      }

      // Check for rapid requests
      const rapidRequestThreat = await this.detectRapidRequests(event);
      if (rapidRequestThreat) {
        threats.push(rapidRequestThreat);
        threatDetected = true;
      }

      // Check for unusual location
      if (event.metadata.location) {
        const locationThreat = await this.detectUnusualLocation(event);
        if (locationThreat) {
          threats.push(locationThreat);
          threatDetected = true;
        }
      }

      if (threatDetected) {
        await this.handleThreat(threats, event);
      }
    } catch (error) {
      console.error('Threat analysis failed:', error);
    }
  }

  // Detect brute force attacks
  async detectBruteForce(event) {
    const key = `login_attempts:${event.userId}`;
    const attempts = await this.redis.incr(key);
    
    if (attempts === 1) {
      await this.redis.expire(key, this.threatPatterns.bruteForce.timeWindow / 1000);
    }

    if (attempts >= this.threatPatterns.bruteForce.maxAttempts) {
      return {
        type: 'brute_force_attack',
        severity: 'high',
        message: `Brute force attack detected for user ${event.userId}`,
        attempts: attempts,
        ipAddress: event.ipAddress
      };
    }

    return null;
  }

  // Detect suspicious IP activity
  async detectSuspiciousIP(event) {
    const key = `ip_activity:${event.ipAddress}`;
    const events = await this.redis.lrange(key, 0, -1);
    
    if (events.length > 50) { // More than 50 events from same IP
      const recentEvents = events.slice(0, 10).map(e => JSON.parse(e));
      const failedLogins = recentEvents.filter(e => e.type === 'login_failed').length;
      
      if (failedLogins > 10) {
        return {
          type: 'suspicious_ip',
          severity: 'medium',
          message: `Suspicious activity detected from IP ${event.ipAddress}`,
          failedLogins: failedLogins,
          totalEvents: events.length
        };
      }
    }

    return null;
  }

  // Detect rapid requests
  async detectRapidRequests(event) {
    const key = `rapid_requests:${event.ipAddress}`;
    const requests = await this.redis.incr(key);
    
    if (requests === 1) {
      await this.redis.expire(key, this.threatPatterns.rapidRequests.timeWindow / 1000);
    }

    if (requests > this.threatPatterns.rapidRequests.maxRequests) {
      return {
        type: 'rapid_requests',
        severity: 'medium',
        message: `Rapid requests detected from IP ${event.ipAddress}`,
        requests: requests,
        timeWindow: this.threatPatterns.rapidRequests.timeWindow
      };
    }

    return null;
  }

  // Detect unusual location
  async detectUnusualLocation(event) {
    if (!event.userId || !event.metadata.location) return null;

    const userLocationsKey = `user_locations:${event.userId}`;
    const userLocations = await this.redis.smembers(userLocationsKey);
    
    if (userLocations.length > 0 && !userLocations.includes(event.metadata.location.country)) {
      return {
        type: 'unusual_location',
        severity: 'medium',
        message: `Unusual location detected for user ${event.userId}`,
        location: event.metadata.location,
        previousLocations: userLocations
      };
    }

    // Store current location
    await this.redis.sadd(userLocationsKey, event.metadata.location.country);
    await this.redis.expire(userLocationsKey, 30 * 24 * 60 * 60); // 30 days

    return null;
  }

  // Handle detected threats
  async handleThreat(threats, originalEvent) {
    try {
      // Log threat event
      await this.logEvent({
        type: 'threat_detected',
        level: 'warning',
        userId: originalEvent.userId,
        ipAddress: originalEvent.ipAddress,
        message: `Threat detected: ${threats.map(t => t.type).join(', ')}`,
        metadata: {
          threats: threats,
          originalEvent: originalEvent
        },
        riskScore: Math.max(...threats.map(t => this.getThreatSeverityScore(t.severity)))
      });

      // Take automated actions
      for (const threat of threats) {
        await this.takeAutomatedAction(threat, originalEvent);
      }
    } catch (error) {
      console.error('Failed to handle threat:', error);
    }
  }

  // Take automated action based on threat
  async takeAutomatedAction(threat, originalEvent) {
    try {
      switch (threat.type) {
        case 'brute_force_attack':
          // Lock account temporarily
          await this.lockAccount(originalEvent.userId, 15 * 60 * 1000); // 15 minutes
          break;

        case 'suspicious_ip':
          // Add IP to watchlist
          await this.addToWatchlist(originalEvent.ipAddress, 'suspicious_ip');
          break;

        case 'rapid_requests':
          // Rate limit IP
          await this.rateLimitIP(originalEvent.ipAddress, 5 * 60 * 1000); // 5 minutes
          break;

        case 'unusual_location':
          // Require additional verification
          await this.requireAdditionalVerification(originalEvent.userId);
          break;
      }
    } catch (error) {
      console.error('Failed to take automated action:', error);
    }
  }

  // Send alert
  async sendAlert(event) {
    try {
      // Store alert in Redis
      const alertKey = `alert:${Date.now()}`;
      await this.redis.setex(alertKey, 86400, JSON.stringify(event)); // Store for 24 hours

      // Send email alert if configured
      if (this.config.alertEmail) {
        await this.sendEmailAlert(event);
      }

      // Log alert
      this.logger.warn('Security alert sent', {
        eventType: event.type,
        userId: event.userId,
        ipAddress: event.ipAddress,
        riskScore: event.riskScore
      });
    } catch (error) {
      console.error('Failed to send alert:', error);
    }
  }

  // Send email alert
  async sendEmailAlert(event) {
    // This would integrate with your email service
    // For now, just log the alert
    this.logger.info('Email alert would be sent', {
      to: this.config.alertEmail,
      subject: `Security Alert: ${event.type}`,
      event: event
    });
  }

  // Get metrics
  async getMetrics(timeframe = '24h') {
    try {
      const now = new Date();
      const startTime = this.getStartTime(timeframe);
      
      const metrics = {
        timeframe: timeframe,
        totalEvents: 0,
        eventsByType: {},
        eventsByLevel: {},
        riskScoreDistribution: {
          low: 0,    // 0-30
          medium: 0, // 31-70
          high: 0    // 71-100
        },
        topIPs: [],
        topUsers: [],
        threats: []
      };

      // Get events from database
      const events = await SecurityEvent.find({
        timestamp: { $gte: startTime }
      }).sort({ timestamp: -1 });

      // Process events
      events.forEach(event => {
        metrics.totalEvents++;
        
        // Count by type
        metrics.eventsByType[event.type] = (metrics.eventsByType[event.type] || 0) + 1;
        
        // Count by level
        metrics.eventsByLevel[event.level] = (metrics.eventsByLevel[event.level] || 0) + 1;
        
        // Risk score distribution
        if (event.riskScore <= 30) metrics.riskScoreDistribution.low++;
        else if (event.riskScore <= 70) metrics.riskScoreDistribution.medium++;
        else metrics.riskScoreDistribution.high++;
      });

      // Get top IPs and users from Redis
      metrics.topIPs = await this.getTopIPs(timeframe);
      metrics.topUsers = await this.getTopUsers(timeframe);
      metrics.threats = await this.getRecentThreats(timeframe);

      return metrics;
    } catch (error) {
      console.error('Failed to get metrics:', error);
      throw error;
    }
  }

  // Get top IPs
  async getTopIPs(timeframe) {
    const pattern = `counter:*:${new Date().toISOString().slice(0, 13)}*`;
    const keys = await this.redis.keys(pattern);
    
    const ipCounts = {};
    for (const key of keys) {
      const count = await this.redis.get(key);
      const ip = key.split(':')[2];
      ipCounts[ip] = (ipCounts[ip] || 0) + parseInt(count || 0);
    }

    return Object.entries(ipCounts)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 10)
      .map(([ip, count]) => ({ ip, count }));
  }

  // Get top users
  async getTopUsers(timeframe) {
    const pattern = `user_activity:*`;
    const keys = await this.redis.keys(pattern);
    
    const userCounts = {};
    for (const key of keys) {
      const userId = key.split(':')[1];
      const events = await this.redis.lrange(key, 0, -1);
      userCounts[userId] = events.length;
    }

    return Object.entries(userCounts)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 10)
      .map(([userId, count]) => ({ userId, count }));
  }

  // Get recent threats
  async getRecentThreats(timeframe) {
    const pattern = `alert:*`;
    const keys = await this.redis.keys(pattern);
    
    const threats = [];
    for (const key of keys) {
      const alert = await this.redis.get(key);
      if (alert) {
        threats.push(JSON.parse(alert));
      }
    }

    return threats
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .slice(0, 20);
  }

  // Helper methods
  getStartTime(timeframe) {
    const now = new Date();
    switch (timeframe) {
      case '1h': return new Date(now.getTime() - 60 * 60 * 1000);
      case '6h': return new Date(now.getTime() - 6 * 60 * 60 * 1000);
      case '24h': return new Date(now.getTime() - 24 * 60 * 60 * 1000);
      case '7d': return new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      case '30d': return new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
      default: return new Date(now.getTime() - 24 * 60 * 60 * 1000);
    }
  }

  getThreatSeverityScore(severity) {
    switch (severity) {
      case 'low': return 30;
      case 'medium': return 60;
      case 'high': return 90;
      default: return 50;
    }
  }

  // Automated action methods
  async lockAccount(userId, duration) {
    const lockKey = `account_locked:${userId}`;
    await this.redis.setex(lockKey, Math.floor(duration / 1000), 'locked');
  }

  async addToWatchlist(ipAddress, reason) {
    const watchlistKey = `watchlist:${ipAddress}`;
    await this.redis.setex(watchlistKey, 24 * 60 * 60, reason); // 24 hours
  }

  async rateLimitIP(ipAddress, duration) {
    const rateLimitKey = `rate_limit:${ipAddress}`;
    await this.redis.setex(rateLimitKey, Math.floor(duration / 1000), 'limited');
  }

  async requireAdditionalVerification(userId) {
    const verificationKey = `verification_required:${userId}`;
    await this.redis.setex(verificationKey, 60 * 60, 'required'); // 1 hour
  }
}

module.exports = MonitoringManager;

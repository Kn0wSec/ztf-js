const crypto = require('crypto');
const geoip = require('geoip-lite');

class Utils {
  // Generate secure random token
  static generateSecureToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }

  // Generate secure random string
  static generateRandomString(length = 16) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }

  // Hash data with salt
  static hashData(data, salt = null) {
    if (!salt) {
      salt = crypto.randomBytes(16).toString('hex');
    }
    const hash = crypto.pbkdf2Sync(data, salt, 1000, 64, 'sha512').toString('hex');
    return { hash, salt };
  }

  // Verify hash
  static verifyHash(data, hash, salt) {
    const { hash: computedHash } = this.hashData(data, salt);
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(computedHash, 'hex'));
  }

  // Encrypt data
  static encryptData(data, key) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipher('aes-256-cbc', key);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return {
      encrypted,
      iv: iv.toString('hex')
    };
  }

  // Decrypt data
  static decryptData(encryptedData, key, iv) {
    const decipher = crypto.createDecipher('aes-256-cbc', key);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }

  // Generate device fingerprint
  static generateDeviceFingerprint(userAgent, ipAddress, additionalData = {}) {
    const fingerprintData = {
      userAgent,
      ipAddress,
      ...additionalData
    };
    
    const fingerprintString = JSON.stringify(fingerprintData);
    return crypto.createHash('sha256').update(fingerprintString).digest('hex');
  }

  // Get location from IP
  static getLocationFromIP(ipAddress) {
    try {
      const geo = geoip.lookup(ipAddress);
      if (geo) {
        return {
          country: geo.country,
          region: geo.region,
          city: geo.city,
          coordinates: {
            lat: geo.ll[0],
            lng: geo.ll[1]
          },
          timezone: geo.timezone
        };
      }
      return null;
    } catch (error) {
      return null;
    }
  }

  // Validate email format
  static isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  // Validate password strength
  static validatePasswordStrength(password) {
    const errors = [];
    
    if (password.length < 8) {
      errors.push('Password must be at least 8 characters long');
    }
    
    if (!/(?=.*[a-z])/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }
    
    if (!/(?=.*[A-Z])/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }
    
    if (!/(?=.*\d)/.test(password)) {
      errors.push('Password must contain at least one number');
    }
    
    if (!/(?=.*[!@#$%^&*])/.test(password)) {
      errors.push('Password must contain at least one special character (!@#$%^&*)');
    }
    
    return {
      isValid: errors.length === 0,
      errors
    };
  }

  // Sanitize input
  static sanitizeInput(input) {
    if (typeof input !== 'string') return input;
    
    return input
      .replace(/[<>]/g, '') // Remove < and >
      .replace(/javascript:/gi, '') // Remove javascript: protocol
      .replace(/on\w+=/gi, '') // Remove event handlers
      .trim();
  }

  // Validate IP address
  static isValidIP(ipAddress) {
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    
    return ipv4Regex.test(ipAddress) || ipv6Regex.test(ipAddress);
  }

  // Check if IP is private
  static isPrivateIP(ipAddress) {
    const privateRanges = [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
      /^192\.168\./
    ];
    
    return privateRanges.some(range => range.test(ipAddress));
  }

  // Calculate risk score
  static calculateRiskScore(factors) {
    let score = 0;
    
    if (factors.suspiciousLocation) score += 30;
    if (factors.unusualTime) score += 20;
    if (factors.newDevice) score += 25;
    if (factors.highRiskIP) score += 35;
    if (factors.vpnDetected) score += 15;
    if (factors.torDetected) score += 40;
    if (factors.bruteForce) score += 50;
    if (factors.rapidRequests) score += 20;
    
    return Math.min(100, score);
  }

  // Format timestamp
  static formatTimestamp(timestamp) {
    return new Date(timestamp).toISOString();
  }

  // Get time difference in human readable format
  static getTimeDifference(startTime, endTime = new Date()) {
    const diff = Math.abs(endTime - startTime);
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (days > 0) return `${days} day${days > 1 ? 's' : ''}`;
    if (hours > 0) return `${hours} hour${hours > 1 ? 's' : ''}`;
    if (minutes > 0) return `${minutes} minute${minutes > 1 ? 's' : ''}`;
    return 'Just now';
  }

  // Parse user agent
  static parseUserAgent(userAgent) {
    const browserRegex = /(chrome|firefox|safari|edge|opera|ie)\/?\s*(\d+)/i;
    const osRegex = /(windows|mac|linux|android|ios)\s*(\d+\.?\d*)/i;
    const deviceRegex = /(mobile|tablet|desktop)/i;
    
    const browser = userAgent.match(browserRegex);
    const os = userAgent.match(osRegex);
    const device = userAgent.match(deviceRegex);
    
    return {
      browser: browser ? browser[1] : 'unknown',
      browserVersion: browser ? browser[2] : 'unknown',
      os: os ? os[1] : 'unknown',
      osVersion: os ? os[2] : 'unknown',
      device: device ? device[1] : 'desktop'
    };
  }

  // Generate audit trail
  static generateAuditTrail(action, userId, details = {}) {
    return {
      action,
      userId,
      timestamp: new Date(),
      ipAddress: details.ipAddress,
      userAgent: details.userAgent,
      details: details.metadata || {},
      sessionId: details.sessionId
    };
  }

  // Validate MongoDB ObjectId
  static isValidObjectId(id) {
    const objectIdRegex = /^[0-9a-fA-F]{24}$/;
    return objectIdRegex.test(id);
  }

  // Deep clone object
  static deepClone(obj) {
    if (obj === null || typeof obj !== 'object') return obj;
    if (obj instanceof Date) return new Date(obj.getTime());
    if (obj instanceof Array) return obj.map(item => this.deepClone(item));
    if (typeof obj === 'object') {
      const clonedObj = {};
      for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
          clonedObj[key] = this.deepClone(obj[key]);
        }
      }
      return clonedObj;
    }
  }

  // Merge objects deeply
  static deepMerge(target, source) {
    const result = this.deepClone(target);
    
    for (const key in source) {
      if (source.hasOwnProperty(key)) {
        if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
          result[key] = this.deepMerge(result[key] || {}, source[key]);
        } else {
          result[key] = source[key];
        }
      }
    }
    
    return result;
  }

  // Retry function with exponential backoff
  static async retry(fn, maxRetries = 3, delay = 1000) {
    for (let i = 0; i < maxRetries; i++) {
      try {
        return await fn();
      } catch (error) {
        if (i === maxRetries - 1) throw error;
        await new Promise(resolve => setTimeout(resolve, delay * Math.pow(2, i)));
      }
    }
  }

  // Debounce function
  static debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  }

  // Throttle function
  static throttle(func, limit) {
    let inThrottle;
    return function() {
      const args = arguments;
      const context = this;
      if (!inThrottle) {
        func.apply(context, args);
        inThrottle = true;
        setTimeout(() => inThrottle = false, limit);
      }
    };
  }

  // Generate UUID v4
  static generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c == 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }

  // Check if string is JSON
  static isJSON(str) {
    try {
      JSON.parse(str);
      return true;
    } catch (e) {
      return false;
    }
  }

  // Safe JSON parse
  static safeJSONParse(str, defaultValue = null) {
    try {
      return JSON.parse(str);
    } catch (e) {
      return defaultValue;
    }
  }

  // Escape HTML
  static escapeHTML(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  // Unescape HTML
  static unescapeHTML(str) {
    const div = document.createElement('div');
    div.innerHTML = str;
    return div.textContent;
  }

  // Generate random color
  static generateRandomColor() {
    return '#' + Math.floor(Math.random() * 16777215).toString(16);
  }

  // Format bytes to human readable
  static formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  }

  // Sleep function
  static sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // Check if running in development
  static isDevelopment() {
    return process.env.NODE_ENV === 'development';
  }

  // Check if running in production
  static isProduction() {
    return process.env.NODE_ENV === 'production';
  }

  // Get environment variable with fallback
  static getEnv(key, fallback = null) {
    return process.env[key] || fallback;
  }

  // Validate required environment variables
  static validateEnv(requiredVars) {
    const missing = [];
    
    for (const varName of requiredVars) {
      if (!process.env[varName]) {
        missing.push(varName);
      }
    }
    
    if (missing.length > 0) {
      throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
    }
  }
}

module.exports = Utils;

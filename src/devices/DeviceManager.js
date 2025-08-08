const crypto = require('crypto');
const UAParser = require('ua-parser-js');
const geoip = require('geoip-lite');
const Device = require('../models/Device');
const Utils = require('../utils/Utils');

class DeviceManager {
  constructor(config, redis, monitoring) {
    this.config = config;
    this.redis = redis;
    this.monitoring = monitoring;
  }

  // Generate device fingerprint
  generateDeviceFingerprint(userAgent, ipAddress, additionalData = {}) {
    try {
      const parser = new UAParser(userAgent);
      const result = parser.getResult();

      const fingerprintData = {
        browser: result.browser.name || 'unknown',
        browserVersion: result.browser.version || 'unknown',
        os: result.os.name || 'unknown',
        osVersion: result.os.version || 'unknown',
        device: result.device.type || 'desktop',
        ipAddress: ipAddress,
        screenResolution: additionalData.screenResolution || 'unknown',
        timezone: additionalData.timezone || 'unknown',
        language: additionalData.language || 'en',
        canvas: additionalData.canvas || 'unknown',
        webgl: additionalData.webgl || 'unknown',
        fonts: additionalData.fonts || 'unknown'
      };

      // Create a hash of the fingerprint data
      const fingerprintString = JSON.stringify(fingerprintData);
      const fingerprint = crypto.createHash('sha256').update(fingerprintString).digest('hex');

      return {
        fingerprint,
        deviceInfo: {
          ...fingerprintData,
          userAgent: userAgent,
          deviceId: fingerprint
        }
      };
    } catch (error) {
      this.monitoring.logEvent({
        type: 'device_fingerprint_error',
        level: 'error',
        error: error.message
      });
      throw new Error('Failed to generate device fingerprint');
    }
  }

  // Register a new device
  async registerDevice(userId, deviceInfo, ipAddress, userAgent) {
    try {
      const { fingerprint, deviceInfo: parsedDeviceInfo } = this.generateDeviceFingerprint(
        userAgent, 
        ipAddress, 
        deviceInfo
      );

      // Check if device already exists
      let device = await Device.findOne({
        userId: userId,
        fingerprint: fingerprint
      });

      if (device) {
        // Update existing device
        device.lastSeen = new Date();
        device.ipAddress = ipAddress;
        device.userAgent = userAgent;
        device.loginCount += 1;
        await device.save();
      } else {
        // Create new device
        const location = this.getLocationFromIP(ipAddress);
        
        device = new Device({
          userId: userId,
          fingerprint: fingerprint,
          deviceInfo: parsedDeviceInfo,
          ipAddress: ipAddress,
          userAgent: userAgent,
          location: location,
          isTrusted: false,
          riskScore: this.calculateInitialRiskScore(parsedDeviceInfo, location),
          firstSeen: new Date(),
          lastSeen: new Date(),
          loginCount: 1
        });

        await device.save();
      }

      // Log device registration
      this.monitoring.logEvent({
        type: 'device_registered',
        userId: userId,
        deviceId: fingerprint,
        ipAddress: ipAddress,
        isNewDevice: !device.isTrusted
      });

      return device;
    } catch (error) {
      this.monitoring.logEvent({
        type: 'device_registration_failed',
        level: 'error',
        userId: userId,
        error: error.message
      });
      throw error;
    }
  }

  // Verify device trust
  async verifyDevice(userId, deviceId, ipAddress, userAgent) {
    try {
      const device = await Device.findOne({
        userId: userId,
        fingerprint: deviceId
      });

      if (!device) {
        return {
          isTrusted: false,
          riskScore: 100,
          flags: ['unknown_device'],
          requiresVerification: true
        };
      }

      // Update device info
      device.lastSeen = new Date();
      device.ipAddress = ipAddress;
      device.userAgent = userAgent;
      await device.save();

      // Calculate current risk score
      const currentRiskScore = this.calculateRiskScore(device, ipAddress, userAgent);
      device.riskScore = currentRiskScore;
      await device.save();

      // Determine if device is trusted
      const isTrusted = device.isTrusted && currentRiskScore < 70;

      // Check for suspicious activity
      const flags = this.detectSuspiciousActivity(device, ipAddress, userAgent);

      return {
        isTrusted,
        riskScore: currentRiskScore,
        flags,
        requiresVerification: !isTrusted || flags.length > 0,
        device: {
          id: device._id,
          name: device.deviceInfo.device || 'Unknown Device',
          browser: device.deviceInfo.browser,
          os: device.deviceInfo.os,
          lastSeen: device.lastSeen,
          loginCount: device.loginCount
        }
      };
    } catch (error) {
      this.monitoring.logEvent({
        type: 'device_verification_failed',
        level: 'error',
        userId: userId,
        deviceId: deviceId,
        error: error.message
      });
      throw error;
    }
  }

  // Trust a device
  async trustDevice(userId, deviceId) {
    try {
      const device = await Device.findOne({
        userId: userId,
        fingerprint: deviceId
      });

      if (!device) {
        throw new Error('Device not found');
      }

      device.isTrusted = true;
      device.trustedAt = new Date();
      device.riskScore = Math.max(0, device.riskScore - 20); // Reduce risk score
      await device.save();

      this.monitoring.logEvent({
        type: 'device_trusted',
        userId: userId,
        deviceId: deviceId
      });

      return { message: 'Device trusted successfully' };
    } catch (error) {
      throw error;
    }
  }

  // Untrust a device
  async untrustDevice(userId, deviceId) {
    try {
      const device = await Device.findOne({
        userId: userId,
        fingerprint: deviceId
      });

      if (!device) {
        throw new Error('Device not found');
      }

      device.isTrusted = false;
      device.trustedAt = null;
      device.riskScore = Math.min(100, device.riskScore + 20); // Increase risk score
      await device.save();

      this.monitoring.logEvent({
        type: 'device_untrusted',
        userId: userId,
        deviceId: deviceId
      });

      return { message: 'Device untrusted successfully' };
    } catch (error) {
      throw error;
    }
  }

  // Get user's devices
  async getUserDevices(userId) {
    try {
      const devices = await Device.find({ userId: userId })
        .sort({ lastSeen: -1 });

      return devices.map(device => ({
        id: device._id,
        fingerprint: device.fingerprint,
        deviceInfo: device.deviceInfo,
        isTrusted: device.isTrusted,
        riskScore: device.riskScore,
        lastSeen: device.lastSeen,
        loginCount: device.loginCount,
        location: device.location
      }));
    } catch (error) {
      throw error;
    }
  }

  // Remove a device
  async removeDevice(userId, deviceId) {
    try {
      const device = await Device.findOneAndDelete({
        userId: userId,
        fingerprint: deviceId
      });

      if (!device) {
        throw new Error('Device not found');
      }

      this.monitoring.logEvent({
        type: 'device_removed',
        userId: userId,
        deviceId: deviceId
      });

      return { message: 'Device removed successfully' };
    } catch (error) {
      throw error;
    }
  }

  // Calculate initial risk score
  calculateInitialRiskScore(deviceInfo, location) {
    let riskScore = 0;

    // Check for suspicious browser/OS combinations
    if (deviceInfo.browser === 'unknown' || deviceInfo.os === 'unknown') {
      riskScore += 20;
    }

    // Check for mobile devices (higher risk)
    if (deviceInfo.device === 'mobile') {
      riskScore += 10;
    }

    // Check for known suspicious locations
    if (location && this.isHighRiskLocation(location)) {
      riskScore += 30;
    }

    // Check for VPN/Tor usage (if detected)
    if (this.isVPNOrTor(deviceInfo)) {
      riskScore += 25;
    }

    return Math.min(100, riskScore);
  }

  // Calculate current risk score
  calculateRiskScore(device, currentIp, currentUserAgent) {
    let riskScore = device.riskScore;

    // Check for IP changes
    if (device.ipAddress !== currentIp) {
      riskScore += 15;
    }

    // Check for user agent changes
    if (device.userAgent !== currentUserAgent) {
      riskScore += 10;
    }

    // Check for unusual login time
    if (this.isUnusualLoginTime()) {
      riskScore += 20;
    }

    // Check for rapid login attempts
    if (await this.hasRapidLoginAttempts(device.userId)) {
      riskScore += 25;
    }

    return Math.min(100, riskScore);
  }

  // Detect suspicious activity
  detectSuspiciousActivity(device, ipAddress, userAgent) {
    const flags = [];

    // Check for location anomalies
    if (device.location && this.isLocationAnomaly(device.location, ipAddress)) {
      flags.push('suspicious_location');
    }

    // Check for unusual login time
    if (this.isUnusualLoginTime()) {
      flags.push('unusual_time');
    }

    // Check for new device
    if (!device.isTrusted) {
      flags.push('new_device');
    }

    // Check for high-risk IP
    if (this.isHighRiskIP(ipAddress)) {
      flags.push('high_risk_ip');
    }

    return flags;
  }

  // Get location from IP address
  getLocationFromIP(ipAddress) {
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

  // Check if location is high risk
  isHighRiskLocation(location) {
    const highRiskCountries = ['XX', 'YY', 'ZZ']; // Add actual high-risk country codes
    return highRiskCountries.includes(location.country);
  }

  // Check if IP is VPN or Tor
  isVPNOrTor(deviceInfo) {
    // This would typically involve checking against VPN/Tor exit node lists
    // For now, return false as a placeholder
    return false;
  }

  // Check if login time is unusual
  isUnusualLoginTime() {
    const hour = new Date().getHours();
    // Consider unusual if between 1 AM and 6 AM
    return hour >= 1 && hour <= 6;
  }

  // Check for rapid login attempts
  async hasRapidLoginAttempts(userId) {
    const key = `rapid_login:${userId}`;
    const attempts = await this.redis.get(key);
    return attempts && parseInt(attempts) > 3;
  }

  // Check for location anomaly
  isLocationAnomaly(deviceLocation, currentIp) {
    const currentLocation = this.getLocationFromIP(currentIp);
    if (!currentLocation || !deviceLocation) return false;

    // Check if country changed
    return deviceLocation.country !== currentLocation.country;
  }

  // Check if IP is high risk
  isHighRiskIP(ipAddress) {
    // This would typically involve checking against threat intelligence feeds
    // For now, return false as a placeholder
    return false;
  }

  // Get device statistics
  async getDeviceStats(userId) {
    try {
      const devices = await Device.find({ userId: userId });
      
      const stats = {
        totalDevices: devices.length,
        trustedDevices: devices.filter(d => d.isTrusted).length,
        highRiskDevices: devices.filter(d => d.riskScore > 70).length,
        lastLoginDevice: devices.sort((a, b) => b.lastSeen - a.lastSeen)[0] || null,
        deviceTypes: {},
        locations: {}
      };

      // Count device types
      devices.forEach(device => {
        const type = device.deviceInfo.device || 'unknown';
        stats.deviceTypes[type] = (stats.deviceTypes[type] || 0) + 1;
      });

      // Count locations
      devices.forEach(device => {
        if (device.location && device.location.country) {
          stats.locations[device.location.country] = (stats.locations[device.location.country] || 0) + 1;
        }
      });

      return stats;
    } catch (error) {
      throw error;
    }
  }
}

module.exports = DeviceManager;

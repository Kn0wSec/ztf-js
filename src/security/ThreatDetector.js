const crypto = require('crypto');
const geoip = require('geoip-lite');
const UAParser = require('ua-parser-js');

class ThreatDetector {
  constructor(config, monitoring) {
    this.config = config;
    this.monitoring = monitoring;
    this.threatPatterns = this.initializeThreatPatterns();
    this.userBehaviorProfiles = new Map();
    this.suspiciousIPs = new Map();
    this.blockedIPs = new Set();
  }

  initializeThreatPatterns() {
    return {
      // SQL Injection patterns
      sqlInjection: [
        /(\b(union|select|insert|update|delete|drop|create|alter|exec|execute|script)\b)/i,
        /(\b(or|and)\b\s+\d+\s*=\s*\d+)/i,
        /(\b(union|select|insert|update|delete|drop|create|alter|exec|execute|script)\b.*\b(union|select|insert|update|delete|drop|create|alter|exec|execute|script)\b)/i,
        /(\b(union|select|insert|update|delete|drop|create|alter|exec|execute|script)\b.*['"`])/i
      ],

      // XSS patterns
      xss: [
        /<script[^>]*>.*?<\/script>/gi,
        /javascript:/gi,
        /on\w+\s*=/gi,
        /<iframe[^>]*>/gi,
        /<object[^>]*>/gi,
        /<embed[^>]*>/gi,
        /<link[^>]*>/gi,
        /<meta[^>]*>/gi
      ],

      // Path traversal
      pathTraversal: [
        /\.\.\//g,
        /\.\.\\/g,
        /%2e%2e%2f/gi,
        /%2e%2e%5c/gi,
        /\.\.%2f/gi,
        /\.\.%5c/gi
      ],

      // Command injection
      commandInjection: [
        /[;&|`$(){}[\]]/g,
        /(\b(cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig|ipconfig)\b)/i
      ],

      // Suspicious user agents
      suspiciousUserAgents: [
        /bot|crawler|spider|scraper/i,
        /curl|wget|python|perl|ruby/i,
        /sqlmap|nikto|nmap|metasploit/i
      ],

      // Rate limiting violations
      rateLimitThresholds: {
        loginAttempts: 5,
        apiRequests: 100,
        suspiciousRequests: 10
      }
    };
  }

  async analyzeRequest(req, userId = null) {
    const threatAnalysis = {
      riskLevel: 'low',
      threats: [],
      score: 0,
      recommendations: []
    };

    try {
      // Analyze request headers
      const headerThreats = this.analyzeHeaders(req.headers);
      threatAnalysis.threats.push(...headerThreats);

      // Analyze request body
      const bodyThreats = this.analyzeBody(req.body);
      threatAnalysis.threats.push(...bodyThreats);

      // Analyze request URL and parameters
      const urlThreats = this.analyzeURL(req.url, req.query);
      threatAnalysis.threats.push(...urlThreats);

      // Analyze IP address
      const ipThreats = await this.analyzeIPAddress(req.ip);
      threatAnalysis.threats.push(...ipThreats);

      // Analyze user behavior if user is authenticated
      if (userId) {
        const behaviorThreats = await this.analyzeUserBehavior(userId, req);
        threatAnalysis.threats.push(...behaviorThreats);
      }

      // Calculate risk score
      threatAnalysis.score = this.calculateRiskScore(threatAnalysis.threats);
      threatAnalysis.riskLevel = this.determineRiskLevel(threatAnalysis.score);

      // Generate recommendations
      threatAnalysis.recommendations = this.generateRecommendations(threatAnalysis);

      // Log threat analysis
      await this.logThreatAnalysis(req, threatAnalysis);

      return threatAnalysis;
    } catch (error) {
      this.monitoring.logEvent({
        type: 'threat_analysis_error',
        level: 'error',
        message: error.message,
        metadata: { userId, ipAddress: req.ip }
      });
      return threatAnalysis;
    }
  }

  analyzeHeaders(headers) {
    const threats = [];

    // Check for suspicious user agent
    if (headers['user-agent']) {
      const userAgent = headers['user-agent'];
      for (const pattern of this.threatPatterns.suspiciousUserAgents) {
        if (pattern.test(userAgent)) {
          threats.push({
            type: 'suspicious_user_agent',
            severity: 'medium',
            description: 'Suspicious user agent detected',
            data: { userAgent }
          });
        }
      }
    }

    // Check for missing security headers
    const requiredHeaders = ['host', 'user-agent'];
    for (const header of requiredHeaders) {
      if (!headers[header]) {
        threats.push({
          type: 'missing_security_header',
          severity: 'low',
          description: `Missing required header: ${header}`,
          data: { header }
        });
      }
    }

    return threats;
  }

  analyzeBody(body) {
    const threats = [];
    if (!body) return threats;

    const bodyString = JSON.stringify(body);

    // Check for SQL injection
    for (const pattern of this.threatPatterns.sqlInjection) {
      if (pattern.test(bodyString)) {
        threats.push({
          type: 'sql_injection_attempt',
          severity: 'high',
          description: 'Potential SQL injection detected in request body',
          data: { pattern: pattern.source }
        });
      }
    }

    // Check for XSS
    for (const pattern of this.threatPatterns.xss) {
      if (pattern.test(bodyString)) {
        threats.push({
          type: 'xss_attempt',
          severity: 'high',
          description: 'Potential XSS attack detected in request body',
          data: { pattern: pattern.source }
        });
      }
    }

    return threats;
  }

  analyzeURL(url, query) {
    const threats = [];
    const fullUrl = url + (query ? '?' + new URLSearchParams(query).toString() : '');

    // Check for path traversal
    for (const pattern of this.threatPatterns.pathTraversal) {
      if (pattern.test(fullUrl)) {
        threats.push({
          type: 'path_traversal_attempt',
          severity: 'high',
          description: 'Path traversal attempt detected',
          data: { url: fullUrl }
        });
      }
    }

    // Check for command injection
    for (const pattern of this.threatPatterns.commandInjection) {
      if (pattern.test(fullUrl)) {
        threats.push({
          type: 'command_injection_attempt',
          severity: 'high',
          description: 'Command injection attempt detected',
          data: { url: fullUrl }
        });
      }
    }

    return threats;
  }

  async analyzeIPAddress(ip) {
    const threats = [];

    // Check if IP is blocked
    if (this.blockedIPs.has(ip)) {
      threats.push({
        type: 'blocked_ip',
        severity: 'high',
        description: 'Request from blocked IP address',
        data: { ip }
      });
      return threats;
    }

    // Check if IP is suspicious
    const suspiciousData = this.suspiciousIPs.get(ip);
    if (suspiciousData && suspiciousData.count > 5) {
      threats.push({
        type: 'suspicious_ip',
        severity: 'medium',
        description: 'IP address showing suspicious behavior',
        data: { ip, count: suspiciousData.count }
      });
    }

    // Analyze geographic location
    const geo = geoip.lookup(ip);
    if (geo) {
      // Check for requests from unusual locations
      if (this.isUnusualLocation(geo)) {
        threats.push({
          type: 'unusual_location',
          severity: 'medium',
          description: 'Request from unusual geographic location',
          data: { ip, country: geo.country, region: geo.region }
        });
      }
    }

    return threats;
  }

  async analyzeUserBehavior(userId, req) {
    const threats = [];
    const now = Date.now();

    // Get or create user behavior profile
    let profile = this.userBehaviorProfiles.get(userId);
    if (!profile) {
      profile = {
        lastRequest: now,
        requestCount: 0,
        locations: new Set(),
        userAgents: new Set(),
        suspiciousActions: 0
      };
      this.userBehaviorProfiles.set(userId, profile);
    }

    // Update profile
    profile.requestCount++;
    profile.lastRequest = now;

    // Check for rapid requests (potential automated attack)
    const timeSinceLastRequest = now - profile.lastRequest;
    if (timeSinceLastRequest < 1000 && profile.requestCount > 10) { // Less than 1 second between requests
      threats.push({
        type: 'rapid_requests',
        severity: 'medium',
        description: 'Unusually rapid requests detected',
        data: { timeSinceLastRequest, requestCount: profile.requestCount }
      });
    }

    // Track locations
    const geo = geoip.lookup(req.ip);
    if (geo) {
      profile.locations.add(geo.country);
      if (profile.locations.size > 3) { // User accessing from more than 3 countries
        threats.push({
          type: 'multiple_locations',
          severity: 'medium',
          description: 'User accessing from multiple geographic locations',
          data: { locations: Array.from(profile.locations) }
        });
      }
    }

    // Track user agents
    if (req.headers['user-agent']) {
      profile.userAgents.add(req.headers['user-agent']);
      if (profile.userAgents.size > 5) { // User with more than 5 different user agents
        threats.push({
          type: 'multiple_user_agents',
          severity: 'low',
          description: 'User with multiple different user agents',
          data: { userAgentCount: profile.userAgents.size }
        });
      }
    }

    return threats;
  }

  calculateRiskScore(threats) {
    let score = 0;
    const severityWeights = {
      low: 1,
      medium: 5,
      high: 10,
      critical: 20
    };

    for (const threat of threats) {
      score += severityWeights[threat.severity] || 1;
    }

    return Math.min(score, 100); // Cap at 100
  }

  determineRiskLevel(score) {
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    if (score >= 20) return 'low';
    return 'minimal';
  }

  generateRecommendations(analysis) {
    const recommendations = [];

    if (analysis.riskLevel === 'critical') {
      recommendations.push('Immediate action required: Block IP and investigate');
    }

    if (analysis.riskLevel === 'high') {
      recommendations.push('Consider implementing additional security measures');
      recommendations.push('Monitor user activity closely');
    }

    if (analysis.threats.some(t => t.type === 'sql_injection_attempt')) {
      recommendations.push('Implement input validation and parameterized queries');
    }

    if (analysis.threats.some(t => t.type === 'xss_attempt')) {
      recommendations.push('Implement output encoding and CSP headers');
    }

    if (analysis.threats.some(t => t.type === 'rapid_requests')) {
      recommendations.push('Implement rate limiting for this user');
    }

    return recommendations;
  }

  async logThreatAnalysis(req, analysis) {
    await this.monitoring.logEvent({
      type: 'threat_analysis',
      level: analysis.riskLevel === 'critical' ? 'error' : 'warn',
      message: `Threat analysis completed - Risk Level: ${analysis.riskLevel}`,
      metadata: {
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        url: req.url,
        method: req.method,
        riskScore: analysis.score,
        threats: analysis.threats,
        recommendations: analysis.recommendations
      }
    });
  }

  isUnusualLocation(geo) {
    // This would typically be configured based on your user base
    // For now, we'll flag requests from countries with low user activity
    const commonCountries = ['US', 'CA', 'GB', 'DE', 'FR', 'AU'];
    return !commonCountries.includes(geo.country);
  }

  blockIP(ip, reason = 'Manual block') {
    this.blockedIPs.add(ip);
    this.monitoring.logEvent({
      type: 'ip_blocked',
      level: 'warn',
      message: `IP address blocked: ${ip}`,
      metadata: { ip, reason }
    });
  }

  unblockIP(ip) {
    this.blockedIPs.delete(ip);
    this.monitoring.logEvent({
      type: 'ip_unblocked',
      level: 'info',
      message: `IP address unblocked: ${ip}`,
      metadata: { ip }
    });
  }

  markSuspiciousIP(ip) {
    const current = this.suspiciousIPs.get(ip) || { count: 0, firstSeen: Date.now() };
    current.count++;
    this.suspiciousIPs.set(ip, current);
  }

  getThreatStatistics() {
    return {
      blockedIPs: this.blockedIPs.size,
      suspiciousIPs: this.suspiciousIPs.size,
      userProfiles: this.userBehaviorProfiles.size,
      threatPatterns: Object.keys(this.threatPatterns).length
    };
  }
}

module.exports = ThreatDetector;

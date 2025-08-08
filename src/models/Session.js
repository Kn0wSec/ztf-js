const mongoose = require('mongoose');

const sessionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  token: {
    type: String,
    required: true,
    unique: true
  },
  refreshToken: {
    type: String,
    required: true,
    unique: true
  },
  expiresAt: {
    type: Date,
    required: true
  },
  isActive: {
    type: Boolean,
    default: true
  },
  deviceInfo: {
    deviceId: String,
    deviceName: String,
    deviceType: String,
    browser: String,
    browserVersion: String,
    os: String,
    osVersion: String,
    userAgent: String
  },
  ipAddress: {
    type: String
  },
  location: {
    country: String,
    countryCode: String,
    region: String,
    city: String,
    coordinates: {
      lat: Number,
      lng: Number
    },
    timezone: String
  },
  security: {
    isTrusted: {
      type: Boolean,
      default: false
    },
    riskScore: {
      type: Number,
      default: 0,
      min: 0,
      max: 100
    },
    flags: [{
      type: String,
      enum: ['suspicious_location', 'unusual_time', 'new_device', 'high_risk_ip']
    }]
  },
  activity: {
    lastActivityAt: {
      type: Date,
      default: Date.now
    },
    requestCount: {
      type: Number,
      default: 0
    },
    endpoints: [{
      path: String,
      method: String,
      count: Number,
      lastAccessed: Date
    }]
  },
  metadata: {
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    tags: [String],
    notes: String
  },
  loggedOutAt: {
    type: Date
  },
  logoutReason: {
    type: String,
    enum: ['user_logout', 'session_expired', 'security_violation', 'admin_logout', 'device_change']
  }
}, {
  timestamps: true
});

// Indexes for performance
sessionSchema.index({ userId: 1 });
sessionSchema.index({ token: 1 });
sessionSchema.index({ refreshToken: 1 });
sessionSchema.index({ isActive: 1 });
sessionSchema.index({ expiresAt: 1 });
sessionSchema.index({ 'deviceInfo.deviceId': 1 });
sessionSchema.index({ ipAddress: 1 });
sessionSchema.index({ createdAt: -1 });

// Instance methods
sessionSchema.methods.isExpired = function() {
  return new Date() > this.expiresAt;
};

sessionSchema.methods.updateActivity = function(endpoint, method) {
  this.activity.lastActivityAt = new Date();
  this.activity.requestCount += 1;
  
  // Update endpoint activity
  const existingEndpoint = this.activity.endpoints.find(
    ep => ep.path === endpoint && ep.method === method
  );
  
  if (existingEndpoint) {
    existingEndpoint.count += 1;
    existingEndpoint.lastAccessed = new Date();
  } else {
    this.activity.endpoints.push({
      path: endpoint,
      method: method,
      count: 1,
      lastAccessed: new Date()
    });
  }
};

sessionSchema.methods.logout = function(reason = 'user_logout') {
  this.isActive = false;
  this.loggedOutAt = new Date();
  this.logoutReason = reason;
};

sessionSchema.methods.addSecurityFlag = function(flag) {
  if (!this.security.flags.includes(flag)) {
    this.security.flags.push(flag);
  }
};

sessionSchema.methods.removeSecurityFlag = function(flag) {
  this.security.flags = this.security.flags.filter(f => f !== flag);
};

sessionSchema.methods.updateRiskScore = function(score) {
  this.security.riskScore = Math.max(0, Math.min(100, score));
};

// Static methods
sessionSchema.statics.findActiveSessions = function(userId) {
  return this.find({
    userId: userId,
    isActive: true,
    expiresAt: { $gt: new Date() }
  });
};

sessionSchema.statics.findByToken = function(token) {
  return this.findOne({ token: token });
};

sessionSchema.statics.findByRefreshToken = function(refreshToken) {
  return this.findOne({ refreshToken: refreshToken });
};

sessionSchema.statics.findExpiredSessions = function() {
  return this.find({
    expiresAt: { $lt: new Date() },
    isActive: true
  });
};

sessionSchema.statics.cleanupExpiredSessions = async function() {
  const result = await this.updateMany(
    {
      expiresAt: { $lt: new Date() },
      isActive: true
    },
    {
      isActive: false,
      logoutReason: 'session_expired',
      loggedOutAt: new Date()
    }
  );
  
  return result.modifiedCount;
};

// Pre-save middleware
sessionSchema.pre('save', function(next) {
  if (this.isModified('activity.lastActivityAt')) {
    this.activity.lastActivityAt = new Date();
  }
  next();
});

// TTL index for automatic cleanup (optional, for very old sessions)
// sessionSchema.index({ createdAt: 1 }, { expireAfterSeconds: 30 * 24 * 60 * 60 }); // 30 days

module.exports = mongoose.model('Session', sessionSchema);

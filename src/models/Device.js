const mongoose = require('mongoose');

const deviceSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  fingerprint: {
    type: String,
    required: true,
    unique: true
  },
  deviceInfo: {
    browser: String,
    browserVersion: String,
    os: String,
    osVersion: String,
    device: String,
    ipAddress: String,
    screenResolution: String,
    timezone: String,
    language: String,
    canvas: String,
    webgl: String,
    fonts: String,
    userAgent: String,
    deviceId: String
  },
  ipAddress: {
    type: String
  },
  userAgent: {
    type: String
  },
  location: {
    country: String,
    region: String,
    city: String,
    coordinates: {
      lat: Number,
      lng: Number
    },
    timezone: String
  },
  isTrusted: {
    type: Boolean,
    default: false
  },
  trustedAt: {
    type: Date
  },
  riskScore: {
    type: Number,
    default: 0,
    min: 0,
    max: 100
  },
  firstSeen: {
    type: Date,
    default: Date.now
  },
  lastSeen: {
    type: Date,
    default: Date.now
  },
  loginCount: {
    type: Number,
    default: 0
  },
  securityFlags: [{
    type: String,
    enum: ['suspicious_location', 'unusual_time', 'new_device', 'high_risk_ip', 'vpn_detected', 'tor_detected']
  }],
  activity: {
    totalRequests: {
      type: Number,
      default: 0
    },
    lastActivity: {
      type: Date,
      default: Date.now
    },
    endpoints: [{
      path: String,
      method: String,
      count: Number,
      lastAccessed: Date
    }]
  },
  metadata: {
    notes: String,
    tags: [String],
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    }
  }
}, {
  timestamps: true
});

// Indexes for performance
deviceSchema.index({ userId: 1 });
deviceSchema.index({ fingerprint: 1 });
deviceSchema.index({ isTrusted: 1 });
deviceSchema.index({ riskScore: -1 });
deviceSchema.index({ lastSeen: -1 });
deviceSchema.index({ ipAddress: 1 });
deviceSchema.index({ 'location.country': 1 });

// Instance methods
deviceSchema.methods.updateActivity = function(endpoint, method) {
  this.activity.totalRequests += 1;
  this.activity.lastActivity = new Date();
  
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

deviceSchema.methods.addSecurityFlag = function(flag) {
  if (!this.securityFlags.includes(flag)) {
    this.securityFlags.push(flag);
  }
};

deviceSchema.methods.removeSecurityFlag = function(flag) {
  this.securityFlags = this.securityFlags.filter(f => f !== flag);
};

deviceSchema.methods.updateRiskScore = function(score) {
  this.riskScore = Math.max(0, Math.min(100, score));
};

deviceSchema.methods.trust = function() {
  this.isTrusted = true;
  this.trustedAt = new Date();
  this.riskScore = Math.max(0, this.riskScore - 20);
};

deviceSchema.methods.untrust = function() {
  this.isTrusted = false;
  this.trustedAt = null;
  this.riskScore = Math.min(100, this.riskScore + 20);
};

deviceSchema.methods.isHighRisk = function() {
  return this.riskScore > 70;
};

deviceSchema.methods.getDeviceName = function() {
  const info = this.deviceInfo;
  if (info.device && info.device !== 'desktop') {
    return `${info.device} (${info.os})`;
  }
  return `${info.browser} on ${info.os}`;
};

// Static methods
deviceSchema.statics.findByFingerprint = function(fingerprint) {
  return this.findOne({ fingerprint: fingerprint });
};

deviceSchema.statics.findUserDevices = function(userId) {
  return this.find({ userId: userId }).sort({ lastSeen: -1 });
};

deviceSchema.statics.findTrustedDevices = function(userId) {
  return this.find({ 
    userId: userId, 
    isTrusted: true 
  }).sort({ lastSeen: -1 });
};

deviceSchema.statics.findHighRiskDevices = function(userId) {
  return this.find({ 
    userId: userId, 
    riskScore: { $gt: 70 } 
  }).sort({ riskScore: -1 });
};

deviceSchema.statics.findByIP = function(ipAddress) {
  return this.find({ ipAddress: ipAddress });
};

deviceSchema.statics.findByLocation = function(country) {
  return this.find({ 'location.country': country });
};

// Pre-save middleware
deviceSchema.pre('save', function(next) {
  if (this.isModified('lastSeen')) {
    this.lastSeen = new Date();
  }
  next();
});

module.exports = mongoose.model('Device', deviceSchema);

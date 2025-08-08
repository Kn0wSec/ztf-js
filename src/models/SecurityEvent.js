const mongoose = require('mongoose');

const securityEventSchema = new mongoose.Schema({
  type: {
    type: String,
    required: true,
    index: true
  },
  level: {
    type: String,
    enum: ['info', 'warning', 'error', 'critical'],
    default: 'info',
    index: true
  },
  timestamp: {
    type: Date,
    default: Date.now,
    index: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    index: true
  },
  ipAddress: {
    type: String,
    index: true
  },
  userAgent: String,
  sessionId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Session'
  },
  deviceId: String,
  message: {
    type: String,
    required: true
  },
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  riskScore: {
    type: Number,
    default: 0,
    min: 0,
    max: 100,
    index: true
  },
  flags: [{
    type: String,
    enum: [
      'suspicious_location',
      'unusual_time',
      'new_device',
      'high_risk_ip',
      'brute_force',
      'rapid_requests',
      'vpn_detected',
      'tor_detected',
      'account_locked',
      'mfa_required',
      'verification_required'
    ]
  }],
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
  deviceInfo: {
    browser: String,
    browserVersion: String,
    os: String,
    osVersion: String,
    device: String
  },
  requestInfo: {
    method: String,
    path: String,
    query: mongoose.Schema.Types.Mixed,
    headers: mongoose.Schema.Types.Mixed,
    body: mongoose.Schema.Types.Mixed
  },
  responseInfo: {
    statusCode: Number,
    responseTime: Number,
    responseSize: Number
  },
  tags: [String],
  source: {
    type: String,
    enum: ['auth', 'device', 'monitoring', 'middleware', 'api', 'system'],
    default: 'system'
  }
}, {
  timestamps: true
});

// Indexes for performance
securityEventSchema.index({ type: 1, timestamp: -1 });
securityEventSchema.index({ level: 1, timestamp: -1 });
securityEventSchema.index({ userId: 1, timestamp: -1 });
securityEventSchema.index({ ipAddress: 1, timestamp: -1 });
securityEventSchema.index({ riskScore: -1, timestamp: -1 });
securityEventSchema.index({ 'flags': 1, timestamp: -1 });
securityEventSchema.index({ source: 1, timestamp: -1 });

// TTL index for automatic cleanup (optional)
// securityEventSchema.index({ timestamp: 1 }, { expireAfterSeconds: 90 * 24 * 60 * 60 }); // 90 days

// Static methods
securityEventSchema.statics.findByType = function(type, limit = 100) {
  return this.find({ type: type })
    .sort({ timestamp: -1 })
    .limit(limit);
};

securityEventSchema.statics.findByLevel = function(level, limit = 100) {
  return this.find({ level: level })
    .sort({ timestamp: -1 })
    .limit(limit);
};

securityEventSchema.statics.findByUser = function(userId, limit = 100) {
  return this.find({ userId: userId })
    .sort({ timestamp: -1 })
    .limit(limit);
};

securityEventSchema.statics.findByIP = function(ipAddress, limit = 100) {
  return this.find({ ipAddress: ipAddress })
    .sort({ timestamp: -1 })
    .limit(limit);
};

securityEventSchema.statics.findHighRiskEvents = function(limit = 100) {
  return this.find({ riskScore: { $gte: 70 } })
    .sort({ timestamp: -1 })
    .limit(limit);
};

securityEventSchema.statics.findByTimeRange = function(startTime, endTime) {
  return this.find({
    timestamp: {
      $gte: startTime,
      $lte: endTime
    }
  }).sort({ timestamp: -1 });
};

securityEventSchema.statics.getEventStats = function(timeframe = '24h') {
  const now = new Date();
  let startTime;
  
  switch (timeframe) {
    case '1h':
      startTime = new Date(now.getTime() - 60 * 60 * 1000);
      break;
    case '6h':
      startTime = new Date(now.getTime() - 6 * 60 * 60 * 1000);
      break;
    case '24h':
      startTime = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      break;
    case '7d':
      startTime = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      break;
    case '30d':
      startTime = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
      break;
    default:
      startTime = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  }

  return this.aggregate([
    {
      $match: {
        timestamp: { $gte: startTime }
      }
    },
    {
      $group: {
        _id: {
          type: '$type',
          level: '$level'
        },
        count: { $sum: 1 },
        avgRiskScore: { $avg: '$riskScore' },
        maxRiskScore: { $max: '$riskScore' }
      }
    },
    {
      $group: {
        _id: '$_id.type',
        levels: {
          $push: {
            level: '$_id.level',
            count: '$count',
            avgRiskScore: '$avgRiskScore',
            maxRiskScore: '$maxRiskScore'
          }
        },
        totalCount: { $sum: '$count' }
      }
    },
    {
      $sort: { totalCount: -1 }
    }
  ]);
};

securityEventSchema.statics.getTopIPs = function(timeframe = '24h', limit = 10) {
  const now = new Date();
  let startTime;
  
  switch (timeframe) {
    case '1h':
      startTime = new Date(now.getTime() - 60 * 60 * 1000);
      break;
    case '6h':
      startTime = new Date(now.getTime() - 6 * 60 * 60 * 1000);
      break;
    case '24h':
      startTime = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      break;
    case '7d':
      startTime = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      break;
    case '30d':
      startTime = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
      break;
    default:
      startTime = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  }

  return this.aggregate([
    {
      $match: {
        timestamp: { $gte: startTime },
        ipAddress: { $exists: true, $ne: null }
      }
    },
    {
      $group: {
        _id: '$ipAddress',
        count: { $sum: 1 },
        avgRiskScore: { $avg: '$riskScore' },
        maxRiskScore: { $max: '$riskScore' },
        eventTypes: { $addToSet: '$type' },
        lastSeen: { $max: '$timestamp' }
      }
    },
    {
      $sort: { count: -1 }
    },
    {
      $limit: limit
    }
  ]);
};

securityEventSchema.statics.getTopUsers = function(timeframe = '24h', limit = 10) {
  const now = new Date();
  let startTime;
  
  switch (timeframe) {
    case '1h':
      startTime = new Date(now.getTime() - 60 * 60 * 1000);
      break;
    case '6h':
      startTime = new Date(now.getTime() - 6 * 60 * 60 * 1000);
      break;
    case '24h':
      startTime = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      break;
    case '7d':
      startTime = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      break;
    case '30d':
      startTime = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
      break;
    default:
      startTime = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  }

  return this.aggregate([
    {
      $match: {
        timestamp: { $gte: startTime },
        userId: { $exists: true, $ne: null }
      }
    },
    {
      $group: {
        _id: '$userId',
        count: { $sum: 1 },
        avgRiskScore: { $avg: '$riskScore' },
        maxRiskScore: { $max: '$riskScore' },
        eventTypes: { $addToSet: '$type' },
        lastSeen: { $max: '$timestamp' }
      }
    },
    {
      $sort: { count: -1 }
    },
    {
      $limit: limit
    }
  ]);
};

// Instance methods
securityEventSchema.methods.isHighRisk = function() {
  return this.riskScore >= 70;
};

securityEventSchema.methods.isCritical = function() {
  return this.level === 'critical' || this.riskScore >= 90;
};

securityEventSchema.methods.addFlag = function(flag) {
  if (!this.flags.includes(flag)) {
    this.flags.push(flag);
  }
};

securityEventSchema.methods.removeFlag = function(flag) {
  this.flags = this.flags.filter(f => f !== flag);
};

securityEventSchema.methods.updateRiskScore = function(score) {
  this.riskScore = Math.max(0, Math.min(100, score));
};

module.exports = mongoose.model('SecurityEvent', securityEventSchema);

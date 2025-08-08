const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$/, 'Please enter a valid email']
  },
  password: {
    type: String,
    required: true,
    minlength: 8
  },
  firstName: {
    type: String,
    required: true,
    trim: true,
    maxlength: 50
  },
  lastName: {
    type: String,
    required: true,
    trim: true,
    maxlength: 50
  },
  isActive: {
    type: Boolean,
    default: true
  },
  emailVerified: {
    type: Boolean,
    default: false
  },
  emailVerificationToken: {
    type: String
  },
  emailVerificationExpires: {
    type: Date
  },
  mfaEnabled: {
    type: Boolean,
    default: false
  },
  mfaSecret: {
    type: String
  },
  mfaBackupCodes: [{
    code: String,
    used: {
      type: Boolean,
      default: false
    }
  }],
  roles: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Role',
    default: []
  }],
  permissions: [{
    type: String
  }],
  lastLoginAt: {
    type: Date
  },
  lastLoginIp: {
    type: String
  },
  lastLoginUserAgent: {
    type: String
  },
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockoutUntil: {
    type: Date
  },
  passwordChangedAt: {
    type: Date
  },
  passwordResetToken: {
    type: String
  },
  passwordResetExpires: {
    type: Date
  },
  profile: {
    avatar: String,
    phone: String,
    address: {
      street: String,
      city: String,
      state: String,
      zipCode: String,
      country: String
    },
    preferences: {
      language: {
        type: String,
        default: 'en'
      },
      timezone: {
        type: String,
        default: 'UTC'
      },
      notifications: {
        email: {
          type: Boolean,
          default: true
        },
        sms: {
          type: Boolean,
          default: false
        },
        push: {
          type: Boolean,
          default: true
        }
      }
    }
  },
  security: {
    twoFactorEnabled: {
      type: Boolean,
      default: false
    },
    trustedDevices: [{
      deviceId: String,
      deviceName: String,
      userAgent: String,
      ipAddress: String,
      lastUsed: Date,
      isTrusted: {
        type: Boolean,
        default: false
      }
    }],
    loginHistory: [{
      timestamp: {
        type: Date,
        default: Date.now
      },
      ipAddress: String,
      userAgent: String,
      location: {
        country: String,
        city: String,
        coordinates: {
          lat: Number,
          lng: Number
        }
      },
      success: Boolean,
      failureReason: String
    }],
    securityQuestions: [{
      question: String,
      answer: String
    }]
  },
  metadata: {
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    updatedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    tags: [String],
    notes: String
  }
}, {
  timestamps: true,
  toJSON: {
    transform: function(doc, ret) {
      delete ret.password;
      delete ret.mfaSecret;
      delete ret.emailVerificationToken;
      delete ret.passwordResetToken;
      delete ret.securityQuestions;
      return ret;
    }
  }
});

// Indexes for performance
userSchema.index({ email: 1 });
userSchema.index({ isActive: 1 });
userSchema.index({ 'security.trustedDevices.deviceId': 1 });
userSchema.index({ createdAt: -1 });

// Pre-save middleware to hash password
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    this.passwordChangedAt = new Date();
    next();
  } catch (error) {
    next(error);
  }
});

// Instance methods
userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.hasRole = function(roleName) {
  return this.roles.some(role => role.name === roleName);
};

userSchema.methods.hasPermission = function(permission) {
  return this.permissions.includes(permission);
};

userSchema.methods.addTrustedDevice = function(deviceInfo) {
  const existingDevice = this.security.trustedDevices.find(
    device => device.deviceId === deviceInfo.deviceId
  );
  
  if (existingDevice) {
    existingDevice.lastUsed = new Date();
    existingDevice.isTrusted = true;
  } else {
    this.security.trustedDevices.push({
      deviceId: deviceInfo.deviceId,
      deviceName: deviceInfo.deviceName,
      userAgent: deviceInfo.userAgent,
      ipAddress: deviceInfo.ipAddress,
      lastUsed: new Date(),
      isTrusted: true
    });
  }
};

userSchema.methods.addLoginAttempt = function(attemptInfo) {
  this.security.loginHistory.push({
    timestamp: new Date(),
    ipAddress: attemptInfo.ipAddress,
    userAgent: attemptInfo.userAgent,
    location: attemptInfo.location,
    success: attemptInfo.success,
    failureReason: attemptInfo.failureReason
  });
  
  // Keep only last 100 login attempts
  if (this.security.loginHistory.length > 100) {
    this.security.loginHistory = this.security.loginHistory.slice(-100);
  }
  
  if (attemptInfo.success) {
    this.lastLoginAt = new Date();
    this.lastLoginIp = attemptInfo.ipAddress;
    this.lastLoginUserAgent = attemptInfo.userAgent;
    this.loginAttempts = 0;
  } else {
    this.loginAttempts += 1;
  }
};

userSchema.methods.isLocked = function() {
  return this.lockoutUntil && this.lockoutUntil > new Date();
};

userSchema.methods.lockAccount = function(durationMinutes = 15) {
  this.lockoutUntil = new Date(Date.now() + durationMinutes * 60 * 1000);
};

userSchema.methods.unlockAccount = function() {
  this.lockoutUntil = null;
  this.loginAttempts = 0;
};

// Static methods
userSchema.statics.findByEmail = function(email) {
  return this.findOne({ email: email.toLowerCase() });
};

userSchema.statics.findActiveUsers = function() {
  return this.find({ isActive: true });
};

userSchema.statics.findByRole = function(roleName) {
  return this.find({ 'roles.name': roleName });
};

module.exports = mongoose.model('User', userSchema);

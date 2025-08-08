const mongoose = require('mongoose');

const roleSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    maxlength: 50
  },
  displayName: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  description: {
    type: String,
    trim: true,
    maxlength: 500
  },
  permissions: [{
    type: String,
    required: true
  }],
  isSystem: {
    type: Boolean,
    default: false
  },
  isActive: {
    type: Boolean,
    default: true
  },
  priority: {
    type: Number,
    default: 0
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
  timestamps: true
});

// Indexes
roleSchema.index({ name: 1 });
roleSchema.index({ isActive: 1 });
roleSchema.index({ priority: -1 });

// Instance methods
roleSchema.methods.hasPermission = function(permission) {
  return this.permissions.includes(permission);
};

roleSchema.methods.addPermission = function(permission) {
  if (!this.permissions.includes(permission)) {
    this.permissions.push(permission);
  }
};

roleSchema.methods.removePermission = function(permission) {
  this.permissions = this.permissions.filter(p => p !== permission);
};

roleSchema.methods.getPermissions = function() {
  return [...this.permissions];
};

// Static methods
roleSchema.statics.findByName = function(name) {
  return this.findOne({ name: name.toLowerCase() });
};

roleSchema.statics.findActiveRoles = function() {
  return this.find({ isActive: true }).sort({ priority: -1 });
};

roleSchema.statics.findByPermission = function(permission) {
  return this.find({ 
    permissions: permission,
    isActive: true 
  });
};

// Pre-save middleware
roleSchema.pre('save', function(next) {
  if (this.isModified('name')) {
    this.name = this.name.toLowerCase();
  }
  next();
});

// Pre-remove middleware to prevent deletion of system roles
roleSchema.pre('remove', function(next) {
  if (this.isSystem) {
    return next(new Error('Cannot delete system roles'));
  }
  next();
});

module.exports = mongoose.model('Role', roleSchema);

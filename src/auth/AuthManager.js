const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const User = require('../models/User');
const Role = require('../models/Role');
const Session = require('../models/Session');
const Utils = require('../utils/Utils');

class AuthManager {
  constructor(config, redis, monitoring) {
    this.config = config;
    this.redis = redis;
    this.monitoring = monitoring;
  }

  // User Registration
  async register(userData) {
    try {
      // Validate input
      this.validateRegistrationData(userData);

      // Check if user already exists
      const existingUser = await User.findOne({ email: userData.email.toLowerCase() });
      if (existingUser) {
        throw new Error('User with this email already exists');
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(userData.password, this.config.security.bcryptRounds);

      // Create user
      const user = new User({
        email: userData.email.toLowerCase(),
        password: hashedPassword,
        firstName: userData.firstName,
        lastName: userData.lastName,
        isActive: true,
        emailVerified: false,
        mfaEnabled: false,
        roles: ['user'] // Default role
      });

      await user.save();

      // Log event
      this.monitoring.logEvent({
        type: 'user_registered',
        userId: user._id,
        email: user.email,
        ipAddress: userData.ipAddress,
        userAgent: userData.userAgent
      });

      return {
        user: {
          id: user._id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          roles: user.roles
        },
        message: 'User registered successfully'
      };
    } catch (error) {
      this.monitoring.logEvent({
        type: 'registration_failed',
        level: 'error',
        email: userData.email,
        error: error.message
      });
      throw error;
    }
  }

  // User Login
  async login(credentials) {
    try {
      const { email, password, deviceInfo, ipAddress, userAgent } = credentials;

      // Find user
      const user = await User.findOne({ email: email.toLowerCase() }).populate('roles');
      if (!user) {
        throw new Error('Invalid credentials');
      }

      // Check if user is active
      if (!user.isActive) {
        throw new Error('Account is deactivated');
      }

      // Check for account lockout
      const lockoutKey = `lockout:${user._id}`;
      const lockoutStatus = await this.redis.get(lockoutKey);
      if (lockoutStatus) {
        throw new Error('Account is temporarily locked due to multiple failed login attempts');
      }

      // Verify password
      const isValidPassword = await bcrypt.compare(password, user.password);
      if (!isValidPassword) {
        await this.handleFailedLogin(user._id);
        throw new Error('Invalid credentials');
      }

      // Check if MFA is required
      if (user.mfaEnabled) {
        return {
          requiresMFA: true,
          userId: user._id,
          message: 'MFA verification required'
        };
      }

      // Create session
      const session = await this.createSession(user, deviceInfo, ipAddress, userAgent);

      // Log successful login
      this.monitoring.logEvent({
        type: 'login_success',
        userId: user._id,
        email: user.email,
        ipAddress,
        userAgent,
        sessionId: session._id
      });

      return {
        user: {
          id: user._id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          roles: user.roles.map(role => role.name),
          permissions: await this.getUserPermissions(user._id)
        },
        session: {
          token: session.token,
          refreshToken: session.refreshToken,
          expiresAt: session.expiresAt
        }
      };
    } catch (error) {
      this.monitoring.logEvent({
        type: 'login_failed',
        level: 'error',
        email: credentials.email,
        ipAddress: credentials.ipAddress,
        error: error.message
      });
      throw error;
    }
  }

  // MFA Verification
  async verifyMFA(userId, token) {
    try {
      const user = await User.findById(userId);
      if (!user || !user.mfaEnabled) {
        throw new Error('MFA not enabled for this user');
      }

      const isValid = speakeasy.totp.verify({
        secret: user.mfaSecret,
        encoding: 'base32',
        token: token,
        window: 2 // Allow 2 time steps for clock skew
      });

      if (!isValid) {
        this.monitoring.logEvent({
          type: 'mfa_verification_failed',
          userId: user._id,
          level: 'warning'
        });
        throw new Error('Invalid MFA token');
      }

      // Create session after successful MFA verification
      const session = await this.createSession(user);

      this.monitoring.logEvent({
        type: 'mfa_verification_success',
        userId: user._id
      });

      return {
        user: {
          id: user._id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          roles: user.roles,
          permissions: await this.getUserPermissions(user._id)
        },
        session: {
          token: session.token,
          refreshToken: session.refreshToken,
          expiresAt: session.expiresAt
        }
      };
    } catch (error) {
      throw error;
    }
  }

  // Enable MFA
  async enableMFA(userId) {
    try {
      const user = await User.findById(userId);
      if (!user) {
        throw new Error('User not found');
      }

      if (user.mfaEnabled) {
        throw new Error('MFA is already enabled');
      }

      // Generate MFA secret
      const secret = speakeasy.generateSecret({
        name: `${this.config.mfa.issuer}:${user.email}`,
        issuer: this.config.mfa.issuer,
        algorithm: this.config.mfa.algorithm
      });

      // Generate QR code
      const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);

      // Update user
      user.mfaSecret = secret.base32;
      user.mfaEnabled = true;
      await user.save();

      this.monitoring.logEvent({
        type: 'mfa_enabled',
        userId: user._id
      });

      return {
        secret: secret.base32,
        qrCode: qrCodeUrl,
        message: 'MFA enabled successfully'
      };
    } catch (error) {
      throw error;
    }
  }

  // Disable MFA
  async disableMFA(userId, token) {
    try {
      const user = await User.findById(userId);
      if (!user || !user.mfaEnabled) {
        throw new Error('MFA not enabled for this user');
      }

      // Verify current MFA token
      const isValid = speakeasy.totp.verify({
        secret: user.mfaSecret,
        encoding: 'base32',
        token: token,
        window: 2
      });

      if (!isValid) {
        throw new Error('Invalid MFA token');
      }

      // Disable MFA
      user.mfaEnabled = false;
      user.mfaSecret = null;
      await user.save();

      this.monitoring.logEvent({
        type: 'mfa_disabled',
        userId: user._id
      });

      return { message: 'MFA disabled successfully' };
    } catch (error) {
      throw error;
    }
  }

  // Create Session
  async createSession(user, deviceInfo = null, ipAddress = null, userAgent = null) {
    const session = new Session({
      userId: user._id,
      token: jwt.sign(
        { userId: user._id, email: user.email },
        this.config.jwtSecret,
        { expiresIn: this.config.jwtExpiry }
      ),
      refreshToken: Utils.generateSecureToken(),
      expiresAt: new Date(Date.now() + this.getTokenExpiryMs()),
      deviceInfo,
      ipAddress,
      userAgent,
      isActive: true
    });

    await session.save();

    // Store in Redis for quick access
    await this.redis.setex(
      `session:${session.token}`,
      this.getTokenExpirySeconds(),
      JSON.stringify({
        userId: user._id,
        sessionId: session._id,
        roles: user.roles
      })
    );

    return session;
  }

  // Verify Token
  async verifyToken(token) {
    try {
      // Check Redis first
      const cachedSession = await this.redis.get(`session:${token}`);
      if (cachedSession) {
        return JSON.parse(cachedSession);
      }

      // Verify JWT
      const decoded = jwt.verify(token, this.config.jwtSecret);
      
      // Check if session exists in database
      const session = await Session.findOne({
        token: token,
        isActive: true,
        expiresAt: { $gt: new Date() }
      });

      if (!session) {
        throw new Error('Session not found or expired');
      }

      // Get user
      const user = await User.findById(decoded.userId).populate('roles');
      if (!user || !user.isActive) {
        throw new Error('User not found or inactive');
      }

      return {
        userId: user._id,
        sessionId: session._id,
        roles: user.roles.map(role => role.name),
        permissions: await this.getUserPermissions(user._id)
      };
    } catch (error) {
      throw new Error('Invalid token');
    }
  }

  // Refresh Token
  async refreshToken(refreshToken) {
    try {
      const session = await Session.findOne({
        refreshToken: refreshToken,
        isActive: true,
        expiresAt: { $gt: new Date() }
      });

      if (!session) {
        throw new Error('Invalid refresh token');
      }

      const user = await User.findById(session.userId);
      if (!user || !user.isActive) {
        throw new Error('User not found or inactive');
      }

      // Create new session
      const newSession = await this.createSession(user, session.deviceInfo, session.ipAddress, session.userAgent);

      // Deactivate old session
      session.isActive = false;
      await session.save();

      return {
        token: newSession.token,
        refreshToken: newSession.refreshToken,
        expiresAt: newSession.expiresAt
      };
    } catch (error) {
      throw error;
    }
  }

  // Logout
  async logout(token) {
    try {
      // Remove from Redis
      await this.redis.del(`session:${token}`);

      // Deactivate session in database
      await Session.updateOne(
        { token: token },
        { isActive: false, loggedOutAt: new Date() }
      );

      this.monitoring.logEvent({
        type: 'user_logout',
        token: token
      });

      return { message: 'Logged out successfully' };
    } catch (error) {
      throw error;
    }
  }

  // Role Management
  async createRole(roleData) {
    try {
      const role = new Role({
        name: roleData.name,
        description: roleData.description,
        permissions: roleData.permissions || []
      });

      await role.save();

      this.monitoring.logEvent({
        type: 'role_created',
        roleId: role._id,
        roleName: role.name
      });

      return role;
    } catch (error) {
      throw error;
    }
  }

  async assignRole(userId, roleId) {
    try {
      const user = await User.findById(userId);
      const role = await Role.findById(roleId);

      if (!user || !role) {
        throw new Error('User or role not found');
      }

      if (!user.roles.includes(roleId)) {
        user.roles.push(roleId);
        await user.save();
      }

      this.monitoring.logEvent({
        type: 'role_assigned',
        userId: user._id,
        roleId: role._id
      });

      return { message: 'Role assigned successfully' };
    } catch (error) {
      throw error;
    }
  }

  // Permission Checking
  async hasPermission(userId, permission) {
    try {
      const user = await User.findById(userId).populate('roles');
      if (!user) return false;

      const userPermissions = await this.getUserPermissions(userId);
      return userPermissions.includes(permission);
    } catch (error) {
      return false;
    }
  }

  async getUserPermissions(userId) {
    try {
      const user = await User.findById(userId).populate('roles');
      if (!user) return [];

      const permissions = new Set();
      for (const role of user.roles) {
        if (role.permissions) {
          role.permissions.forEach(permission => permissions.add(permission));
        }
      }

      return Array.from(permissions);
    } catch (error) {
      return [];
    }
  }

  // Middleware functions
  requireAuth() {
    return async (req, res, next) => {
      try {
        const token = req.headers.authorization?.replace('Bearer ', '');
        if (!token) {
          return res.status(401).json({ error: 'Authentication required' });
        }

        const session = await this.verifyToken(token);
        req.user = session;
        next();
      } catch (error) {
        return res.status(401).json({ error: 'Invalid token' });
      }
    };
  }

  requirePermission(permission) {
    return async (req, res, next) => {
      try {
        if (!req.user) {
          return res.status(401).json({ error: 'Authentication required' });
        }

        const hasPermission = await this.hasPermission(req.user.userId, permission);
        if (!hasPermission) {
          return res.status(403).json({ error: 'Insufficient permissions' });
        }

        next();
      } catch (error) {
        return res.status(500).json({ error: 'Permission check failed' });
      }
    };
  }

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

  // Helper methods
  validateRegistrationData(userData) {
    if (!userData.email || !userData.password) {
      throw new Error('Email and password are required');
    }

    if (userData.password.length < 8) {
      throw new Error('Password must be at least 8 characters long');
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(userData.email)) {
      throw new Error('Invalid email format');
    }
  }

  async handleFailedLogin(userId) {
    const key = `failed_attempts:${userId}`;
    const attempts = await this.redis.incr(key);
    
    if (attempts === 1) {
      await this.redis.expire(key, this.config.security.lockoutDuration / 1000);
    }

    if (attempts >= this.config.security.maxLoginAttempts) {
      const lockoutKey = `lockout:${userId}`;
      await this.redis.setex(lockoutKey, this.config.security.lockoutDuration / 1000, 'locked');
      
      this.monitoring.logEvent({
        type: 'account_locked',
        userId: userId,
        level: 'warning'
      });
    }
  }

  getTokenExpiryMs() {
    const match = this.config.jwtExpiry.match(/^(\d+)([smhd])$/);
    if (!match) return 24 * 60 * 60 * 1000; // Default 24 hours

    const value = parseInt(match[1]);
    const unit = match[2];

    switch (unit) {
      case 's': return value * 1000;
      case 'm': return value * 60 * 1000;
      case 'h': return value * 60 * 60 * 1000;
      case 'd': return value * 24 * 60 * 60 * 1000;
      default: return 24 * 60 * 60 * 1000;
    }
  }

  getTokenExpirySeconds() {
    return Math.floor(this.getTokenExpiryMs() / 1000);
  }
}

module.exports = AuthManager;

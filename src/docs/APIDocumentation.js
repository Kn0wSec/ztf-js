const fs = require('fs');
const path = require('path');

class APIDocumentation {
  constructor() {
    this.endpoints = [];
    this.models = [];
    this.examples = [];
  }

  generateDocumentation(framework) {
    const docs = {
      title: 'ZTF-JS Zero Trust Framework API Documentation',
      version: '1.0.0',
      description: 'Comprehensive API documentation for the Zero Trust Framework',
      sections: {
        overview: this.generateOverview(),
        authentication: this.generateAuthDocs(framework),
        authorization: this.generateAuthorizationDocs(framework),
        deviceManagement: this.generateDeviceDocs(framework),
        monitoring: this.generateMonitoringDocs(framework),
        security: this.generateSecurityDocs(framework),
        examples: this.generateExamples(),
        errors: this.generateErrorDocs()
      }
    };

    return docs;
  }

  generateOverview() {
    return {
      title: 'Overview',
      content: `
# ZTF-JS Zero Trust Framework

A comprehensive zero trust security framework for MERN stack applications.

## Key Features

- **Multi-Factor Authentication (MFA)**: TOTP-based authentication
- **Device Fingerprinting**: Advanced device identification and verification
- **Threat Detection**: Real-time threat analysis and response
- **Role-Based Access Control**: Granular permission management
- **Session Management**: Secure session handling with Redis
- **Monitoring & Analytics**: Comprehensive security event logging
- **Rate Limiting**: Advanced DDoS protection
- **Geographic Restrictions**: Location-based access control

## Architecture

The framework follows a modular architecture with the following components:

- **AuthManager**: Handles authentication and authorization
- **DeviceManager**: Manages device fingerprinting and trust
- **ThreatDetector**: Analyzes requests for security threats
- **MonitoringManager**: Logs and monitors security events
- **SecurityMiddleware**: Express.js middleware for zero trust
- **Dashboard**: Web-based security monitoring interface

## Quick Start

\`\`\`javascript
const { ZeroTrustFramework } = require('ztf-js');

const ztf = new ZeroTrustFramework({
  mongoUri: 'mongodb://localhost:27017/ztf-app',
  redisUrl: 'redis://localhost:6379',
  jwtSecret: 'your-secret-key'
});

await ztf.initialize();
app.use(ztf.middleware());
\`\`\`
      `
    };
  }

  generateAuthDocs(framework) {
    return {
      title: 'Authentication',
      endpoints: [
        {
          method: 'POST',
          path: '/auth/register',
          description: 'Register a new user',
          parameters: {
            body: {
              email: 'string (required)',
              password: 'string (required)',
              firstName: 'string (required)',
              lastName: 'string (required)'
            }
          },
          responses: {
            200: 'User registered successfully',
            400: 'Validation error',
            409: 'User already exists'
          }
        },
        {
          method: 'POST',
          path: '/auth/login',
          description: 'Authenticate user',
          parameters: {
            body: {
              email: 'string (required)',
              password: 'string (required)'
            }
          },
          responses: {
            200: 'Login successful',
            401: 'Invalid credentials',
            423: 'Account locked'
          }
        },
        {
          method: 'POST',
          path: '/auth/mfa/verify',
          description: 'Verify MFA token',
          parameters: {
            body: {
              userId: 'string (required)',
              token: 'string (required)'
            }
          },
          responses: {
            200: 'MFA verified successfully',
            400: 'Invalid token'
          }
        }
      ]
    };
  }

  generateAuthorizationDocs(framework) {
    return {
      title: 'Authorization',
      middleware: [
        {
          name: 'requireAuth',
          description: 'Requires valid authentication token',
          usage: 'ztf.auth.requireAuth()'
        },
        {
          name: 'requirePermission',
          description: 'Requires specific permission',
          usage: 'ztf.auth.requirePermission("read:users")'
        },
        {
          name: 'requireRole',
          description: 'Requires specific role',
          usage: 'ztf.auth.requireRole("admin")'
        }
      ],
      permissions: [
        'read:users',
        'write:users',
        'delete:users',
        'read:logs',
        'write:logs',
        'admin:all'
      ]
    };
  }

  generateDeviceDocs(framework) {
    return {
      title: 'Device Management',
      endpoints: [
        {
          method: 'GET',
          path: '/api/devices',
          description: 'Get user devices',
          auth: 'required',
          responses: {
            200: 'List of user devices',
            401: 'Unauthorized'
          }
        },
        {
          method: 'POST',
          path: '/api/devices/trust/:deviceId',
          description: 'Trust a device',
          auth: 'required',
          responses: {
            200: 'Device trusted successfully',
            404: 'Device not found'
          }
        }
      ],
      fingerprinting: {
        algorithms: ['canvas', 'webgl', 'audio', 'fonts', 'plugins'],
        clientScript: 'Available via ztf.devices.getClientScript()'
      }
    };
  }

  generateMonitoringDocs(framework) {
    return {
      title: 'Monitoring & Analytics',
      endpoints: [
        {
          method: 'GET',
          path: '/admin/security/dashboard',
          description: 'Security dashboard',
          auth: 'admin required',
          features: [
            'Real-time security events',
            'User activity logs',
            'Threat analysis',
            'Device trust status'
          ]
        }
      ],
      events: [
        'login_attempt',
        'login_success',
        'login_failed',
        'logout',
        'mfa_enabled',
        'mfa_disabled',
        'device_registered',
        'device_trusted',
        'threat_detected',
        'permission_denied'
      ]
    };
  }

  generateSecurityDocs(framework) {
    return {
      title: 'Security Features',
      threatDetection: {
        patterns: [
          'SQL Injection',
          'XSS Attacks',
          'Path Traversal',
          'Command Injection',
          'Suspicious User Agents'
        ],
        riskLevels: ['minimal', 'low', 'medium', 'high', 'critical']
      },
      rateLimiting: {
        default: '100 requests per 15 minutes',
        configurable: true
      },
      sessionManagement: {
        storage: 'Redis',
        timeout: '30 minutes (configurable)',
        refreshTokens: 'Supported'
      }
    };
  }

  generateExamples() {
    return {
      title: 'Code Examples',
      examples: [
        {
          title: 'Basic Setup',
          code: `
const express = require('express');
const { ZeroTrustFramework } = require('ztf-js');

const app = express();
const ztf = new ZeroTrustFramework({
  mongoUri: process.env.MONGO_URI,
  redisUrl: process.env.REDIS_URL,
  jwtSecret: process.env.JWT_SECRET
});

await ztf.initialize();
app.use(ztf.middleware());
          `
        },
        {
          title: 'Protected Route',
          code: `
app.get('/api/profile', 
  ztf.auth.requireAuth(),
  (req, res) => {
    res.json({ user: req.user });
  }
);
          `
        },
        {
          title: 'Role-Based Access',
          code: `
app.post('/api/admin/users',
  ztf.auth.requireAuth(),
  ztf.auth.requireRole('admin'),
  (req, res) => {
    // Admin logic here
  }
);
          `
        }
      ]
    };
  }

  generateErrorDocs() {
    return {
      title: 'Error Codes',
      errors: [
        {
          code: 'AUTH_REQUIRED',
          message: 'Authentication required',
          status: 401
        },
        {
          code: 'INVALID_TOKEN',
          message: 'Invalid or expired token',
          status: 401
        },
        {
          code: 'PERMISSION_DENIED',
          message: 'Insufficient permissions',
          status: 403
        },
        {
          code: 'DEVICE_NOT_TRUSTED',
          message: 'Device not trusted',
          status: 403
        },
        {
          code: 'RATE_LIMIT_EXCEEDED',
          message: 'Too many requests',
          status: 429
        }
      ]
    };
  }

  generateMarkdown(docs) {
    let markdown = `# ${docs.title}\n\n`;
    markdown += `**Version:** ${docs.version}\n\n`;
    markdown += `${docs.description}\n\n`;

    // Overview
    markdown += `## ${docs.sections.overview.title}\n\n`;
    markdown += docs.sections.overview.content + '\n\n';

    // Authentication
    markdown += `## ${docs.sections.authentication.title}\n\n`;
    docs.sections.authentication.endpoints.forEach(endpoint => {
      markdown += `### ${endpoint.method} ${endpoint.path}\n\n`;
      markdown += `${endpoint.description}\n\n`;
      if (endpoint.parameters) {
        markdown += '**Parameters:**\n\n';
        Object.entries(endpoint.parameters).forEach(([type, params]) => {
          markdown += `**${type}:**\n`;
          Object.entries(params).forEach(([name, desc]) => {
            markdown += `- \`${name}\`: ${desc}\n`;
          });
          markdown += '\n';
        });
      }
      if (endpoint.responses) {
        markdown += '**Responses:**\n\n';
        Object.entries(endpoint.responses).forEach(([code, desc]) => {
          markdown += `- \`${code}\`: ${desc}\n`;
        });
        markdown += '\n';
      }
    });

    return markdown;
  }

  saveDocumentation(docs, outputPath = './docs') {
    if (!fs.existsSync(outputPath)) {
      fs.mkdirSync(outputPath, { recursive: true });
    }

    // Save JSON documentation
    fs.writeFileSync(
      path.join(outputPath, 'api-docs.json'),
      JSON.stringify(docs, null, 2)
    );

    // Save Markdown documentation
    const markdown = this.generateMarkdown(docs);
    fs.writeFileSync(
      path.join(outputPath, 'README.md'),
      markdown
    );

    console.log(`Documentation saved to ${outputPath}`);
  }
}

module.exports = APIDocumentation;

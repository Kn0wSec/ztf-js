
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import { createHash } from 'crypto';
import { MongoClient, Db } from 'mongodb';
import { createClient, RedisClientType } from 'redis';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

interface ZtfContext {
  user?: {
    id: string;
    role: string;
    permissions: string[];
    mfaVerified?: boolean;
  };
  resource: {
    path: string;
    method: string;
    classification: 'public' | 'internal' | 'confidential' | 'restricted';
  };
  network: {
    ip: string;
    userAgent: string;
    geolocation?: {
      country?: string;
      city?: string;
    };
  };
  temporal: {
    timestamp: string;
    timezone: string;
  };
  device?: {
    fingerprint: string;
    trusted: boolean;
    lastSeen: string;
  };
}

interface PolicyDecision {
  allow: boolean;
  reason: string;
  riskScore: number;
  appliedPolicies: string[];
  sessionId: string;
  expiresAt: Date;
  conditions?: {
    requiresMfa?: boolean;
    sessionTimeout?: number;
    allowedNetworks?: string[];
  };
}

interface PolicyRule {
  name: string;
  description: string;
  type: 'role_based' | 'resource_classification' | 'risk_threshold' | 'time_based' | 'location_based';
  priority: number;
  conditions: any;
  action: 'allow' | 'deny' | 'require_mfa';
  enabled: boolean;
}

class RiskCalculator {
  calculateRisk(context: ZtfContext): number {
    let riskScore = 0.0;

    // Base risk factors
    if (!context.user) {
      riskScore += 0.3; // Anonymous users are riskier
    }

    // Time-based risk
    const hour = new Date().getHours();
    if (hour < 6 || hour > 22) {
      riskScore += 0.2; // After hours access
    }

    // Resource classification risk
    switch (context.resource.classification) {
      case 'restricted':
        riskScore += 0.4;
        break;
      case 'confidential':
        riskScore += 0.3;
        break;
      case 'internal':
        riskScore += 0.1;
        break;
      default:
        break;
    }

    // Device trust
    if (context.device && !context.device.trusted) {
      riskScore += 0.2;
    }

    // Geographic risk (simplified)
    if (context.network.geolocation?.country && 
        !['US', 'CA', 'GB', 'AU'].includes(context.network.geolocation.country)) {
      riskScore += 0.1;
    }

    return Math.min(riskScore, 1.0); // Cap at 1.0
  }
}

class PolicyEngine {
  private policies: Map<string, PolicyRule> = new Map();
  private riskCalculator: RiskCalculator;

  constructor() {
    this.riskCalculator = new RiskCalculator();
    this.loadDefaultPolicies();
  }

  async evaluate(context: ZtfContext): Promise<{
    allow: boolean;
    reason: string;
    policies: string[];
    conditions?: any;
  }> {
    const results = [];
    const riskScore = this.riskCalculator.calculateRisk(context);

    // Evaluate each policy
    for (const [name, policy] of this.policies) {
      if (!policy.enabled) continue;

      const result = await this.evaluatePolicy(policy, { ...context, riskScore });
      results.push({ name, ...result, priority: policy.priority });
    }

    // Sort by priority and combine results
    results.sort((a, b) => b.priority - a.priority);

    return this.combineResults(results);
  }

  private async evaluatePolicy(policy: PolicyRule, context: ZtfContext & { riskScore: number }) {
    try {
      switch (policy.type) {
        case 'role_based':
          return this.evaluateRoleBasedPolicy(policy, context);

        case 'resource_classification':
          return this.evaluateResourcePolicy(policy, context);

        case 'risk_threshold':
          return this.evaluateRiskPolicy(policy, context);

        case 'time_based':
          return this.evaluateTimePolicy(policy, context);

        case 'location_based':
          return this.evaluateLocationPolicy(policy, context);

        default:
          return { allow: true, reason: 'Unknown policy type' };
      }
    } catch (error) {
      console.error(`Policy evaluation error for ${policy.name}:`, error);
      return { allow: false, reason: 'Policy evaluation failed' };
    }
  }

  private evaluateRoleBasedPolicy(policy: PolicyRule, context: ZtfContext & { riskScore: number }) {
    const userRole = context.user?.role || 'anonymous';
    const allowedRoles = policy.conditions.allowedRoles || [];

    const allow = allowedRoles.includes(userRole);
    return {
      allow,
      reason: allow ? 'Role authorized' : `Role '${userRole}' not in approved list: ${allowedRoles.join(', ')}`
    };
  }

  private evaluateResourcePolicy(policy: PolicyRule, context: ZtfContext & { riskScore: number }) {
    const classification = context.resource.classification;
    const maxLevel = policy.conditions.maxClassification || 'public';

    const levels = ['public', 'internal', 'confidential', 'restricted'];
    const currentLevel = levels.indexOf(classification);
    const maxAllowedLevel = levels.indexOf(maxLevel);

    const allow = currentLevel <= maxAllowedLevel;
    return {
      allow,
      reason: allow 
        ? 'Resource classification authorized' 
        : `Resource classification '${classification}' exceeds maximum '${maxLevel}'`
    };
  }

  private evaluateRiskPolicy(policy: PolicyRule, context: ZtfContext & { riskScore: number }) {
    const maxRisk = policy.conditions.maxRiskScore || 0.5;
    const allow = context.riskScore <= maxRisk;

    return {
      allow,
      reason: allow 
        ? `Risk score ${context.riskScore.toFixed(2)} within threshold` 
        : `Risk score ${context.riskScore.toFixed(2)} exceeds threshold ${maxRisk}`
    };
  }

  private evaluateTimePolicy(policy: PolicyRule, context: ZtfContext & { riskScore: number }) {
    const now = new Date();
    const hour = now.getHours();
    const allowedHours = policy.conditions.allowedHours || [9, 17]; // 9 AM to 5 PM

    const allow = hour >= allowedHours[0] && hour <= allowedHours[1];
    return {
      allow,
      reason: allow 
        ? 'Access within allowed hours' 
        : `Access denied outside business hours (${allowedHours[0]}:00-${allowedHours[1]}:00)`
    };
  }

  private evaluateLocationPolicy(policy: PolicyRule, context: ZtfContext & { riskScore: number }) {
    const country = context.network.geolocation?.country;
    const allowedCountries = policy.conditions.allowedCountries || [];

    if (!country) {
      return { allow: true, reason: 'Location unknown, allowing access' };
    }

    const allow = allowedCountries.length === 0 || allowedCountries.includes(country);
    return {
      allow,
      reason: allow 
        ? 'Location authorized' 
        : `Access from ${country} not permitted`
    };
  }

  private combineResults(results: any[]): {
    allow: boolean;
    reason: string;
    policies: string[];
    conditions?: any;
  } {
    // Find explicit denies first
    const denies = results.filter(r => !r.allow);

    if (denies.length > 0) {
      return {
        allow: false,
        reason: denies[0].reason,
        policies: results.map(r => r.name)
      };
    }

    // Check for conditional allows
    const conditionalAllows = results.filter(r => r.allow && r.conditions);
    if (conditionalAllows.length > 0) {
      return {
        allow: true,
        reason: 'Conditional access granted',
        policies: results.map(r => r.name),
        conditions: conditionalAllows[0].conditions
      };
    }

    // Default allow if no denies
    const allows = results.filter(r => r.allow);
    return {
      allow: allows.length > 0,
      reason: allows.length > 0 ? 'Policies satisfied' : 'No matching policies',
      policies: results.map(r => r.name)
    };
  }

  private loadDefaultPolicies() {
    // Authenticated user policy
    this.policies.set('authenticated_users', {
      name: 'authenticated_users',
      description: 'Require authentication for non-public resources',
      type: 'role_based',
      priority: 10,
      conditions: {
        allowedRoles: ['user', 'admin', 'moderator']
      },
      action: 'allow',
      enabled: true
    });

    // Admin resource protection
    this.policies.set('admin_resources', {
      name: 'admin_resources',
      description: 'Restrict admin resources to admin users',
      type: 'resource_classification',
      priority: 20,
      conditions: {
        maxClassification: 'internal'
      },
      action: 'allow',
      enabled: true
    });

    // Risk threshold policy
    this.policies.set('risk_threshold', {
      name: 'risk_threshold',
      description: 'Block high-risk requests',
      type: 'risk_threshold',
      priority: 15,
      conditions: {
        maxRiskScore: 0.7
      },
      action: 'deny',
      enabled: true
    });

    // Business hours policy
    this.policies.set('business_hours', {
      name: 'business_hours',
      description: 'Restrict sensitive access to business hours',
      type: 'time_based',
      priority: 5,
      conditions: {
        allowedHours: [8, 18],
        resourceTypes: ['confidential', 'restricted']
      },
      action: 'allow',
      enabled: false // Disabled by default
    });
  }

  addPolicy(policy: PolicyRule) {
    this.policies.set(policy.name, policy);
  }

  removePolicy(name: string) {
    this.policies.delete(name);
  }

  getPolicies(): PolicyRule[] {
    return Array.from(this.policies.values());
  }
}

class AuditLogger {
  private db?: Db;

  constructor(db?: Db) {
    this.db = db;
  }

  async logDecision(decision: PolicyDecision, context: ZtfContext) {
    const logEntry = {
      timestamp: new Date(),
      decision: {
        allow: decision.allow,
        reason: decision.reason,
        riskScore: decision.riskScore,
        appliedPolicies: decision.appliedPolicies,
        sessionId: decision.sessionId
      },
      context: this.sanitizeContext(context),
      service: 'ztf-policy-service',
      version: '1.0.0'
    };

    // Log to console always
    console.log('Policy Decision:', JSON.stringify(logEntry, null, 2));

    // Log to database if available
    if (this.db) {
      try {
        await this.db.collection('audit_logs').insertOne(logEntry);
      } catch (error) {
        console.error('Failed to write audit log to database:', error);
      }
    }
  }

  private sanitizeContext(context: ZtfContext) {
    return {
      user: context.user ? {
        id: context.user.id,
        role: context.user.role,
        mfaVerified: context.user.mfaVerified
      } : null,
      resource: context.resource,
      network: {
        ip: this.maskIP(context.network.ip),
        userAgent: context.network.userAgent?.substring(0, 100),
        geolocation: context.network.geolocation
      },
      temporal: context.temporal,
      device: context.device ? {
        fingerprint: context.device.fingerprint,
        trusted: context.device.trusted
      } : null
    };
  }

  private maskIP(ip: string): string {
    if (ip.includes(':')) {
      // IPv6 - mask last 64 bits
      const parts = ip.split(':');
      return parts.slice(0, 4).join(':') + '::xxxx';
    } else {
      // IPv4 - mask last octet
      const parts = ip.split('.');
      return parts.slice(0, 3).join('.') + '.xxx';
    }
  }
}

export class PolicyDecisionService {
  private app: express.Application;
  private policyEngine: PolicyEngine;
  private auditLogger: AuditLogger;
  private redis?: RedisClientType;
  private mongodb?: MongoClient;
  private db?: Db;

  constructor() {
    this.app = express();
    this.policyEngine = new PolicyEngine();
    this.auditLogger = new AuditLogger();

    this.setupMiddleware();
    this.setupRoutes();
  }

  private setupMiddleware() {
    this.app.use(helmet());
    this.app.use(cors({
      origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
      credentials: true
    }));
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(morgan('combined'));
  }

  private setupRoutes() {
    this.app.get('/health', this.healthCheck.bind(this));
    this.app.post('/evaluate', this.handleEvaluation.bind(this));
    this.app.get('/policies', this.listPolicies.bind(this));
    this.app.post('/policies', this.createPolicy.bind(this));
    this.app.put('/policies/:name', this.updatePolicy.bind(this));
    this.app.delete('/policies/:name', this.deletePolicy.bind(this));
  }

  private async healthCheck(req: express.Request, res: express.Response) {
    const health = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      version: '1.0.0',
      services: {
        redis: this.redis?.isOpen || false,
        mongodb: this.mongodb?.topology?.isConnected() || false
      }
    };

    res.json(health);
  }

  private async handleEvaluation(req: express.Request, res: express.Response) {
    const startTime = Date.now();
    const requestId = this.generateRequestId();

    try {
      const context = req.body as ZtfContext;

      // Validate input
      if (!context || !context.resource) {
        return res.status(400).json({
          allow: false,
          reason: 'Invalid request context',
          sessionId: requestId,
          riskScore: 1.0,
          appliedPolicies: []
        });
      }

      // Check cache first
      const cacheKey = this.generateCacheKey(context);
      let decision = await this.getCachedDecision(cacheKey);

      if (!decision) {
        // Evaluate policies
        const policyResult = await this.policyEngine.evaluate(context);

        decision = {
          allow: policyResult.allow,
          reason: policyResult.reason,
          riskScore: this.calculateRiskScore(context),
          appliedPolicies: policyResult.policies,
          sessionId: requestId,
          expiresAt: new Date(Date.now() + 3600000), // 1 hour
          conditions: policyResult.conditions
        };

        // Cache the decision
        await this.cacheDecision(cacheKey, decision);
      }

      // Log decision for audit
      await this.auditLogger.logDecision(decision, context);

      // Add performance metrics
      (decision as any).evaluationTime = Date.now() - startTime;

      res.json(decision);

    } catch (error) {
      console.error('Policy evaluation error:', error);

      const errorDecision = {
        allow: false,
        reason: 'Policy evaluation failed',
        riskScore: 1.0,
        appliedPolicies: [],
        sessionId: requestId,
        expiresAt: new Date(),
        evaluationTime: Date.now() - startTime
      };

      res.status(500).json(errorDecision);
    }
  }

  private async listPolicies(req: express.Request, res: express.Response) {
    try {
      const policies = this.policyEngine.getPolicies();
      res.json(policies);
    } catch (error) {
      console.error('Error listing policies:', error);
      res.status(500).json({ error: 'Failed to list policies' });
    }
  }

  private async createPolicy(req: express.Request, res: express.Response) {
    try {
      const policy = req.body as PolicyRule;

      // Validate policy
      if (!policy.name || !policy.type) {
        return res.status(400).json({ error: 'Invalid policy structure' });
      }

      this.policyEngine.addPolicy(policy);
      res.status(201).json({ message: 'Policy created successfully' });
    } catch (error) {
      console.error('Error creating policy:', error);
      res.status(500).json({ error: 'Failed to create policy' });
    }
  }

  private async updatePolicy(req: express.Request, res: express.Response) {
    try {
      const name = req.params.name;
      const policy = { ...req.body, name } as PolicyRule;

      this.policyEngine.addPolicy(policy); // addPolicy overwrites existing
      res.json({ message: 'Policy updated successfully' });
    } catch (error) {
      console.error('Error updating policy:', error);
      res.status(500).json({ error: 'Failed to update policy' });
    }
  }

  private async deletePolicy(req: express.Request, res: express.Response) {
    try {
      const name = req.params.name;
      this.policyEngine.removePolicy(name);
      res.json({ message: 'Policy deleted successfully' });
    } catch (error) {
      console.error('Error deleting policy:', error);
      res.status(500).json({ error: 'Failed to delete policy' });
    }
  }

  private calculateRiskScore(context: ZtfContext): number {
    // This would be expanded with more sophisticated risk calculation
    let score = 0.1; // Base score

    if (!context.user) score += 0.3;
    if (context.resource.classification === 'restricted') score += 0.4;
    if (context.resource.classification === 'confidential') score += 0.2;

    return Math.min(score, 1.0);
  }

  private async getCachedDecision(key: string): Promise<PolicyDecision | null> {
    if (!this.redis) return null;

    try {
      const cached = await this.redis.get(key);
      return cached ? JSON.parse(cached) : null;
    } catch (error) {
      console.error('Cache read error:', error);
      return null;
    }
  }

  private async cacheDecision(key: string, decision: PolicyDecision): Promise<void> {
    if (!this.redis) return;

    try {
      await this.redis.setEx(key, 300, JSON.stringify(decision)); // 5 minutes
    } catch (error) {
      console.error('Cache write error:', error);
    }
  }

  private generateCacheKey(context: ZtfContext): string {
    const keyData = {
      userId: context.user?.id || 'anonymous',
      resource: `${context.resource.method}:${context.resource.path}`,
      classification: context.resource.classification
    };

    return createHash('sha256')
      .update(JSON.stringify(keyData))
      .digest('hex');
  }

  private generateRequestId(): string {
    return `ztf_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  async initialize() {
    try {
      // Initialize Redis connection
      if (process.env.REDIS_URL) {
        this.redis = createClient({ url: process.env.REDIS_URL });
        await this.redis.connect();
        console.log('Connected to Redis');
      }

      // Initialize MongoDB connection
      if (process.env.MONGODB_URL) {
        this.mongodb = new MongoClient(process.env.MONGODB_URL);
        await this.mongodb.connect();
        this.db = this.mongodb.db('ztf');
        this.auditLogger = new AuditLogger(this.db);
        console.log('Connected to MongoDB');
      }
    } catch (error) {
      console.error('Failed to initialize external services:', error);
      console.log('Continuing without external services...');
    }
  }

  public start(port: number = 3001) {
    this.initialize().then(() => {
      this.app.listen(port, () => {
        console.log(`Policy Decision Service running on port ${port}`);
        console.log(`Health check: http://localhost:${port}/health`);
      });
    });
  }

  public async stop() {
    if (this.redis) {
      await this.redis.quit();
    }
    if (this.mongodb) {
      await this.mongodb.close();
    }
  }
}

// Start the service if this file is run directly
if (require.main === module) {
  const service = new PolicyDecisionService();

  // Graceful shutdown
  process.on('SIGTERM', async () => {
    console.log('Received SIGTERM, shutting down gracefully');
    await service.stop();
    process.exit(0);
  });

  process.on('SIGINT', async () => {
    console.log('Received SIGINT, shutting down gracefully');
    await service.stop();
    process.exit(0);
  });

  service.start(parseInt(process.env.PORT || '3001'));
}

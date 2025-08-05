
import { Request, Response, NextFunction } from 'express';
import LRU from 'lru-cache';
import axios, { AxiosResponse } from 'axios';
import { createHash } from 'crypto';

// Import from core package
export interface ZtfContext {
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

export interface PolicyDecision {
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

export interface ZtfExpressOptions {
  policyService: string;
  cacheTTL?: number;
  bypassRoutes?: string[];
  failureMode?: 'secure' | 'open';
  timeout?: number;
  retries?: number;
}

class PolicyServiceClient {
  private baseUrl: string;
  private timeout: number;
  private retries: number;

  constructor(baseUrl: string, timeout = 5000, retries = 3) {
    this.baseUrl = baseUrl;
    this.timeout = timeout;
    this.retries = retries;
  }

  async evaluate(context: ZtfContext): Promise<PolicyDecision> {
    for (let attempt = 1; attempt <= this.retries; attempt++) {
      try {
        const response: AxiosResponse = await axios.post(
          `${this.baseUrl}/evaluate`,
          context,
          {
            timeout: this.timeout,
            headers: {
              'Content-Type': 'application/json',
              'X-ZTF-Version': '1.0.0'
            }
          }
        );

        return response.data;
      } catch (error) {
        if (attempt === this.retries) {
          throw error;
        }
        await this.delay(Math.pow(2, attempt) * 1000); // Exponential backoff
      }
    }

    throw new Error('Max retries exceeded');
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

class DecisionCache {
  private cache: LRU<string, PolicyDecision>;

  constructor(ttl: number = 300000) {
    this.cache = new LRU({
      max: 1000,
      ttl
    });
  }

  async get(key: string): Promise<PolicyDecision | undefined> {
    return this.cache.get(key);
  }

  async set(key: string, decision: PolicyDecision): Promise<void> {
    this.cache.set(key, decision);
  }

  clear(): void {
    this.cache.clear();
  }
}

export class ZtfExpressMiddleware {
  private client: PolicyServiceClient;
  private cache: DecisionCache;
  private options: Required<ZtfExpressOptions>;

  constructor(options: ZtfExpressOptions) {
    this.options = {
      cacheTTL: 300000, // 5 minutes
      bypassRoutes: ['/health', '/metrics', '/favicon.ico'],
      failureMode: 'secure',
      timeout: 5000,
      retries: 3,
      ...options
    };

    this.client = new PolicyServiceClient(
      this.options.policyService,
      this.options.timeout,
      this.options.retries
    );
    this.cache = new DecisionCache(this.options.cacheTTL);
  }

  middleware() {
    return async (req: Request, res: Response, next: NextFunction) => {
      try {
        // Skip bypass routes
        if (this.shouldBypass(req.path)) {
          return next();
        }

        // Extract context
        const context = this.extractContext(req);

        // Check cache first
        const cacheKey = this.generateCacheKey(context);
        let decision = await this.cache.get(cacheKey);

        if (!decision) {
          // Query policy service
          decision = await this.client.evaluate(context);
          await this.cache.set(cacheKey, decision);
        }

        // Enforce decision
        this.enforceDecision(decision, req, res, next);

      } catch (error) {
        this.handleError(error, req, res, next);
      }
    };
  }

  private shouldBypass(path: string): boolean {
    return this.options.bypassRoutes.some(route => {
      if (route.includes('*')) {
        const pattern = route.replace(/\*/g, '.*');
        return new RegExp(`^${pattern}$`).test(path);
      }
      return path === route || path.startsWith(route);
    });
  }

  private extractContext(req: Request): ZtfContext {
    return {
      user: (req as any).user || null,
      resource: {
        path: req.path,
        method: req.method,
        classification: this.classifyResource(req.path)
      },
      network: {
        ip: req.ip || req.connection.remoteAddress || '',
        userAgent: req.get('User-Agent') || '',
        geolocation: this.extractGeolocation(req)
      },
      temporal: {
        timestamp: new Date().toISOString(),
        timezone: req.get('X-Timezone') || 'UTC'
      },
      device: this.extractDeviceInfo(req)
    };
  }

  private classifyResource(path: string): 'public' | 'internal' | 'confidential' | 'restricted' {
    if (path.includes('/admin') || path.includes('/system')) return 'restricted';
    if (path.includes('/api/private') || path.includes('/secure')) return 'confidential';
    if (path.includes('/api/internal') || path.includes('/dashboard')) return 'internal';
    return 'public';
  }

  private extractGeolocation(req: Request) {
    // Extract from headers set by CDN/proxy
    return {
      country: req.get('CF-IPCountry') || req.get('X-Country-Code'),
      city: req.get('CF-IPCity') || req.get('X-City')
    };
  }

  private extractDeviceInfo(req: Request) {
    const userAgent = req.get('User-Agent') || '';
    const ip = req.ip || '';

    // Simple device fingerprinting
    const fingerprint = createHash('md5')
      .update(userAgent + ip)
      .digest('hex');

    return {
      fingerprint,
      trusted: false, // Would be determined by previous interactions
      lastSeen: new Date().toISOString()
    };
  }

  private enforceDecision(
    decision: PolicyDecision,
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    if (decision.allow) {
      // Attach decision metadata to request
      (req as any).ztf = {
        decision,
        riskScore: decision.riskScore,
        policies: decision.appliedPolicies,
        sessionId: decision.sessionId
      };

      // Set security headers
      res.set({
        'X-ZTF-Risk-Score': decision.riskScore.toString(),
        'X-ZTF-Session-Id': decision.sessionId,
        'X-ZTF-Policies': decision.appliedPolicies.join(',')
      });

      // Handle conditional access
      if (decision.conditions?.requiresMfa && !(req as any).user?.mfaVerified) {
        return res.status(402).json({
          error: 'MFA required',
          reason: 'Multi-factor authentication required for this resource',
          sessionId: decision.sessionId,
          mfaChallenge: true
        });
      }

      return next();
    } else {
      return res.status(403).json({
        error: 'Access denied',
        reason: decision.reason,
        sessionId: decision.sessionId,
        riskScore: decision.riskScore
      });
    }
  }

  private handleError(
    error: any,
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    console.error('ZTF Middleware Error:', {
      error: error.message,
      path: req.path,
      method: req.method,
      ip: req.ip,
      timestamp: new Date().toISOString()
    });

    if (this.options.failureMode === 'open') {
      // Fail open - allow access when policy service is down
      console.warn('ZTF: Failing open due to policy service error');
      return next();
    } else {
      // Fail secure - deny access when policy service is down
      return res.status(503).json({
        error: 'Security service unavailable',
        reason: 'Unable to evaluate security policy',
        timestamp: new Date().toISOString()
      });
    }
  }

  private generateCacheKey(context: ZtfContext): string {
    const keyData = {
      userId: context.user?.id || 'anonymous',
      resource: `${context.resource.method}:${context.resource.path}`,
      classification: context.resource.classification,
      ip: context.network.ip
    };

    return createHash('sha256')
      .update(JSON.stringify(keyData))
      .digest('hex');
  }
}

// Export factory function for easy use
export function ztfExpress(options: ZtfExpressOptions) {
  const middleware = new ZtfExpressMiddleware(options);
  return middleware.middleware();
}

// Export class for advanced usage
export { ZtfExpressMiddleware };

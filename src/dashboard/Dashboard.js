const express = require('express');
const path = require('path');

class Dashboard {
  constructor(config, auth, devices, monitoring) {
    this.config = config;
    this.auth = auth;
    this.devices = devices;
    this.monitoring = monitoring;
    this.router = express.Router();
    this.setupRoutes();
  }

  setupRoutes() {
    // Dashboard middleware - require admin role
    this.router.use(this.auth.requireRole('admin'));

    // Dashboard home
    this.router.get('/', this.renderDashboard.bind(this));

    // API endpoints for dashboard data
    this.router.get('/api/metrics', this.getMetrics.bind(this));
    this.router.get('/api/events', this.getEvents.bind(this));
    this.router.get('/api/devices', this.getDevices.bind(this));
    this.router.get('/api/users', this.getUsers.bind(this));
    this.router.get('/api/threats', this.getThreats.bind(this));

    // Real-time updates
    this.router.get('/api/events/stream', this.streamEvents.bind(this));

    // Static files
    this.router.use('/static', express.static(path.join(__dirname, 'public')));
  }

  // Render main dashboard
  async renderDashboard(req, res) {
    try {
      const dashboardData = await this.getDashboardData();
      res.json({
        success: true,
        data: dashboardData
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  // Get dashboard overview data
  async getDashboardData() {
    const [
      metrics,
      recentEvents,
      topThreats,
      deviceStats,
      userStats
    ] = await Promise.all([
      this.monitoring.getMetrics('24h'),
      this.getRecentEvents(10),
      this.getRecentThreats(5),
      this.getDeviceStats(),
      this.getUserStats()
    ]);

    return {
      metrics,
      recentEvents,
      topThreats,
      deviceStats,
      userStats,
      lastUpdated: new Date()
    };
  }

  // Get metrics API endpoint
  async getMetrics(req, res) {
    try {
      const timeframe = req.query.timeframe || '24h';
      const metrics = await this.monitoring.getMetrics(timeframe);
      
      res.json({
        success: true,
        data: metrics
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  // Get events API endpoint
  async getEvents(req, res) {
    try {
      const limit = parseInt(req.query.limit) || 50;
      const type = req.query.type;
      const level = req.query.level;
      const userId = req.query.userId;
      const ipAddress = req.query.ipAddress;

      const events = await this.getFilteredEvents({
        limit,
        type,
        level,
        userId,
        ipAddress
      });

      res.json({
        success: true,
        data: events
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  // Get devices API endpoint
  async getDevices(req, res) {
    try {
      const userId = req.query.userId;
      const devices = userId 
        ? await this.devices.getUserDevices(userId)
        : await this.getAllDevices();

      res.json({
        success: true,
        data: devices
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  // Get users API endpoint
  async getUsers(req, res) {
    try {
      const users = await this.getUserStats();
      
      res.json({
        success: true,
        data: users
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  // Get threats API endpoint
  async getThreats(req, res) {
    try {
      const threats = await this.getRecentThreats(20);
      
      res.json({
        success: true,
        data: threats
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  // Stream events for real-time updates
  streamEvents(req, res) {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*'
    });

    const sendEvent = (data) => {
      res.write(`data: ${JSON.stringify(data)}\n\n`);
    };

    // Send initial data
    this.getDashboardData().then(data => {
      sendEvent({ type: 'initial', data });
    });

    // Set up periodic updates
    const interval = setInterval(async () => {
      try {
        const data = await this.getDashboardData();
        sendEvent({ type: 'update', data });
      } catch (error) {
        sendEvent({ type: 'error', error: error.message });
      }
    }, 30000); // Update every 30 seconds

    // Clean up on client disconnect
    req.on('close', () => {
      clearInterval(interval);
    });
  }

  // Helper methods
  async getRecentEvents(limit = 10) {
    const SecurityEvent = require('../models/SecurityEvent');
    return await SecurityEvent.find()
      .sort({ timestamp: -1 })
      .limit(limit)
      .populate('userId', 'email firstName lastName');
  }

  async getFilteredEvents(filters) {
    const SecurityEvent = require('../models/SecurityEvent');
    const query = {};

    if (filters.type) query.type = filters.type;
    if (filters.level) query.level = filters.level;
    if (filters.userId) query.userId = filters.userId;
    if (filters.ipAddress) query.ipAddress = filters.ipAddress;

    return await SecurityEvent.find(query)
      .sort({ timestamp: -1 })
      .limit(filters.limit)
      .populate('userId', 'email firstName lastName');
  }

  async getRecentThreats(limit = 10) {
    const SecurityEvent = require('../models/SecurityEvent');
    return await SecurityEvent.find({
      type: 'threat_detected',
      level: { $in: ['warning', 'error', 'critical'] }
    })
      .sort({ timestamp: -1 })
      .limit(limit)
      .populate('userId', 'email firstName lastName');
  }

  async getDeviceStats() {
    const Device = require('../models/Device');
    const stats = await Device.aggregate([
      {
        $group: {
          _id: null,
          totalDevices: { $sum: 1 },
          trustedDevices: { $sum: { $cond: ['$isTrusted', 1, 0] } },
          highRiskDevices: { $sum: { $cond: [{ $gte: ['$riskScore', 70] }, 1, 0] } },
          avgRiskScore: { $avg: '$riskScore' }
        }
      }
    ]);

    return stats[0] || {
      totalDevices: 0,
      trustedDevices: 0,
      highRiskDevices: 0,
      avgRiskScore: 0
    };
  }

  async getAllDevices() {
    const Device = require('../models/Device');
    return await Device.find()
      .sort({ lastSeen: -1 })
      .populate('userId', 'email firstName lastName');
  }

  async getUserStats() {
    const User = require('../models/User');
    const stats = await User.aggregate([
      {
        $group: {
          _id: null,
          totalUsers: { $sum: 1 },
          activeUsers: { $sum: { $cond: ['$isActive', 1, 0] } },
          mfaEnabled: { $sum: { $cond: ['$mfaEnabled', 1, 0] } },
          verifiedUsers: { $sum: { $cond: ['$emailVerified', 1, 0] } }
        }
      }
    ]);

    return stats[0] || {
      totalUsers: 0,
      activeUsers: 0,
      mfaEnabled: 0,
      verifiedUsers: 0
    };
  }

  // Get middleware for Express app
  middleware() {
    return this.router;
  }

  // Generate dashboard HTML
  generateDashboardHTML() {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZTF-JS Security Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5;
            color: #333;
        }
        
        .dashboard {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        
        .header h1 {
            color: #2c3e50;
            margin-bottom: 10px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .stat-card h3 {
            color: #7f8c8d;
            font-size: 14px;
            text-transform: uppercase;
            margin-bottom: 10px;
        }
        
        .stat-card .value {
            font-size: 32px;
            font-weight: bold;
            color: #2c3e50;
        }
        
        .events-section {
            background: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .events-section h2 {
            color: #2c3e50;
            margin-bottom: 20px;
        }
        
        .event-item {
            padding: 15px;
            border-bottom: 1px solid #ecf0f1;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .event-item:last-child {
            border-bottom: none;
        }
        
        .event-info {
            flex: 1;
        }
        
        .event-type {
            font-weight: bold;
            color: #2c3e50;
        }
        
        .event-message {
            color: #7f8c8d;
            font-size: 14px;
            margin-top: 5px;
        }
        
        .event-time {
            color: #95a5a6;
            font-size: 12px;
        }
        
        .risk-high {
            color: #e74c3c;
        }
        
        .risk-medium {
            color: #f39c12;
        }
        
        .risk-low {
            color: #27ae60;
        }
        
        .loading {
            text-align: center;
            padding: 40px;
            color: #7f8c8d;
        }
    </style>
</head>
<body>
    <div class="dashboard">
        <div class="header">
            <h1>🛡️ ZTF-JS Security Dashboard</h1>
            <p>Real-time security monitoring and threat detection</p>
        </div>
        
        <div class="stats-grid" id="stats-grid">
            <div class="loading">Loading dashboard data...</div>
        </div>
        
        <div class="events-section">
            <h2>Recent Security Events</h2>
            <div id="events-list">
                <div class="loading">Loading events...</div>
            </div>
        </div>
    </div>

    <script>
        // Dashboard JavaScript
        class Dashboard {
            constructor() {
                this.init();
            }
            
            async init() {
                await this.loadDashboardData();
                this.setupEventStream();
                this.startAutoRefresh();
            }
            
            async loadDashboardData() {
                try {
                    const response = await fetch('/admin/security/api/metrics');
                    const data = await response.json();
                    
                    if (data.success) {
                        this.updateStats(data.data);
                    }
                } catch (error) {
                    console.error('Failed to load dashboard data:', error);
                }
            }
            
            updateStats(metrics) {
                const statsGrid = document.getElementById('stats-grid');
                
                statsGrid.innerHTML = \`
                    <div class="stat-card">
                        <h3>Total Events (24h)</h3>
                        <div class="value">\${metrics.totalEvents || 0}</div>
                    </div>
                    <div class="stat-card">
                        <h3>High Risk Events</h3>
                        <div class="value risk-high">\${metrics.riskScoreDistribution?.high || 0}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Active Users</h3>
                        <div class="value">\${metrics.topUsers?.length || 0}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Threats Detected</h3>
                        <div class="value risk-medium">\${metrics.threats?.length || 0}</div>
                    </div>
                \`;
            }
            
            setupEventStream() {
                const eventSource = new EventSource('/admin/security/api/events/stream');
                
                eventSource.onmessage = (event) => {
                    const data = JSON.parse(event.data);
                    if (data.type === 'update') {
                        this.updateStats(data.data.metrics);
                        this.updateEvents(data.data.recentEvents);
                    }
                };
                
                eventSource.onerror = (error) => {
                    console.error('Event stream error:', error);
                };
            }
            
            updateEvents(events) {
                const eventsList = document.getElementById('events-list');
                
                if (!events || events.length === 0) {
                    eventsList.innerHTML = '<div class="loading">No recent events</div>';
                    return;
                }
                
                eventsList.innerHTML = events.map(event => \`
                    <div class="event-item">
                        <div class="event-info">
                            <div class="event-type">\${event.type}</div>
                            <div class="event-message">\${event.message}</div>
                        </div>
                        <div class="event-time">\${new Date(event.timestamp).toLocaleString()}</div>
                    </div>
                \`).join('');
            }
            
            startAutoRefresh() {
                setInterval(() => {
                    this.loadDashboardData();
                }, 60000); // Refresh every minute
            }
        }
        
        // Initialize dashboard when page loads
        document.addEventListener('DOMContentLoaded', () => {
            new Dashboard();
        });
    </script>
</body>
</html>
    `;
  }
}

module.exports = Dashboard;

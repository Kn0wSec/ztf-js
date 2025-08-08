const ZeroTrustFramework = require('./core/ZeroTrustFramework');
const AuthManager = require('./auth/AuthManager');
const DeviceManager = require('./devices/DeviceManager');
const MonitoringManager = require('./monitoring/MonitoringManager');
const SecurityMiddleware = require('./middleware/SecurityMiddleware');
const Dashboard = require('./dashboard/Dashboard');
const Utils = require('./utils/Utils');
const ConfigManager = require('./config/ConfigManager');
const ThreatDetector = require('./security/ThreatDetector');
const DeviceFingerprinter = require('./devices/DeviceFingerprinter');
const APIDocumentation = require('./docs/APIDocumentation');

// Export the main framework class
module.exports = {
  ZeroTrustFramework,
  AuthManager,
  DeviceManager,
  MonitoringManager,
  SecurityMiddleware,
  Dashboard,
  Utils,
  ConfigManager,
  ThreatDetector,
  DeviceFingerprinter,
  APIDocumentation
};

module.exports.default = ZeroTrustFramework;

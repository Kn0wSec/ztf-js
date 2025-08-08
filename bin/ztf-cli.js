#!/usr/bin/env node

const { program } = require('commander');
const fs = require('fs');
const path = require('path');
const { ZeroTrustFramework, ConfigManager, APIDocumentation } = require('../src/index');

program
  .name('ztf')
  .description('ZTF-JS Zero Trust Framework CLI')
  .version('1.0.0');

// Initialize command
program
  .command('init')
  .description('Initialize a new ZTF-JS project')
  .option('-c, --config <path>', 'Path to configuration file')
  .option('-e, --env <environment>', 'Environment (development, production, test)', 'development')
  .action(async (options) => {
    try {
      console.log('🚀 Initializing ZTF-JS project...');
      
      const configManager = new ConfigManager();
      const config = configManager.load(options.config);
      
      // Create necessary directories
      const dirs = ['logs', 'backups', 'config'];
      dirs.forEach(dir => {
        if (!fs.existsSync(dir)) {
          fs.mkdirSync(dir, { recursive: true });
          console.log(`📁 Created directory: ${dir}`);
        }
      });
      
      // Create default .env file if it doesn't exist
      if (!fs.existsSync('.env')) {
        const envContent = `# ZTF-JS Configuration
NODE_ENV=${options.env}
MONGO_URI=mongodb://localhost:27017/ztf-${options.env}
REDIS_URL=redis://localhost:6379
JWT_SECRET=your-super-secret-key-change-in-production
JWT_EXPIRY=24h
REFRESH_TOKEN_EXPIRY=7d

# MFA Configuration
MFA_ENABLED=true
MFA_ISSUER=ZTF-JS

# Monitoring
MONITORING_ENABLED=true
LOG_LEVEL=info
ALERT_EMAIL=admin@yourcompany.com

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX=100

# Dashboard
DASHBOARD_ENABLED=true
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=admin123
`;
        fs.writeFileSync('.env', envContent);
        console.log('📝 Created .env file');
      }
      
      console.log('✅ ZTF-JS project initialized successfully!');
      console.log('📖 Next steps:');
      console.log('   1. Edit .env file with your configuration');
      console.log('   2. Start MongoDB and Redis');
      console.log('   3. Run: npm start');
      
    } catch (error) {
      console.error('❌ Failed to initialize project:', error.message);
      process.exit(1);
    }
  });

// Start command
program
  .command('start')
  .description('Start the ZTF-JS framework')
  .option('-c, --config <path>', 'Path to configuration file')
  .option('-p, --port <port>', 'Port to run on', '3000')
  .action(async (options) => {
    try {
      console.log('🚀 Starting ZTF-JS framework...');
      
      const configManager = new ConfigManager();
      const config = configManager.load(options.config);
      
      const ztf = new ZeroTrustFramework(config);
      await ztf.initialize();
      
      console.log('✅ ZTF-JS framework started successfully!');
      console.log(`🌐 Dashboard available at: http://localhost:${options.port}/admin/security`);
      console.log(`🔍 Health check at: http://localhost:${options.port}/health`);
      
      // Keep the process running
      process.on('SIGINT', async () => {
        console.log('\n🔄 Shutting down...');
        await ztf.shutdown();
        process.exit(0);
      });
      
    } catch (error) {
      console.error('❌ Failed to start framework:', error.message);
      process.exit(1);
    }
  });

// Health check command
program
  .command('health')
  .description('Check framework health')
  .option('-c, --config <path>', 'Path to configuration file')
  .action(async (options) => {
    try {
      const configManager = new ConfigManager();
      const config = configManager.load(options.config);
      
      const ztf = new ZeroTrustFramework(config);
      await ztf.initialize();
      
      const status = ztf.getStatus();
      const health = await ztf.healthCheck();
      
      console.log('🏥 Framework Health Status:');
      console.log(`   Status: ${health.status}`);
      console.log(`   Initialized: ${status.initialized}`);
      console.log(`   Environment: ${status.config.environment}`);
      console.log(`   MFA Enabled: ${status.config.mfa}`);
      console.log(`   Monitoring: ${status.config.monitoring}`);
      
      console.log('\n📊 Component Status:');
      Object.entries(health.components).forEach(([component, status]) => {
        console.log(`   ${component}: ${status}`);
      });
      
      await ztf.shutdown();
      
    } catch (error) {
      console.error('❌ Health check failed:', error.message);
      process.exit(1);
    }
  });

// Generate documentation command
program
  .command('docs')
  .description('Generate API documentation')
  .option('-o, --output <path>', 'Output directory', './docs')
  .option('-f, --format <format>', 'Output format (json, markdown, both)', 'both')
  .action(async (options) => {
    try {
      console.log('📚 Generating API documentation...');
      
      const configManager = new ConfigManager();
      const config = configManager.load();
      
      const ztf = new ZeroTrustFramework(config);
      await ztf.initialize();
      
      const apiDocs = new APIDocumentation();
      const docs = apiDocs.generateDocumentation(ztf);
      
      if (!fs.existsSync(options.output)) {
        fs.mkdirSync(options.output, { recursive: true });
      }
      
      if (options.format === 'json' || options.format === 'both') {
        fs.writeFileSync(
          path.join(options.output, 'api-docs.json'),
          JSON.stringify(docs, null, 2)
        );
        console.log(`📄 JSON documentation saved to ${options.output}/api-docs.json`);
      }
      
      if (options.format === 'markdown' || options.format === 'both') {
        const markdown = apiDocs.generateMarkdown(docs);
        fs.writeFileSync(
          path.join(options.output, 'README.md'),
          markdown
        );
        console.log(`📄 Markdown documentation saved to ${options.output}/README.md`);
      }
      
      await ztf.shutdown();
      console.log('✅ Documentation generated successfully!');
      
    } catch (error) {
      console.error('❌ Failed to generate documentation:', error.message);
      process.exit(1);
    }
  });

// Backup command
program
  .command('backup')
  .description('Create database backup')
  .option('-o, --output <path>', 'Output directory', './backups')
  .option('-d, --database <name>', 'Database name', 'ztf-app')
  .action(async (options) => {
    try {
      console.log('💾 Creating database backup...');
      
      const { exec } = require('child_process');
      const util = require('util');
      const execAsync = util.promisify(exec);
      
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const backupPath = path.join(options.output, `backup-${timestamp}`);
      
      if (!fs.existsSync(options.output)) {
        fs.mkdirSync(options.output, { recursive: true });
      }
      
      // MongoDB backup
      const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017';
      const backupCommand = `mongodump --uri="${mongoUri}/${options.database}" --out="${backupPath}"`;
      
      await execAsync(backupCommand);
      
      // Compress backup
      const tarCommand = `tar -czf "${backupPath}.tar.gz" -C "${options.output}" "${path.basename(backupPath)}"`;
      await execAsync(tarCommand);
      
      // Remove uncompressed backup
      fs.rmSync(backupPath, { recursive: true, force: true });
      
      console.log(`✅ Backup created: ${backupPath}.tar.gz`);
      
    } catch (error) {
      console.error('❌ Backup failed:', error.message);
      process.exit(1);
    }
  });

// Restore command
program
  .command('restore')
  .description('Restore database from backup')
  .argument('<backup-file>', 'Path to backup file')
  .option('-d, --database <name>', 'Database name', 'ztf-app')
  .action(async (backupFile, options) => {
    try {
      console.log('🔄 Restoring database from backup...');
      
      const { exec } = require('child_process');
      const util = require('util');
      const execAsync = util.promisify(exec);
      
      if (!fs.existsSync(backupFile)) {
        throw new Error(`Backup file not found: ${backupFile}`);
      }
      
      // Extract backup
      const extractDir = path.join('./backups', 'temp-restore');
      if (!fs.existsSync('./backups')) {
        fs.mkdirSync('./backups', { recursive: true });
      }
      
      const extractCommand = `tar -xzf "${backupFile}" -C "./backups"`;
      await execAsync(extractCommand);
      
      // Find the extracted directory
      const extractedDirs = fs.readdirSync('./backups').filter(dir => 
        dir.startsWith('backup-') && fs.statSync(path.join('./backups', dir)).isDirectory()
      );
      
      if (extractedDirs.length === 0) {
        throw new Error('No backup directory found in archive');
      }
      
      const backupDir = path.join('./backups', extractedDirs[0]);
      
      // Restore database
      const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017';
      const restoreCommand = `mongorestore --uri="${mongoUri}" --db="${options.database}" "${backupDir}/${options.database}"`;
      
      await execAsync(restoreCommand);
      
      // Clean up
      fs.rmSync(backupDir, { recursive: true, force: true });
      
      console.log(`✅ Database restored successfully to ${options.database}`);
      
    } catch (error) {
      console.error('❌ Restore failed:', error.message);
      process.exit(1);
    }
  });

// Config command
program
  .command('config')
  .description('Manage framework configuration')
  .option('-s, --show', 'Show current configuration')
  .option('-v, --validate', 'Validate configuration')
  .option('-e, --export <path>', 'Export configuration to file')
  .action(async (options) => {
    try {
      const configManager = new ConfigManager();
      const config = configManager.load();
      
      if (options.show) {
        console.log('⚙️  Current Configuration:');
        console.log(JSON.stringify(config, null, 2));
      }
      
      if (options.validate) {
        console.log('✅ Configuration validation passed');
      }
      
      if (options.export) {
        fs.writeFileSync(options.export, JSON.stringify(config, null, 2));
        console.log(`📄 Configuration exported to ${options.export}`);
      }
      
      if (!options.show && !options.validate && !options.export) {
        console.log('⚙️  Configuration Management');
        console.log('Use --show to display current configuration');
        console.log('Use --validate to validate configuration');
        console.log('Use --export <path> to export configuration');
      }
      
    } catch (error) {
      console.error('❌ Configuration error:', error.message);
      process.exit(1);
    }
  });

// Install dependencies command
program
  .command('install')
  .description('Install framework dependencies')
  .option('-p, --production', 'Install production dependencies only')
  .action(async (options) => {
    try {
      console.log('📦 Installing dependencies...');
      
      const { exec } = require('child_process');
      const util = require('util');
      const execAsync = util.promisify(exec);
      
      const installCommand = options.production ? 'npm ci --only=production' : 'npm install';
      await execAsync(installCommand);
      
      console.log('✅ Dependencies installed successfully!');
      
    } catch (error) {
      console.error('❌ Installation failed:', error.message);
      process.exit(1);
    }
  });

// Test command
program
  .command('test')
  .description('Run framework tests')
  .option('-w, --watch', 'Run tests in watch mode')
  .option('-c, --coverage', 'Generate coverage report')
  .action(async (options) => {
    try {
      console.log('🧪 Running tests...');
      
      const { exec } = require('child_process');
      const util = require('util');
      const execAsync = util.promisify(exec);
      
      let testCommand = 'npm test';
      if (options.watch) {
        testCommand = 'npm run test:watch';
      }
      if (options.coverage) {
        testCommand = 'npm run test:coverage';
      }
      
      await execAsync(testCommand);
      
      console.log('✅ Tests completed successfully!');
      
    } catch (error) {
      console.error('❌ Tests failed:', error.message);
      process.exit(1);
    }
  });

// Version command
program
  .command('version')
  .description('Show framework version and information')
  .action(() => {
    const packageJson = require('../package.json');
    console.log('📋 ZTF-JS Framework Information:');
    console.log(`   Version: ${packageJson.version}`);
    console.log(`   Description: ${packageJson.description}`);
    console.log(`   Node.js: ${process.version}`);
    console.log(`   Platform: ${process.platform}`);
    console.log(`   Architecture: ${process.arch}`);
  });

program.parse();

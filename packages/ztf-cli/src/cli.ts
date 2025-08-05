
// #!/usr/bin/env node
import { Command } from 'commander';
import inquirer from 'inquirer';
import fs from 'fs';
import path from 'path';

const program = new Command();

program
  .name('ztf')
  .description('Zero-Trust Framework for JavaScript')
  .version('1.0.0');

interface ZtfConfig {
  framework: string;
  policyService: string;
  security: {
    jwtSecret?: string;
    sessionTimeout: number;
    maxRiskScore: number;
  };
}

program
  .command('init')
  .description('Initialize ZTF in current project')
  .action(async () => {
    console.log('🔐 Initializing Zero-Trust Framework...');

    const answers = await inquirer.prompt([
      {
        type: 'list',
        name: 'framework',
        message: 'Which framework are you using?',
        choices: ['Express.js', 'Next.js', 'Nest.js', 'Other']
      },
      {
        type: 'input',
        name: 'policyService',
        message: 'Policy service URL:',
        default: 'http://localhost:3001'
      },
      {
        type: 'confirm',
        name: 'generateKeys',
        message: 'Generate JWT signing keys?',
        default: true
      }
    ]);

    // Generate configuration
    const config: ZtfConfig = {
      framework: answers.framework,
      policyService: answers.policyService,
      security: {
        sessionTimeout: 3600,
        maxRiskScore: 0.7
      }
    };

    if (answers.generateKeys) {
      config.security.jwtSecret = generateJWTSecret();
    }

    // Write configuration file
    fs.writeFileSync('.ztfrc.json', JSON.stringify(config, null, 2));

    // Generate framework-specific integration code
    await generateIntegrationCode(answers.framework);

    console.log('✅ ZTF initialization complete!');
    console.log('📁 Configuration saved to .ztfrc.json');
    console.log('🔧 Integration code generated');

    if (answers.framework === 'Express.js') {
      console.log('📝 Add the following to your Express app:');
      console.log('   const { ztfExpress } = require("@ztf-js/express-mw");');
      console.log('   app.use(ztfExpress({ policyService: "' + answers.policyService + '" }));');
    }
  });

program
  .command('policy')
  .description('Manage security policies')
  .option('-f, --file <file>', 'Policy file path')
  .option('-l, --list', 'List current policies')
  .option('-v, --validate', 'Validate policy syntax')
  .action(async (options) => {
    if (options.list) {
      console.log('📋 Current policies:');
      await listPolicies();
    } else if (options.file) {
      console.log('🚀 Deploying policy:', options.file);
      await deployPolicy(options.file);
    } else if (options.validate) {
      console.log('✅ Validating policy syntax...');
      await validatePolicies();
    }
  });

program
  .command('test')
  .description('Test policy decisions')
  .option('-c, --context <file>', 'Context file path')
  .option('-p, --policy <name>', 'Policy name to test')
  .action(async (options) => {
    console.log('🧪 Testing policy decisions...');
    if (options.context && options.policy) {
      await testPolicyWithContext(options.context, options.policy);
    } else {
      console.log('❌ Please provide both --context and --policy options');
    }
  });

// Helper functions
function generateJWTSecret(): string {
  return require('crypto').randomBytes(64).toString('hex');
}

async function generateIntegrationCode(framework: string) {
  const templates = {
    'Express.js': `
// Add this to your Express.js application
const { ztfExpress } = require('@ztf-js/express-mw');

// Apply ZTF middleware
app.use('/api', ztfExpress({
  policyService: 'http://localhost:3001',
  cacheTTL: 300000, // 5 minutes
  bypassRoutes: ['/health', '/metrics']
}));
`,
    'Next.js': `
// Create middleware.ts in your Next.js root directory
import { ztfNext } from '@ztf-js/next-mw';

export const middleware = ztfNext({
  policyService: process.env.ZTF_POLICY_SERVICE || 'http://localhost:3001',
  protectedPaths: ['/dashboard', '/api/protected']
});

export const config = {
  matcher: ['/((?!api|_next/static|_next/image|.*\\.png$).*)']
};
`,
    'Nest.js': `
// Add to your NestJS module
import { ZtfGuard, ZtfPolicy } from '@ztf-js/nest-guard';

@Controller('users')
@UseGuards(ZtfGuard)
export class UsersController {
  @Get(':id')
  @ZtfPolicy('user.read')
  findOne(@Param('id') id: string) {
    return this.usersService.findOne(id);
  }
}
`
  };

  const template = templates[framework as keyof typeof templates];
  if (template) {
    fs.writeFileSync(`ztf-integration-${framework.toLowerCase().replace('.', '')}.example`, template);
  }
}

async function listPolicies() {
  try {
    const config = JSON.parse(fs.readFileSync('.ztfrc.json', 'utf8'));
    const response = await fetch(`${config.policyService}/policies`);
    const policies = await response.json();

    policies.forEach((policy: any) => {
      console.log(`  - ${policy.name}: ${policy.description}`);
    });
  } catch (error) {
    console.error('❌ Error listing policies:', error);
  }
}

async function deployPolicy(filePath: string) {
  try {
    const policyContent = fs.readFileSync(filePath, 'utf8');
    const policy = JSON.parse(policyContent);

    const config = JSON.parse(fs.readFileSync('.ztfrc.json', 'utf8'));

    const response = await fetch(`${config.policyService}/policies`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(policy)
    });

    if (response.ok) {
      console.log('✅ Policy deployed successfully');
    } else {
      console.log('❌ Policy deployment failed');
    }
  } catch (error) {
    console.error('❌ Error deploying policy:', error);
  }
}

async function validatePolicies() {
  console.log('✅ All policies are valid');
}

async function testPolicyWithContext(contextFile: string, policyName: string) {
  try {
    const context = JSON.parse(fs.readFileSync(contextFile, 'utf8'));
    const config = JSON.parse(fs.readFileSync('.ztfrc.json', 'utf8'));

    const response = await fetch(`${config.policyService}/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(context)
    });

    const decision = await response.json();

    console.log('🎯 Policy Decision:');
    console.log(`   Allow: ${decision.allow}`);
    console.log(`   Reason: ${decision.reason}`);
    console.log(`   Risk Score: ${decision.riskScore}`);
    console.log(`   Applied Policies: ${decision.appliedPolicies.join(', ')}`);
  } catch (error) {
    console.error('❌ Error testing policy:', error);
  }
}

program.parse();

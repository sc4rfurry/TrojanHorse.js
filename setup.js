#!/usr/bin/env node

/**
 * TrojanHorse.js Interactive Setup Script
 * Guides users through initial configuration and API key setup
 */

import inquirer from 'inquirer';
import chalk from 'chalk';
import ora from 'ora';
import { promises as fs } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { createRequire } from 'module';
import { execSync } from 'child_process';

// ES module compatibility
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const require = createRequire(import.meta.url);

console.log(chalk.blue(`
🏰 Welcome to TrojanHorse.js Setup
==================================

The only Trojan you actually want in your system!

This interactive setup will help you configure TrojanHorse.js
for your environment and use case.
`));

async function main() {
  try {
    console.log(chalk.yellow('📋 Let\'s gather some information about your setup...\n'));

    // Environment questions
    const answers = await inquirer.prompt([
      {
        type: 'list',
        name: 'environment',
        message: 'What environment are you setting up?',
        choices: [
          { name: 'Development (local testing)', value: 'development' },
          { name: 'Staging (pre-production)', value: 'staging' },
          { name: 'Production (live system)', value: 'production' }
        ]
      },
      {
        type: 'list',
        name: 'deployment',
        message: 'How will you deploy TrojanHorse.js?',
        choices: [
          { name: 'Node.js Application', value: 'nodejs' },
          { name: 'Browser/Static Site', value: 'browser' },
          { name: 'REST API Server', value: 'api' },
          { name: 'CLI Tool', value: 'cli' },
          { name: 'All of the above', value: 'full' }
        ]
      },
      {
        type: 'checkbox',
        name: 'features',
        message: 'Which features do you need?',
        choices: [
          { name: 'Threat Detection & Analysis', value: 'threat', checked: true },
          { name: 'Secure API Key Management', value: 'vault', checked: true },
          { name: 'Real-time Webhooks', value: 'webhooks' },
          { name: 'Stream Processing', value: 'streaming' },
          { name: 'Circuit Breaker Protection', value: 'circuit-breaker' },
          { name: 'Performance Monitoring', value: 'monitoring' },
          { name: 'Data Export (JSON/CSV/STIX)', value: 'export' }
        ]
      },
      {
        type: 'checkbox',
        name: 'feeds',
        message: 'Which threat intelligence feeds do you want to use?',
        choices: [
          { name: 'URLhaus (Free, no key required)', value: 'urlhaus', checked: true },
          { name: 'AlienVault OTX (Free tier available)', value: 'alienvault' },
          { name: 'AbuseIPDB (Free tier: 1000/day)', value: 'abuseipdb' },
          { name: 'VirusTotal (Free tier: 1000/day)', value: 'virustotal' },
          { name: 'CrowdSec CTI (Free tier available)', value: 'crowdsec' }
        ]
      }
    ]);

    // API Key collection
    const apiKeys = {};
    
    if (answers.feeds.includes('alienvault')) {
      const alienVaultKey = await inquirer.prompt([
        {
          type: 'input',
          name: 'key',
          message: 'AlienVault OTX API Key (optional for free tier):',
          default: ''
        }
      ]);
      if (alienVaultKey.key) apiKeys.alienVault = alienVaultKey.key;
    }

    if (answers.feeds.includes('abuseipdb')) {
      const abuseipdbKey = await inquirer.prompt([
        {
          type: 'input',
          name: 'key',
          message: 'AbuseIPDB API Key:',
          validate: (input) => input.length > 0 || 'AbuseIPDB requires an API key'
        }
      ]);
      apiKeys.abuseipdb = abuseipdbKey.key;
    }

    if (answers.feeds.includes('virustotal')) {
      const virustotalKey = await inquirer.prompt([
        {
          type: 'input',
          name: 'key',
          message: 'VirusTotal API Key:',
          validate: (input) => input.length > 0 || 'VirusTotal requires an API key'
        }
      ]);
      apiKeys.virustotal = virustotalKey.key;
    }

    if (answers.feeds.includes('crowdsec')) {
      const crowdsecKey = await inquirer.prompt([
        {
          type: 'input',
          name: 'key',
          message: 'CrowdSec API Key (optional):',
          default: ''
        }
      ]);
      if (crowdsecKey.key) apiKeys.crowdsec = crowdsecKey.key;
    }

    // Advanced configuration
    const advanced = await inquirer.prompt([
      {
        type: 'list',
        name: 'strategy',
        message: 'Choose analysis strategy:',
        choices: [
          { name: 'Defensive (high accuracy, conservative)', value: 'defensive' },
          { name: 'Balanced (good speed/accuracy balance)', value: 'balanced' },
          { name: 'Aggressive (fast detection, higher false positives)', value: 'aggressive' },
          { name: 'Fort Knox (maximum security, strict validation)', value: 'fort-knox' }
        ],
        default: 'balanced'
      },
      {
        type: 'confirm',
        name: 'corsProxy',
        message: 'Do you need CORS proxy support for browser usage?',
        default: answers.deployment === 'browser' || answers.deployment === 'full',
        when: () => answers.deployment === 'browser' || answers.deployment === 'full'
      }
    ]);

    let corsProxyUrl = '';
    if (advanced.corsProxy) {
      const proxy = await inquirer.prompt([
        {
          type: 'input',
          name: 'url',
          message: 'CORS Proxy URL (leave empty to use demo mode):',
          default: 'https://still-water-daf2.zeeahanm900.workers.dev'
        }
      ]);
      corsProxyUrl = proxy.url;
    }

    // Generate configuration
    console.log(chalk.blue('\n🔧 Generating configuration files...\n'));
    
    await generateConfigurations(answers, apiKeys, advanced, corsProxyUrl);
    
    // Setup dependencies
    if (answers.environment !== 'browser') {
      const installDeps = await inquirer.prompt([
        {
          type: 'confirm',
          name: 'install',
          message: 'Install dependencies now?',
          default: true
        }
      ]);

      if (installDeps.install) {
        await installDependencies();
      }
    }

    // Run tests
    const runTests = await inquirer.prompt([
      {
        type: 'confirm',
        name: 'test',
        message: 'Run a quick test to verify setup?',
        default: true
      }
    ]);

    if (runTests.test) {
      await runQuickTest(answers, apiKeys);
    }

    // Generate documentation
    await generateSetupDocs(answers, apiKeys, advanced, corsProxyUrl);

    console.log(chalk.green(`
🎉 Setup Complete!
==================

TrojanHorse.js has been configured for your ${answers.environment} environment.

Generated files:
📄 trojanhorse.config.js - Main configuration
📄 .env.example - Environment variables template
📄 docker-compose.yml - Docker setup (if needed)
📄 setup-guide.md - Detailed setup instructions

Next steps:
${answers.deployment === 'nodejs' ? `
1. Import TrojanHorse in your app:
   import { TrojanHorse } from 'trojanhorse-js';

2. Initialize with your config:
   const config = await import('./trojanhorse.config.js');
   const trojan = new TrojanHorse(config.default);

3. Start detecting threats:
   const result = await trojan.scout('suspicious-domain.com');
` : ''}${answers.deployment === 'browser' ? `
1. Include the browser build:
   <script src="dist/trojanhorse.browser.min.js"></script>

2. Create simple lookup:
   const lookup = TrojanHorse.createLookup(${corsProxyUrl ? `{
     proxyUrl: '${corsProxyUrl}'
   }` : ''});

3. Check threats:
   const isMalicious = await lookup.checkDomain('test.com');
` : ''}${answers.deployment === 'api' ? `
1. Start the API server:
   npm run start:api

2. View API docs:
   http://localhost:3000/api/docs

3. Make requests:
   POST /api/threat/check
` : ''}${answers.deployment === 'cli' ? `
1. Use the CLI globally:
   npm install -g

2. Check threats:
   trojanhorse threat check suspicious-domain.com

3. Create secure vault:
   trojanhorse vault create
` : ''}
Happy threat hunting! 🛡️
    `));

  } catch (error) {
    console.error(chalk.red(`Setup failed: ${error.message}`));
    process.exit(1);
  }
}

async function generateConfigurations(answers, apiKeys, advanced, corsProxyUrl) {
  // Main configuration (ES module export)
  const config = `// TrojanHorse.js Configuration
// Generated by setup script

export default {
  // API Keys
  apiKeys: {
    ${Object.entries(apiKeys).map(([key, value]) => `${key}: process.env.${key.toUpperCase()}_API_KEY || '${value}'`).join(',\n    ')}
  },
  
  // Data Sources
  sources: [${answers.feeds.map(f => `'${f}'`).join(', ')}],
  
  // Analysis Strategy
  strategy: '${advanced.strategy}',
  
  // Security Settings
  security: {
    enforceHttps: ${answers.environment === 'production'},
    autoLock: true,
    lockTimeout: 300000, // 5 minutes
    auditLogging: ${answers.environment === 'production'}
  },
  
  // Performance Settings
  caching: {
    enabled: true,
    ttl: 3600000, // 1 hour
    maxSize: ${answers.environment === 'production' ? 10000 : 1000}
  },
  
  // Rate Limiting
  rateLimit: {
    enabled: true,
    maxConcurrent: ${answers.environment === 'production' ? 20 : 10},
    timeout: 30000
  }${corsProxyUrl ? `,
  
  // Browser Configuration
  browser: {
    corsProxy: '${corsProxyUrl}',
    fallbackMode: 'demo'
  }` : ''}${answers.features.includes('circuit-breaker') ? `,
  
  // Circuit Breaker
  circuitBreaker: {
    enabled: true,
    failureThreshold: 5,
    timeout: 60000
  }` : ''}${answers.features.includes('monitoring') ? `,
  
  // Monitoring
  monitoring: {
    enabled: true,
    metricsPort: 9090
  }` : ''}
};`;

  await fs.writeFile('trojanhorse.config.js', config);

  // Environment variables template
  const envTemplate = `# TrojanHorse.js Environment Variables
# Copy this to .env and fill in your API keys

NODE_ENV=${answers.environment}
${Object.keys(apiKeys).map(key => `${key.toUpperCase()}_API_KEY=your_${key}_api_key_here`).join('\n')}

# Security
JWT_SECRET=generate_a_secure_random_string_here
ENCRYPTION_KEY=generate_a_32_byte_random_key_here

# Server Configuration (for API deployment)
PORT=3000
API_USERNAME=admin
API_PASSWORD_HASH=generate_bcrypt_hash_here

# Monitoring (optional)
SENTRY_DSN=your_sentry_dsn_here
LOG_LEVEL=info
`;

  await fs.writeFile('.env.example', envTemplate);

  // Docker configuration (if needed)
  if (answers.deployment === 'api' || answers.deployment === 'full') {
    const dockerCompose = `version: '3.8'

services:
  trojanhorse-api:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=${answers.environment}
    env_file:
      - .env
    restart: unless-stopped
    
  redis:
    image: redis:6-alpine
    restart: unless-stopped
    
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
    depends_on:
      - trojanhorse-api
    restart: unless-stopped
`;

    await fs.writeFile('docker-compose.yml', dockerCompose);
  }
}

async function installDependencies() {
    const spinner = ora('Installing dependencies...').start();
    
    try {
      execSync('npm install', { stdio: 'pipe' });
      spinner.succeed('Dependencies installed successfully');
      return true;
    } catch (error) {
      spinner.fail('Failed to install dependencies');
      console.error(chalk.red(`Error: ${error.message}`));
      return false;
    }
  }

async function runQuickTest(answers, apiKeys) {
  const spinner = ora('Running quick test...').start();
  
  try {
    // Test basic functionality
    const { TrojanHorse } = await import('./dist/trojanhorse.esm.js');
    
    const testConfig = {
      sources: ['urlhaus'], // Always use URLhaus for testing (no key required)
      strategy: 'defensive'
    };

    const trojan = new TrojanHorse(testConfig);
    const result = await trojan.scout('google.com'); // Safe domain for testing
    
    spinner.succeed('Quick test passed! TrojanHorse.js is working correctly.');
    
    console.log(chalk.blue('Test Results:'));
    console.log(`  Target: google.com`);
    console.log(`  Threats Found: ${Array.isArray(result) ? result.length : 0}`);
    console.log(`  Status: ${Array.isArray(result) && result.length === 0 ? 'Clean (no threats detected)' : 'Analysis completed'}`);
    console.log(`  Sources Used: URLhaus`);
    
  } catch (error) {
    spinner.fail('Quick test failed');
    console.log(chalk.yellow(`Error: ${error.message}`));
    console.log(chalk.yellow('This might be due to network connectivity or configuration issues.'));
  }
}

async function generateSetupDocs(answers, apiKeys, advanced, corsProxyUrl) {
  const docs = `# TrojanHorse.js Setup Guide

This guide was generated by the interactive setup script.

## Configuration Summary

- **Environment**: ${answers.environment}
- **Deployment**: ${answers.deployment}
- **Strategy**: ${advanced.strategy}
- **Threat Feeds**: ${answers.feeds.join(', ')}
- **Features**: ${answers.features.join(', ')}

## Quick Start

### 1. Environment Setup

Copy \`.env.example\` to \`.env\` and fill in your API keys:

\`\`\`bash
cp .env.example .env
# Edit .env with your actual API keys
\`\`\`

### 2. Basic Usage

\`\`\`javascript
import { TrojanHorse } from 'trojanhorse-js';
import config from './trojanhorse.config.js';

const trojan = new TrojanHorse(config);

// Check a domain for threats
const result = await trojan.scout('suspicious-domain.com');
console.log('Threat Score:', result.correlationScore);
\`\`\`

${answers.deployment === 'browser' ? `
### 3. Browser Usage

Include the browser build in your HTML:

\`\`\`html
<script src="dist/trojanhorse.browser.min.js"></script>
<script>
  const lookup = TrojanHorse.createLookup(${corsProxyUrl ? `{
    proxyUrl: '${corsProxyUrl}'
  }` : ''});
  
  lookup.checkDomain('test.com').then(isMalicious => {
    console.log(isMalicious ? 'Threat detected!' : 'Domain is safe');
  });
</script>
\`\`\`
` : ''}

${answers.deployment === 'api' ? `
### 3. API Server

Start the REST API server:

\`\`\`bash
npm run start:api
\`\`\`

Access the API documentation at: http://localhost:3000/api/docs
` : ''}

${answers.deployment === 'cli' ? `
### 3. CLI Usage

Install globally and use the CLI:

\`\`\`bash
npm install -g
trojanhorse threat check suspicious-domain.com
trojanhorse vault create
\`\`\`
` : ''}

## API Keys Setup

${Object.keys(apiKeys).length > 0 ? `
You'll need API keys for the following services:

${Object.keys(apiKeys).map(key => {
  const serviceUrls = {
    alienVault: 'https://otx.alienvault.com/',
    abuseipdb: 'https://www.abuseipdb.com/api',
    virustotal: 'https://www.virustotal.com/gui/join-us',
    crowdsec: 'https://app.crowdsec.net/'
  };
  return `- **${key}**: ${serviceUrls[key] || 'Check their website for API access'}`;
}).join('\n')}
` : 'No API keys required for your current configuration.'}

## Security Notes

- Store API keys in environment variables, never in code
- Use HTTPS in production
- Enable audit logging for compliance
- Regularly rotate API keys
- Monitor webhook endpoints for security

## Troubleshooting

### Common Issues

1. **CORS errors in browser**: Use the CORS proxy or implement backend routing
2. **Rate limiting**: Check your API key limits and upgrade if needed
3. **Memory usage**: Adjust caching settings for your environment
4. **Network timeouts**: Increase timeout values in config

### Getting Help

- 📚 Documentation: https://github.com/sc4rfurry/TrojanHorse.js
- 🐛 Issues: https://github.com/sc4rfurry/TrojanHorse.js/issues
- 💬 Discussions: https://github.com/sc4rfurry/TrojanHorse.js/discussions

---

Generated on ${new Date().toISOString()}
TrojanHorse.js v1.0.0
`;

  await fs.writeFile('setup-guide.md', docs);
}

// Run the setup
main().catch(console.error); 
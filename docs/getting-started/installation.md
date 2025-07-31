# Installation Guide

Get TrojanHorse.js up and running in your environment.

## System Requirements

### Node.js Environment
- **Node.js**: 16.0.0 or higher
- **NPM**: 7.0.0 or higher (or Yarn 1.22.0+)
- **Operating System**: Windows, macOS, Linux
- **Memory**: Minimum 512MB RAM, 2GB recommended
- **Storage**: 100MB available space

### Browser Environment
- **Modern Browsers**: Chrome 90+, Firefox 88+, Safari 14+, Edge 90+
- **ES6 Support**: Required for ES module builds
- **Web Crypto API**: Required for security features
- **CORS Support**: Required for threat feed access

## Installation Methods

### NPM Installation

#### Standard Installation
```bash
# Install via NPM
npm install trojanhorse-js

# Or via Yarn
yarn add trojanhorse-js
```

#### Global CLI Installation
```bash
# Install CLI globally
npm install -g trojanhorse-js

# Verify installation
trojanhorse --version
```

### CDN Installation

#### unpkg CDN
```html
<!-- Latest version -->
    <script src="https://unpkg.com/trojanhorse-js@latest/dist/trojanhorse.browser.min.js"></script>
    
<!-- Specific version -->
<script src="https://unpkg.com/trojanhorse-js@1.0.0/dist/trojanhorse.browser.min.js"></script>
```

#### jsDelivr CDN
```html
<!-- Latest version -->
<script src="https://cdn.jsdelivr.net/npm/trojanhorse-js@latest/dist/trojanhorse.browser.min.js"></script>

<!-- ES Modules -->
<script type="module">
  import { TrojanHorse } from 'https://cdn.jsdelivr.net/npm/trojanhorse-js@latest/dist/trojanhorse.browser.esm.js';
</script>
```

### Docker Installation

#### Pull Official Image
```bash
# Pull from Docker Hub
docker pull sc4rfurry/trojanhorse-js:latest

# Or from GitHub Container Registry
docker pull ghcr.io/sc4rfurry/trojanhorse-js:latest
```

#### Run Container
```bash
# Basic container run
docker run -p 3000:3000 sc4rfurry/trojanhorse-js:latest

# With environment variables
docker run -p 3000:3000 \
  -e ALIENVAULT_API_KEY=your-key \
  -e ABUSEIPDB_API_KEY=your-key \
  sc4rfurry/trojanhorse-js:latest
```

### From Source

```bash
# Clone repository
git clone https://github.com/sc4rfurry/TrojanHorse.js.git
cd TrojanHorse.js

# Install dependencies
npm install

# Build project
npm run build:all

# Run tests
npm test
```

## Package Formats

TrojanHorse.js is distributed in multiple formats:

| Format | File | Use Case |
|--------|------|----------|
| **CommonJS** | `dist/trojanhorse.js` | Node.js applications |
| **ES Modules** | `dist/trojanhorse.esm.js` | Modern bundlers (Webpack, Rollup) |
| **UMD** | `dist/trojanhorse.umd.js` | Universal module definition |
| **Browser (Minified)** | `dist/trojanhorse.browser.min.js` | CDN, static sites |
| **Browser (ES Modules)** | `dist/trojanhorse.browser.esm.js` | Modern browsers |
| **Browser (IIFE)** | `dist/trojanhorse.browser.iife.js` | Legacy browser support |
| **TypeScript** | `dist/types/` | Type definitions |

## Environment Setup

### API Keys Configuration

1. **Get API Keys** from threat intelligence providers:
   - [AlienVault OTX](https://otx.alienvault.com/api)
   - [AbuseIPDB](https://www.abuseipdb.com/api)
   - [VirusTotal](https://www.virustotal.com/gui/join-us)
   - [CrowdSec](https://app.crowdsec.net/)

2. **Create Configuration File**:
```bash
# Copy example configuration
cp trojanhorse.config.example.js trojanhorse.config.js

# Edit with your API keys
nano trojanhorse.config.js
```

3. **Environment Variables** (Recommended):
```bash
# Create .env file
echo "ALIENVAULT_API_KEY=your-key-here" >> .env
echo "ABUSEIPDB_API_KEY=your-key-here" >> .env
echo "VIRUSTOTAL_API_KEY=your-key-here" >> .env
echo "CROWDSEC_API_KEY=your-key-here" >> .env
```

### Interactive Setup

```bash
# Run interactive setup wizard
npm run setup

# Or if installed globally
trojanhorse setup
```

## Verification

### Node.js Verification
```javascript
// test-installation.js
import { TrojanHorse } from 'trojanhorse-js';

const trojan = new TrojanHorse({
  sources: ['urlhaus'] // Free source, no API key needed
});

// Test basic functionality
trojan.scout('example.com').then(threats => {
  console.log('✅ Installation successful!');
  console.log(`Found ${threats.length} threats`);
}).catch(error => {
  console.error('❌ Installation issue:', error.message);
});
```

### Browser Verification
```html
<!DOCTYPE html>
<html>
<head>
    <title>TrojanHorse.js Test</title>
</head>
<body>
    <h1>TrojanHorse.js Installation Test</h1>
    <div id="result">Testing...</div>
    
    <script src="https://unpkg.com/trojanhorse-js@latest/dist/trojanhorse.browser.min.js"></script>
<script>
        const trojan = new TrojanHorse({ sources: ['urlhaus'] });
        
        trojan.scout('example.com').then(threats => {
            document.getElementById('result').innerHTML = 
                `✅ Installation successful! Found ${threats.length} threats`;
        }).catch(error => {
            document.getElementById('result').innerHTML = 
                `❌ Installation issue: ${error.message}`;
        });
</script>
</body>
</html>
```

### Docker Verification
```bash
# Test Docker installation
docker run --rm sc4rfurry/trojanhorse-js:latest npm test
```

## Troubleshooting

### Common Installation Issues

#### Node.js Version Issues
```bash
# Check Node.js version
node --version

# Update Node.js if needed
npm install -g n
n latest
```

#### NPM Permission Issues
```bash
# Fix NPM permissions (macOS/Linux)
sudo chown -R $(whoami) $(npm config get prefix)/{lib/node_modules,bin,share}

# Or use NPM's permission fix
npm config set prefix ~/.npm-global
export PATH=~/.npm-global/bin:$PATH
```

#### Network/Proxy Issues
```bash
# Configure NPM proxy
npm config set proxy http://proxy.company.com:8080
npm config set https-proxy http://proxy.company.com:8080

# Clear NPM cache
npm cache clean --force
```

#### TypeScript Issues
```bash
# Install TypeScript globally
npm install -g typescript

# Or add to project
npm install --save-dev typescript @types/node
```

### Build Issues

#### Missing Dependencies
```bash
# Clear node_modules and reinstall
rm -rf node_modules package-lock.json
npm install
```

#### Build Tool Issues
```bash
# Update build tools
npm update rollup jest eslint

# Or reinstall build dependencies
npm install --only=dev
```

### Runtime Issues

#### API Key Problems
- Verify API keys are valid and not expired
- Check API rate limits and quotas
- Ensure environment variables are properly set

#### Network Connectivity
- Test internet connection
- Check firewall settings
- Verify DNS resolution for threat feed URLs

#### Memory Issues
```bash
# Increase Node.js memory limit
node --max-old-space-size=4096 your-script.js

# Or set environment variable
export NODE_OPTIONS="--max-old-space-size=4096"
```

### Getting Help

If installation issues persist:

1. **Check System Requirements**: Ensure you meet minimum requirements
2. **Clear NPM Cache**: `npm cache clean --force`
3. **Update Dependencies**: `npm update`
4. **Check GitHub Issues**: [Known Issues](https://github.com/sc4rfurry/TrojanHorse.js/issues)
5. **Community Support**: [Discord Server](https://discord.gg/trojanhorse-js)

## Next Steps

After successful installation:

1. **📖 [Quick Start Guide](quickstart.md)** - Get up and running in minutes
2. **⚙️ [Configuration](../user-guide/configuration.md)** - Customize for your needs
3. **🏗️ [Architecture](concepts.md)** - Understand the system design
4. **🚀 [Deployment](../deployment/production.md)** - Deploy to production

---

**Ready to protect your digital fortress?** Continue to the [Quick Start Guide](quickstart.md) to begin threat hunting!
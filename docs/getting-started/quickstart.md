# Quick Start Guide

Get up and running with TrojanHorse.js in minutes. This guide covers the fastest path to threat detection.

## 5-Minute Setup

### 1. Installation

=== "NPM"
    ```bash
    npm install trojanhorse-js
    ```

=== "Yarn"
    ```bash
    yarn add trojanhorse-js
    ```

=== "CDN (Browser)"
    ```html
    <script src="https://unpkg.com/trojanhorse-js@latest/dist/trojanhorse.browser.min.js"></script>
    ```

### 2. Basic Usage

#### Node.js Application

```javascript
import { TrojanHorse } from 'trojanhorse-js';

// Initialize with URLhaus (no API key required)
const trojan = new TrojanHorse({
  sources: ['urlhaus'],
  strategy: 'defensive'
});

// Check for threats
const threats = await trojan.scout('suspicious-domain.com');
console.log(`Found ${threats.length} threats`);

// Export data
const jsonData = await trojan.plunder('json');
console.log(`Exported ${Object.keys(jsonData).length} threat indicators`);
```

#### Browser Usage

```html
<!DOCTYPE html>
<html>
<head>
    <title>Threat Check Demo</title>
</head>
<body>
    <script src="https://unpkg.com/trojanhorse-js@latest/dist/trojanhorse.browser.min.js"></script>
    <script>
        // Simple threat lookup (demo mode)
        const lookup = TrojanHorse.createLookup({ demoMode: true });
        
        async function checkDomain() {
            const isMalicious = await lookup.checkDomain('test-malware.com');
            console.log(isMalicious ? '🚨 Threat detected!' : '✅ Domain appears safe');
        }
        
        checkDomain();
    </script>
</body>
</html>
```

### 3. With API Keys (Recommended)

Create a secure vault for your API keys:

```javascript
import { TrojanHorse } from 'trojanhorse-js';

// Create encrypted vault
const { trojan, vault } = await TrojanHorse.createVault('your-secure-password', {
  alienVault: 'your-alienvault-api-key',
  abuseipdb: 'your-abuseipdb-api-key',
  virustotal: 'your-virustotal-api-key'
});

// Enable multiple threat feeds
const result = await trojan.scout('suspicious-domain.com');
console.log('Threat analysis:', result);
```

## Interactive Setup

For guided configuration, run the setup wizard:

```bash
node setup.js
```

This creates:
- `trojanhorse.config.js` - Main configuration
- `quick-start.mjs` - Ready-to-run example
- Browser examples with your settings

## Next Steps

### Learn Core Concepts
- [Basic Concepts](concepts.md) - Understanding threat intelligence
- [Configuration](../user-guide/configuration.md) - Advanced settings
- [Vault Management](../user-guide/vault-management.md) - Secure API key storage

### Production Deployment
- [Production Guide](../deployment/production.md) - Deploy to production
- [Browser Usage](../deployment/browser.md) - Static site integration
- [Docker Setup](../deployment/docker.md) - Containerized deployment

### Advanced Usage
- [Threat Detection](../user-guide/threat-detection.md) - Deep dive into detection
- [Event System](../user-guide/events.md) - Real-time monitoring
- [Custom Feeds](../examples/custom-feeds.md) - Add your own data sources

## Common Use Cases

### Security Monitoring

```javascript
const trojan = new TrojanHorse({
  sources: ['urlhaus', 'alienvault', 'abuseipdb'],
  strategy: 'aggressive',
  events: {
    threatFound: (threat) => {
      console.log(`🚨 Threat detected: ${threat.indicator}`);
      // Send alert, log to SIEM, etc.
    }
  }
});

// Monitor specific targets
await trojan.scout('company-domain.com');
```

### Batch Processing

```javascript
const domains = ['site1.com', 'site2.com', 'site3.com'];

for (const domain of domains) {
  const threats = await trojan.scout(domain);
  if (threats.length > 0) {
    console.log(`${domain}: ${threats.length} threats found`);
  }
}
```

### API Integration

```javascript
// Express.js endpoint
app.post('/api/threat-check', async (req, res) => {
  try {
    const threats = await trojan.scout(req.body.target);
    res.json({
      safe: threats.length === 0,
      threatCount: threats.length,
      threats: threats.slice(0, 5) // Limit response size
    });
  } catch (error) {
    res.status(500).json({ error: 'Threat check failed' });
  }
});
```

## Troubleshooting

### Common Issues

**Build Errors**
```bash
# Clear cache and reinstall
npm cache clean --force
rm -rf node_modules package-lock.json
npm install
```

**Browser CORS Issues**
- Use demo mode for development: `demoMode: true`
- Set up CORS proxy for production
- Consider backend API approach

**API Rate Limits**
- Enable caching: `caching: { enabled: true }`
- Use circuit breakers: `resilience: { enabled: true }`
- Implement request throttling

### Getting Help

- 📖 [Full Documentation](../index.md)
- 🐛 [GitHub Issues](https://github.com/sc4rfurry/TrojanHorse.js/issues)
- 💬 [Community Discussions](https://github.com/sc4rfurry/TrojanHorse.js/discussions)
- 🚀 [Enterprise Support](mailto:enterprise@trojanhorse-js.com)

---

**Ready to dive deeper?** Check out our [Configuration Guide](../user-guide/configuration.md) for advanced settings and optimization.
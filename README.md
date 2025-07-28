# 🏰 TrojanHorse.js

<div align="center">

[![npm version](https://badge.fury.io/js/trojanhorse-js.svg)](https://badge.fury.io/js/trojanhorse-js)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-007ACC?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Security](https://img.shields.io/badge/Security-First-green)](https://github.com/sc4rfurry/TrojanHorse.js)

**The only Trojan you actually want in your system**

*A comprehensive, enterprise-grade JavaScript library for threat intelligence aggregation, analysis, and automation. Built with security-first principles and designed for production environments.*

[**📚 Documentation**](https://trojanhorse-js.readthedocs.io) • [**🚀 Quick Start**](#quick-start) • [**🔧 API Reference**](./API_DOCUMENTATION.md) • [**💼 Enterprise**](#enterprise-features)

</div>

---

## ✨ Features

### 🛡️ **Enterprise Threat Intelligence**
- **Multi-Source Aggregation**: URLhaus, AlienVault OTX, AbuseIPDB, CrowdSec CTI, VirusTotal
- **Real-Time Correlation**: Advanced cross-feed validation and confidence scoring
- **Pattern Detection**: ML-powered behavioral and temporal threat analysis
- **Risk Assessment**: Composite scoring with geolocation and reputation analysis

### 🔒 **Production Security**
- **Zero-Knowledge Storage**: AES-256-GCM encryption with Argon2id key derivation
- **Secure API Key Vault**: Auto-lock, rotation, and secure memory management
- **Enterprise Authentication**: OAuth2, SAML, LDAP, MFA, and RBAC support
- **Audit Logging**: Comprehensive security event tracking with PII masking

### 🌐 **Universal Deployment**
- **Multi-Platform**: Node.js, Browser (Static Sites), REST API, CLI Tool
- **Container Ready**: Docker, Kubernetes, Helm charts included
- **CDN Optimized**: UMD, ES Modules, IIFE builds with polyfills
- **Enterprise Integration**: SIEM connectors (Splunk, QRadar, Elastic)

### 🚀 **High Performance**
- **Stream Processing**: Memory-efficient handling of large datasets (GB+)
- **Worker Pools**: Parallel processing with automatic load balancing
- **Circuit Breakers**: Resilient external API integration
- **Smart Caching**: Intelligent TTL with encryption at rest

---

## 🚀 Quick Start

### Installation

```bash
# NPM
npm install trojanhorse-js

# Yarn
yarn add trojanhorse-js

# CDN (Browser)
<script src="https://unpkg.com/trojanhorse-js@latest/dist/trojanhorse.browser.min.js"></script>
```

### Basic Usage

```javascript
import { TrojanHorse } from 'trojanhorse-js';

// Initialize with basic configuration
const trojan = new TrojanHorse({
  sources: ['urlhaus', 'alienvault'],
  strategy: 'defensive'
});

// Scan for threats
const threats = await trojan.scout('suspicious-domain.com');
console.log(`Found ${threats.length} threats`);

// Create secure vault for API keys
const { vault } = await trojan.createVault('strong-password', {
  alienVault: 'your-api-key',
  abuseipdb: 'your-api-key'
});
```

### Enterprise Setup

```javascript
import { TrojanHorse, SIEMManager } from 'trojanhorse-js';

// Enterprise configuration
const trojan = new TrojanHorse({
  vault: {
    algorithm: 'AES-256-GCM',
    keyDerivation: 'Argon2id',
    autoLock: true,
    lockTimeout: 300000
  },
  security: {
    mode: 'enhanced',
    httpsOnly: true,
    certificatePinning: true,
    auditLogging: true
  }
});

// SIEM Integration
const siem = new SIEMManager();
siem.addConnector('splunk', {
  type: 'splunk',
  endpoint: 'https://splunk.company.com:8088',
  apiKey: process.env.SPLUNK_HEC_TOKEN
});

// Real-time threat monitoring
trojan.on('threat:detected', async (threat) => {
  await siem.sendEvent({
    timestamp: new Date(),
    source: 'TrojanHorse.js',
    eventType: 'threat_detected',
    severity: threat.severity,
    data: threat
  });
});
```

---

## 📖 Documentation

### Core Concepts

- **[Architecture Overview](./docs/architecture.md)** - System design and components
- **[Security Model](./SECURITY.md)** - Cryptographic implementation details
- **[API Reference](./API_DOCUMENTATION.md)** - Complete API documentation
- **[Configuration Guide](./docs/configuration.md)** - Advanced configuration options

### Deployment Guides

- **[Production Deployment](./PRODUCTION_DEPLOYMENT.md)** - Enterprise deployment strategies
- **[Docker & Kubernetes](./docs/containers.md)** - Container orchestration
- **[Browser Integration](./BROWSER_USAGE.md)** - Static site implementation
- **[CLI Usage](./docs/cli.md)** - Command-line interface guide

### Integration Examples

- **[SIEM Integration](./examples/siem-integration.js)** - Splunk, QRadar, Elastic
- **[Webhook Automation](./examples/webhook-automation.js)** - Real-time notifications
- **[Custom Feeds](./examples/custom-feed.js)** - Building custom threat feeds
- **[Stream Processing](./examples/large-dataset.js)** - Processing large files

---

## 💼 Enterprise Features

### Authentication & Authorization
```javascript
// OAuth2/SAML Enterprise SSO
const auth = new EnterpriseAuth({
  oauth2: {
    provider: 'microsoft',
    clientId: process.env.AZURE_CLIENT_ID,
    clientSecret: process.env.AZURE_CLIENT_SECRET
  },
  mfa: { enabled: true, issuer: 'YourCompany' },
  rbac: {
    roles: [
      { name: 'analyst', permissions: ['threat:read', 'export:basic'] },
      { name: 'admin', permissions: ['*'] }
    ]
  }
});
```

### Real-Time Analytics
```javascript
// Enterprise monitoring dashboard
const analytics = new RealTimeAnalytics({
  notifications: [
    { type: 'email', config: { smtp: {...}, to: 'security@company.com' } },
    { type: 'slack', config: { webhook: process.env.SLACK_WEBHOOK } },
    { type: 'pagerduty', config: { serviceKey: process.env.PD_SERVICE_KEY } }
  ]
});

analytics.createAlert({
  title: 'High-Risk Domain Detected',
  severity: 'critical',
  category: 'security',
  description: 'Domain shows indicators of active C2 infrastructure'
});
```

### High-Performance Processing
```javascript
// Process large threat feeds (GB+ files)
const processor = new StreamingProcessor({
  chunkSize: 1024 * 1024, // 1MB chunks
  maxConcurrency: 8,
  workerPoolSize: 4
});

const results = await processor.processStream(
  fs.createReadStream('large-threat-feed.csv'),
  'csv'
);
```

---

## 🔧 API Reference

### Core Methods

| Method | Description | Parameters | Return Type |
|--------|-------------|------------|-------------|
| `scout(target?, options?)` | Analyze target for threats | `target: string`, `options: ScoutOptions` | `Promise<ThreatIndicator[]>` |
| `createVault(password, keys)` | Create encrypted API key vault | `password: string`, `keys: ApiKeyConfig` | `Promise<EncryptedVault>` |
| `unlock(password)` | Unlock existing vault | `password: string` | `Promise<void>` |
| `plunder(format?, options?)` | Export threat intelligence | `format: 'json'\|'csv'\|'stix'` | `Promise<string>` |

### Configuration Options

```typescript
interface TrojanHorseConfig {
  apiKeys?: ApiKeyConfig;
  sources?: string[];
  strategy?: 'defensive' | 'balanced' | 'aggressive' | 'fort-knox';
  vault?: SecureVaultOptions;
  security?: SecurityConfig;
  audit?: AuditConfig;
}
```

### Event System

```javascript
// Subscribe to events
trojan.on('threat:detected', (threat) => { ... });
trojan.on('vault:locked', () => { ... });
trojan.on('feed:updated', (source, count) => { ... });
trojan.on('security:alert', (alert) => { ... });
```

---

## 🛠️ Development

### Prerequisites

- Node.js 16+ or modern browser
- TypeScript 4.5+
- Docker (for containerized development)

### Building from Source

```bash
# Clone repository
git clone https://github.com/sc4rfurry/TrojanHorse.js.git
cd trojanhorse-js

# Install dependencies
npm install

# Build all targets
npm run build:all

# Run tests
npm test

# Start development server
npm run dev:api
```

### Testing

```bash
# Unit tests
npm test

# Integration tests
npm run test:integration

# Security tests
npm run test:security

# Performance benchmarks
npm run performance:benchmark
```

### CLI Development

```bash
# Interactive setup
npm run setup

# CLI operations
npm run cli -- threat check example.com
npm run cli -- vault create
npm run cli -- monitor status
```

---

## 📊 Performance

### Benchmarks

| Operation | Performance | Memory Usage |
|-----------|-------------|--------------|
| Single threat lookup | ~250ms | <10MB |
| Batch processing (1000 items) | ~15s | <50MB |
| Large file processing (1GB) | ~5min | <100MB |
| Vault operations | ~50ms | <5MB |

### Scalability

- **Concurrent Requests**: 1000+ simultaneous API calls
- **Data Processing**: Multi-GB threat feeds with streaming
- **Memory Efficiency**: Constant memory usage regardless of dataset size
- **Network Resilience**: Circuit breakers and exponential backoff

---

## 🔒 Security

### Cryptographic Standards

- **Encryption**: AES-256-GCM (NIST approved)
- **Key Derivation**: Argon2id (password hashing competition winner)
- **Random Generation**: Cryptographically secure (Web Crypto API / Node.js crypto)
- **Memory Protection**: Secure memory cleanup and erasure

### Compliance

- **OWASP Top 10**: Comprehensive protection against web vulnerabilities
- **SOC 2 Type II**: Security controls and monitoring
- **ISO 27001**: Information security management
- **GDPR**: Privacy by design with PII masking

### Security Reporting

Found a security vulnerability? Please report it responsibly:
- **Email**: security@trojanhorse-js.com
- **PGP**: [Public Key](./security-pgp-key.asc)
- **Bug Bounty**: [HackerOne Program](https://hackerone.com/trojanhorse-js)

---

## 🌟 Examples

### Basic Threat Detection

```javascript
import { TrojanHorse } from 'trojanhorse-js';

const trojan = new TrojanHorse({
  sources: ['urlhaus', 'alienvault']
});

// Check single target
const threats = await trojan.scout('malicious-domain.com');
console.log(`Threat score: ${threats[0]?.confidence || 0}`);

// Batch analysis
const targets = ['domain1.com', 'domain2.com', '192.168.1.100'];
const results = await Promise.all(
  targets.map(target => trojan.scout(target))
);
```

### Secure API Key Management

```javascript
// Create encrypted vault
const { vault, trojan } = await createVault('secure-password-123!', {
  alienVault: 'your-alienvault-api-key',
  abuseipdb: 'your-abuseipdb-api-key',
  virustotal: 'your-virustotal-api-key'
});

// Save vault to file
fs.writeFileSync('secure-vault.json', JSON.stringify(vault));

// Later, load and unlock
const savedVault = JSON.parse(fs.readFileSync('secure-vault.json'));
trojan.loadVault(savedVault);
await trojan.unlock('secure-password-123!');
```

### Browser Integration

```html
<!DOCTYPE html>
<html>
<head>
    <title>Threat Intelligence Dashboard</title>
    <script src="https://unpkg.com/trojanhorse-js@latest/dist/trojanhorse.browser.min.js"></script>
</head>
<body>
    <script>
        const trojan = new TrojanHorse({ sources: ['urlhaus'] });
        
        async function checkThreat(domain) {
            const threats = await trojan.scout(domain);
            document.getElementById('results').innerHTML = 
                `Found ${threats.length} threats for ${domain}`;
        }
    </script>
</body>
</html>
```

---

## 📦 Distribution

### Package Formats

| Format | File | Use Case |
|--------|------|-----------|
| ES Module | `dist/trojanhorse.esm.js` | Modern bundlers (Webpack, Rollup) |
| CommonJS | `dist/trojanhorse.js` | Node.js applications |
| UMD | `dist/trojanhorse.umd.js` | Universal module definition |
| Browser | `dist/trojanhorse.browser.min.js` | CDN, static sites |
| TypeScript | `dist/types/` | Type definitions |

### CDN Links

```html
<!-- Latest version -->
<script src="https://unpkg.com/trojanhorse-js@latest/dist/trojanhorse.browser.min.js"></script>

<!-- Specific version -->
<script src="https://unpkg.com/trojanhorse-js@1.0.0/dist/trojanhorse.browser.min.js"></script>

<!-- ES Module -->
<script type="module">
  import { TrojanHorse } from 'https://unpkg.com/trojanhorse-js@latest/dist/trojanhorse.browser.esm.js';
</script>
```

---

## 🤝 Contributing

We welcome contributions! Please read our [Contributing Guide](./CONTRIBUTING.md) for details.

### Development Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Style

- **TypeScript**: Strict mode enabled
- **ESLint**: Airbnb configuration with security rules
- **Prettier**: Consistent code formatting
- **Tests**: Jest with >90% coverage requirement

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **URLhaus** by Abuse.ch for free malicious URL feeds
- **AlienVault OTX** for open threat intelligence
- **Node.js Security Working Group** for crypto guidance
- **OWASP** for security best practices

---

## 📞 Support

### Community

- **GitHub Issues**: [Bug reports and feature requests](https://github.com/sc4rfurry/TrojanHorse.js/issues)
- **Discussions**: [Community Q&A](https://github.com/sc4rfurry/TrojanHorse.js/discussions)
- **Discord**: [Real-time chat](https://discord.gg/trojanhorse-js)

### Enterprise Support

- **Commercial License**: Available for enterprise customers
- **Professional Services**: Implementation and consulting
- **SLA Support**: 24/7 enterprise support available
- **Contact**: [enterprise@trojanhorse-js.com](mailto:enterprise@trojanhorse-js.com)

---

<div align="center">

**Built with ❤️ for the cybersecurity community**

[⭐ Star on GitHub](https://github.com/sc4rfurry/TrojanHorse.js) • [📖 Read the Docs](https://trojanhorse-js.readthedocs.io) • [🐦 Follow Updates](https://twitter.com/trojanhorse_js)

</div> 

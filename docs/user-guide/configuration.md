# Configuration Guide

Complete guide to configuring TrojanHorse.js for your specific use case, from basic setups to enterprise deployments.

## Configuration Methods

### 1. Constructor Configuration

```javascript
import { TrojanHorse } from 'trojanhorse-js';

const trojan = new TrojanHorse({
  // Basic configuration
  sources: ['urlhaus', 'alienvault'],
  strategy: 'defensive',
  
  // API keys
  apiKeys: {
    alienVault: 'your-api-key',
    abuseipdb: 'your-api-key'
  },
  
  // Security settings
  security: {
    enforceHttps: true,
    autoLock: true,
    lockTimeout: 300000 // 5 minutes
  },
  
  // Performance settings
  performance: {
    maxConcurrency: 5,
    requestTimeout: 30000,
    retryAttempts: 3
  }
});
```

### 2. Configuration File

Create `trojanhorse.config.js`:

```javascript
// trojanhorse.config.js
module.exports = {
  // Production configuration
  production: {
    sources: ['urlhaus', 'alienvault', 'abuseipdb', 'virustotal'],
    strategy: 'balanced',
    apiKeys: {
      alienVault: process.env.ALIENVAULT_API_KEY,
      abuseipdb: process.env.ABUSEIPDB_API_KEY,
      virustotal: process.env.VIRUSTOTAL_API_KEY
    },
    security: {
      enforceHttps: true,
      autoLock: true,
      lockTimeout: 600000 // 10 minutes
    },
    performance: {
      maxConcurrency: 10,
      requestTimeout: 45000,
      retryAttempts: 3,
      circuitBreaker: {
        enabled: true,
        failureThreshold: 5,
        resetTimeout: 60000
      }
    },
    caching: {
      enabled: true,
      ttl: 3600000, // 1 hour
      maxSize: 10000
    }
  },
  
  // Development configuration
  development: {
    sources: ['urlhaus'],
    strategy: 'defensive',
    security: {
      enforceHttps: false,
      autoLock: false
    },
    logging: {
      level: 'debug',
      enabled: true
    }
  }
};
```

Load configuration:

```javascript
const config = require('./trojanhorse.config.js');
const trojan = new TrojanHorse(config.production);
```

### 3. Environment Variables

```bash
# .env file
TROJANHORSE_STRATEGY=aggressive
TROJANHORSE_MAX_CONCURRENCY=15
TROJANHORSE_AUTO_LOCK=true
TROJANHORSE_LOCK_TIMEOUT=300000

# API Keys
ALIENVAULT_API_KEY=your-key-here
ABUSEIPDB_API_KEY=your-key-here
VIRUSTOTAL_API_KEY=your-key-here
```

```javascript
import { TrojanHorse } from 'trojanhorse-js';

const trojan = new TrojanHorse({
  strategy: process.env.TROJANHORSE_STRATEGY || 'defensive',
  apiKeys: {
    alienVault: process.env.ALIENVAULT_API_KEY,
    abuseipdb: process.env.ABUSEIPDB_API_KEY,
    virustotal: process.env.VIRUSTOTAL_API_KEY
  },
  performance: {
    maxConcurrency: parseInt(process.env.TROJANHORSE_MAX_CONCURRENCY) || 5
  },
  security: {
    autoLock: process.env.TROJANHORSE_AUTO_LOCK === 'true',
    lockTimeout: parseInt(process.env.TROJANHORSE_LOCK_TIMEOUT) || 300000
  }
});
```

## Configuration Options

### Core Settings

#### Sources
Configure which threat intelligence feeds to use:

```javascript
{
  sources: [
    'urlhaus',     // Malicious URLs (no API key required)
    'alienvault',  // AlienVault OTX (API key required)
    'abuseipdb',   // AbuseIPDB (API key required)
    'crowdsec',    // CrowdSec CTI (API key required)
    'virustotal'   // VirusTotal (API key required)
  ]
}
```

#### Strategy
Detection strategy affects sensitivity and false positive rates:

```javascript
{
  strategy: 'defensive',   // Conservative, fewer false positives
  // strategy: 'balanced',  // Moderate detection
  // strategy: 'aggressive' // Sensitive, more comprehensive
}
```

#### Custom Thresholds
Override strategy defaults:

```javascript
{
  strategy: 'custom',
  thresholds: {
    confidence: 0.7,        // Minimum confidence score (0-1)
    consensus: 2,           // Minimum sources agreeing
    riskScore: 5,          // Minimum risk score (1-10)
    correlationWeight: 0.3 // Weight for cross-source correlation
  }
}
```

### API Key Configuration

#### Basic Configuration

```javascript
{
  apiKeys: {
    alienVault: 'your-api-key',
    abuseipdb: 'your-api-key',
    virustotal: 'your-api-key',
    crowdsec: 'your-api-key'
  }
}
```

#### Advanced API Key Objects

```javascript
{
  apiKeys: {
    alienVault: {
      key: 'your-api-key',
      endpoint: 'https://otx.alienvault.com/api/v1',
      rateLimit: 100, // requests per hour
      timeout: 30000
    },
    abuseipdb: {
      key: 'your-api-key',
      endpoint: 'https://api.abuseipdb.com/api/v2',
      rateLimit: 1000, // requests per day
      categories: [18, 19, 20] // Specific abuse categories
    }
  }
}
```

#### Secure Vault Configuration

```javascript
// Create encrypted vault for API keys
const { trojan, vault } = await TrojanHorse.createVault('secure-password', {
  alienVault: 'your-api-key',
  abuseipdb: 'your-api-key'
}, {
  // Vault configuration
  autoLock: true,
  lockTimeout: 600000, // 10 minutes
  rotationEnabled: true,
  rotationInterval: 24 * 60 * 60 * 1000 // 24 hours
});
```

### Security Configuration

#### Basic Security

```javascript
{
  security: {
    enforceHttps: true,        // Require HTTPS for all requests
    validateCertificates: true, // Validate SSL certificates
    autoLock: true,            // Auto-lock vault
    lockTimeout: 300000,       // Lock after 5 minutes
    enableAuditLog: true       // Log security events
  }
}
```

#### Advanced Security

```javascript
{
  security: {
    // Encryption settings
    encryption: {
      algorithm: 'aes-256-gcm',
      keyDerivation: 'argon2id', // or 'pbkdf2'
      iterations: 100000,
      saltSize: 32,
      tagSize: 16
    },
    
    // Authentication
    authentication: {
      type: 'oauth2', // 'basic', 'oauth2', 'jwt'
      tokenEndpoint: 'https://auth.example.com/token',
      clientId: 'your-client-id',
      scopes: ['threat-intel:read']
    },
    
    // Memory protection
    memoryProtection: {
      secureErase: true,         // Secure memory cleanup
      preventDumps: true,        // Prevent memory dumps
      obfuscateKeys: true        // Obfuscate keys in memory
    }
  }
}
```

### Performance Configuration

#### Concurrency and Timeouts

```javascript
{
  performance: {
    maxConcurrency: 10,        // Max parallel requests
    requestTimeout: 30000,     // 30 second timeout
    retryAttempts: 3,          // Retry failed requests
    retryDelay: 1000,          // Base retry delay (ms)
    backoffMultiplier: 2       // Exponential backoff
  }
}
```

#### Circuit Breakers

```javascript
{
  performance: {
    circuitBreaker: {
      enabled: true,
      failureThreshold: 5,     // Failures before opening
      resetTimeout: 60000,     // Time before retry (ms)
      monitoringWindow: 300000 // Monitoring window (ms)
    }
  }
}
```

#### Rate Limiting

```javascript
{
  performance: {
    rateLimit: {
      enabled: true,
      requestsPerSecond: 10,   // Global rate limit
      burstSize: 20,           // Burst capacity
      
      // Per-feed limits
      feeds: {
        alienvault: { requestsPerHour: 1000 },
        abuseipdb: { requestsPerDay: 1000 },
        virustotal: { requestsPerMinute: 4 }
      }
    }
  }
}
```

### Caching Configuration

#### Memory Caching

```javascript
{
  caching: {
    enabled: true,
    type: 'memory',            // 'memory', 'redis', 'file'
    ttl: 3600000,             // 1 hour TTL
    maxSize: 10000,           // Max cached items
    compression: true         // Compress cached data
  }
}
```

#### Redis Caching

```javascript
{
  caching: {
    enabled: true,
    type: 'redis',
    redis: {
      host: 'localhost',
      port: 6379,
      password: 'your-password',
      db: 0,
      keyPrefix: 'trojanhorse:'
    },
    ttl: 7200000,             // 2 hour TTL
    compression: true
  }
}
```

#### File System Caching

```javascript
{
  caching: {
    enabled: true,
    type: 'file',
    filesystem: {
      directory: './cache',
      maxSize: '100MB',
      cleanupInterval: 3600000 // Cleanup every hour
    },
    ttl: 1800000              // 30 minute TTL
  }
}
```

### Event Configuration

#### Basic Events

```javascript
{
  events: {
    threatFound: (threat) => {
      console.log('🚨 Threat detected:', threat.indicator);
    },
    
    feedError: (error, feed) => {
      console.error(`Feed ${feed} error:`, error.message);
    },
    
    vaultLocked: () => {
      console.log('🔒 Vault auto-locked');
    }
  }
}
```

#### Advanced Event Handling

```javascript
{
  events: {
    // Real-time threat monitoring
    threatFound: async (threat) => {
      // Send to SIEM
      await sendToSIEM(threat);
      
      // Send alert
      if (threat.severity >= 7) {
        await sendAlert(threat);
      }
      
      // Log to database
      await logThreat(threat);
    },
    
    // Performance monitoring
    requestComplete: (duration, feed) => {
      metrics.recordLatency(feed, duration);
    },
    
    // Error handling
    feedError: async (error, feed) => {
      await errorTracker.record({
        source: feed,
        error: error.message,
        timestamp: new Date(),
        context: error.context
      });
    }
  }
}
```

### Browser-Specific Configuration

#### CORS and Proxy

```javascript
{
  // Browser configuration
  browser: {
    corsProxy: 'https://your-proxy.com',
    fallbackMode: 'demo',     // 'demo', 'offline', 'error'
    secureContext: true       // Require secure context
  },
  
  // Storage configuration
  storage: {
    type: 'indexeddb',        // 'indexeddb', 'localstorage', 'memory'
    dbName: 'trojanhorse-cache',
    version: 1,
    encryptionKey: 'user-key'
  }
}
```

#### Progressive Web App

```javascript
{
  pwa: {
    enabled: true,
    cacheStrategy: 'cache-first', // 'cache-first', 'network-first'
    offlineData: true,            // Cache threat data for offline use
    syncOnReconnect: true         // Sync when back online
  }
}
```

### Logging Configuration

#### Console Logging

```javascript
{
  logging: {
    enabled: true,
    level: 'info',            // 'debug', 'info', 'warn', 'error'
    format: 'json',           // 'json', 'text', 'structured'
    
    // Log filtering
    filters: {
      excludeFeeds: ['urlhaus'], // Don't log URLhaus operations
      includeOnly: ['security', 'errors']
    }
  }
}
```

#### File Logging

```javascript
{
  logging: {
    enabled: true,
    level: 'info',
    transports: [
      {
        type: 'file',
        filename: './logs/trojanhorse.log',
        maxSize: '10MB',
        maxFiles: 5,
        compress: true
      },
      {
        type: 'file',
        filename: './logs/security.log',
        level: 'warn',
        filter: (log) => log.category === 'security'
      }
    ]
  }
}
```

#### External Logging

```javascript
{
  logging: {
    enabled: true,
    transports: [
      {
        type: 'webhook',
        url: 'https://your-log-service.com/webhook',
        headers: {
          'Authorization': 'Bearer your-token'
        },
        batchSize: 100,
        flushInterval: 30000
      },
      {
        type: 'syslog',
        host: 'syslog.example.com',
        port: 514,
        facility: 'user',
        protocol: 'udp'
      }
    ]
  }
}
```

## Configuration Profiles

### Development Profile

```javascript
// config/development.js
module.exports = {
  sources: ['urlhaus'], // Free source only
  strategy: 'defensive',
  
  security: {
    enforceHttps: false,
    autoLock: false
  },
  
  logging: {
    level: 'debug',
    enabled: true
  },
  
  performance: {
    maxConcurrency: 2,
    requestTimeout: 10000
  },
  
  caching: {
    enabled: false // Disable for fresh data
  }
};
```

### Production Profile

```javascript
// config/production.js
module.exports = {
  sources: ['urlhaus', 'alienvault', 'abuseipdb', 'virustotal'],
  strategy: 'balanced',
  
  apiKeys: {
    alienVault: process.env.ALIENVAULT_API_KEY,
    abuseipdb: process.env.ABUSEIPDB_API_KEY,
    virustotal: process.env.VIRUSTOTAL_API_KEY
  },
  
  security: {
    enforceHttps: true,
    autoLock: true,
    lockTimeout: 600000,
    enableAuditLog: true
  },
  
  performance: {
    maxConcurrency: 15,
    requestTimeout: 45000,
    retryAttempts: 3,
    circuitBreaker: {
      enabled: true,
      failureThreshold: 5
    }
  },
  
  caching: {
    enabled: true,
    type: 'redis',
    ttl: 3600000
  },
  
  logging: {
    level: 'info',
    transports: [
      { type: 'file', filename: './logs/app.log' },
      { type: 'syslog', host: 'logs.example.com' }
    ]
  }
};
```

### Enterprise Profile

```javascript
// config/enterprise.js
module.exports = {
  sources: ['urlhaus', 'alienvault', 'abuseipdb', 'virustotal', 'crowdsec'],
  strategy: 'custom',
  
  thresholds: {
    confidence: 0.6,
    consensus: 3,
    riskScore: 4
  },
  
  security: {
    encryption: {
      algorithm: 'aes-256-gcm',
      keyDerivation: 'argon2id'
    },
    authentication: {
      type: 'oauth2',
      tokenEndpoint: process.env.AUTH_ENDPOINT
    },
    memoryProtection: {
      secureErase: true,
      preventDumps: true
    }
  },
  
  performance: {
    maxConcurrency: 25,
    circuitBreaker: { enabled: true },
    rateLimit: {
      enabled: true,
      requestsPerSecond: 20
    }
  },
  
  enterprise: {
    siemIntegration: {
      enabled: true,
      endpoint: process.env.SIEM_ENDPOINT,
      format: 'cef' // 'json', 'cef', 'leef'
    },
    
    streamProcessing: {
      enabled: true,
      batchSize: 1000,
      flushInterval: 5000
    },
    
    monitoring: {
      healthChecks: true,
      metrics: true,
      alerts: {
        email: process.env.ALERT_EMAIL,
        webhook: process.env.ALERT_WEBHOOK
      }
    }
  }
};
```

## Configuration Validation

### Schema Validation

```javascript
import Joi from 'joi';

const configSchema = Joi.object({
  sources: Joi.array().items(
    Joi.string().valid('urlhaus', 'alienvault', 'abuseipdb', 'virustotal', 'crowdsec')
  ).required(),
  
  strategy: Joi.string().valid('defensive', 'balanced', 'aggressive', 'custom').default('defensive'),
  
  apiKeys: Joi.object().pattern(
    Joi.string(),
    Joi.alternatives().try(
      Joi.string(),
      Joi.object({
        key: Joi.string().required(),
        endpoint: Joi.string().uri(),
        rateLimit: Joi.number().positive(),
        timeout: Joi.number().positive()
      })
    )
  ),
  
  security: Joi.object({
    enforceHttps: Joi.boolean().default(true),
    autoLock: Joi.boolean().default(true),
    lockTimeout: Joi.number().positive().default(300000)
  }),
  
  performance: Joi.object({
    maxConcurrency: Joi.number().positive().max(50).default(10),
    requestTimeout: Joi.number().positive().default(30000),
    retryAttempts: Joi.number().min(0).max(10).default(3)
  })
});

// Validate configuration
const { error, value } = configSchema.validate(config);
if (error) {
  throw new Error(`Configuration invalid: ${error.message}`);
}
```

### Runtime Validation

```javascript
class ConfigValidator {
  static validateApiKeys(config) {
    const requiredKeys = {
      'alienvault': 'AlienVault OTX',
      'abuseipdb': 'AbuseIPDB',
      'virustotal': 'VirusTotal',
      'crowdsec': 'CrowdSec'
    };
    
    for (const source of config.sources) {
      if (requiredKeys[source] && !config.apiKeys?.[source]) {
        console.warn(`⚠️  ${requiredKeys[source]} requires an API key`);
      }
    }
  }
  
  static validatePerformance(config) {
    if (config.performance?.maxConcurrency > 20) {
      console.warn('⚠️  High concurrency may trigger rate limits');
    }
    
    if (config.performance?.requestTimeout < 10000) {
      console.warn('⚠️  Low timeout may cause failures');
    }
  }
  
  static validateSecurity(config) {
    if (!config.security?.enforceHttps) {
      console.warn('⚠️  HTTPS enforcement disabled - security risk');
    }
    
    if (!config.security?.autoLock) {
      console.warn('⚠️  Auto-lock disabled - security risk');
    }
  }
}

// Use validator
ConfigValidator.validateApiKeys(config);
ConfigValidator.validatePerformance(config);
ConfigValidator.validateSecurity(config);
```

## Configuration Management

### Environment-Based Loading

```javascript
// config/index.js
const environment = process.env.NODE_ENV || 'development';

const configs = {
  development: require('./development'),
  staging: require('./staging'),
  production: require('./production')
};

const baseConfig = require('./base');
const envConfig = configs[environment];

module.exports = {
  ...baseConfig,
  ...envConfig,
  environment
};
```

### Dynamic Configuration

```javascript
class ConfigManager {
  constructor(initialConfig) {
    this.config = initialConfig;
    this.watchers = [];
  }
  
  // Watch for configuration changes
  watch(callback) {
    this.watchers.push(callback);
  }
  
  // Update configuration at runtime
  update(newConfig) {
    const oldConfig = { ...this.config };
    this.config = { ...this.config, ...newConfig };
    
    // Notify watchers
    this.watchers.forEach(callback => {
      callback(this.config, oldConfig);
    });
  }
  
  // Get current configuration
  get() {
    return { ...this.config };
  }
}

// Usage
const configManager = new ConfigManager(initialConfig);

const trojan = new TrojanHorse(configManager.get());

// Update configuration dynamically
configManager.watch((newConfig, oldConfig) => {
  if (newConfig.performance?.maxConcurrency !== oldConfig.performance?.maxConcurrency) {
    trojan.updateConcurrency(newConfig.performance.maxConcurrency);
  }
});
```

## Best Practices

### Security
- Always use HTTPS in production
- Enable auto-lock for vaults
- Use strong passwords for encryption
- Regularly rotate API keys
- Enable audit logging

### Performance
- Start with conservative concurrency limits
- Enable caching for production
- Use circuit breakers for resilience
- Monitor rate limits and adjust accordingly
- Implement proper retry strategies

### Monitoring
- Enable comprehensive logging
- Set up health checks
- Monitor API key usage
- Track performance metrics
- Configure alerts for failures

### Development
- Use demo mode for testing
- Disable HTTPS for local development
- Enable debug logging
- Use separate API keys for testing
- Document configuration changes

## Troubleshooting

### Common Configuration Issues

**Invalid API Keys**
```javascript
// Add key validation
const trojan = new TrojanHorse({
  apiKeys: { alienVault: 'invalid-key' },
  events: {
    feedError: (error, feed) => {
      if (error.message.includes('401')) {
        console.error(`Invalid API key for ${feed}`);
      }
    }
  }
});
```

**Rate Limit Exceeded**
```javascript
// Implement backoff strategy
const trojan = new TrojanHorse({
  performance: {
    retryAttempts: 5,
    retryDelay: 2000,
    backoffMultiplier: 2
  },
  events: {
    rateLimited: (feed) => {
      console.warn(`Rate limited on ${feed}, backing off...`);
    }
  }
});
```

**Memory Issues**
```javascript
// Enable garbage collection hints
const trojan = new TrojanHorse({
  caching: {
    maxSize: 5000,  // Reduce cache size
    ttl: 1800000    // Shorter TTL
  },
  events: {
    cacheEvicted: () => {
      if (global.gc) global.gc(); // Force GC if available
    }
  }
});
```

## Next Steps

- **[Threat Detection Guide](threat-detection.md)** - Configure detection strategies
- **[Vault Management](vault-management.md)** - Secure API key handling
- **[Event System](events.md)** - Real-time monitoring setup
- **[Production Deployment](../deployment/production.md)** - Deploy with proper configuration

---

**Need help with configuration?** Check our [examples](../examples/basic.md) or join the [community discussions](https://github.com/sc4rfurry/TrojanHorse.js/discussions).
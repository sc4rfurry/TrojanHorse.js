# Core API Reference

Complete API reference for TrojanHorse.js core functionality, including classes, methods, types, and examples.

## TrojanHorse Class

The main class providing threat intelligence aggregation and analysis capabilities.

### Constructor

```typescript
new TrojanHorse(config: TrojanHorseConfig)
```

Creates a new TrojanHorse instance with the specified configuration.

**Parameters:**
- `config` (TrojanHorseConfig): Configuration object

**Example:**
```javascript
import { TrojanHorse } from 'trojanhorse-js';

const trojan = new TrojanHorse({
  sources: ['urlhaus', 'alienvault'],
  strategy: 'defensive',
  apiKeys: {
    alienVault: 'your-api-key'
  }
});
```

### Methods

#### scout(target, options?)

Performs threat intelligence analysis on a target.

```typescript
async scout(target: string, options?: ScoutOptions): Promise<ThreatIndicator[]>
```

**Parameters:**
- `target` (string): The target to analyze (domain, URL, IP, hash)
- `options` (ScoutOptions, optional): Additional options

**Returns:**
- Promise<ThreatIndicator[]>: Array of threat indicators found

**Example:**
```javascript
const threats = await trojan.scout('suspicious-domain.com');
console.log(`Found ${threats.length} threats`);

// With options
const threats = await trojan.scout('malware.exe', {
  type: 'hash',
  includeMetadata: true,
  timeout: 10000
});
```

**ScoutOptions:**
```typescript
interface ScoutOptions {
  type?: 'auto' | 'domain' | 'url' | 'ip' | 'hash' | 'email';
  includeMetadata?: boolean;
  timeout?: number;
  sources?: string[];
  strategy?: 'defensive' | 'balanced' | 'aggressive';
}
```

#### plunder(format, options?)

Exports threat intelligence data in various formats.

```typescript
async plunder(format: 'json' | 'csv' | 'xml' | 'stix', options?: PlunderOptions): Promise<any>
```

**Parameters:**
- `format` (string): Export format ('json', 'csv', 'xml', 'stix')
- `options` (PlunderOptions, optional): Export options

**Returns:**
- Promise<any>: Exported data in specified format

**Example:**
```javascript
// Export as JSON
const jsonData = await trojan.plunder('json');

// Export as CSV with filtering
const csvData = await trojan.plunder('csv', {
  filter: {
    severity: { min: 5 },
    sources: ['urlhaus', 'alienvault']
  },
  limit: 1000
});
```

**PlunderOptions:**
```typescript
interface PlunderOptions {
  filter?: {
    severity?: { min?: number; max?: number };
    confidence?: { min?: number; max?: number };
    sources?: string[];
    dateRange?: { start?: Date; end?: Date };
    types?: string[];
  };
  limit?: number;
  offset?: number;
  includeMetadata?: boolean;
  compression?: boolean;
}
```

#### clearCache()

Clears the internal threat intelligence cache.

```typescript
async clearCache(): Promise<void>
```

**Example:**
```javascript
await trojan.clearCache();
console.log('Cache cleared');
```

#### getCacheStats()

Returns cache statistics and information.

```typescript
async getCacheStats(): Promise<CacheStats>
```

**Returns:**
- Promise<CacheStats>: Cache statistics

**Example:**
```javascript
const stats = await trojan.getCacheStats();
console.log(`Cache entries: ${stats.count}, Size: ${stats.size}`);
```

**CacheStats:**
```typescript
interface CacheStats {
  count: number;
  size: number;
  hitRate: number;
  missRate: number;
  evictionCount: number;
  oldestEntry: Date;
  newestEntry: Date;
}
```

#### updateConfiguration(config)

Updates the configuration at runtime.

```typescript
updateConfiguration(config: Partial<TrojanHorseConfig>): void
```

**Parameters:**
- `config` (Partial<TrojanHorseConfig>): Configuration updates

**Example:**
```javascript
trojan.updateConfiguration({
  performance: {
    maxConcurrency: 15
  },
  strategy: 'aggressive'
});
```

#### getHealth()

Returns health status of all components.

```typescript
async getHealth(): Promise<HealthStatus>
```

**Returns:**
- Promise<HealthStatus>: Health status information

**Example:**
```javascript
const health = await trojan.getHealth();
console.log('System health:', health.overall);
console.log('Feed statuses:', health.feeds);
```

**HealthStatus:**
```typescript
interface HealthStatus {
  overall: 'healthy' | 'degraded' | 'unhealthy';
  feeds: Record<string, FeedHealth>;
  vault: VaultHealth;
  cache: CacheHealth;
  uptime: number;
  version: string;
}

interface FeedHealth {
  status: 'operational' | 'degraded' | 'down';
  latency: number;
  errorRate: number;
  lastSuccess: Date;
  rateLimitStatus: {
    remaining: number;
    resetTime: Date;
  };
}
```

### Static Methods

#### createVault(password, apiKeys, options?)

Creates an encrypted vault for secure API key storage.

```typescript
static async createVault(
  password: string, 
  apiKeys: Record<string, string | ApiKeyObject>, 
  options?: VaultOptions
): Promise<{ vault: KeyVault; trojan: TrojanHorse }>
```

**Parameters:**
- `password` (string): Master password for encryption
- `apiKeys` (Record<string, string | ApiKeyObject>): API keys to store
- `options` (VaultOptions, optional): Vault configuration

**Returns:**
- Promise<{ vault: KeyVault; trojan: TrojanHorse }>: Vault and configured TrojanHorse instance

**Example:**
```javascript
const { vault, trojan } = await TrojanHorse.createVault('secure-password', {
  alienVault: 'your-api-key',
  abuseipdb: {
    key: 'your-api-key',
    endpoint: 'https://api.abuseipdb.com/api/v2',
    rateLimit: 1000
  }
}, {
  autoLock: true,
  lockTimeout: 300000
});
```

**VaultOptions:**
```typescript
interface VaultOptions {
  autoLock?: boolean;
  lockTimeout?: number;
  rotationEnabled?: boolean;
  rotationInterval?: number;
  backupEnabled?: boolean;
  compressionEnabled?: boolean;
}
```

#### createLookup(options?)

Creates a simplified lookup interface for basic threat checking.

```typescript
static createLookup(options?: LookupOptions): ThreatLookup
```

**Parameters:**
- `options` (LookupOptions, optional): Lookup configuration

**Returns:**
- ThreatLookup: Simplified lookup interface

**Example:**
```javascript
// Demo mode for development
const lookup = TrojanHorse.createLookup({ demoMode: true });

// Production with proxy
const lookup = TrojanHorse.createLookup({
  proxyUrl: 'https://your-proxy.com',
  apiKeys: { alienVault: 'your-key' }
});
```

**LookupOptions:**
```typescript
interface LookupOptions {
  demoMode?: boolean;
  proxyUrl?: string;
  apiKeys?: Record<string, string>;
  timeout?: number;
  cache?: boolean;
}
```

### Events

TrojanHorse emits events for monitoring and integration.

#### Event Types

```typescript
interface TrojanHorseEvents {
  threatFound: (threat: ThreatIndicator) => void;
  feedError: (error: Error, feedName: string) => void;
  vaultLocked: () => void;
  vaultUnlocked: () => void;
  rateLimited: (feedName: string, resetTime: Date) => void;
  correlationComplete: (result: CorrelationResult) => void;
  cacheHit: (key: string) => void;
  cacheMiss: (key: string) => void;
  requestComplete: (duration: number, feedName: string) => void;
}
```

#### Event Registration

```javascript
const trojan = new TrojanHorse({
  events: {
    threatFound: (threat) => {
      console.log('🚨 Threat detected:', threat.indicator);
      
      // Send to SIEM
      sendToSIEM(threat);
      
      // High severity alerts
      if (threat.severity >= 8) {
        sendAlert(threat);
      }
    },
    
    feedError: (error, feedName) => {
      console.error(`Feed ${feedName} error:`, error.message);
      
      // Log to error tracking
      errorTracker.record({
        service: feedName,
        error: error.message,
        timestamp: new Date()
      });
    },
    
    rateLimited: (feedName, resetTime) => {
      console.warn(`Rate limited on ${feedName}, reset at ${resetTime}`);
      
      // Implement backoff strategy
      scheduleRetry(feedName, resetTime);
    }
  }
});
```

## ThreatLookup Interface

Simplified interface for basic threat checking, returned by `TrojanHorse.createLookup()`.

### Methods

#### checkDomain(domain)

```typescript
async checkDomain(domain: string): Promise<boolean>
```

Checks if a domain is malicious.

**Parameters:**
- `domain` (string): Domain to check

**Returns:**
- Promise<boolean>: true if malicious, false if safe

**Example:**
```javascript
const lookup = TrojanHorse.createLookup({ demoMode: true });
const isMalicious = await lookup.checkDomain('suspicious-site.com');
console.log(isMalicious ? '🚨 Malicious' : '✅ Safe');
```

#### checkIP(ip)

```typescript
async checkIP(ip: string): Promise<boolean>
```

Checks if an IP address is malicious.

**Example:**
```javascript
const isMalicious = await lookup.checkIP('192.0.2.1');
```

#### checkURL(url)

```typescript
async checkURL(url: string): Promise<boolean>
```

Checks if a URL is malicious.

**Example:**
```javascript
const isMalicious = await lookup.checkURL('http://suspicious-site.com/malware.exe');
```

#### checkHash(hash)

```typescript
async checkHash(hash: string): Promise<boolean>
```

Checks if a file hash is malicious.

**Example:**
```javascript
const isMalicious = await lookup.checkHash('d41d8cd98f00b204e9800998ecf8427e');
```

## Type Definitions

### TrojanHorseConfig

Main configuration interface for TrojanHorse.

```typescript
interface TrojanHorseConfig {
  sources: string[];
  strategy: 'defensive' | 'balanced' | 'aggressive' | 'custom';
  apiKeys?: ApiKeyConfig;
  security?: SecurityConfig;
  performance?: PerformanceConfig;
  caching?: CachingConfig;
  logging?: LoggingConfig;
  events?: Partial<TrojanHorseEvents>;
  browser?: BrowserConfig;
  enterprise?: EnterpriseConfig;
}
```

### ApiKeyConfig

Configuration for API keys and authentication.

```typescript
interface ApiKeyConfig {
  [feedName: string]: string | ApiKeyObject;
}

interface ApiKeyObject {
  key: string;
  endpoint?: string;
  rateLimit?: number;
  timeout?: number;
  headers?: Record<string, string>;
  authentication?: {
    type: 'basic' | 'bearer' | 'oauth2';
    username?: string;
    clientId?: string;
    tokenEndpoint?: string;
  };
}
```

### ThreatIndicator

Represents a threat intelligence indicator.

```typescript
interface ThreatIndicator {
  indicator: string;
  type: 'domain' | 'url' | 'ip' | 'hash' | 'email';
  severity: number; // 1-10 scale
  confidence: number; // 0-1 scale
  sources: string[];
  firstSeen: Date;
  lastSeen: Date;
  tags: string[];
  malwareFamily?: string;
  campaignId?: string;
  metadata: {
    correlationScore: number;
    consensusLevel: number;
    riskScore: number;
    geolocation?: {
      country: string;
      region: string;
      city: string;
    };
    networkInfo?: {
      asn: number;
      organization: string;
    };
    [key: string]: any;
  };
}
```

### SecurityConfig

Security-related configuration options.

```typescript
interface SecurityConfig {
  enforceHttps?: boolean;
  validateCertificates?: boolean;
  autoLock?: boolean;
  lockTimeout?: number;
  enableAuditLog?: boolean;
  encryption?: {
    algorithm: string;
    keyDerivation: 'argon2id' | 'pbkdf2';
    iterations?: number;
    saltSize?: number;
    tagSize?: number;
  };
  authentication?: {
    type: 'basic' | 'oauth2' | 'jwt';
    tokenEndpoint?: string;
    clientId?: string;
    scopes?: string[];
  };
  memoryProtection?: {
    secureErase?: boolean;
    preventDumps?: boolean;
    obfuscateKeys?: boolean;
  };
}
```

### PerformanceConfig

Performance and reliability configuration.

```typescript
interface PerformanceConfig {
  maxConcurrency?: number;
  requestTimeout?: number;
  retryAttempts?: number;
  retryDelay?: number;
  backoffMultiplier?: number;
  circuitBreaker?: {
    enabled: boolean;
    failureThreshold: number;
    resetTimeout: number;
    monitoringWindow?: number;
  };
  rateLimit?: {
    enabled: boolean;
    requestsPerSecond?: number;
    burstSize?: number;
    feeds?: Record<string, {
      requestsPerSecond?: number;
      requestsPerMinute?: number;
      requestsPerHour?: number;
      requestsPerDay?: number;
    }>;
  };
}
```

### BrowserConfig

Browser-specific configuration options.

```typescript
interface BrowserConfig {
  corsProxy?: string;
  fallbackMode?: 'demo' | 'offline' | 'error';
  secureContext?: boolean;
  storage?: {
    type: 'indexeddb' | 'localstorage' | 'memory';
    dbName?: string;
    version?: number;
    encryptionKey?: string;
  };
  pwa?: {
    enabled: boolean;
    cacheStrategy: 'cache-first' | 'network-first';
    offlineData: boolean;
    syncOnReconnect: boolean;
  };
}
```

### Error Classes

#### TrojanHorseError

Base error class for all TrojanHorse-related errors.

```typescript
class TrojanHorseError extends Error {
  constructor(message: string, code?: string, context?: any);
  
  readonly code?: string;
  readonly context?: any;
  readonly timestamp: Date;
}
```

#### FeedError

Error specific to threat feed operations.

```typescript
class FeedError extends TrojanHorseError {
  constructor(message: string, feedName: string, statusCode?: number);
  
  readonly feedName: string;
  readonly statusCode?: number;
}
```

#### VaultError

Error specific to vault operations.

```typescript
class VaultError extends TrojanHorseError {
  constructor(message: string, operation: string);
  
  readonly operation: string;
}
```

#### RateLimitError

Error for rate limit violations.

```typescript
class RateLimitError extends FeedError {
  constructor(feedName: string, resetTime: Date, remaining?: number);
  
  readonly resetTime: Date;
  readonly remaining?: number;
}
```

## Usage Examples

### Basic Threat Analysis

```javascript
import { TrojanHorse } from 'trojanhorse-js';

const trojan = new TrojanHorse({
  sources: ['urlhaus', 'alienvault'],
  strategy: 'balanced',
  apiKeys: {
    alienVault: process.env.ALIENVAULT_API_KEY
  }
});

async function analyzeThreat(target) {
  try {
    const threats = await trojan.scout(target);
    
    if (threats.length === 0) {
      console.log('✅ No threats detected');
      return { safe: true };
    }
    
    const highSeverity = threats.filter(t => t.severity >= 7);
    const mediumSeverity = threats.filter(t => t.severity >= 4 && t.severity < 7);
    
    return {
      safe: false,
      total: threats.length,
      high: highSeverity.length,
      medium: mediumSeverity.length,
      threats: threats.slice(0, 5) // Top 5 threats
    };
  } catch (error) {
    console.error('Analysis failed:', error.message);
    throw error;
  }
}

// Usage
analyzeThreat('suspicious-domain.com').then(result => {
  console.log('Analysis result:', result);
});
```

### Batch Processing

```javascript
async function processBatch(targets) {
  const results = [];
  const batchSize = 10;
  
  for (let i = 0; i < targets.length; i += batchSize) {
    const batch = targets.slice(i, i + batchSize);
    
    const promises = batch.map(async (target) => {
      try {
        const threats = await trojan.scout(target);
        return {
          target,
          safe: threats.length === 0,
          threatCount: threats.length,
          highRisk: threats.filter(t => t.severity >= 8).length
        };
      } catch (error) {
        return {
          target,
          error: error.message
        };
      }
    });
    
    const batchResults = await Promise.allSettled(promises);
    results.push(...batchResults.map(r => r.value || r.reason));
    
    // Progress update
    console.log(`Processed ${Math.min(i + batchSize, targets.length)}/${targets.length}`);
  }
  
  return results;
}
```

### Real-time Monitoring

```javascript
class ThreatMonitor {
  constructor(targets) {
    this.targets = targets;
    this.trojan = new TrojanHorse({
      sources: ['urlhaus', 'alienvault', 'abuseipdb'],
      strategy: 'aggressive',
      events: {
        threatFound: this.handleThreat.bind(this),
        feedError: this.handleError.bind(this)
      }
    });
  }
  
  async start() {
    console.log('🚀 Starting threat monitoring...');
    
    while (true) {
      for (const target of this.targets) {
        try {
          await this.trojan.scout(target);
        } catch (error) {
          console.error(`Monitor error for ${target}:`, error.message);
        }
      }
      
      // Wait 5 minutes before next scan
      await new Promise(resolve => setTimeout(resolve, 5 * 60 * 1000));
    }
  }
  
  handleThreat(threat) {
    console.log(`🚨 THREAT DETECTED: ${threat.indicator}`);
    console.log(`   Severity: ${threat.severity}/10`);
    console.log(`   Sources: ${threat.sources.join(', ')}`);
    
    // Send alert for high-severity threats
    if (threat.severity >= 8) {
      this.sendAlert(threat);
    }
  }
  
  handleError(error, feedName) {
    console.error(`Feed ${feedName} error:`, error.message);
  }
  
  async sendAlert(threat) {
    // Implementation for sending alerts
    console.log('📧 Sending high-severity threat alert...');
  }
}

// Usage
const monitor = new ThreatMonitor([
  'company-domain.com',
  'partner-site.com',
  'critical-service.net'
]);
monitor.start();
```

### Enterprise Integration

```javascript
class EnterpriseThreatIntelligence {
  constructor() {
    this.trojan = new TrojanHorse({
      sources: ['urlhaus', 'alienvault', 'abuseipdb', 'virustotal'],
      strategy: 'custom',
      thresholds: {
        confidence: 0.7,
        consensus: 3
      },
      events: {
        threatFound: this.processNewThreat.bind(this),
        correlationComplete: this.updateRiskScores.bind(this)
      }
    });
    
    this.siemConnector = new SIEMConnector();
    this.threatDatabase = new ThreatDatabase();
  }
  
  async processNewThreat(threat) {
    // Store in threat database
    await this.threatDatabase.store(threat);
    
    // Send to SIEM
    await this.siemConnector.send({
      type: 'threat_indicator',
      data: threat,
      timestamp: new Date(),
      source: 'TrojanHorse.js'
    });
    
    // Update risk assessments
    await this.updateAssetRisk(threat);
  }
  
  async updateAssetRisk(threat) {
    // Get affected assets
    const assets = await this.getAffectedAssets(threat.indicator);
    
    for (const asset of assets) {
      const riskIncrease = this.calculateRiskIncrease(threat, asset);
      await this.updateAssetRiskScore(asset.id, riskIncrease);
    }
  }
  
  calculateRiskIncrease(threat, asset) {
    // Risk calculation logic
    const baseThreatScore = threat.severity * threat.confidence;
    const assetCriticality = asset.criticality || 1;
    const exposureLevel = asset.exposure || 1;
    
    return baseThreatScore * assetCriticality * exposureLevel;
  }
}
```

## Migration Guide

### From v0.x to v1.0

```javascript
// v0.x
const trojan = new TrojanHorse(['urlhaus', 'alienvault']);
const result = await trojan.check('domain.com');

// v1.0
const trojan = new TrojanHorse({
  sources: ['urlhaus', 'alienvault'],
  strategy: 'defensive'
});
const result = await trojan.scout('domain.com');
```

### Configuration Changes

```javascript
// Old configuration (v0.x)
const config = {
  feeds: ['urlhaus'],
  apiKey: 'your-key',
  timeout: 30000
};

// New configuration (v1.0)
const config = {
  sources: ['urlhaus'],
  apiKeys: {
    alienVault: 'your-key'
  },
  performance: {
    requestTimeout: 30000
  }
};
```

## Performance Considerations

### Memory Usage

- Enable caching for repeated queries
- Set appropriate cache TTL values
- Use streaming for large exports
- Clear cache periodically in long-running processes

### Rate Limiting

- Respect API rate limits
- Implement exponential backoff
- Use circuit breakers for resilience
- Monitor rate limit status

### Concurrency

- Start with conservative concurrency limits
- Monitor performance and adjust
- Consider feed-specific limits
- Balance throughput with reliability

## Security Best Practices

### API Key Management

- Use encrypted vaults for API keys
- Enable auto-lock features
- Rotate keys regularly
- Use environment variables in production

### Network Security

- Always use HTTPS in production
- Validate SSL certificates
- Implement proper CORS handling
- Use secure headers

### Data Protection

- Enable audit logging
- Implement secure memory cleanup
- Use proper encryption algorithms
- Protect against timing attacks

## Next Steps

- **[Threat Detection Guide](../user-guide/threat-detection.md)** - Advanced detection strategies
- **[Security Reference](security.md)** - Security APIs and best practices
- **[Feeds Reference](feeds.md)** - Individual feed APIs
- **[Browser Integration](../deployment/browser.md)** - Browser-specific usage

---

**Questions about the API?** Check our [examples](../examples/basic.md) or join the [community discussions](https://github.com/sc4rfurry/TrojanHorse.js/discussions).
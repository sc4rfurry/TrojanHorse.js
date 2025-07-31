# Integrations API Reference

TrojanHorse.js provides extensive integration capabilities with external security systems, SIEM platforms, and automation tools.

## SIEM Connectors

### SIEMConnector Class

The `SIEMConnector` class provides unified interfaces for major SIEM platforms.

```javascript
import { SIEMConnector } from 'trojanhorse-js';

const siem = new SIEMConnector({
  platform: 'splunk', // 'splunk', 'qradar', 'elastic', 'sentinel'
  host: 'splunk.company.com',
  port: 8089,
  credentials: {
    username: 'admin',
    password: 'secure_password'
  }
});
```

#### Supported Platforms

| Platform | Status | Features |
|----------|--------|----------|
| **Splunk** | ✅ Production | HTTP Event Collector, Search API |
| **IBM QRadar** | ✅ Production | Offense API, Reference Data |
| **Elastic Stack** | ✅ Production | Elasticsearch, Kibana Integration |
| **Azure Sentinel** | ✅ Production | Log Analytics, Incident API |
| **Chronicle** | 🔄 Beta | Detection Engine, Asset API |

### Methods

#### `sendAlert(alert)`

Send threat intelligence alerts to SIEM platform.

```javascript
const alert = {
  title: 'Malicious Domain Detected',
  severity: 'high',
  description: 'Domain badsite.com flagged by multiple feeds',
  indicators: [{
    type: 'domain',
    value: 'badsite.com',
    confidence: 95
  }],
  timestamp: new Date().toISOString()
};

await siem.sendAlert(alert);
```

#### `createCase(caseData)`

Create investigation cases in SIEM platforms.

```javascript
const caseData = {
  title: 'APT Campaign Investigation',
  description: 'Multiple IOCs linked to APT29',
  priority: 'critical',
  assignee: 'security-team@company.com',
  indicators: threatResults.map(t => ({
    type: t.type,
    value: t.indicator,
    source: t.source
  }))
};

const caseId = await siem.createCase(caseData);
```

#### `enrichIndicator(indicator)`

Enrich indicators with additional context from SIEM.

```javascript
const enriched = await siem.enrichIndicator({
  type: 'ip',
  value: '192.0.2.1'
});

console.log(enriched);
// {
//   indicator: '192.0.2.1',
//   firstSeen: '2025-01-15T10:00:00Z',
//   lastSeen: '2025-01-29T15:30:00Z',
//   associatedEvents: 127,
//   riskScore: 85
// }
```

## Webhook Integration

### WebhookManager Class

Manage incoming and outgoing webhooks for real-time threat intelligence.

```javascript
import { WebhookManager } from 'trojanhorse-js';

const webhooks = new WebhookManager({
  server: {
    port: 3000,
    path: '/webhooks'
  },
  authentication: {
    type: 'hmac',
    secret: 'webhook-secret'
  }
});
```

#### Incoming Webhooks

Handle threat intelligence updates from external sources:

```javascript
// Register webhook handlers
webhooks.on('threat-update', async (data) => {
  console.log('New threat detected:', data.indicator);
  
  // Correlate with existing intelligence
  const correlation = await trojan.correlate(data.indicator);
  
  // Send to SIEM if high confidence
  if (correlation.confidence > 80) {
    await siem.sendAlert({
      title: 'High Confidence Threat',
      indicator: data.indicator,
      correlation: correlation
    });
  }
});

// Start webhook server
await webhooks.start();
```

#### Outgoing Webhooks

Send threat intelligence to external systems:

```javascript
// Configure outgoing webhooks
webhooks.addOutgoing({
  name: 'security-team-slack',
  url: 'https://hooks.slack.com/services/...',
  events: ['high-confidence-threat', 'campaign-detected'],
  headers: {
    'Authorization': 'Bearer slack-token'
  }
});

// Trigger webhook
await webhooks.trigger('high-confidence-threat', {
  indicator: 'malicious-domain.com',
  confidence: 95,
  sources: ['urlhaus', 'alienvault']
});
```

## API Gateway Integration

### REST API Server

Built-in REST API server for integration with external applications.

```javascript
import { APIServer } from 'trojanhorse-js';

const apiServer = new APIServer({
  port: 8080,
  authentication: {
    type: 'bearer',
    tokens: ['api-token-1', 'api-token-2']
  },
  rateLimit: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
  }
});

// Mount TrojanHorse API
apiServer.mount('/api/v1', trojan);

await apiServer.start();
```

#### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/threats/scan` | POST | Scan indicators for threats |
| `/threats/batch` | POST | Batch threat scanning |
| `/feeds/status` | GET | Get feed status and health |
| `/correlate` | POST | Correlate indicators |
| `/alerts` | GET/POST | Manage alerts |

Example API usage:

```bash
# Scan a domain
curl -X POST http://localhost:8080/api/v1/threats/scan \
  -H "Authorization: Bearer api-token-1" \
  -H "Content-Type: application/json" \
  -d '{"indicator": "suspicious-domain.com", "type": "domain"}'
```

## Message Queue Integration

### RabbitMQ Integration

Process threats through message queues for scalable architectures.

```javascript
import { MessageQueueProcessor } from 'trojanhorse-js';

const mqProcessor = new MessageQueueProcessor({
  type: 'rabbitmq',
  connection: 'amqp://localhost:5672',
  queues: {
    incoming: 'threats.incoming',
    processed: 'threats.processed',
    alerts: 'security.alerts'
  }
});

// Process incoming threats
mqProcessor.consume('threats.incoming', async (message) => {
  const { indicator, type } = JSON.parse(message.content);
  
  // Scan with TrojanHorse
  const results = await trojan.scout(indicator);
  
  // Publish results
  await mqProcessor.publish('threats.processed', {
    indicator,
    results,
    processedAt: new Date().toISOString()
  });
});
```

### Apache Kafka Integration

```javascript
const kafkaProcessor = new MessageQueueProcessor({
  type: 'kafka',
  brokers: ['kafka-1:9092', 'kafka-2:9092'],
  topics: {
    threats: 'security.threats',
    alerts: 'security.alerts'
  }
});

// Produce threat events
await kafkaProcessor.produce('security.threats', {
  key: indicator,
  value: {
    indicator,
    threatLevel: 'high',
    sources: results.sources,
    timestamp: Date.now()
  }
});
```

## Database Integration

### MongoDB Integration

Store threat intelligence in MongoDB for persistence and analytics.

```javascript
import { MongoStorage } from 'trojanhorse-js';

const storage = new MongoStorage({
  uri: 'mongodb://localhost:27017',
  database: 'threat_intelligence',
  collections: {
    threats: 'threats',
    campaigns: 'campaigns',
    indicators: 'indicators'
  }
});

// Store threat results
await storage.store('threats', {
  indicator: 'malicious-domain.com',
  results: threatResults,
  scanDate: new Date(),
  ttl: 30 * 24 * 60 * 60 // 30 days
});

// Query historical data
const historicalThreats = await storage.query('threats', {
  'results.confidence': { $gte: 80 },
  scanDate: { 
    $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) 
  }
});
```

### Elasticsearch Integration

Index threat data for advanced search and analytics.

```javascript
import { ElasticsearchStorage } from 'trojanhorse-js';

const esStorage = new ElasticsearchStorage({
  node: 'https://elasticsearch:9200',
  auth: {
    username: 'elastic',
    password: 'password'
  },
  indices: {
    threats: 'threat-intelligence',
    campaigns: 'threat-campaigns'
  }
});

// Index threat data
await esStorage.index('threats', {
  indicator: 'suspicious-ip.com',
  threat_type: 'malware',
  confidence: 92,
  sources: ['urlhaus', 'virustotal'],
  '@timestamp': new Date().toISOString()
});
```

## Cloud Platform Integration

### AWS Integration

Integrate with AWS security services.

```javascript
import { AWSIntegration } from 'trojanhorse-js';

const aws = new AWSIntegration({
  region: 'us-east-1',
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  }
});

// Send to GuardDuty
await aws.guardDuty.createThreatIntelSet({
  name: 'TrojanHorse-IOCs',
  format: 'TXT',
  location: 's3://security-bucket/iocs.txt',
  activate: true
});

// Store in S3
await aws.s3.putObject({
  Bucket: 'threat-intelligence',
  Key: `threats/${Date.now()}.json`,
  Body: JSON.stringify(threatResults)
});
```

### Azure Sentinel Integration

```javascript
import { AzureSentinelIntegration } from 'trojanhorse-js';

const sentinel = new AzureSentinelIntegration({
  subscriptionId: 'subscription-id',
  resourceGroupName: 'security-rg',
  workspaceName: 'sentinel-workspace',
  credentials: defaultAzureCredential
});

// Create custom threat intelligence indicator
await sentinel.createIndicator({
  pattern: "[domain-name:value = 'malicious-domain.com']",
  labels: ['malicious-activity'],
  confidence: 95,
  threatTypes: ['malicious-activity']
});
```

## Custom Integration Framework

### Plugin System

Create custom integrations using the plugin framework.

```javascript
class CustomSIEMIntegration {
  constructor(config) {
    this.config = config;
  }
  
  async sendAlert(alert) {
    // Custom SIEM API implementation
    const response = await fetch(`${this.config.endpoint}/alerts`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.config.token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(alert)
    });
    
    return response.json();
  }
  
  async enrichIndicator(indicator) {
    // Custom enrichment logic
    return {
      indicator: indicator.value,
      enrichment: 'custom data'
    };
  }
}

// Register custom integration
trojan.registerIntegration('custom-siem', CustomSIEMIntegration);
```

## Configuration Examples

### Complete Integration Setup

```javascript
import { TrojanHorse } from 'trojanhorse-js';

const trojan = new TrojanHorse({
  integrations: {
    siem: {
      platform: 'splunk',
      host: 'splunk.company.com',
      credentials: {
        token: process.env.SPLUNK_TOKEN
      }
    },
    webhooks: {
      incoming: {
        port: 3000,
        authentication: {
          type: 'hmac',
          secret: process.env.WEBHOOK_SECRET
        }
      },
      outgoing: [{
        name: 'slack-alerts',
        url: process.env.SLACK_WEBHOOK_URL,
        events: ['high-confidence-threat']
      }]
    },
    storage: {
      type: 'mongodb',
      uri: process.env.MONGODB_URI,
      database: 'threat_intelligence'
    },
    messageQueue: {
      type: 'rabbitmq',
      connection: process.env.RABBITMQ_URL,
      queues: {
        incoming: 'threats.scan',
        processed: 'threats.results'
      }
    }
  }
});

// Start all integrations
await trojan.start();
```

## Best Practices

### Security
- Use encrypted connections for all integrations
- Implement proper authentication and authorization
- Rotate API keys and tokens regularly
- Monitor integration access logs

### Performance
- Implement connection pooling for databases
- Use batch operations where possible
- Configure appropriate timeouts
- Monitor integration performance metrics

### Reliability
- Implement retry logic with exponential backoff
- Use circuit breakers for external services
- Have fallback mechanisms for critical integrations
- Monitor integration health and availability

## Troubleshooting

### Common Issues

**Connection Timeouts**
```javascript
// Increase timeout for slow SIEM APIs
const siem = new SIEMConnector({
  platform: 'qradar',
  timeout: 30000, // 30 seconds
  retries: 3
});
```

**Authentication Failures**
```javascript
// Verify credentials and permissions
try {
  await siem.testConnection();
} catch (error) {
  console.error('SIEM authentication failed:', error.message);
}
```

**Rate Limiting**
```javascript
// Implement proper rate limiting
const rateLimiter = new RateLimiter({
  tokensPerInterval: 10,
  interval: 'minute'
});

await rateLimiter.removeTokens(1);
await siem.sendAlert(alert);
```

---

**Next Steps**: Check out [Enterprise Features](../enterprise/features.md) for advanced integration capabilities or [Examples](../examples/enterprise.md) for complete integration setups.
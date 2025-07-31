# Basic Usage Examples

Practical examples demonstrating common TrojanHorse.js usage patterns, from simple threat checks to complex integrations.

## Quick Start Examples

### 1. Simple Domain Check

```javascript
import { TrojanHorse } from 'trojanhorse-js';

// Basic setup with URLhaus (no API key required)
const trojan = new TrojanHorse({
  sources: ['urlhaus'],
  strategy: 'defensive'
});

async function checkDomain(domain) {
  try {
    const threats = await trojan.scout(domain);
    
    if (threats.length === 0) {
      console.log(`✅ ${domain} appears safe`);
      return { safe: true };
    }
    
    console.log(`🚨 ${domain}: ${threats.length} threats detected`);
    threats.forEach(threat => {
      console.log(`   - ${threat.indicator} (severity: ${threat.severity}/10)`);
    });
    
    return { safe: false, threats };
  } catch (error) {
    console.error('Check failed:', error.message);
    return { error: error.message };
  }
}

// Usage
checkDomain('suspicious-site.com');
checkDomain('google.com');
```

### 2. Multiple Sources with API Keys

```javascript
import { TrojanHorse } from 'trojanhorse-js';

const trojan = new TrojanHorse({
  sources: ['urlhaus', 'alienvault', 'abuseipdb'],
  strategy: 'balanced',
  apiKeys: {
    alienVault: process.env.ALIENVAULT_API_KEY,
    abuseipdb: process.env.ABUSEIPDB_API_KEY
  }
});

async function comprehensiveCheck(target) {
  console.log(`🔍 Analyzing ${target}...`);
  
  const threats = await trojan.scout(target);
  
  if (threats.length === 0) {
    console.log('✅ No threats found across all sources');
    return;
  }
  
  // Group by severity
  const critical = threats.filter(t => t.severity >= 8);
  const high = threats.filter(t => t.severity >= 6 && t.severity < 8);
  const medium = threats.filter(t => t.severity >= 4 && t.severity < 6);
  
  console.log('🚨 Threat Summary:');
  console.log(`   Critical: ${critical.length}`);
  console.log(`   High: ${high.length}`);
  console.log(`   Medium: ${medium.length}`);
  
  // Show sources contributing to detection
  const sources = [...new Set(threats.flatMap(t => t.sources))];
  console.log(`   Sources: ${sources.join(', ')}`);
  
  return { critical, high, medium, sources };
}

// Usage
comprehensiveCheck('malware-site.com');
```

### 3. Secure Vault Setup

```javascript
import { TrojanHorse } from 'trojanhorse-js';

async function setupSecureInstance() {
  // Create encrypted vault for API keys
  const { vault, trojan } = await TrojanHorse.createVault('my-secure-password', {
    alienVault: 'your-alienvault-key',
    abuseipdb: 'your-abuseipdb-key',
    virustotal: 'your-virustotal-key'
  }, {
    autoLock: true,
    lockTimeout: 5 * 60 * 1000 // 5 minutes
  });
  
  console.log('🔐 Secure vault created and configured');
  
  // Use the instance
  const threats = await trojan.scout('test-domain.com');
  console.log(`Found ${threats.length} threats`);
  
  // Vault will auto-lock after 5 minutes of inactivity
  return { vault, trojan };
}

setupSecureInstance();
```

## Data Export Examples

### 1. JSON Export

```javascript
async function exportToJSON() {
  const trojan = new TrojanHorse({
    sources: ['urlhaus', 'alienvault']
  });
  
  // Export all threat data as JSON
  const data = await trojan.plunder('json');
  
  console.log(`📊 Exported ${Object.keys(data).length} threat indicators`);
  
  // Save to file
  const fs = require('fs').promises;
  await fs.writeFile('threats.json', JSON.stringify(data, null, 2));
  
  console.log('💾 Data saved to threats.json');
  
  return data;
}
```

### 2. Filtered CSV Export

```javascript
async function exportHighSeverityThreats() {
  const trojan = new TrojanHorse({
    sources: ['urlhaus', 'alienvault', 'abuseipdb']
  });
  
  // Export only high-severity threats as CSV
  const csvData = await trojan.plunder('csv', {
    filter: {
      severity: { min: 7 },
      confidence: { min: 0.8 }
    },
    limit: 5000
  });
  
  console.log('📋 High-severity threats exported to CSV');
  
  // Save to file
  const fs = require('fs').promises;
  await fs.writeFile('high-severity-threats.csv', csvData);
  
  return csvData;
}
```

### 3. STIX Format Export

```javascript
async function exportToSTIX() {
  const trojan = new TrojanHorse({
    sources: ['urlhaus', 'alienvault']
  });
  
  // Export in STIX format for SIEM integration
  const stixData = await trojan.plunder('stix', {
    filter: {
      dateRange: {
        start: new Date(Date.now() - 24 * 60 * 60 * 1000), // Last 24 hours
        end: new Date()
      }
    },
    includeMetadata: true
  });
  
  console.log('🔗 Data exported in STIX format for SIEM integration');
  
  return stixData;
}
```

## Browser Integration Examples

### 1. Simple Browser Usage

```html
<!DOCTYPE html>
<html>
<head>
    <title>Threat Checker</title>
</head>
<body>
    <h1>Domain Threat Checker</h1>
    
    <input type="text" id="domain" placeholder="Enter domain to check">
    <button onclick="checkThreat()">Check Threat</button>
    
    <div id="result"></div>
    
    <script src="https://unpkg.com/trojanhorse-js@latest/dist/trojanhorse.browser.min.js"></script>
    <script>
        // Create simple lookup (demo mode for development)
        const lookup = TrojanHorse.createLookup({ demoMode: true });
        
        async function checkThreat() {
            const domain = document.getElementById('domain').value;
            const resultDiv = document.getElementById('result');
            
            if (!domain) {
                resultDiv.innerHTML = '⚠️ Please enter a domain';
                return;
            }
            
            resultDiv.innerHTML = '🔍 Checking...';
            
            try {
                const isMalicious = await lookup.checkDomain(domain);
                
                resultDiv.innerHTML = isMalicious 
                    ? `🚨 ${domain} appears to be malicious`
                    : `✅ ${domain} appears safe`;
            } catch (error) {
                resultDiv.innerHTML = `❌ Error: ${error.message}`;
            }
        }
    </script>
</body>
</html>
```

### 2. Advanced Browser Integration

```html
<!DOCTYPE html>
<html>
<head>
    <title>Advanced Threat Analysis</title>
    <style>
        .threat-card { 
            border: 1px solid #ddd; 
            margin: 10px; 
            padding: 15px; 
            border-radius: 5px; 
        }
        .severity-high { border-left: 5px solid #ff4444; }
        .severity-medium { border-left: 5px solid #ffaa00; }
        .severity-low { border-left: 5px solid #44ff44; }
    </style>
</head>
<body>
    <h1>Advanced Threat Analysis</h1>
    
    <form id="threatForm">
        <input type="text" id="target" placeholder="Domain, URL, or IP" required>
        <select id="type">
            <option value="auto">Auto-detect</option>
            <option value="domain">Domain</option>
            <option value="url">URL</option>
            <option value="ip">IP Address</option>
        </select>
        <button type="submit">Analyze</button>
    </form>
    
    <div id="loading" style="display: none;">🔍 Analyzing threat...</div>
    <div id="results"></div>
    
    <script type="module">
        import { TrojanHorse, BrowserUtils } from 'https://unpkg.com/trojanhorse-js@latest/dist/trojanhorse.browser.esm.js';
        
        // Check browser support
        const support = BrowserUtils.checkBrowserSupport();
        if (!support.supported) {
            document.body.innerHTML = `
                <h1>Browser Not Supported</h1>
                <p>Missing features: ${support.missing.join(', ')}</p>
            `;
        }
        
        // Create browser-optimized instance
        const trojan = await BrowserUtils.createBrowserInstance({
            feeds: ['urlhaus'],
            demoMode: true // Use demo mode for this example
        });
        
        document.getElementById('threatForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const target = document.getElementById('target').value;
            const type = document.getElementById('type').value;
            const loading = document.getElementById('loading');
            const results = document.getElementById('results');
            
            loading.style.display = 'block';
            results.innerHTML = '';
            
            try {
                const threats = await trojan.scout(target, { type });
                
                loading.style.display = 'none';
                
                if (threats.length === 0) {
                    results.innerHTML = '<div class="threat-card">✅ No threats detected</div>';
                    return;
                }
                
                const threatCards = threats.map(threat => {
                    const severityClass = threat.severity >= 7 ? 'severity-high' 
                        : threat.severity >= 4 ? 'severity-medium' 
                        : 'severity-low';
                    
                    return `
                        <div class="threat-card ${severityClass}">
                            <h3>🚨 ${threat.indicator}</h3>
                            <p><strong>Type:</strong> ${threat.type}</p>
                            <p><strong>Severity:</strong> ${threat.severity}/10</p>
                            <p><strong>Confidence:</strong> ${(threat.confidence * 100).toFixed(1)}%</p>
                            <p><strong>Sources:</strong> ${threat.sources.join(', ')}</p>
                            <p><strong>First Seen:</strong> ${new Date(threat.firstSeen).toLocaleDateString()}</p>
                            ${threat.tags.length > 0 ? `<p><strong>Tags:</strong> ${threat.tags.join(', ')}</p>` : ''}
                        </div>
                    `;
                }).join('');
                
                results.innerHTML = threatCards;
                
            } catch (error) {
                loading.style.display = 'none';
                results.innerHTML = `<div class="threat-card">❌ Error: ${error.message}</div>`;
            }
        });
    </script>
</body>
</html>
```

## Event-Driven Examples

### 1. Real-time Monitoring

```javascript
import { TrojanHorse } from 'trojanhorse-js';

class ThreatMonitor {
  constructor(watchList) {
    this.watchList = watchList;
    this.alertCounts = new Map();
    
    this.trojan = new TrojanHorse({
      sources: ['urlhaus', 'alienvault', 'abuseipdb'],
      strategy: 'aggressive',
      events: {
        threatFound: this.onThreatFound.bind(this),
        feedError: this.onFeedError.bind(this),
        rateLimited: this.onRateLimit.bind(this)
      }
    });
  }
  
  onThreatFound(threat) {
    console.log(`🚨 [${new Date().toISOString()}] Threat detected:`);
    console.log(`   Indicator: ${threat.indicator}`);
    console.log(`   Severity: ${threat.severity}/10`);
    console.log(`   Sources: ${threat.sources.join(', ')}`);
    
    // Track alert frequency
    const key = threat.indicator;
    this.alertCounts.set(key, (this.alertCounts.get(key) || 0) + 1);
    
    // Send immediate alert for critical threats
    if (threat.severity >= 9) {
      this.sendCriticalAlert(threat);
    }
    
    // Check for repeated alerts (possible campaign)
    if (this.alertCounts.get(key) >= 3) {
      this.detectCampaign(threat);
    }
  }
  
  onFeedError(error, feedName) {
    console.error(`❌ Feed ${feedName} error: ${error.message}`);
    
    // Implement exponential backoff
    setTimeout(() => {
      console.log(`🔄 Retrying ${feedName}...`);
    }, 30000); // 30 second delay
  }
  
  onRateLimit(feedName, resetTime) {
    console.warn(`⏱️  Rate limited on ${feedName}, reset at ${resetTime}`);
  }
  
  async start() {
    console.log('🚀 Starting threat monitoring...');
    console.log(`📋 Monitoring ${this.watchList.length} targets`);
    
    // Monitor loop
    while (true) {
      for (const target of this.watchList) {
        try {
          await this.trojan.scout(target);
        } catch (error) {
          console.error(`Monitor error for ${target}:`, error.message);
        }
        
        // Small delay between targets
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
      
      // Wait 10 minutes before next full scan
      console.log('⏳ Waiting 10 minutes before next scan...');
      await new Promise(resolve => setTimeout(resolve, 10 * 60 * 1000));
    }
  }
  
  sendCriticalAlert(threat) {
    console.log('🚨🚨 CRITICAL THREAT ALERT 🚨🚨');
    console.log(`Immediate action required for: ${threat.indicator}`);
    
    // In real implementation, send email/SMS/webhook
  }
  
  detectCampaign(threat) {
    console.log('🎯 POSSIBLE CAMPAIGN DETECTED');
    console.log(`${threat.indicator} has been flagged ${this.alertCounts.get(threat.indicator)} times`);
    
    // Analyze for campaign patterns
  }
  
  getStats() {
    return {
      totalAlerts: Array.from(this.alertCounts.values()).reduce((a, b) => a + b, 0),
      uniqueThreats: this.alertCounts.size,
      topThreats: Array.from(this.alertCounts.entries())
        .sort(([,a], [,b]) => b - a)
        .slice(0, 10)
    };
  }
}

// Usage
const monitor = new ThreatMonitor([
  'company-website.com',
  'partner-domain.com',
  'critical-service.net'
]);

monitor.start();

// Check stats periodically
setInterval(() => {
  const stats = monitor.getStats();
  console.log('📊 Monitor Stats:', stats);
}, 60 * 60 * 1000); // Every hour
```

### 2. Automated Response System

```javascript
import { TrojanHorse } from 'trojanhorse-js';

class AutomatedThreatResponse {
  constructor() {
    this.trojan = new TrojanHorse({
      sources: ['urlhaus', 'alienvault', 'abuseipdb', 'virustotal'],
      strategy: 'balanced',
      events: {
        threatFound: this.processNewThreat.bind(this),
        correlationComplete: this.analyzeCorrelation.bind(this)
      }
    });
    
    this.actionLog = [];
    this.quarantineList = new Set();
  }
  
  async processNewThreat(threat) {
    const response = await this.determineResponse(threat);
    
    switch (response.action) {
      case 'quarantine':
        await this.quarantineThreat(threat);
        break;
        
      case 'monitor':
        await this.addToWatchList(threat);
        break;
        
      case 'alert':
        await this.sendAlert(threat, response.priority);
        break;
        
      case 'investigate':
        await this.triggerInvestigation(threat);
        break;
    }
    
    this.logAction(threat, response);
  }
  
  determineResponse(threat) {
    // Critical severity - immediate quarantine
    if (threat.severity >= 9) {
      return { action: 'quarantine', priority: 'critical', reason: 'High severity threat' };
    }
    
    // High confidence + multiple sources - quarantine
    if (threat.confidence >= 0.9 && threat.sources.length >= 3) {
      return { action: 'quarantine', priority: 'high', reason: 'High confidence multi-source detection' };
    }
    
    // Medium-high severity - alert and investigate
    if (threat.severity >= 6) {
      return { action: 'investigate', priority: 'medium', reason: 'Medium-high severity requires investigation' };
    }
    
    // Single source or low confidence - monitor
    if (threat.sources.length === 1 || threat.confidence < 0.7) {
      return { action: 'monitor', priority: 'low', reason: 'Low confidence or single source' };
    }
    
    // Default action
    return { action: 'alert', priority: 'medium', reason: 'Standard threat detected' };
  }
  
  async quarantineThreat(threat) {
    console.log(`🔒 QUARANTINING: ${threat.indicator}`);
    
    this.quarantineList.add(threat.indicator);
    
    // In real implementation:
    // - Update firewall rules
    // - Block DNS resolution
    // - Update proxy blacklists
    // - Notify security team
    
    await this.notifySecurityTeam({
      action: 'quarantine',
      threat: threat.indicator,
      severity: threat.severity,
      reason: 'Automated quarantine due to high-risk threat'
    });
  }
  
  async addToWatchList(threat) {
    console.log(`👁️  MONITORING: ${threat.indicator}`);
    
    // Add to monitoring system
    // Increase scanning frequency
    // Set up additional alerts
  }
  
  async sendAlert(threat, priority) {
    console.log(`🚨 ALERT (${priority}): ${threat.indicator}`);
    
    const alertData = {
      timestamp: new Date().toISOString(),
      priority,
      threat: threat.indicator,
      severity: threat.severity,
      confidence: threat.confidence,
      sources: threat.sources,
      metadata: threat.metadata
    };
    
    // Send to alerting system
    await this.dispatchAlert(alertData);
  }
  
  async triggerInvestigation(threat) {
    console.log(`🔍 INVESTIGATING: ${threat.indicator}`);
    
    // Create investigation ticket
    const ticket = {
      id: `INV-${Date.now()}`,
      threat: threat.indicator,
      severity: threat.severity,
      assignee: this.getAnalystOnDuty(),
      deadline: new Date(Date.now() + 4 * 60 * 60 * 1000), // 4 hours
      context: {
        sources: threat.sources,
        confidence: threat.confidence,
        firstSeen: threat.firstSeen,
        tags: threat.tags
      }
    };
    
    await this.createInvestigationTicket(ticket);
  }
  
  logAction(threat, response) {
    this.actionLog.push({
      timestamp: new Date(),
      threat: threat.indicator,
      action: response.action,
      priority: response.priority,
      reason: response.reason,
      severity: threat.severity
    });
  }
  
  // Mock implementations (replace with real integrations)
  async notifySecurityTeam(notification) {
    console.log('📧 Security team notification:', notification);
  }
  
  async dispatchAlert(alert) {
    console.log('🔔 Alert dispatched:', alert);
  }
  
  async createInvestigationTicket(ticket) {
    console.log('🎫 Investigation ticket created:', ticket);
  }
  
  getAnalystOnDuty() {
    const analysts = ['alice@company.com', 'bob@company.com', 'charlie@company.com'];
    return analysts[Math.floor(Math.random() * analysts.length)];
  }
  
  getActionSummary() {
    const summary = {
      totalActions: this.actionLog.length,
      quarantined: this.quarantineList.size,
      actionBreakdown: {}
    };
    
    this.actionLog.forEach(log => {
      summary.actionBreakdown[log.action] = (summary.actionBreakdown[log.action] || 0) + 1;
    });
    
    return summary;
  }
}

// Usage
const responseSystem = new AutomatedThreatResponse();

// Simulate threat detection
setInterval(() => {
  console.log('📊 Response Summary:', responseSystem.getActionSummary());
}, 30 * 60 * 1000); // Every 30 minutes
```

## Batch Processing Examples

### 1. Domain List Processing

```javascript
import { TrojanHorse } from 'trojanhorse-js';
import fs from 'fs/promises';

async function processDomainList(filename) {
  const trojan = new TrojanHorse({
    sources: ['urlhaus', 'alienvault'],
    strategy: 'balanced',
    performance: {
      maxConcurrency: 5 // Limit concurrent requests
    }
  });
  
  // Read domain list
  const content = await fs.readFile(filename, 'utf-8');
  const domains = content.split('\n').filter(d => d.trim());
  
  console.log(`📋 Processing ${domains.length} domains...`);
  
  const results = [];
  const batchSize = 20;
  
  for (let i = 0; i < domains.length; i += batchSize) {
    const batch = domains.slice(i, i + batchSize);
    console.log(`Processing batch ${Math.floor(i/batchSize) + 1}/${Math.ceil(domains.length/batchSize)}`);
    
    const batchPromises = batch.map(async (domain) => {
      try {
        const threats = await trojan.scout(domain.trim());
        return {
          domain: domain.trim(),
          safe: threats.length === 0,
          threatCount: threats.length,
          maxSeverity: threats.length > 0 ? Math.max(...threats.map(t => t.severity)) : 0,
          sources: threats.length > 0 ? [...new Set(threats.flatMap(t => t.sources))] : []
        };
      } catch (error) {
        return {
          domain: domain.trim(),
          error: error.message
        };
      }
    });
    
    const batchResults = await Promise.allSettled(batchPromises);
    results.push(...batchResults.map(r => r.value || { error: r.reason?.message }));
    
    // Progress update
    console.log(`   Completed: ${Math.min(i + batchSize, domains.length)}/${domains.length}`);
    
    // Small delay between batches to be respectful
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  
  // Generate report
  const report = generateReport(results);
  await fs.writeFile('threat-analysis-report.json', JSON.stringify(report, null, 2));
  
  console.log('✅ Analysis complete! Report saved to threat-analysis-report.json');
  
  return report;
}

function generateReport(results) {
  const clean = results.filter(r => r.safe);
  const threats = results.filter(r => !r.safe && !r.error);
  const errors = results.filter(r => r.error);
  
  const severityBreakdown = {
    critical: threats.filter(t => t.maxSeverity >= 9).length,
    high: threats.filter(t => t.maxSeverity >= 7 && t.maxSeverity < 9).length,
    medium: threats.filter(t => t.maxSeverity >= 4 && t.maxSeverity < 7).length,
    low: threats.filter(t => t.maxSeverity < 4).length
  };
  
  return {
    summary: {
      total: results.length,
      clean: clean.length,
      threats: threats.length,
      errors: errors.length,
      cleanPercentage: ((clean.length / results.length) * 100).toFixed(2)
    },
    severityBreakdown,
    topThreats: threats
      .sort((a, b) => b.maxSeverity - a.maxSeverity)
      .slice(0, 10),
    errorDetails: errors.slice(0, 10),
    timestamp: new Date().toISOString()
  };
}

// Usage
processDomainList('domains.txt');
```

### 2. Continuous Monitoring Pipeline

```javascript
import { TrojanHorse } from 'trojanhorse-js';

class ThreatPipeline {
  constructor(config) {
    this.trojan = new TrojanHorse(config);
    this.queue = [];
    this.processing = false;
    this.results = new Map();
    this.stats = {
      processed: 0,
      threats: 0,
      errors: 0
    };
  }
  
  // Add items to processing queue
  enqueue(items) {
    if (Array.isArray(items)) {
      this.queue.push(...items);
    } else {
      this.queue.push(items);
    }
    
    if (!this.processing) {
      this.processQueue();
    }
  }
  
  async processQueue() {
    if (this.processing || this.queue.length === 0) return;
    
    this.processing = true;
    console.log(`🚀 Starting pipeline processing (${this.queue.length} items queued)`);
    
    while (this.queue.length > 0) {
      const batch = this.queue.splice(0, 10); // Process 10 at a time
      
      const promises = batch.map(item => this.processItem(item));
      const results = await Promise.allSettled(promises);
      
      results.forEach((result, index) => {
        const item = batch[index];
        if (result.status === 'fulfilled') {
          this.results.set(item, result.value);
          this.updateStats(result.value);
        } else {
          console.error(`Processing failed for ${item}:`, result.reason.message);
          this.stats.errors++;
        }
      });
      
      // Small delay between batches
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    this.processing = false;
    console.log('✅ Pipeline processing complete');
    this.printStats();
  }
  
  async processItem(item) {
    try {
      const threats = await this.trojan.scout(item);
      this.stats.processed++;
      
      if (threats.length > 0) {
        this.stats.threats++;
        
        // Trigger real-time actions for high-severity threats
        const critical = threats.filter(t => t.severity >= 8);
        if (critical.length > 0) {
          await this.handleCriticalThreat(item, critical);
        }
      }
      
      return {
        item,
        safe: threats.length === 0,
        threats,
        processedAt: new Date()
      };
    } catch (error) {
      this.stats.errors++;
      throw error;
    }
  }
  
  async handleCriticalThreat(item, threats) {
    console.log(`🚨 CRITICAL THREAT: ${item}`);
    threats.forEach(threat => {
      console.log(`   - Severity: ${threat.severity}/10`);
      console.log(`   - Sources: ${threat.sources.join(', ')}`);
    });
    
    // In real implementation:
    // - Send immediate alerts
    // - Update security controls
    // - Create incident tickets
  }
  
  updateStats(result) {
    // Custom stats logic
  }
  
  printStats() {
    console.log('📊 Pipeline Statistics:');
    console.log(`   Processed: ${this.stats.processed}`);
    console.log(`   Threats Found: ${this.stats.threats}`);
    console.log(`   Errors: ${this.stats.errors}`);
    console.log(`   Success Rate: ${((this.stats.processed / (this.stats.processed + this.stats.errors)) * 100).toFixed(2)}%`);
  }
  
  getResults() {
    return Array.from(this.results.entries());
  }
  
  exportResults(format = 'json') {
    const data = this.getResults();
    
    if (format === 'csv') {
      const csv = ['Item,Safe,Threat Count,Max Severity,Sources'];
      data.forEach(([item, result]) => {
        const maxSeverity = result.threats.length > 0 ? Math.max(...result.threats.map(t => t.severity)) : 0;
        const sources = result.threats.length > 0 ? [...new Set(result.threats.flatMap(t => t.sources))].join(';') : '';
        csv.push(`${item},${result.safe},${result.threats.length},${maxSeverity},"${sources}"`);
      });
      return csv.join('\n');
    }
    
    return JSON.stringify(data, null, 2);
  }
}

// Usage
const pipeline = new ThreatPipeline({
  sources: ['urlhaus', 'alienvault', 'abuseipdb'],
  strategy: 'balanced'
});

// Add domains to process
pipeline.enqueue([
  'suspicious-site.com',
  'malware-domain.net',
  'phishing-example.org'
]);

// Add more items later
setTimeout(() => {
  pipeline.enqueue(['another-domain.com', 'test-site.net']);
}, 5000);

// Export results after processing
setTimeout(() => {
  const csv = pipeline.exportResults('csv');
  console.log('CSV Export:', csv);
}, 30000);
```

## Integration Examples

### 1. Express.js API Integration

```javascript
import express from 'express';
import { TrojanHorse } from 'trojanhorse-js';

const app = express();
app.use(express.json());

// Initialize TrojanHorse
const trojan = new TrojanHorse({
  sources: ['urlhaus', 'alienvault', 'abuseipdb'],
  strategy: 'balanced',
  apiKeys: {
    alienVault: process.env.ALIENVAULT_API_KEY,
    abuseipdb: process.env.ABUSEIPDB_API_KEY
  }
});

// Health check endpoint
app.get('/health', async (req, res) => {
  try {
    const health = await trojan.getHealth();
    res.json(health);
  } catch (error) {
    res.status(500).json({ error: 'Health check failed' });
  }
});

// Single threat check
app.post('/api/v1/threat-check', async (req, res) => {
  try {
    const { target, type = 'auto' } = req.body;
    
    if (!target) {
      return res.status(400).json({ error: 'Target parameter required' });
    }
    
    const threats = await trojan.scout(target, { type });
    
    res.json({
      target,
      safe: threats.length === 0,
      threatCount: threats.length,
      threats: threats.slice(0, 10), // Limit response size
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Threat check error:', error);
    res.status(500).json({ error: 'Threat check failed' });
  }
});

// Batch threat check
app.post('/api/v1/threat-check-batch', async (req, res) => {
  try {
    const { targets } = req.body;
    
    if (!Array.isArray(targets) || targets.length === 0) {
      return res.status(400).json({ error: 'Targets array required' });
    }
    
    if (targets.length > 100) {
      return res.status(400).json({ error: 'Too many targets (max 100)' });
    }
    
    const results = await Promise.allSettled(
      targets.map(target => trojan.scout(target))
    );
    
    const response = results.map((result, index) => {
      if (result.status === 'fulfilled') {
        return {
          target: targets[index],
          safe: result.value.length === 0,
          threatCount: result.value.length
        };
      } else {
        return {
          target: targets[index],
          error: result.reason.message
        };
      }
    });
    
    res.json({
      results: response,
      processed: targets.length,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Batch check error:', error);
    res.status(500).json({ error: 'Batch check failed' });
  }
});

// Export threat data
app.get('/api/v1/export/:format', async (req, res) => {
  try {
    const { format } = req.params;
    const { limit = 1000 } = req.query;
    
    if (!['json', 'csv'].includes(format)) {
      return res.status(400).json({ error: 'Unsupported format' });
    }
    
    const data = await trojan.plunder(format, { limit: parseInt(limit) });
    
    res.setHeader('Content-Type', format === 'json' ? 'application/json' : 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="threats.${format}"`);
    res.send(data);
  } catch (error) {
    console.error('Export error:', error);
    res.status(500).json({ error: 'Export failed' });
  }
});

app.listen(3000, () => {
  console.log('🚀 TrojanHorse API server running on port 3000');
});
```

These examples demonstrate the flexibility and power of TrojanHorse.js across different use cases and environments. Each example is self-contained and can be adapted to your specific needs.

## Next Steps

- **[Advanced Examples](advanced.md)** - Complex integration patterns
- **[Custom Feeds](custom-feeds.md)** - Create your own threat feeds
- **[Enterprise Examples](enterprise.md)** - Large-scale deployments
- **[API Reference](../api/core.md)** - Complete API documentation

---

**Want more examples?** Check our [GitHub repository](https://github.com/sc4rfurry/TrojanHorse.js/tree/main/examples) for additional code samples and templates.
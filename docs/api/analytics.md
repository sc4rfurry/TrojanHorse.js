# Analytics API Reference

TrojanHorse.js provides comprehensive analytics and monitoring capabilities for threat intelligence operations.

## Real-Time Analytics

### RealTimeAnalytics Class

Monitor threat intelligence operations in real-time with detailed metrics and insights.

```javascript
import { RealTimeAnalytics } from 'trojanhorse-js';

const analytics = new RealTimeAnalytics({
  retention: '30d',
  aggregationWindow: '1m',
  storage: {
    type: 'memory', // 'memory', 'redis', 'mongodb'
    config: {}
  }
});
```

### Performance Metrics

#### Threat Detection Metrics

```javascript
// Get threat detection statistics
const stats = await analytics.getThreatStats({
  timeRange: '24h',
  granularity: '1h'
});

console.log(stats);
// {
//   totalScans: 1247,
//   threatsDetected: 89,
//   detectionRate: 7.14,
//   averageConfidence: 82.5,
//   topSources: ['urlhaus', 'virustotal', 'alienvault']
// }
```

#### Feed Performance

Monitor individual threat feed performance:

```javascript
const feedStats = await analytics.getFeedPerformance({
  feeds: ['urlhaus', 'alienvault', 'abuseipdb'],
  timeRange: '7d'
});

console.log(feedStats);
// {
//   urlhaus: {
//     requests: 542,
//     successes: 538,
//     failures: 4,
//     successRate: 99.26,
//     avgResponseTime: 245,
//     threatsFound: 67
//   },
//   alienvault: {
//     requests: 489,
//     successes: 465,
//     failures: 24,
//     successRate: 95.09,
//     avgResponseTime: 1823,
//     threatsFound: 123
//   }
// }
```

### Real-Time Dashboards

#### Metrics Dashboard

```javascript
// Start real-time metrics collection
analytics.startMetricsCollection({
  interval: 5000, // 5 seconds
  metrics: [
    'requests_per_second',
    'threats_detected',
    'response_times',
    'error_rates'
  ]
});

// Subscribe to real-time updates
analytics.on('metrics', (data) => {
  updateDashboard(data);
});
```

#### Performance Charts

Generate performance visualization data:

```javascript
const chartData = await analytics.generateChartData({
  type: 'timeline',
  metric: 'threats_detected',
  timeRange: '24h',
  granularity: '1h'
});

// Use with Chart.js, D3, or other visualization libraries
const chart = new Chart(ctx, {
  type: 'line',
  data: {
    labels: chartData.labels,
    datasets: [{
      label: 'Threats Detected',
      data: chartData.values,
      borderColor: '#dc2626',
      tension: 0.1
    }]
  }
});
```

## Threat Intelligence Analytics

### Campaign Detection

Automatically detect threat campaigns using analytics:

```javascript
const campaigns = await analytics.detectCampaigns({
  timeWindow: '7d',
  similarity: {
    threshold: 0.8,
    features: ['domains', 'ips', 'file_hashes']
  },
  clustering: {
    algorithm: 'dbscan',
    minSamples: 3
  }
});

console.log(campaigns);
// [
//   {
//     id: 'campaign_001',
//     name: 'Suspected APT Campaign',
//     confidence: 0.89,
//     indicators: 45,
//     timespan: '2025-01-15 to 2025-01-22',
//     tactics: ['phishing', 'malware_distribution']
//   }
// ]
```

### Trend Analysis

Analyze threat trends over time:

```javascript
const trends = await analytics.analyzeTrends({
  indicators: ['domains', 'ips', 'urls'],
  timeRange: '30d',
  analysis: {
    seasonal: true,
    outliers: true,
    forecast: '7d'
  }
});

console.log(trends.domains);
// {
//   current: 145,
//   trend: 'increasing',
//   changePercent: 23.4,
//   seasonalPattern: 'weekly_peak_tuesday',
//   forecast: [152, 158, 149, 167, 171]
// }
```

### Risk Scoring

Advanced risk scoring based on multiple factors:

```javascript
const riskScore = await analytics.calculateRiskScore({
  indicator: 'suspicious-domain.com',
  factors: {
    sources: 0.3,        // Weight for number of sources
    confidence: 0.4,     // Weight for confidence scores
    recency: 0.2,        // Weight for how recent the threat is
    prevalence: 0.1      // Weight for how common the threat is
  }
});

console.log(riskScore);
// {
//   score: 87.5,
//   level: 'high',
//   factors: {
//     sources: { value: 4, score: 80 },
//     confidence: { value: 92, score: 92 },
//     recency: { value: '2h', score: 95 },
//     prevalence: { value: 'rare', score: 85 }
//   }
// }
```

## Advanced Analytics Features

### Machine Learning Integration

#### Anomaly Detection

Detect anomalous patterns in threat intelligence:

```javascript
const anomalies = await analytics.detectAnomalies({
  features: ['request_volume', 'threat_rate', 'response_times'],
  algorithm: 'isolation_forest',
  sensitivity: 0.1
});

console.log(anomalies);
// [
//   {
//     timestamp: '2025-01-29T14:30:00Z',
//     type: 'volume_spike',
//     severity: 'medium',
//     description: 'Unusual increase in scan requests',
//     score: 0.78
//   }
// ]
```

#### Predictive Analytics

Predict future threat levels:

```javascript
const prediction = await analytics.predictThreatLevel({
  horizon: '24h',
  model: 'lstm',
  features: ['historical_threats', 'external_intel', 'time_patterns']
});

console.log(prediction);
// {
//   next24h: {
//     expected: 'medium',
//     confidence: 0.82,
//     hourly: [
//       { hour: 15, level: 'medium', probability: 0.75 },
//       { hour: 16, level: 'high', probability: 0.89 }
//     ]
//   }
// }
```

### Correlation Analytics

#### Multi-Indicator Correlation

Find relationships between different threat indicators:

```javascript
const correlations = await analytics.findCorrelations({
  indicators: threatResults.map(t => t.indicator),
  types: ['temporal', 'geographical', 'behavioral'],
  strength: 0.7
});

console.log(correlations);
// {
//   temporal: [
//     {
//       indicators: ['badsite.com', '192.0.2.1'],
//       correlation: 0.89,
//       pattern: 'simultaneous_detection'
//     }
//   ],
//   geographical: [
//     {
//       indicators: ['malware1.exe', 'malware2.exe'],
//       correlation: 0.93,
//       pattern: 'same_hosting_provider'
//     }
//   ]
// }
```

#### Attribution Analysis

Analyze potential threat actor attribution:

```javascript
const attribution = await analytics.analyzeAttribution({
  indicators: campaignIndicators,
  techniques: {
    ttp_matching: true,
    infrastructure_overlap: true,
    timing_patterns: true
  }
});

console.log(attribution);
// {
//   likely_actors: [
//     {
//       name: 'APT29',
//       confidence: 0.78,
//       evidence: ['infrastructure_reuse', 'ttp_similarity']
//     }
//   ],
//   confidence: 0.72,
//   reasoning: 'Multiple TTPs match known APT29 campaigns'
// }
```

## Reporting and Visualizations

### Automated Reports

Generate comprehensive analytics reports:

```javascript
const report = await analytics.generateReport({
  type: 'weekly_summary',
  timeRange: '7d',
  sections: [
    'executive_summary',
    'threat_overview',
    'feed_performance',
    'trending_threats',
    'recommendations'
  ],
  format: 'pdf' // 'pdf', 'html', 'json'
});

// Save or email the report
await report.saveTo('./reports/weekly_' + Date.now() + '.pdf');
```

### Custom Visualizations

Create custom charts and graphs:

```javascript
// Threat distribution by type
const distributionData = await analytics.getThreatDistribution({
  groupBy: 'type',
  timeRange: '30d'
});

// Geographic threat map data
const geoData = await analytics.getGeographicThreats({
  timeRange: '24h',
  aggregation: 'country'
});

// Timeline of major threats
const timelineData = await analytics.getThreatTimeline({
  severity: 'high',
  timeRange: '30d'
});
```

### Interactive Dashboards

#### Threat Intelligence Dashboard

```html
<!-- HTML Dashboard Template -->
<div id="threat-dashboard">
  <div class="metrics-row">
    <div class="metric-card" id="total-threats"></div>
    <div class="metric-card" id="detection-rate"></div>
    <div class="metric-card" id="avg-confidence"></div>
  </div>
  
  <div class="charts-row">
    <canvas id="threats-timeline"></canvas>
    <canvas id="feed-performance"></canvas>
  </div>
  
  <div class="data-table" id="recent-threats"></div>
</div>
```

```javascript
// Dashboard JavaScript
class ThreatDashboard {
  constructor(analytics) {
    this.analytics = analytics;
    this.initializeCharts();
    this.startRealTimeUpdates();
  }
  
  async updateMetrics() {
    const stats = await this.analytics.getThreatStats({ timeRange: '24h' });
    
    document.getElementById('total-threats').textContent = stats.threatsDetected;
    document.getElementById('detection-rate').textContent = `${stats.detectionRate}%`;
    document.getElementById('avg-confidence').textContent = stats.averageConfidence;
  }
  
  startRealTimeUpdates() {
    setInterval(() => this.updateMetrics(), 30000); // Update every 30 seconds
    
    this.analytics.on('new-threat', (threat) => {
      this.addThreatToTable(threat);
      this.updateCharts();
    });
  }
}

const dashboard = new ThreatDashboard(analytics);
```

## Configuration and Customization

### Analytics Configuration

```javascript
const analytics = new RealTimeAnalytics({
  // Data retention
  retention: {
    raw: '7d',        // Raw event data
    hourly: '30d',    // Hourly aggregates
    daily: '1y'       // Daily aggregates
  },
  
  // Alert thresholds
  alerts: {
    high_threat_rate: {
      threshold: 50,
      window: '1h',
      action: 'email'
    },
    feed_failure: {
      threshold: 5,
      window: '5m',
      action: 'webhook'
    }
  },
  
  // Machine learning
  ml: {
    enabled: true,
    models: ['anomaly_detection', 'trend_analysis'],
    retraining: 'weekly'
  }
});
```

### Custom Metrics

Define custom metrics for your specific use case:

```javascript
// Register custom metric
analytics.registerMetric('custom_threat_score', {
  type: 'gauge',
  description: 'Custom threat scoring algorithm',
  calculate: (threats) => {
    return threats.reduce((sum, threat) => {
      return sum + (threat.confidence * threat.sourceCount);
    }, 0) / threats.length;
  }
});

// Use custom metric
const customScore = await analytics.getMetric('custom_threat_score', {
  timeRange: '1h'
});
```

## Performance and Scaling

### Memory Management

```javascript
// Configure memory usage for large-scale deployments
const analytics = new RealTimeAnalytics({
  memory: {
    maxSize: '2GB',
    evictionPolicy: 'lru',
    compressionEnabled: true
  },
  
  // Sampling for high-volume environments
  sampling: {
    enabled: true,
    rate: 0.1, // Sample 10% of events
    preserveThreats: true // Always keep threat detections
  }
});
```

### Distributed Analytics

Scale analytics across multiple instances:

```javascript
const distributedAnalytics = new DistributedAnalytics({
  cluster: {
    nodes: ['analytics-1:8080', 'analytics-2:8080'],
    coordination: 'redis://localhost:6379'
  },
  
  sharding: {
    strategy: 'time_based',
    shardSize: '1d'
  }
});
```

---

**Next Steps**: Explore [Enterprise Monitoring](../enterprise/monitoring.md) for advanced analytics features or check [Examples](../examples/advanced.md) for complete analytics implementations.
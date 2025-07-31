# Advanced Examples

Complex real-world scenarios and enterprise use cases for TrojanHorse.js.

## Enterprise SOC Integration

### Complete SIEM Integration Pipeline

```javascript
import { TrojanHorse, SIEMConnector, WebhookManager } from 'trojanhorse-js/enterprise';

class EnterpriseSOCIntegration {
  constructor() {
    this.initializePlatforms();
    this.setupWorkflows();
  }

  async initializePlatforms() {
    // Initialize TrojanHorse with enterprise configuration
    this.trojan = new TrojanHorse({
      sources: ['urlhaus', 'alienvault', 'abuseipdb', 'virustotal', 'crowdsec'],
      strategy: 'comprehensive',
      
      performance: {
        workers: 8,
        batchSize: 100,
        cacheEnabled: true,
        cacheTTL: 3600
      },
      
      enterprise: {
        encryption: true,
        auditLogging: true,
        complianceMode: 'SOC2'
      }
    });

    // Setup multiple SIEM connectors
    this.splunk = new SIEMConnector({
      platform: 'splunk',
      host: 'splunk-enterprise.company.com',
      hecToken: process.env.SPLUNK_HEC_TOKEN,
      index: 'threat_intelligence'
    });

    this.qradar = new SIEMConnector({
      platform: 'qradar',
      host: 'qradar.company.com',
      token: process.env.QRADAR_TOKEN,
      referenceSet: 'TrojanHorse_IOCs'
    });

    this.sentinel = new SIEMConnector({
      platform: 'sentinel',
      workspaceId: process.env.SENTINEL_WORKSPACE_ID,
      tenantId: process.env.AZURE_TENANT_ID
    });

    // Setup webhook manager for real-time notifications
    this.webhooks = new WebhookManager({
      endpoints: {
        slack: process.env.SLACK_WEBHOOK_URL,
        teams: process.env.TEAMS_WEBHOOK_URL,
        pagerduty: process.env.PAGERDUTY_WEBHOOK_URL
      }
    });
  }

  async setupWorkflows() {
    // High-confidence threat workflow
    this.trojan.on('threatDetected', async (threat) => {
      if (threat.confidence >= 90) {
        await this.handleHighConfidenceThreat(threat);
      } else if (threat.confidence >= 70) {
        await this.handleMediumConfidenceThreat(threat);
      }
    });

    // Campaign detection workflow
    this.trojan.on('campaignDetected', async (campaign) => {
      await this.handleCampaignDetection(campaign);
    });
  }

  async handleHighConfidenceThreat(threat) {
    console.log(`🚨 HIGH CONFIDENCE THREAT: ${threat.indicator}`);

    // Create SIEM events across all platforms
    const siemEvent = {
      indicator: threat.indicator,
      type: threat.type,
      confidence: threat.confidence,
      sources: threat.sources,
      severity: 'high',
      timestamp: new Date().toISOString(),
      ttl: 30 * 24 * 60 * 60 // 30 days
    };

    await Promise.all([
      this.splunk.sendEvent(siemEvent),
      this.qradar.addToReferenceSet(threat.indicator, siemEvent),
      this.sentinel.createThreatIndicator(siemEvent)
    ]);

    // Create incident in Sentinel for investigation
    const incident = await this.sentinel.createIncident({
      title: `High Confidence Threat: ${threat.indicator}`,
      description: `TrojanHorse.js detected ${threat.indicator} with ${threat.confidence}% confidence`,
      severity: 'High',
      assignee: 'tier2-analysts@company.com'
    });

    // Send real-time notifications
    await this.webhooks.sendToSlack({
      channel: '#security-alerts',
      text: `🚨 Critical Threat Detected`,
      attachments: [{
        color: 'danger',
        fields: [
          { title: 'Indicator', value: threat.indicator, short: true },
          { title: 'Confidence', value: `${threat.confidence}%`, short: true },
          { title: 'Sources', value: threat.sources.join(', '), short: false },
          { title: 'Incident', value: `<https://portal.azure.com/#view/HubsExtension/BrowseResource/resourceType/Microsoft.SecurityInsights%2FIncidents/menuId/|${incident.id}>`, short: false }
        ]
      }]
    });

    // Trigger PagerDuty for critical threats
    if (threat.confidence >= 95) {
      await this.webhooks.sendToPagerDuty({
        routing_key: process.env.PAGERDUTY_ROUTING_KEY,
        event_action: 'trigger',
        payload: {
          summary: `Critical Threat: ${threat.indicator}`,
          severity: 'critical',
          source: 'TrojanHorse.js',
          custom_details: threat
        }
      });
    }
  }

  async handleMediumConfidenceThreat(threat) {
    console.log(`⚠️ MEDIUM CONFIDENCE THREAT: ${threat.indicator}`);

    // Send to SIEM for correlation
    await this.splunk.sendEvent({
      indicator: threat.indicator,
      confidence: threat.confidence,
      sources: threat.sources,
      severity: 'medium'
    });

    // Add to watchlist for monitoring
    await this.qradar.addToWatchlist(threat.indicator);

    // Create low-priority ticket
    await this.webhooks.sendToSlack({
      channel: '#security-monitoring',
      text: `⚠️ Medium confidence threat detected: ${threat.indicator} (${threat.confidence}%)`
    });
  }

  async handleCampaignDetection(campaign) {
    console.log(`📊 CAMPAIGN DETECTED: ${campaign.name}`);

    // Create comprehensive incident
    const incident = await this.sentinel.createIncident({
      title: `Threat Campaign: ${campaign.name}`,
      description: `Multi-indicator campaign detected with ${campaign.indicators.length} IOCs`,
      severity: 'High',
      tags: ['campaign', 'apt', 'coordinated-attack']
    });

    // Send detailed analysis to Teams
    await this.webhooks.sendToTeams({
      title: '🎯 Threat Campaign Detected',
      summary: `Campaign "${campaign.name}" detected with ${campaign.indicators.length} indicators`,
      sections: [{
        activityTitle: 'Campaign Details',
        facts: [
          { name: 'Campaign ID', value: campaign.id },
          { name: 'Confidence', value: `${campaign.confidence}%` },
          { name: 'Indicators', value: campaign.indicators.length },
          { name: 'Attribution', value: campaign.attribution || 'Unknown' },
          { name: 'First Seen', value: campaign.firstSeen },
          { name: 'Last Seen', value: campaign.lastSeen }
        ]
      }]
    });

    // Create Splunk investigation dashboard
    await this.splunk.createDashboard({
      name: `Campaign_${campaign.id}`,
      searches: campaign.indicators.map(ioc => ({
        query: `index=* "${ioc}"`,
        title: `IOC: ${ioc}`
      }))
    });
  }

  // Automated threat hunting based on external intelligence
  async performThreatHunt(externalIntel) {
    const huntResults = [];

    for (const intel of externalIntel) {
      const results = await this.trojan.scout(intel.indicator);
      
      if (results.length > 0) {
        huntResults.push({
          indicator: intel.indicator,
          externalSource: intel.source,
          trojanResults: results,
          correlation: await this.trojan.correlate(intel.indicator)
        });
      }
    }

    if (huntResults.length > 0) {
      await this.webhooks.sendToSlack({
        channel: '#threat-hunting',
        text: `🔍 Threat Hunt Results: ${huntResults.length} matches found`,
        attachments: huntResults.map(result => ({
          color: 'warning',
          fields: [
            { title: 'Indicator', value: result.indicator, short: true },
            { title: 'External Source', value: result.externalSource, short: true },
            { title: 'TrojanHorse Sources', value: result.trojanResults.map(r => r.source).join(', '), short: false }
          ]
        }))
      });
    }

    return huntResults;
  }
}

// Initialize and start the SOC integration
const socIntegration = new EnterpriseSOCIntegration();
```

## Advanced Analytics Pipeline

### Machine Learning Threat Scoring

```javascript
import { MLThreatEngine, ThreatAnalytics } from 'trojanhorse-js/enterprise';

class AdvancedThreatAnalytics {
  constructor() {
    this.mlEngine = new MLThreatEngine({
      models: ['xgboost', 'neural_network', 'ensemble'],
      features: [
        'source_reputation',
        'indicator_age',
        'prevalence_score',
        'context_analysis',
        'behavioral_patterns'
      ]
    });

    this.analytics = new ThreatAnalytics({
      correlation: {
        enabled: true,
        algorithms: ['pearson', 'spearman', 'mutual_information']
      },
      
      clustering: {
        enabled: true,
        algorithms: ['dbscan', 'kmeans', 'hierarchical']
      },
      
      anomalyDetection: {
        enabled: true,
        sensitivity: 0.1,
        models: ['isolation_forest', 'one_class_svm']
      }
    });
  }

  async enhancedThreatScoring(threats) {
    const enhancedThreats = [];

    for (const threat of threats) {
      // Base TrojanHorse confidence
      let confidence = threat.confidence;
      
      // ML-enhanced scoring
      const mlScore = await this.mlEngine.predict({
        indicator: threat.indicator,
        type: threat.type,
        sources: threat.sources,
        metadata: threat.metadata
      });

      // Context analysis
      const contextScore = await this.analyzeContext(threat);
      
      // Historical analysis
      const historicalScore = await this.analyzeHistoricalData(threat);
      
      // Ensemble scoring
      const finalScore = this.calculateEnsembleScore({
        base: confidence,
        ml: mlScore.confidence,
        context: contextScore,
        historical: historicalScore
      });

      enhancedThreats.push({
        ...threat,
        originalConfidence: confidence,
        mlScore: mlScore,
        contextScore: contextScore,
        historicalScore: historicalScore,
        finalScore: finalScore,
        riskLevel: this.calculateRiskLevel(finalScore)
      });
    }

    return enhancedThreats;
  }

  async analyzeContext(threat) {
    // Analyze the context around the threat indicator
    const context = {
      networkContext: await this.analyzeNetworkContext(threat.indicator),
      temporalContext: await this.analyzeTemporalPatterns(threat),
      geographicContext: await this.analyzeGeographic(threat),
      infrastructureContext: await this.analyzeInfrastructure(threat)
    };

    return this.calculateContextScore(context);
  }

  async performCampaignAnalysis(threats, timeWindow = '7d') {
    // Group threats by similarity
    const clusters = await this.analytics.clusterThreats(threats, {
      features: ['infrastructure', 'timing', 'tactics'],
      algorithm: 'dbscan',
      minSamples: 3
    });

    const campaigns = [];

    for (const cluster of clusters) {
      if (cluster.size >= 3) { // Minimum threshold for campaign
        const campaign = {
          id: `campaign_${Date.now()}_${cluster.id}`,
          confidence: cluster.cohesion,
          indicators: cluster.threats.map(t => t.indicator),
          characteristics: await this.extractCampaignCharacteristics(cluster),
          attribution: await this.performAttribution(cluster),
          timeline: this.createTimeline(cluster.threats),
          infrastructure: this.analyzeInfrastructureOverlap(cluster.threats)
        };

        campaigns.push(campaign);
      }
    }

    return campaigns;
  }

  async performAttribution(cluster) {
    // TTPs analysis
    const ttps = await this.extractTTPs(cluster.threats);
    
    // Infrastructure fingerprinting
    const infraFingerprint = await this.createInfrastructureFingerprint(cluster);
    
    // Compare with known threat actor profiles
    const attributionScores = await this.compareWithKnownActors(ttps, infraFingerprint);
    
    return {
      likelyActors: attributionScores.filter(a => a.confidence > 0.7),
      confidence: Math.max(...attributionScores.map(a => a.confidence)),
      reasoning: this.generateAttributionReasoning(attributionScores)
    };
  }

  calculateEnsembleScore(scores) {
    // Weighted ensemble scoring
    const weights = {
      base: 0.3,
      ml: 0.4,
      context: 0.2,
      historical: 0.1
    };

    return Object.keys(weights).reduce((sum, key) => {
      return sum + (scores[key] * weights[key]);
    }, 0);
  }

  calculateRiskLevel(score) {
    if (score >= 90) return 'CRITICAL';
    if (score >= 80) return 'HIGH';
    if (score >= 60) return 'MEDIUM';
    if (score >= 40) return 'LOW';
    return 'INFO';
  }
}
```

## Distributed Processing Architecture

### Multi-Node Threat Processing

```javascript
import { DistributedProcessor, ClusterCoordinator } from 'trojanhorse-js/enterprise';

class DistributedThreatIntelligence {
  constructor(nodeType = 'worker') {
    this.nodeType = nodeType;
    this.setupNode();
  }

  async setupNode() {
    if (this.nodeType === 'coordinator') {
      await this.setupCoordinator();
    } else {
      await this.setupWorker();
    }
  }

  async setupCoordinator() {
    this.coordinator = new ClusterCoordinator({
      redis: {
        host: 'redis-cluster.company.com',
        port: 6379
      },
      
      scheduling: {
        algorithm: 'load_balanced',
        maxTasksPerWorker: 100,
        taskTimeout: 300000 // 5 minutes
      },
      
      monitoring: {
        healthCheckInterval: 30000,
        metricsCollectionInterval: 10000
      }
    });

    // Task distribution logic
    this.coordinator.on('newTask', async (task) => {
      const worker = await this.coordinator.selectOptimalWorker(task);
      await this.coordinator.assignTask(worker, task);
    });

    // Handle worker failures
    this.coordinator.on('workerFailure', async (workerId, tasks) => {
      console.log(`Worker ${workerId} failed, redistributing ${tasks.length} tasks`);
      await this.coordinator.redistributeTasks(tasks);
    });

    console.log('🎯 Coordinator node started');
  }

  async setupWorker() {
    this.processor = new DistributedProcessor({
      workerId: `worker-${process.env.HOSTNAME || 'local'}`,
      coordinator: 'redis://redis-cluster.company.com:6379',
      
      capabilities: {
        maxConcurrentTasks: 10,
        supportedSources: ['urlhaus', 'alienvault', 'abuseipdb'],
        processingTypes: ['scan', 'correlate', 'enrich']
      },
      
      trojanHorse: {
        sources: ['urlhaus', 'alienvault', 'abuseipdb'],
        performance: {
          workers: 4,
          batchSize: 50
        }
      }
    });

    // Register task handlers
    this.processor.on('scanTask', async (task) => {
      const results = await this.processor.trojan.scout(task.indicators);
      return this.enrichResults(results, task);
    });

    this.processor.on('correlateTask', async (task) => {
      const correlations = await this.processor.trojan.correlate(
        task.indicator,
        { timeWindow: task.timeWindow }
      );
      return correlations;
    });

    this.processor.on('enrichTask', async (task) => {
      return await this.performEnrichment(task.indicator, task.context);
    });

    await this.processor.start();
    console.log(`🔧 Worker node ${this.processor.workerId} started`);
  }

  async submitLargeBatch(indicators) {
    if (this.nodeType !== 'coordinator') {
      throw new Error('Only coordinator can submit batch jobs');
    }

    // Split large batch into optimal chunks
    const chunks = this.chunkIndicators(indicators, 100);
    const jobId = `batch_${Date.now()}`;

    console.log(`📦 Submitting batch job ${jobId} with ${chunks.length} chunks`);

    const promises = chunks.map((chunk, index) => 
      this.coordinator.submitTask({
        id: `${jobId}_chunk_${index}`,
        type: 'scanTask',
        indicators: chunk,
        priority: 'normal',
        metadata: {
          jobId: jobId,
          chunkIndex: index,
          totalChunks: chunks.length
        }
      })
    );

    // Wait for all chunks to complete
    const results = await Promise.all(promises);
    
    // Consolidate results
    const consolidatedResults = this.consolidateResults(results);
    
    console.log(`✅ Batch job ${jobId} completed: ${consolidatedResults.length} threats found`);
    
    return {
      jobId: jobId,
      totalIndicators: indicators.length,
      threatsFound: consolidatedResults.length,
      results: consolidatedResults,
      processingTime: Date.now() - parseInt(jobId.split('_')[1])
    };
  }

  chunkIndicators(indicators, chunkSize) {
    const chunks = [];
    for (let i = 0; i < indicators.length; i += chunkSize) {
      chunks.push(indicators.slice(i, i + chunkSize));
    }
    return chunks;
  }

  consolidateResults(chunkResults) {
    return chunkResults.flat().filter(result => 
      result && result.threats && result.threats.length > 0
    );
  }

  async performEnrichment(indicator, context) {
    // Perform additional enrichment based on context
    const enrichment = {
      whoisData: await this.getWhoisData(indicator),
      dnsData: await this.getDNSData(indicator),
      geoData: await this.getGeoLocationData(indicator),
      historicalData: await this.getHistoricalData(indicator),
      relationshipData: await this.getRelationshipData(indicator)
    };

    return {
      indicator: indicator,
      enrichment: enrichment,
      enrichedAt: new Date().toISOString()
    };
  }
}

// Example usage for different node types
const nodeType = process.env.NODE_TYPE || 'worker';
const distributedTI = new DistributedThreatIntelligence(nodeType);

// For coordinator nodes - submit large batch jobs
if (nodeType === 'coordinator') {
  // Example: Process a large list of indicators
  const indicators = [
    // ... thousands of indicators from various sources
  ];
  
  distributedTI.submitLargeBatch(indicators).then(results => {
    console.log('Batch processing completed:', results);
  });
}
```

## Real-time Threat Streaming

### High-Volume Real-time Processing

```javascript
import { StreamingProcessor, RealTimeAnalytics } from 'trojanhorse-js/enterprise';

class RealTimeThreatStream {
  constructor() {
    this.setupStreamProcessor();
    this.setupAnalytics();
    this.setupAlertingSystem();
  }

  setupStreamProcessor() {
    this.streamer = new StreamingProcessor({
      input: {
        kafka: {
          brokers: ['kafka-1:9092', 'kafka-2:9092', 'kafka-3:9092'],
          topics: ['threat-feeds', 'external-intel', 'user-submissions'],
          groupId: 'trojanhorse-stream-processor'
        }
      },
      
      processing: {
        batchSize: 1000,
        maxWaitTime: 5000, // 5 seconds
        parallelism: 8
      },
      
      output: {
        kafka: {
          topics: ['processed-threats', 'high-priority-alerts'],
          compression: 'gzip'
        },
        elasticsearch: {
          index: 'threat-intelligence-stream',
          refresh: 'wait_for'
        }
      }
    });

    // Real-time threat processing pipeline
    this.streamer.process(async (batch) => {
      const processed = [];
      
      for (const message of batch) {
        try {
          const indicator = this.extractIndicator(message);
          const results = await this.quickScan(indicator);
          
          if (results.length > 0) {
            const enriched = await this.fastEnrich(results[0]);
            processed.push(enriched);
            
            // Real-time alerting for high-confidence threats
            if (enriched.confidence >= 90) {
              await this.sendRealTimeAlert(enriched);
            }
          }
        } catch (error) {
          console.error('Error processing message:', error);
        }
      }
      
      return processed;
    });
  }

  async quickScan(indicator) {
    // Optimized scanning for real-time processing
    return await this.trojan.scout(indicator, {
      sources: ['urlhaus', 'alienvault'], // Use fastest sources only
      timeout: 2000, // 2 second timeout
      cache: true
    });
  }

  async fastEnrich(threat) {
    // Fast enrichment with caching
    const enrichment = await Promise.race([
      this.getBasicEnrichment(threat),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Enrichment timeout')), 1000)
      )
    ]).catch(() => ({})); // Fallback to empty enrichment

    return {
      ...threat,
      enrichment,
      processedAt: new Date().toISOString(),
      streamId: `stream_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    };
  }

  async sendRealTimeAlert(threat) {
    // Multiple alert channels for critical threats
    await Promise.all([
      this.sendToSlack(threat),
      this.sendToSIEM(threat),
      this.updateThreatIntelPlatform(threat)
    ]);
  }

  setupAnalytics() {
    this.analytics = new RealTimeAnalytics({
      retention: '24h',
      aggregationWindows: ['1m', '5m', '15m', '1h'],
      
      metrics: [
        'threats_per_second',
        'confidence_distribution',
        'source_performance',
        'processing_latency'
      ]
    });

    // Real-time metric collection
    this.streamer.on('processed', (batch) => {
      this.analytics.recordBatch({
        count: batch.length,
        avgConfidence: batch.reduce((sum, t) => sum + t.confidence, 0) / batch.length,
        processingTime: Date.now() - batch.startTime
      });
    });
  }

  setupAlertingSystem() {
    // Threshold-based alerting
    this.analytics.on('metric', (metric) => {
      if (metric.name === 'threats_per_second' && metric.value > 100) {
        this.sendAlert({
          type: 'high_volume',
          message: `High threat volume detected: ${metric.value} threats/second`,
          severity: 'warning'
        });
      }
      
      if (metric.name === 'processing_latency' && metric.value > 5000) {
        this.sendAlert({
          type: 'performance',
          message: `High processing latency: ${metric.value}ms`,
          severity: 'critical'
        });
      }
    });
  }

  async startStreaming() {
    console.log('🌊 Starting real-time threat streaming...');
    
    await this.streamer.start();
    await this.analytics.start();
    
    console.log('✅ Real-time threat streaming is active');
    
    // Health monitoring
    setInterval(async () => {
      const health = await this.checkHealth();
      if (!health.healthy) {
        console.error('❌ Stream health check failed:', health.issues);
      }
    }, 30000);
  }

  async checkHealth() {
    const health = {
      healthy: true,
      issues: []
    };

    try {
      // Check Kafka connectivity
      await this.streamer.ping();
    } catch (error) {
      health.healthy = false;
      health.issues.push('Kafka connectivity issue');
    }

    // Check processing metrics
    const recentMetrics = await this.analytics.getRecentMetrics('5m');
    if (recentMetrics.processing_latency > 10000) {
      health.healthy = false;
      health.issues.push('High processing latency');
    }

    return health;
  }
}

// Start the real-time streaming system
const realTimeStream = new RealTimeThreatStream();
realTimeStream.startStreaming();
```

---

**Next Steps**: Explore [API Reference](../api/core.md) for detailed API documentation or check [Enterprise Features](../enterprise/features.md) for advanced capabilities.
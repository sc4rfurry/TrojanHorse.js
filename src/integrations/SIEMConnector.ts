/**
 * TrojanHorse.js SIEM Integration
 * Enterprise SIEM connector for real-time threat intelligence sharing
 */

import { EventEmitter } from 'events';
import axios, { AxiosInstance } from 'axios';

// ===== SIEM INTERFACES =====

export interface SIEMConfig {
  type: 'splunk' | 'qradar' | 'elastic' | 'sentinel' | 'generic';
  endpoint: string;
  apiKey?: string;
  username?: string;
  password?: string;
  timeout?: number;
  retries?: number;
  batchSize?: number;
  flushInterval?: number;
}

export interface SIEMEvent {
  timestamp: Date;
  source: string;
  eventType: 'threat_detected' | 'indicator_added' | 'alert_generated';
  severity: 'low' | 'medium' | 'high' | 'critical';
  data: any;
  metadata?: Record<string, any>;
}

// ===== BASE SIEM CONNECTOR =====

abstract class BaseSIEMConnector extends EventEmitter {
  protected config: SIEMConfig;
  protected httpClient: AxiosInstance;
  protected eventQueue: SIEMEvent[] = [];

  constructor(config: SIEMConfig) {
    super();
    this.config = config;
    this.httpClient = axios.create({
      baseURL: config.endpoint,
      timeout: config.timeout || 30000,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'TrojanHorse.js/1.0.1'
      }
    });

    this.setupAuthentication();
    this.setupInterceptors();
  }

  private setupAuthentication(): void {
    if (this.config.apiKey) {
      this.httpClient.defaults.headers.common['Authorization'] = `Bearer ${this.config.apiKey}`;
    } else if (this.config.username && this.config.password) {
      this.httpClient.defaults.auth = {
        username: this.config.username,
        password: this.config.password
      };
    }
  }

  private setupInterceptors(): void {
    this.httpClient.interceptors.response.use(
      (response) => {
        this.emit('siem_success', { response: response.data });
        return response;
      },
      (error) => {
        const errorMessage = error instanceof Error ? error.message : String(error);
        this.emit('siem_error', { error: errorMessage });
        return Promise.reject(error);
      }
    );
  }

  // Abstract methods to be implemented by specific SIEM connectors
  abstract sendEvent(event: SIEMEvent): Promise<void>;
  abstract formatEvent(event: SIEMEvent): any;
  abstract validateConnection(): Promise<boolean>;

  // Common methods
  public async sendEvents(events: SIEMEvent[]): Promise<void> {
    for (const event of events) {
      try {
        await this.sendEvent(event);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        this.emit('send_error', { event, error: errorMessage });
      }
    }
  }

  public queueEvent(event: SIEMEvent): void {
    this.eventQueue.push(event);
    
    if (this.eventQueue.length >= (this.config.batchSize || 100)) {
      this.flushQueue();
    }
  }

  public async flushQueue(): Promise<void> {
    if (this.eventQueue.length === 0) {
      return;
    }

    const events = this.eventQueue.splice(0);
    await this.sendEvents(events);
  }

  public getQueueSize(): number {
    return this.eventQueue.length;
  }
}

// ===== SPLUNK CONNECTOR =====

class SplunkConnector extends BaseSIEMConnector {
  public async sendEvent(event: SIEMEvent): Promise<void> {
    const formattedEvent = this.formatEvent(event);
    
    await this.httpClient.post('/services/collector/event', {
      event: formattedEvent,
      time: Math.floor(event.timestamp.getTime() / 1000),
      source: 'trojanhorse-js',
      sourcetype: 'threat_intelligence'
    });
  }

  public formatEvent(event: SIEMEvent): any {
    return {
      timestamp: event.timestamp.toISOString(),
      source: event.source,
      event_type: event.eventType,
      severity: event.severity,
      data: event.data,
      metadata: event.metadata
    };
  }

  public async validateConnection(): Promise<boolean> {
    try {
      await this.httpClient.get('/services/server/info');
      return true;
    } catch (error) {
      return false;
    }
  }
}

// ===== QRADAR CONNECTOR =====

class QRadarConnector extends BaseSIEMConnector {
  public async sendEvent(event: SIEMEvent): Promise<void> {
    const formattedEvent = this.formatEvent(event);
    
    await this.httpClient.post('/api/siem/offenses', formattedEvent);
  }

  public formatEvent(event: SIEMEvent): any {
    return {
      offense_type: event.eventType,
      severity: this.mapSeverity(event.severity),
      description: `TrojanHorse.js: ${event.eventType}`,
      source_address_ids: [],
      local_destination_address_ids: [],
      remote_destination_count: 0,
      start_time: event.timestamp.getTime(),
      event_count: 1,
      flow_count: 0,
      offense_source: event.source,
      categories: ['Threat Intelligence'],
      custom_properties: event.data
    };
  }

  private mapSeverity(severity: string): number {
    const mapping = {
      'low': 3,
      'medium': 5,
      'high': 7,
      'critical': 10
    };
    return mapping[severity as keyof typeof mapping] || 5;
  }

  public async validateConnection(): Promise<boolean> {
    try {
      await this.httpClient.get('/api/system/about');
      return true;
    } catch (error) {
      return false;
    }
  }
}

// ===== ELASTIC CONNECTOR =====

class ElasticConnector extends BaseSIEMConnector {
  public async sendEvent(event: SIEMEvent): Promise<void> {
    const formattedEvent = this.formatEvent(event);
    const index = `trojanhorse-${new Date().toISOString().slice(0, 7)}`; // monthly indices
    
    await this.httpClient.post(`/${index}/_doc`, formattedEvent);
  }

  public formatEvent(event: SIEMEvent): any {
    return {
      '@timestamp': event.timestamp.toISOString(),
      event: {
        category: 'threat',
        type: event.eventType,
        severity: event.severity,
        dataset: 'trojanhorse.threat_intelligence'
      },
      source: {
        name: event.source
      },
      threat: event.data,
      tags: ['trojanhorse', 'threat-intelligence'],
      metadata: event.metadata
    };
  }

  public async validateConnection(): Promise<boolean> {
    try {
      await this.httpClient.get('/');
      return true;
    } catch (error) {
      return false;
    }
  }
}

// ===== SIEM MANAGER =====

class SIEMManager extends EventEmitter {
  private connectors: Map<string, BaseSIEMConnector> = new Map();

  public addConnector(name: string, config: SIEMConfig): void {
    let connector: BaseSIEMConnector;

    switch (config.type) {
    case 'splunk':
      connector = new SplunkConnector(config);
      break;
    case 'qradar':
      connector = new QRadarConnector(config);
      break;
    case 'elastic':
      connector = new ElasticConnector(config);
      break;
    default:
      throw new Error(`Unsupported SIEM type: ${config.type}`);
    }

    // Forward events
    connector.on('siem_success', (data) => this.emit('connector_success', { name, ...data }));
    connector.on('siem_error', (data) => this.emit('connector_error', { name, ...data }));

    this.connectors.set(name, connector);
  }

  public async sendEvent(event: SIEMEvent, connectorNames?: string[]): Promise<void> {
    const targets = connectorNames || Array.from(this.connectors.keys());

    const promises = targets.map(async (name) => {
      const connector = this.connectors.get(name);
      if (connector) {
        await connector.sendEvent(event);
      }
    });

    await Promise.allSettled(promises);
  }

  public async validateConnections(): Promise<Record<string, boolean>> {
    const results: Record<string, boolean> = {};

    for (const [name, connector] of this.connectors) {
      try {
        results[name] = await connector.validateConnection();
      } catch (error) {
        results[name] = false;
      }
    }

    return results;
  }

  public getConnector(name: string): BaseSIEMConnector | undefined {
    return this.connectors.get(name);
  }

  public listConnectors(): string[] {
    return Array.from(this.connectors.keys());
  }
}

// Export classes and types
export { BaseSIEMConnector, SplunkConnector, QRadarConnector, ElasticConnector, SIEMManager }; 
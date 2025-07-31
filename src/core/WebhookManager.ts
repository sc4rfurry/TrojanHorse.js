/**
 * Webhook Manager for Real-time Threat Alerts
 * 
 * Provides secure webhook delivery, retry logic, signature verification,
 * and event filtering for threat intelligence notifications.
 */

import { EventEmitter } from 'events';
import axios, { AxiosResponse } from 'axios';
import crypto from 'crypto';
import { ThreatIndicator } from '../types';

export interface WebhookConfig {
  id: string;
  name: string;
  url: string;
  secret: string;
  events: WebhookEvent[];
  headers?: Record<string, string>;
  timeout?: number;
  retries?: number;
  retryDelay?: number;
  enabled: boolean;
  filters?: WebhookFilter[];
  rateLimit?: {
    maxRequests: number;
    windowMs: number;
  };
}

export type WebhookEvent = 
  | 'threat.detected'
  | 'threat.high_confidence'
  | 'threat.critical'
  | 'feed.updated'
  | 'feed.error'
  | 'system.alert'
  | 'batch.completed'
  | 'correlation.completed';

export interface WebhookFilter {
  field: string;
  operator: 'equals' | 'contains' | 'greater_than' | 'less_than' | 'regex';
  value: string | number;
}

export interface WebhookPayload {
  id: string;
  event: WebhookEvent;
  timestamp: string;
  data: any;
  metadata: {
    source: string;
    version: string;
    environment: string;
  };
}

export interface WebhookDelivery {
  id: string;
  webhookId: string;
  event: WebhookEvent;
  payload: WebhookPayload;
  attempt: number;
  status: 'pending' | 'success' | 'failed' | 'retrying';
  responseCode?: number;
  responseTime?: number;
  error?: string;
  createdAt: Date;
  deliveredAt?: Date;
  nextRetryAt?: Date;
}

export class WebhookManager extends EventEmitter {
  private webhooks: Map<string, WebhookConfig> = new Map();
  private deliveries: Map<string, WebhookDelivery> = new Map();
  private rateLimiters: Map<string, { requests: number; windowStart: number }> = new Map();
  private retryQueue: WebhookDelivery[] = [];
  private retryTimer?: NodeJS.Timeout;

  constructor() {
    super();
    this.startRetryProcessor();
  }

  /**
   * Register a new webhook
   */
  public registerWebhook(config: WebhookConfig): void {
    this.validateWebhookConfig(config);
    this.webhooks.set(config.id, config);
    this.emit('webhook:registered', config);
  }

  /**
   * Unregister a webhook
   */
  public unregisterWebhook(webhookId: string): boolean {
    const webhook = this.webhooks.get(webhookId);
    if (webhook) {
      this.webhooks.delete(webhookId);
      this.emit('webhook:unregistered', webhook);
      return true;
    }
    return false;
  }

  /**
   * Update webhook configuration
   */
  public updateWebhook(webhookId: string, updates: Partial<WebhookConfig>): boolean {
    const webhook = this.webhooks.get(webhookId);
    if (webhook) {
      const updatedWebhook = { ...webhook, ...updates };
      this.validateWebhookConfig(updatedWebhook);
      this.webhooks.set(webhookId, updatedWebhook);
      this.emit('webhook:updated', updatedWebhook);
      return true;
    }
    return false;
  }

  /**
   * Trigger a webhook event
   */
  public async triggerEvent(event: WebhookEvent, data: any, metadata?: any): Promise<void> {
    const eligibleWebhooks = Array.from(this.webhooks.values())
      .filter(webhook => webhook.enabled)
      .filter(webhook => webhook.events.includes(event))
      .filter(webhook => this.passesFilters(webhook, data));

    const payload: WebhookPayload = {
      id: this.generateId(),
      event,
      timestamp: new Date().toISOString(),
      data,
      metadata: {
        source: 'TrojanHorse.js',
        version: '1.0.1',
        environment: process.env.NODE_ENV || 'development',
        ...metadata
      }
    };

    const deliveryPromises = eligibleWebhooks.map(webhook => 
      this.deliverWebhook(webhook, payload)
    );

    await Promise.allSettled(deliveryPromises);
    
    this.emit('event:triggered', {
      event,
      webhookCount: eligibleWebhooks.length,
      payload
    });
  }

  /**
   * Deliver a webhook
   */
  private async deliverWebhook(webhook: WebhookConfig, payload: WebhookPayload): Promise<void> {
    // Check rate limiting
    if (!this.checkRateLimit(webhook)) {
      this.emit('webhook:rate_limited', { webhookId: webhook.id });
      return;
    }

    const delivery: WebhookDelivery = {
      id: this.generateId(),
      webhookId: webhook.id,
      event: payload.event,
      payload,
      attempt: 1,
      status: 'pending',
      createdAt: new Date()
    };

    this.deliveries.set(delivery.id, delivery);

    try {
      await this.sendWebhook(webhook, delivery);
    } catch (error) {
      await this.handleDeliveryFailure(webhook, delivery, error);
    }
  }

  /**
   * Send webhook HTTP request
   */
  private async sendWebhook(webhook: WebhookConfig, delivery: WebhookDelivery): Promise<void> {
    const signature = this.generateSignature(webhook.secret, delivery.payload);
    const startTime = Date.now();

    try {
      const response: AxiosResponse = await axios.post(webhook.url, delivery.payload, {
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'TrojanHorse.js-Webhook/1.0.1',
          'X-TrojanHorse-Signature': signature,
          'X-TrojanHorse-Event': delivery.event,
          'X-TrojanHorse-Delivery': delivery.id,
          'X-TrojanHorse-Timestamp': delivery.payload.timestamp,
          ...webhook.headers
        },
        timeout: webhook.timeout || 10000,
        validateStatus: (status) => status >= 200 && status < 300
      });

      const responseTime = Date.now() - startTime;

      // Update delivery record
      delivery.status = 'success';
      delivery.responseCode = response.status;
      delivery.responseTime = responseTime;
      delivery.deliveredAt = new Date();

      this.emit('webhook:delivered', {
        webhookId: webhook.id,
        deliveryId: delivery.id,
        responseTime,
        attempt: delivery.attempt
      });

    } catch (error: any) {
      const responseTime = Date.now() - startTime;
      delivery.responseTime = responseTime;
      delivery.responseCode = error.response?.status;
      delivery.error = error.message;

      throw error;
    }
  }

  /**
   * Handle delivery failure and retry logic
   */
  private async handleDeliveryFailure(
    webhook: WebhookConfig, 
    delivery: WebhookDelivery, 
    error: any
  ): Promise<void> {
    const maxRetries = webhook.retries || 3;
    const retryDelay = webhook.retryDelay || 5000;

    delivery.status = 'failed';
    delivery.error = error.message;

    if (delivery.attempt < maxRetries) {
      // Schedule retry
      delivery.status = 'retrying';
      delivery.nextRetryAt = new Date(Date.now() + (retryDelay * Math.pow(2, delivery.attempt - 1)));
      this.retryQueue.push(delivery);

      this.emit('webhook:retry_scheduled', {
        webhookId: webhook.id,
        deliveryId: delivery.id,
        attempt: delivery.attempt,
        nextRetryAt: delivery.nextRetryAt
      });
    } else {
      // Max retries exceeded
      this.emit('webhook:failed', {
        webhookId: webhook.id,
        deliveryId: delivery.id,
        finalAttempt: delivery.attempt,
        error: error.message
      });
    }
  }

  /**
   * Start retry processor
   */
  private startRetryProcessor(): void {
    this.retryTimer = setInterval(() => {
      this.processRetryQueue();
    }, 5000); // Check every 5 seconds
  }

  /**
   * Process retry queue
   */
  private async processRetryQueue(): Promise<void> {
    const now = new Date();
    const readyRetries = this.retryQueue.filter(delivery => 
      delivery.nextRetryAt && delivery.nextRetryAt <= now
    );

    if (readyRetries.length === 0) {
      return;
    }

    // Remove processed items from queue
    this.retryQueue = this.retryQueue.filter(delivery =>
      !readyRetries.includes(delivery)
    );

    for (const delivery of readyRetries) {
      const webhook = this.webhooks.get(delivery.webhookId);
      if (!webhook || !webhook.enabled) {
        continue;
      }

      delivery.attempt++;
      delivery.status = 'pending';
      delete delivery.nextRetryAt;

      try {
        await this.sendWebhook(webhook, delivery);
      } catch (error) {
        await this.handleDeliveryFailure(webhook, delivery, error);
      }
    }
  }

  /**
   * Check rate limiting for webhook
   */
  private checkRateLimit(webhook: WebhookConfig): boolean {
    if (!webhook.rateLimit) {
      return true;
    }

    const now = Date.now();
    const limiter = this.rateLimiters.get(webhook.id) || {
      requests: 0,
      windowStart: now
    };

    // Reset window if expired
    if (now - limiter.windowStart >= webhook.rateLimit.windowMs) {
      limiter.requests = 0;
      limiter.windowStart = now;
    }

    // Check if under limit
    if (limiter.requests < webhook.rateLimit.maxRequests) {
      limiter.requests++;
      this.rateLimiters.set(webhook.id, limiter);
      return true;
    }

    return false;
  }

  /**
   * Check if data passes webhook filters
   */
  private passesFilters(webhook: WebhookConfig, data: any): boolean {
    if (!webhook.filters || webhook.filters.length === 0) {
      return true;
    }

    return webhook.filters.every(filter => {
      const fieldValue = this.getFieldValue(data, filter.field);
      return this.evaluateFilter(fieldValue, filter);
    });
  }

  /**
   * Get field value from data object
   */
  private getFieldValue(data: any, field: string): any {
    const parts = field.split('.');
    let value = data;

    for (const part of parts) {
      if (value && typeof value === 'object' && part in value) {
        value = value[part];
      } else {
        return undefined;
      }
    }

    return value;
  }

  /**
   * Evaluate filter condition
   */
  private evaluateFilter(value: any, filter: WebhookFilter): boolean {
    switch (filter.operator) {
    case 'equals':
      return value === filter.value;
      
    case 'contains':
      return typeof value === 'string' && value.includes(String(filter.value));
      
    case 'greater_than':
      return typeof value === 'number' && value > Number(filter.value);
      
    case 'less_than':
      return typeof value === 'number' && value < Number(filter.value);
      
    case 'regex':
      return typeof value === 'string' && new RegExp(String(filter.value)).test(value);
      
    default:
      return false;
    }
  }

  /**
   * Generate webhook signature
   */
  private generateSignature(secret: string, payload: WebhookPayload): string {
    const data = JSON.stringify(payload);
    return crypto
      .createHmac('sha256', secret)
      .update(data)
      .digest('hex');
  }

  /**
   * Verify webhook signature
   */
  public verifySignature(secret: string, payload: WebhookPayload, signature: string): boolean {
    const expectedSignature = this.generateSignature(secret, payload);
    return crypto.timingSafeEqual(
      Buffer.from(signature, 'hex'),
      Buffer.from(expectedSignature, 'hex')
    );
  }

  /**
   * Generate unique ID
   */
  private generateId(): string {
    return crypto.randomBytes(16).toString('hex');
  }

  /**
   * Validate webhook configuration
   */
  private validateWebhookConfig(config: WebhookConfig): void {
    if (!config.id || !config.url || !config.secret) {
      throw new Error('Webhook must have id, url, and secret');
    }

    if (!config.events || config.events.length === 0) {
      throw new Error('Webhook must specify at least one event');
    }

    // Validate URL
    try {
      new URL(config.url);
    } catch {
      throw new Error('Invalid webhook URL');
    }

    // Validate secret length
    if (config.secret.length < 16) {
      throw new Error('Webhook secret must be at least 16 characters');
    }
  }

  /**
   * Get webhook statistics
   */
  public getWebhookStats(webhookId?: string): any {
    const deliveries = Array.from(this.deliveries.values());
    const filteredDeliveries = webhookId 
      ? deliveries.filter(d => d.webhookId === webhookId)
      : deliveries;

    const stats = {
      total: filteredDeliveries.length,
      successful: filteredDeliveries.filter(d => d.status === 'success').length,
      failed: filteredDeliveries.filter(d => d.status === 'failed').length,
      pending: filteredDeliveries.filter(d => d.status === 'pending').length,
      retrying: filteredDeliveries.filter(d => d.status === 'retrying').length,
      averageResponseTime: 0,
      retryQueueSize: this.retryQueue.length
    };

    const successfulDeliveries = filteredDeliveries.filter(d => 
      d.status === 'success' && d.responseTime
    );

    if (successfulDeliveries.length > 0) {
      stats.averageResponseTime = Math.round(
        successfulDeliveries.reduce((sum, d) => sum + (d.responseTime || 0), 0) / 
        successfulDeliveries.length
      );
    }

    return stats;
  }

  /**
   * Get delivery history
   */
  public getDeliveryHistory(webhookId?: string, limit = 100): WebhookDelivery[] {
    let deliveries = Array.from(this.deliveries.values());
    
    if (webhookId) {
      deliveries = deliveries.filter(d => d.webhookId === webhookId);
    }

    return deliveries
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
      .slice(0, limit);
  }

  /**
   * Clean up old delivery records
   */
  public cleanupDeliveries(maxAge = 7 * 24 * 60 * 60 * 1000): number { // 7 days default
    const cutoff = new Date(Date.now() - maxAge);
    let cleaned = 0;

    for (const [id, delivery] of this.deliveries.entries()) {
      if (delivery.createdAt < cutoff) {
        this.deliveries.delete(id);
        cleaned++;
      }
    }

    return cleaned;
  }

  /**
   * Shutdown webhook manager
   */
  public shutdown(): void {
    if (this.retryTimer) {
      clearInterval(this.retryTimer);
      delete this.retryTimer;
    }

    this.emit('shutdown');
  }
}

/**
 * Webhook event builder for common scenarios
 */
export class WebhookEventBuilder {
  /**
   * Build threat detected event
   */
  static threatDetected(result: any, target: string): { event: WebhookEvent; data: any } {
    return {
      event: 'threat.detected',
      data: {
        target,
        correlationScore: result.correlationScore,
        consensusLevel: result.consensusLevel,
        riskScore: result.riskScore,
        sources: result.sources,
        indicatorCount: result.indicators.length,
        patterns: result.patterns,
        summary: {
          threatLevel: result.correlationScore > 0.8 ? 'critical' : 
            result.correlationScore > 0.6 ? 'high' :
              result.correlationScore > 0.4 ? 'medium' : 'low',
          confidence: result.correlationScore,
          recommendation: result.correlationScore > 0.7 ? 'block' : 'monitor'
        }
      }
    };
  }

  /**
   * Build high confidence threat event
   */
  static highConfidenceThreat(indicator: ThreatIndicator, target: string): { event: WebhookEvent; data: any } {
    return {
      event: 'threat.high_confidence',
      data: {
        target,
        indicator: {
          type: indicator.type,
          value: indicator.value,
          confidence: indicator.confidence,
          severity: indicator.severity,
          source: indicator.source,
          tags: indicator.tags,
          malwareFamily: indicator.malwareFamily
        },
        alert: {
          priority: 'high',
          action: 'immediate_review',
          message: `High confidence ${indicator.type} threat detected: ${indicator.value}`
        }
      }
    };
  }

  /**
   * Build feed error event
   */
  static feedError(feedName: string, error: string): { event: WebhookEvent; data: any } {
    return {
      event: 'feed.error',
      data: {
        feed: feedName,
        error,
        timestamp: new Date().toISOString(),
        impact: 'reduced_coverage',
        recommendation: 'check_api_keys_and_connectivity'
      }
    };
  }

  /**
   * Build batch completed event
   */
  static batchCompleted(summary: any): { event: WebhookEvent; data: any } {
    return {
      event: 'batch.completed',
      data: {
        summary,
        completed_at: new Date().toISOString(),
        performance: {
          throughput: summary.total / (summary.processingTime / 1000),
          success_rate: (summary.successful / summary.total) * 100
        }
      }
    };
  }
}

/**
 * Utility function to create webhook manager with common configurations
 */
export function createWebhookManager(presets?: {
  slack?: { url: string; events?: WebhookEvent[] };
  discord?: { url: string; events?: WebhookEvent[] };
  teams?: { url: string; events?: WebhookEvent[] };
  custom?: WebhookConfig[];
}): WebhookManager {
  const manager = new WebhookManager();

  if (presets?.slack) {
    manager.registerWebhook({
      id: 'slack-alerts',
      name: 'Slack Notifications',
      url: presets.slack.url,
      secret: crypto.randomBytes(32).toString('hex'),
      events: presets.slack.events || ['threat.high_confidence', 'threat.critical'],
      enabled: true,
      timeout: 10000,
      retries: 3
    });
  }

  if (presets?.discord) {
    manager.registerWebhook({
      id: 'discord-alerts',
      name: 'Discord Notifications',
      url: presets.discord.url,
      secret: crypto.randomBytes(32).toString('hex'),
      events: presets.discord.events || ['threat.detected', 'feed.error'],
      enabled: true,
      timeout: 10000,
      retries: 3
    });
  }

  if (presets?.teams) {
    manager.registerWebhook({
      id: 'teams-alerts',
      name: 'Microsoft Teams',
      url: presets.teams.url,
      secret: crypto.randomBytes(32).toString('hex'),
      events: presets.teams.events || ['threat.critical', 'system.alert'],
      enabled: true,
      timeout: 10000,
      retries: 3
    });
  }

  if (presets?.custom) {
    presets.custom.forEach(config => {
      manager.registerWebhook(config);
    });
  }

  return manager;
} 
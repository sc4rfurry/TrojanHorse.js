/**
 * TrojanHorse.js Real-Time Analytics Engine
 * Enterprise-grade threat analytics and monitoring
 */

import { EventEmitter } from 'events';
// import { WebSocket } from 'ws'; // TODO: Implement WebSocket analytics
import nodemailer from 'nodemailer';

// ===== ANALYTICS INTERFACES =====

export interface MetricPoint {
  timestamp: Date;
  metric: string;
  value: number;
  labels: Record<string, string>;
  unit: 'count' | 'rate' | 'gauge' | 'histogram' | 'bytes' | 'milliseconds';
  metadata?: Record<string, any>;
}

export interface Alert {
  id: string;
  title: string;
  description: string;
  severity: 'info' | 'warning' | 'critical' | 'emergency';
  category: 'performance' | 'security' | 'system' | 'business';
  source: string;
  timestamp: Date;
  resolved: boolean;
  metadata?: Record<string, any>;
}

export interface NotificationChannel {
  type: 'email' | 'slack' | 'webhook' | 'pagerduty';
  config: any;
  enabled: boolean;
}

export interface AnalyticsConfig {
  retention: {
    metrics: number; // days
    alerts: number; // days
    logs: number; // days
  };
  notifications: NotificationChannel[];
  aggregation: {
    intervals: string[];
    defaultInterval: string;
  };
}

// ===== METRICS COLLECTOR =====

class MetricsCollector extends EventEmitter {
  private metrics: Map<string, MetricPoint[]> = new Map();
  private config: AnalyticsConfig;

  constructor(config: AnalyticsConfig) {
    super();
    this.config = config;
  }

  public recordMetric(point: MetricPoint): void {
    const key = `${point.metric}:${JSON.stringify(point.labels)}`;
    if (!this.metrics.has(key)) {
      this.metrics.set(key, []);
    }
    this.metrics.get(key)!.push(point);
    this.emit('metric_recorded', point);
  }

  public queryMetrics(query: {
    metric: string;
    from: Date;
    to: Date;
    aggregation?: 'sum' | 'avg' | 'min' | 'max' | 'count';
    groupBy?: string[];
    filters?: Record<string, string>;
  }): MetricPoint[] {
    const key = `${query.metric}:${JSON.stringify(query.filters || {})}`;
    const points = this.metrics.get(key) || [];
    
    return points.filter(p => 
      p.timestamp >= query.from && p.timestamp <= query.to
    );
  }

  public getMetrics(): Map<string, MetricPoint[]> {
    return this.metrics;
  }
}

// ===== ALERTING ENGINE =====

class AlertingEngine extends EventEmitter {
  private alerts: Map<string, Alert> = new Map();
  private config: AnalyticsConfig;

  constructor(config: AnalyticsConfig) {
    super();
    this.config = config;
  }

  public createAlert(alert: Omit<Alert, 'id' | 'timestamp' | 'resolved'>): string {
    const id = `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const fullAlert: Alert = {
      id,
      timestamp: new Date(),
      resolved: false,
      ...alert
    };
    
    this.alerts.set(id, fullAlert);
    this.emit('alert_created', fullAlert);
    this.sendNotifications(fullAlert);
    
    return id;
  }

  public resolveAlert(alertId: string): boolean {
    const alert = this.alerts.get(alertId);
    if (alert) {
      alert.resolved = true;
      this.emit('alert_resolved', alert);
      return true;
    }
    return false;
  }

  public getAlerts(): Alert[] {
    return Array.from(this.alerts.values());
  }

  private async sendNotifications(alert: Alert): Promise<void> {
    for (const channel of this.config.notifications) {
      if (!channel.enabled) {
        continue;
      }

      try {
        switch (channel.type) {
        case 'email':
          await this.sendEmailNotification(alert, channel.config);
          break;
        case 'slack':
          await this.sendSlackNotification(alert, channel.config);
          break;
        case 'webhook':
          await this.sendWebhookNotification(alert, channel.config);
          break;
        case 'pagerduty':
          await this.sendPagerDutyNotification(alert, channel.config);
          break;
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        this.emit('notification_error', { channel: channel.type, error: errorMessage });
      }
    }
  }

  private async sendEmailNotification(alert: Alert, config: any): Promise<void> {
    try {
      const transporter = nodemailer.createTransport({
        host: config.smtp?.host || 'localhost',
        port: config.smtp?.port || 587,
        secure: config.smtp?.secure || false,
        auth: config.smtp?.auth ? {
          user: config.smtp.auth.user,
          pass: config.smtp.auth.pass
        } : undefined
      });

      const mailOptions = {
        from: config.from || 'alerts@trojanhorse.enterprise.com',
        to: config.to || 'security@company.com',
        subject: `🚨 TrojanHorse Alert: ${alert.title}`,
        html: this.generateAlertEmailHTML(alert),
        text: this.generateAlertEmailText(alert)
      };

      const result = await transporter.sendMail(mailOptions);
      
      if (!result.messageId) {
        throw new Error('Email sending failed - no message ID returned');
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      throw new Error(`Email notification failed: ${errorMessage}`);
    }
  }

  private generateAlertEmailHTML(alert: Alert): string {
    const severityColor = this.getSeverityColor(alert.severity);
    
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>TrojanHorse Security Alert</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
          .container { max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
          .header { background-color: ${severityColor}; color: white; padding: 20px; border-radius: 8px 8px 0 0; }
          .content { padding: 20px; }
          .severity { display: inline-block; padding: 4px 12px; border-radius: 4px; color: white; font-weight: bold; background-color: ${severityColor}; }
          .metadata { background-color: #f8f9fa; padding: 15px; border-radius: 4px; margin: 15px 0; }
          .footer { background-color: #f8f9fa; padding: 15px; border-radius: 0 0 8px 8px; text-align: center; font-size: 12px; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🚨 Security Alert</h1>
            <h2>${alert.title}</h2>
          </div>
          <div class="content">
            <p><strong>Severity:</strong> <span class="severity">${alert.severity.toUpperCase()}</span></p>
            <p><strong>Category:</strong> ${alert.category}</p>
            <p><strong>Source:</strong> ${alert.source}</p>
            <p><strong>Timestamp:</strong> ${alert.timestamp.toISOString()}</p>
            <div class="metadata">
              <h3>Description</h3>
              <p>${alert.description}</p>
              ${alert.metadata ? `
                <h3>Additional Details</h3>
                <pre>${JSON.stringify(alert.metadata, null, 2)}</pre>
              ` : ''}
            </div>
          </div>
          <div class="footer">
            <p>This alert was generated by TrojanHorse.js Enterprise Security Platform</p>
            <p>Alert ID: ${alert.id}</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  private generateAlertEmailText(alert: Alert): string {
    return `
TrojanHorse Security Alert

Title: ${alert.title}
Severity: ${alert.severity.toUpperCase()}
Category: ${alert.category}
Source: ${alert.source}
Timestamp: ${alert.timestamp.toISOString()}

Description:
${alert.description}

${alert.metadata ? `
Additional Details:
${JSON.stringify(alert.metadata, null, 2)}
` : ''}

Alert ID: ${alert.id}

This alert was generated by TrojanHorse.js Enterprise Security Platform.
    `.trim();
  }

  private getSeverityColor(severity: string): string {
    const colors = {
      'info': '#17a2b8',
      'warning': '#ffc107', 
      'critical': '#dc3545',
      'emergency': '#6f42c1'
    };
    return colors[severity] || '#6c757d';
  }

  private async sendSlackNotification(alert: Alert, config: any): Promise<void> {
    if (!config.webhook) {
      throw new Error('Slack webhook URL not configured');
    }

    try {
      const payload = {
        text: `🚨 *${alert.title}*`,
        attachments: [{
          color: this.getSeverityColor(alert.severity),
          fields: [
            { title: 'Severity', value: alert.severity.toUpperCase(), short: true },
            { title: 'Category', value: alert.category, short: true },
            { title: 'Source', value: alert.source, short: true },
            { title: 'Alert ID', value: alert.id, short: true },
            { title: 'Description', value: alert.description, short: false }
          ],
          footer: 'TrojanHorse.js Enterprise',
          ts: Math.floor(alert.timestamp.getTime() / 1000)
        }]
      };

      const response = await fetch(config.webhook, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        throw new Error(`Slack API error: ${response.status} ${response.statusText}`);
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      throw new Error(`Slack notification failed: ${errorMessage}`);
    }
  }

  private async sendWebhookNotification(alert: Alert, config: any): Promise<void> {
    if (!config.url) {
      throw new Error('Webhook URL not configured');
    }

    try {
      const payload = {
        event: 'alert_created',
        alert: {
          id: alert.id,
          title: alert.title,
          description: alert.description,
          severity: alert.severity,
          category: alert.category,
          source: alert.source,
          timestamp: alert.timestamp.toISOString(),
          metadata: alert.metadata
        },
        system: {
          platform: 'TrojanHorse.js Enterprise',
          version: '1.0.0'
        }
      };

      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'User-Agent': 'TrojanHorse.js/1.0.0'
      };

      if (config.auth?.type === 'bearer' && config.auth.token) {
        headers.Authorization = `Bearer ${config.auth.token}`;
      } else if (config.auth?.type === 'api_key' && config.auth.key) {
        headers['X-API-Key'] = config.auth.key;
      }

      const response = await fetch(config.url, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        throw new Error(`Webhook error: ${response.status} ${response.statusText}`);
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      throw new Error(`Webhook notification failed: ${errorMessage}`);
    }
  }

  private async sendPagerDutyNotification(alert: Alert, config: any): Promise<void> {
    if (!config.routingKey) {
      throw new Error('PagerDuty routing key not configured');
    }

    try {
      const payload = {
        routing_key: config.routingKey,
        event_action: 'trigger',
        dedup_key: `trojanhorse-${alert.id}`,
        payload: {
          summary: alert.title,
          severity: this.mapSeverityToPagerDuty(alert.severity),
          source: alert.source,
          component: 'TrojanHorse.js',
          group: alert.category,
          class: 'security_alert',
          custom_details: {
            description: alert.description,
            alert_id: alert.id,
            category: alert.category,
            timestamp: alert.timestamp.toISOString(),
            metadata: alert.metadata
          }
        },
        client: 'TrojanHorse.js Enterprise',
        client_url: config.clientUrl || 'https://trojanhorse.enterprise.com'
      };

      const response = await fetch('https://events.pagerduty.com/v2/enqueue', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`PagerDuty API error: ${response.status} ${errorText}`);
      }

      const result = await response.json();
      if (!result.dedup_key) {
        throw new Error('PagerDuty response missing dedup_key');
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      throw new Error(`PagerDuty notification failed: ${errorMessage}`);
    }
  }

  private mapSeverityToPagerDuty(severity: string): string {
    const mapping = {
      'info': 'info',
      'warning': 'warning', 
      'critical': 'critical',
      'emergency': 'critical'
    };
    return mapping[severity] || 'warning';
  }
}

// ===== ANALYTICS MANAGER =====

export class AnalyticsManager extends EventEmitter {
  private config: AnalyticsConfig;
  private metricsCollector: MetricsCollector;
  private alertingEngine: AlertingEngine;

  constructor(config: AnalyticsConfig) {
    super();
    this.config = config;
    this.metricsCollector = new MetricsCollector(config);
    this.alertingEngine = new AlertingEngine(config);
    this.setupEventHandlers();
  }

  private setupEventHandlers(): void {
    this.metricsCollector.on('metric_recorded', (metric: MetricPoint) => {
      this.emit('metric_recorded', metric);
    });

    this.alertingEngine.on('alert_created', (alert: Alert) => {
      this.emit('alert_created', alert);
    });

    this.alertingEngine.on('alert_resolved', (alert: Alert) => {
      this.emit('alert_resolved', alert);
    });
  }

  public recordMetric(metric: MetricPoint): void {
    this.metricsCollector.recordMetric(metric);
  }

  public createAlert(alert: Omit<Alert, 'id' | 'timestamp' | 'resolved'>): string {
    return this.alertingEngine.createAlert(alert);
  }

  public queryMetrics(query: {
    metric: string;
    from: Date;
    to: Date;
    aggregation?: 'sum' | 'avg' | 'min' | 'max' | 'count';
    groupBy?: string[];
    filters?: Record<string, string>;
  }): MetricPoint[] {
    return this.metricsCollector.queryMetrics(query);
  }

  public getAlerts(): Alert[] {
    return this.alertingEngine.getAlerts();
  }

  public getMetricsCollector(): MetricsCollector {
    return this.metricsCollector;
  }

  public getAlertingEngine(): AlertingEngine {
    return this.alertingEngine;
  }
}

// Export types and classes
export { MetricsCollector, AlertingEngine }; 
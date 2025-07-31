/**
 * TrojanHorse.js Enterprise Platform
 * Production-ready enterprise threat intelligence platform
 */

import { EventEmitter } from 'events';
import { TrojanHorse } from '../index';
import { AnalyticsManager, AnalyticsConfig } from '../analytics/RealTimeAnalytics';
import { EnterpriseAuthManager, AuthenticationConfig } from '../auth/EnterpriseAuth';

// ===== ENTERPRISE CONFIGURATION =====

export interface EnterpriseConfig {
  // Core configuration
  apiKeys: Record<string, string>;
  security?: {
    mode: 'standard' | 'enhanced' | 'fort-knox';
    encryption: boolean;
    audit: boolean;
  };
  
  // Analytics configuration
  analytics?: AnalyticsConfig;
  
  // Authentication configuration
  authentication?: AuthenticationConfig;
  
  // Deployment configuration
  deployment?: {
    mode: 'standalone' | 'cluster' | 'cloud';
    replicas?: number;
    autoScale?: boolean;
  };
  
  // Enterprise features
  enterprise?: {
    licenseKey: string;
    maxNodes: number;
    features: string[];
  };
}

// ===== ENTERPRISE THREAT INTELLIGENCE PLATFORM =====

class TrojanHorseEnterprise extends EventEmitter {
  private config: EnterpriseConfig;
  private core: TrojanHorse;
  private authManager?: EnterpriseAuthManager;
  private analyticsManager?: AnalyticsManager;
  private initialized = false;

  constructor(config: EnterpriseConfig) {
    super();
    this.config = config;
    
    // Initialize core TrojanHorse
    this.core = new TrojanHorse({
      apiKeys: config.apiKeys,
      security: config.security || {},
      sources: ['all']
    });
    
    this.initializeComponents();
  }

  private async initializeComponents(): Promise<void> {
    try {
      // Initialize enterprise authentication
      if (this.config.authentication) {
        this.authManager = new EnterpriseAuthManager(this.config.authentication);
      }

      // Initialize analytics
      if (this.config.analytics) {
        this.analyticsManager = new AnalyticsManager(this.config.analytics);
      }

      this.setupEventHandlers();
      this.initialized = true;
      this.emit('enterprise_initialized');

    } catch (error) {
      this.emit('initialization_error', { error });
      throw error;
    }
  }

  private setupEventHandlers(): void {
    // Forward core events
    this.core.on('threat:detected', (threat) => {
      this.emit('enterprise_threat_detected', threat);
      
      // Record metrics
      if (this.analyticsManager) {
        this.analyticsManager.recordMetric({
          timestamp: new Date(),
          metric: 'threats_detected',
          value: 1,
          labels: { source: threat.source },
          unit: 'count'
        });
      }
    });

    this.core.on('error', (error) => {
      this.emit('enterprise_error', error);
    });

    // Analytics events
    if (this.analyticsManager) {
      this.analyticsManager.on('alert_created', (alert) => {
        this.emit('enterprise_alert', alert);
      });
    }

    // Authentication events
    if (this.authManager) {
      this.authManager.on('user_authenticated', (event) => {
        this.emit('user_authenticated', event);
        
        if (this.analyticsManager) {
          this.analyticsManager.recordMetric({
            timestamp: new Date(),
            metric: 'user_logins',
            value: 1,
            labels: { method: event.method },
            unit: 'count'
          });
        }
      });
    }
  }

  // ===== PUBLIC API =====

  public async scanTarget(target: string, options?: any): Promise<any[]> {
    if (!this.initialized) {
      throw new Error('Enterprise platform not initialized');
    }

    try {
      const scoutResult = await this.core.scout(target, options);
      const results = scoutResult.indicators || []; // Extract indicators array
      
      // Record enterprise metrics
      if (this.analyticsManager) {
        this.analyticsManager.recordMetric({
          timestamp: new Date(),
          metric: 'scans_performed',
          value: 1,
          labels: { target_type: this.detectTargetType(target) },
          unit: 'count'
        });
      }

      this.emit('scan_completed', { target, results });
      return results;
      
    } catch (error) {
      this.emit('scan_failed', { target, error });
      throw error;
    }
  }

  public async authenticate(method: 'oauth2' | 'saml', credentials: any): Promise<any> {
    if (!this.authManager) {
      throw new Error('Authentication not configured');
    }

    return this.authManager.authenticate(method, credentials);
  }

  public createAlert(alert: any): string {
    if (!this.analyticsManager) {
      throw new Error('Analytics not configured');
    }

    return this.analyticsManager.createAlert(alert);
  }

  public getMetrics(query: any): any[] {
    if (!this.analyticsManager) {
      throw new Error('Analytics not configured');
    }

    return this.analyticsManager.queryMetrics(query);
  }

  public getStatus(): any {
    return {
      initialized: this.initialized,
      coreStatus: this.core.getStatus(),
      analytics: !!this.analyticsManager,
      authentication: !!this.authManager,
      uptime: process.uptime(),
      version: '1.0.0',
      enterprise: true
    };
  }

  public getCore(): TrojanHorse {
    return this.core;
  }

  public getAuthManager(): EnterpriseAuthManager | undefined {
    return this.authManager;
  }

  public getAnalyticsManager(): AnalyticsManager | undefined {
    return this.analyticsManager;
  }

  private detectTargetType(target: string): string {
    if (target.match(/^https?:\/\//)) {
      return 'url';
    } else if (target.match(/^\d+\.\d+\.\d+\.\d+$/)) {
      return 'ip';
    } else if (target.includes('.')) {
      return 'domain';
    }
    return 'unknown';
  }
}

// Export the enterprise platform
export { TrojanHorseEnterprise }; 
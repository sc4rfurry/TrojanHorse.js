/**
 * Feed-specific type definitions for TrojanHorse.js
 */

export interface FeedMetrics {
  successfulRequests: number;
  failedRequests: number;
  averageResponseTime: number;
  lastErrorTime?: Date;
  rateLimitHits: number;
}

export interface FeedHealthStatus {
  healthy: boolean;
  lastCheck: Date;
  responseTime: number;
  errorRate: number;
  uptime: number;
}

export interface FeedParser<T = any> {
  parse(data: string): T[];
  validate(data: T): boolean;
  normalize(data: T): any;
}

export interface FeedSchedule {
  interval: number;
  maxRetries: number;
  backoffMultiplier: number;
  jitter: boolean;
} 
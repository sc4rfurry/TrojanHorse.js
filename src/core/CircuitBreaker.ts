/**
 * Circuit Breaker Pattern Implementation
 * 
 * Provides fault tolerance and resilience for external API calls
 * with configurable failure thresholds, recovery timeouts, and monitoring.
 */

import { EventEmitter } from 'events';

export type CircuitState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export interface CircuitBreakerConfig {
  failureThreshold: number;      // Number of failures before opening
  successThreshold: number;      // Number of successes to close from half-open
  timeout: number;              // Time in ms before trying half-open
  monitoringWindow: number;     // Time window for failure tracking
  volumeThreshold: number;      // Minimum requests before considering failure rate
  errorFilter?: (error: Error) => boolean; // Filter which errors count as failures
  onStateChange?: (state: CircuitState) => void; // Callback for state changes
}

interface CircuitBreakerStats {
  state: CircuitState;
  failureCount: number;
  successCount: number;
  totalRequests: number;
  lastFailureTime: number | null;
  lastSuccessTime: number | null;
  stateChangeTime: number;
  requestStats: {
    total: number;
    failures: number;
    successes: number;
    timeouts: number;
    circuitOpen: number;
  };
  responseTimeStats: {
    average: number;
    min: number;
    max: number;
    p95: number;
    p99: number;
  };
}

interface RequestRecord {
  timestamp: number;
  success: boolean;
  responseTime: number;
  error?: string;
}

export class CircuitBreaker extends EventEmitter {
  private config: CircuitBreakerConfig;
  private state: CircuitState = 'CLOSED';
  private failureCount: number = 0;
  private successCount: number = 0;
  private lastFailureTime: number | null = null;
  private lastSuccessTime: number | null = null;
  private stateChangeTime: number = Date.now();
  private requestHistory: RequestRecord[] = [];
  private responseTimes: number[] = [];

  constructor(config: Partial<CircuitBreakerConfig> = {}) {
    super();
    
    this.config = {
      failureThreshold: 5,
      successThreshold: 3,
      timeout: 60000, // 1 minute
      monitoringWindow: 60000, // 1 minute
      volumeThreshold: 10,
      errorFilter: () => true, // All errors count by default
      ...config
    };

    // Cleanup old records periodically
    setInterval(() => this.cleanupOldRecords(), this.config.monitoringWindow);
  }

  /**
   * Execute a function with circuit breaker protection
   */
  public async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (this.state === 'OPEN') {
      if (this.shouldAttemptReset()) {
        this.setState('HALF_OPEN');
      } else {
        const error = new Error('Circuit breaker is OPEN');
        this.recordRequest(false, 0, error.message);
        throw error;
      }
    }

    const startTime = Date.now();
    
    try {
      const result = await fn();
      const responseTime = Date.now() - startTime;
      
      this.onSuccess(responseTime);
      return result;
      
    } catch (error) {
      const responseTime = Date.now() - startTime;
      this.onFailure(error as Error, responseTime);
      throw error;
    }
  }

  /**
   * Execute with automatic retry logic
   */
  public async executeWithRetry<T>(
    fn: () => Promise<T>,
    maxRetries: number = 3,
    retryDelay: number = 1000
  ): Promise<T> {
    let lastError: Error;
    
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        return await this.execute(fn);
      } catch (error) {
        lastError = error as Error;
        
        // Don't retry if circuit is open
        if (this.state === 'OPEN') {
          throw error;
        }
        
        // Don't retry on last attempt
        if (attempt === maxRetries) {
          throw error;
        }
        
        // Exponential backoff
        const delay = retryDelay * Math.pow(2, attempt);
        await this.sleep(delay);
      }
    }
    
    throw lastError!;
  }

  /**
   * Execute multiple functions with circuit breaker protection
   */
  public async executeBatch<T>(
    functions: Array<() => Promise<T>>,
    options: {
      maxConcurrency?: number;
      failFast?: boolean;
      continueOnFailure?: boolean;
    } = {}
  ): Promise<Array<{ success: boolean; result?: T; error?: Error }>> {
    const {
      maxConcurrency = 5,
      failFast = false,
      continueOnFailure = true
    } = options;

    const results: Array<{ success: boolean; result?: T; error?: Error }> = [];
    const executing: Promise<unknown>[] = [];

    for (let i = 0; i < functions.length; i++) {
      const fn = functions[i];
      
      const executePromise: Promise<unknown> = fn ? this.execute(fn) : Promise.reject(new Error('No function provided'))
        .then(result => {
          results[i] = { success: true, result };
        })
        .catch(error => {
          results[i] = { success: false, error };
          
          if (failFast && !continueOnFailure) {
            throw error;
          }
        });

      executing.push(executePromise);

      // Limit concurrency
      if (executing.length >= maxConcurrency) {
        await Promise.race(executing);
        // Remove completed promises
        const completed = executing.filter(p => 
          p === Promise.resolve() // This is a simplification
        );
        completed.forEach(p => {
          const index = executing.indexOf(p);
          if (index > -1) {
            executing.splice(index, 1);
          }
        });
      }
    }

    // Wait for all remaining executions
    await Promise.allSettled(executing);

    return results;
  }

  private onSuccess(responseTime: number): void {
    this.recordRequest(true, responseTime);
    this.lastSuccessTime = Date.now();
    
    if (this.state === 'HALF_OPEN') {
      this.successCount++;
      
      if (this.successCount >= this.config.successThreshold) {
        this.setState('CLOSED');
        this.reset();
      }
    } else if (this.state === 'CLOSED') {
      this.failureCount = Math.max(0, this.failureCount - 1);
    }

    this.emit('success', { responseTime, state: this.state });
  }

  private onFailure(error: Error, responseTime: number): void {
    // Check if this error should be counted
    if (this.config.errorFilter && !this.config.errorFilter(error)) {
      this.recordRequest(false, responseTime, 'filtered-error');
      return;
    }

    this.recordRequest(false, responseTime, error.message);
    this.lastFailureTime = Date.now();
    this.failureCount++;

    if (this.state === 'HALF_OPEN' || this.shouldOpen()) {
      this.setState('OPEN');
    }

    this.emit('failure', { 
      error: error.message, 
      responseTime, 
      state: this.state,
      failureCount: this.failureCount 
    });
  }

  private shouldOpen(): boolean {
    if (this.state === 'OPEN') {
      return false;
    }
    
    const recentRequests = this.getRecentRequests();
    
    // Need minimum volume to consider opening
    if (recentRequests.length < this.config.volumeThreshold) {
      return false;
    }

    // Check failure rate
    return this.failureCount >= this.config.failureThreshold;
  }

  private shouldAttemptReset(): boolean {
    return this.lastFailureTime !== null && 
           (Date.now() - this.lastFailureTime) >= this.config.timeout;
  }

  private setState(newState: CircuitState): void {
    if (this.state !== newState) {
      const oldState = this.state;
      this.state = newState;
      this.stateChangeTime = Date.now();

      if (this.config.onStateChange) {
        this.config.onStateChange(newState);
      }

      this.emit('stateChange', { 
        from: oldState, 
        to: newState, 
        timestamp: this.stateChangeTime 
      });

      // Log state changes
      console.log(`Circuit breaker state changed: ${oldState} -> ${newState}`);
    }
  }

  private reset(): void {
    this.failureCount = 0;
    this.successCount = 0;
    this.lastFailureTime = null;
  }

  private recordRequest(success: boolean, responseTime: number, error?: string): void {
    const record: RequestRecord = {
      timestamp: Date.now(),
      success,
      responseTime,
      error: error || ''
    };

    this.requestHistory.push(record);
    this.responseTimes.push(responseTime);

    // Keep response times for percentile calculations
    if (this.responseTimes.length > 1000) {
      this.responseTimes = this.responseTimes.slice(-1000);
    }

    // Emit metrics
    this.emit('request', record);
  }

  private getRecentRequests(): RequestRecord[] {
    const cutoff = Date.now() - this.config.monitoringWindow;
    return this.requestHistory.filter(record => record.timestamp >= cutoff);
  }

  private cleanupOldRecords(): void {
    const cutoff = Date.now() - this.config.monitoringWindow;
    this.requestHistory = this.requestHistory.filter(record => 
      record.timestamp >= cutoff
    );
  }

  private calculatePercentile(values: number[], percentile: number): number {
    if (values.length === 0) {
      return 0;
    }
    
    const sorted = [...values].sort((a, b) => a - b);
    const index = Math.ceil((percentile / 100) * sorted.length) - 1;
    const validIndex = Math.max(0, Math.min(index, sorted.length - 1));
    return sorted[validIndex] ?? 0;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Get current circuit breaker statistics
   */
  public getStats(): CircuitBreakerStats {
    const recentRequests = this.getRecentRequests();
    const recentFailures = recentRequests.filter(r => !r.success);
    const recentSuccesses = recentRequests.filter(r => r.success);
    
    const responseTimeStats = this.responseTimes.length > 0 ? {
      average: this.responseTimes.reduce((a, b) => a + b, 0) / this.responseTimes.length,
      min: Math.min(...this.responseTimes),
      max: Math.max(...this.responseTimes),
      p95: this.calculatePercentile(this.responseTimes, 95),
      p99: this.calculatePercentile(this.responseTimes, 99)
    } : {
      average: 0, min: 0, max: 0, p95: 0, p99: 0
    };

    return {
      state: this.state,
      failureCount: this.failureCount,
      successCount: this.successCount,
      totalRequests: this.requestHistory.length,
      lastFailureTime: this.lastFailureTime,
      lastSuccessTime: this.lastSuccessTime,
      stateChangeTime: this.stateChangeTime,
      requestStats: {
        total: recentRequests.length,
        failures: recentFailures.length,
        successes: recentSuccesses.length,
        timeouts: recentFailures.filter(r => r.error?.includes('timeout')).length,
        circuitOpen: recentRequests.filter(r => r.error === 'Circuit breaker is OPEN').length
      },
      responseTimeStats
    };
  }

  /**
   * Get current state
   */
  public getState(): CircuitState {
    return this.state;
  }

  /**
   * Get configuration
   */
  public getConfig(): CircuitBreakerConfig {
    return { ...this.config };
  }

  /**
   * Update configuration
   */
  public updateConfig(newConfig: Partial<CircuitBreakerConfig>): void {
    this.config = { ...this.config, ...newConfig };
    this.emit('configUpdate', this.config);
  }

  /**
   * Manually open the circuit
   */
  public open(): void {
    this.setState('OPEN');
    this.lastFailureTime = Date.now();
  }

  /**
   * Manually close the circuit
   */
  public close(): void {
    this.setState('CLOSED');
    this.reset();
  }

  /**
   * Force reset to half-open state
   */
  public halfOpen(): void {
    this.setState('HALF_OPEN');
    this.successCount = 0;
  }

  /**
   * Check if circuit is healthy
   */
  public isHealthy(): boolean {
    if (this.state === 'OPEN') {
      return false;
    }
    
    const recentRequests = this.getRecentRequests();
    if (recentRequests.length < this.config.volumeThreshold) {
      return true;
    }
    
    const failureRate = recentRequests.filter(r => !r.success).length / recentRequests.length;
    return failureRate < (this.config.failureThreshold / this.config.volumeThreshold);
  }

  /**
   * Get health score (0-100)
   */
  public getHealthScore(): number {
    if (this.state === 'OPEN') {
      return 0;
    }
    
    const recentRequests = this.getRecentRequests();
    if (recentRequests.length === 0) {
      return 100;
    }
    
    const successRate = recentRequests.filter(r => r.success).length / recentRequests.length;
    const baseScore = successRate * 100;
    
    // Adjust based on response times
    const avgResponseTime = this.responseTimes.reduce((a, b) => a + b, 0) / this.responseTimes.length;
    const responseTimePenalty = Math.min(avgResponseTime / 5000, 1) * 20; // Max 20 point penalty
    
    return Math.max(0, baseScore - responseTimePenalty);
  }

  /**
   * Export metrics for monitoring systems
   */
  public exportMetrics(): Record<string, number> {
    const stats = this.getStats();
    
    return {
      'circuit_breaker_state': this.state === 'CLOSED' ? 0 : this.state === 'HALF_OPEN' ? 1 : 2,
      'circuit_breaker_failure_count': stats.failureCount,
      'circuit_breaker_success_count': stats.successCount,
      'circuit_breaker_total_requests': stats.totalRequests,
      'circuit_breaker_recent_failures': stats.requestStats.failures,
      'circuit_breaker_recent_successes': stats.requestStats.successes,
      'circuit_breaker_response_time_avg': stats.responseTimeStats.average,
      'circuit_breaker_response_time_p95': stats.responseTimeStats.p95,
      'circuit_breaker_response_time_p99': stats.responseTimeStats.p99,
      'circuit_breaker_health_score': this.getHealthScore()
    };
  }
}

/**
 * Circuit Breaker Manager for multiple services
 */
export class CircuitBreakerManager {
  private breakers: Map<string, CircuitBreaker> = new Map();
  private globalConfig: Partial<CircuitBreakerConfig>;

  constructor(globalConfig: Partial<CircuitBreakerConfig> = {}) {
    this.globalConfig = globalConfig;
  }

  /**
   * Get or create a circuit breaker for a service
   */
  public getBreaker(serviceName: string, config?: Partial<CircuitBreakerConfig>): CircuitBreaker {
    if (!this.breakers.has(serviceName)) {
      const breakerConfig = { ...this.globalConfig, ...config };
      const breaker = new CircuitBreaker(breakerConfig);
      
      breaker.on('stateChange', (event) => {
        console.log(`[${serviceName}] Circuit breaker: ${event.from} -> ${event.to}`);
      });
      
      this.breakers.set(serviceName, breaker);
    }
    
    return this.breakers.get(serviceName)!;
  }

  /**
   * Execute function with service-specific circuit breaker
   */
  public async execute<T>(
    serviceName: string, 
    fn: () => Promise<T>,
    config?: Partial<CircuitBreakerConfig>
  ): Promise<T> {
    const breaker = this.getBreaker(serviceName, config);
    return breaker.execute(fn);
  }

  /**
   * Get all circuit breaker stats
   */
  public getAllStats(): Record<string, CircuitBreakerStats> {
    const stats: Record<string, CircuitBreakerStats> = {};
    
    for (const [serviceName, breaker] of this.breakers) {
      stats[serviceName] = breaker.getStats();
    }
    
    return stats;
  }

  /**
   * Get overall system health
   */
  public getSystemHealth(): {
    healthy: number;
    degraded: number;
    unhealthy: number;
    totalServices: number;
    overallScore: number;
    } {
    let healthy = 0;
    let degraded = 0;
    let unhealthy = 0;
    let totalScore = 0;

    for (const breaker of this.breakers.values()) {
      const score = breaker.getHealthScore();
      totalScore += score;
      
      if (score >= 80) {
        healthy++;
      } else if (score >= 50) {
        degraded++;
      } else {
        unhealthy++;
      }
    }

    return {
      healthy,
      degraded,
      unhealthy,
      totalServices: this.breakers.size,
      overallScore: this.breakers.size > 0 ? totalScore / this.breakers.size : 100
    };
  }

  /**
   * Reset all circuit breakers
   */
  public resetAll(): void {
    for (const breaker of this.breakers.values()) {
      breaker.close();
    }
  }

  /**
   * Remove a circuit breaker
   */
  public removeBreaker(serviceName: string): boolean {
    return this.breakers.delete(serviceName);
  }
}

/**
 * Utility function to create a circuit breaker with common patterns
 */
export function createCircuitBreaker(pattern: 'aggressive' | 'conservative' | 'api' | 'database' | 'custom', customConfig?: Partial<CircuitBreakerConfig>): CircuitBreaker {
  let config: Partial<CircuitBreakerConfig>;

  switch (pattern) {
  case 'aggressive':
    config = {
      failureThreshold: 3,
      successThreshold: 2,
      timeout: 30000, // 30 seconds
      monitoringWindow: 30000,
      volumeThreshold: 5
    };
    break;

  case 'conservative':
    config = {
      failureThreshold: 10,
      successThreshold: 5,
      timeout: 120000, // 2 minutes
      monitoringWindow: 120000,
      volumeThreshold: 20
    };
    break;

  case 'api':
    config = {
      failureThreshold: 5,
      successThreshold: 3,
      timeout: 60000, // 1 minute
      monitoringWindow: 60000,
      volumeThreshold: 10,
      errorFilter: (error) => {
        // Don't count 4xx errors as circuit breaker failures
        return !error.message.includes('4') || error.message.includes('429');
      }
    };
    break;

  case 'database':
    config = {
      failureThreshold: 3,
      successThreshold: 2,
      timeout: 30000,
      monitoringWindow: 60000,
      volumeThreshold: 5,
      errorFilter: (error) => {
        // Count connection and timeout errors
        return error.message.includes('connection') || 
                 error.message.includes('timeout') ||
                 error.message.includes('ECONNREFUSED');
      }
    };
    break;

  default: // custom
    config = customConfig || {};
  }

  return new CircuitBreaker({ ...config, ...customConfig });
} 
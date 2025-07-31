/**
 * CrowdSec CTI Feed Integration
 * 
 * Integrates with CrowdSec's Cyber Threat Intelligence API
 * - Behavior-based threat detection
 * - IP reputation and malicious activity analysis
 * - Scenarios: http_crawl, ssh_bruteforce, port_scan, etc.
 * - Free tier: 1000 requests/day, Premium: unlimited
 */

import axios, { AxiosResponse } from 'axios';
import { FeedConfiguration, ThreatIndicator, ThreatFeedResult } from '../types';

// CrowdSec API response interfaces
interface CrowdSecIPInfo {
  ip: string;
  ip_range?: string;
  ip_range_score?: number;
  country?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  as_name?: string;
  as_num?: number;
  background_noise_score?: number;
  scores?: {
    overall?: {
      aggressiveness: number;
      threat: number;
      trust: number;
      anomaly: number;
      total: number;
    };
  };
  attack_details?: Array<{
    name: string;
    label: string;
    description: string;
    references?: string[];
  }>;
  behaviors?: Array<{
    name: string;
    label: string;
    description: string;
  }>;
  history?: {
    first_seen: string;
    last_seen: string;
    full_age: number;
    days_age: number;
  };
  classifications?: {
    false_positives?: Array<{
      name: string;
      label: string;
      description: string;
    }>;
    classifications?: Array<{
      name: string;
      label: string;
      description: string;
    }>;
  };
  target_countries?: Record<string, number>;
  background_noise?: boolean;
  cves?: string[];
}

interface CrowdSecSmokeResponse {
  ip_range_score: number;
  ip: string;
  ip_range: string;
  as_name: string;
  as_num: number;
  location: {
    country: string;
    city: string;
    latitude: number;
    longitude: number;
  };
  reverse_dns: string;
  behaviors: Array<{
    name: string;
    label: string;
    description: string;
  }>;
  history: {
    first_seen: string;
    last_seen: string;
    full_age: number;
    days_age: number;
  };
  classifications: {
    false_positives: any[];
    classifications: Array<{
      name: string;
      label: string;
      description: string;
    }>;
  };
  attack_details: Array<{
    name: string;
    label: string;
    description: string;
    references: string[];
  }>;
  target_countries: Record<string, number>;
  background_noise: boolean;
  scores: {
    overall: {
      aggressiveness: number;
      threat: number;
      trust: number;
      anomaly: number;
      total: number;
    };
  };
}

interface CrowdSecError {
  message: string;
  errors?: string[];
}

export class CrowdSecFeed {
  private config: FeedConfiguration;
  private apiKey: string;
  private baseUrl: string = 'https://cti-api.crowdsec.net/v2';
  private rateLimitRemaining: number = 1000;
  private rateLimitReset: Date = new Date();
  private requestCount: number = 0;
  private dailyLimit: number = 1000; // Free tier default

  constructor(config: Partial<FeedConfiguration> = {}) {
    this.config = {
      name: 'CrowdSec CTI',
      type: 'api',
      endpoint: 'https://cti-api.crowdsec.net/v2',
      authentication: {
        type: 'api_key',
        required: true,
        header: 'x-api-key',
        credentials: {}
      },
      rateLimit: {
        requestsPerHour: 1000, // Conservative for free tier
        burstLimit: 10,
        retryAfter: 1000
      },
      enabled: true,
      priority: 'high',
      sslPinning: true,
      timeout: 30000,
      retries: 3,
      ...config
    };

    this.apiKey = config.apiKey || process.env.CROWDSEC_API_KEY || '';
    
    if (!this.apiKey) {
      console.warn('CrowdSec API key not provided. Some features may be limited.');
    }

    // Set daily limit based on tier
    if (this.apiKey) {
      // TODO: Detect premium tier from API response headers
      this.dailyLimit = 1000; // Default to free tier
    }
  }

  /**
   * Fetch threat intelligence data (main interface method)
   * Uses a curated list of known malicious IPs and recent threat data
   */
  public async fetchThreatData(): Promise<ThreatFeedResult> {
    // Since CrowdSec CTI is primarily for querying specific IPs,
    // we'll use a smoke API or community blocklist to get general threats
    return this.fetchRecentThreats();
  }

  /**
   * Fetch recent threat intelligence using CrowdSec's smoke endpoint
   * This provides a sample of recent malicious activity
   */
  public async fetchRecentThreats(): Promise<ThreatFeedResult> {
    try {
      const response = await axios.get(`${this.baseUrl}/smoke/`, {
        headers: {
          'User-Agent': 'TrojanHorse.js/1.0.0',
          'Accept': 'application/json',
          ...(this.apiKey && { 'x-api-key': this.apiKey })
        },
        timeout: this.config.timeout
      });

      const smokeData: CrowdSecSmokeResponse[] = Array.isArray(response.data) ? response.data : [response.data];
      const indicators: ThreatIndicator[] = [];

      for (const entry of smokeData) {
        const indicator = this.mapToThreatIndicator(entry.ip, entry);
        if (indicator) {
          indicators.push(indicator);
        }
      }

      return {
        source: this.config.name,
        timestamp: new Date(),
        indicators,
        metadata: {
          totalCount: indicators.length,
          totalIndicators: indicators.length,
          hasMore: false,
          requestsProcessed: 1
        }
      };
    } catch (error: any) {
      throw new Error(`Failed to fetch CrowdSec smoke data: ${error.message}`);
    }
  }

  /**
   * Fetch threat intelligence for a specific IP address
   */
  public async fetchIPInfo(ip: string): Promise<CrowdSecIPInfo> {
    if (!this.apiKey) {
      throw new Error('CrowdSec API key is required for IP information');
    }

    await this.checkRateLimit();

    try {
      const response: AxiosResponse<CrowdSecIPInfo> = await axios.get(
        `${this.baseUrl}/cti/${ip}`,
        {
          headers: {
            'x-api-key': this.apiKey,
            'User-Agent': 'TrojanHorse.js/1.0.0',
            'Accept': 'application/json'
          },
          timeout: this.config.timeout
        }
      );

      this.updateRateLimitInfo(response.headers);
      this.requestCount++;

      return response.data;
    } catch (error: any) {
      if (error.response?.status === 429) {
        const retryAfter = parseInt(error.response.headers['retry-after'] || '60');
        throw new Error(`Rate limit exceeded. Retry after ${retryAfter} seconds`);
      }
      
      if (error.response?.status === 404) {
        // IP not found in CrowdSec database - not necessarily an error
        throw new Error(`IP ${ip} not found in CrowdSec database`);
      }

      if (error.response?.status === 401) {
        throw new Error('Invalid CrowdSec API key');
      }

      throw new Error(`CrowdSec API error: ${error.message}`);
    }
  }

  /**
   * Fetch smoke data (lightweight IP check)
   */
  public async fetchSmokeData(ip: string): Promise<CrowdSecSmokeResponse> {
    await this.checkRateLimit();

    try {
      const url = this.apiKey 
        ? `${this.baseUrl}/smoke/${ip}`
        : `${this.baseUrl}/smoke/${ip}`;

      const headers: Record<string, string> = {
        'User-Agent': 'TrojanHorse.js/1.0.0',
        'Accept': 'application/json'
      };

      if (this.apiKey) {
        headers['x-api-key'] = this.apiKey;
      }

      const response: AxiosResponse<CrowdSecSmokeResponse> = await axios.get(url, {
        headers,
        timeout: this.config.timeout
      });

      this.updateRateLimitInfo(response.headers);
      this.requestCount++;

      return response.data;
    } catch (error: any) {
      if (error.response?.status === 429) {
        const retryAfter = parseInt(error.response.headers['retry-after'] || '60');
        throw new Error(`Rate limit exceeded. Retry after ${retryAfter} seconds`);
      }

      if (error.response?.status === 404) {
        throw new Error(`IP ${ip} not found in CrowdSec smoke database`);
      }

      throw new Error(`CrowdSec Smoke API error: ${error.message}`);
    }
  }

  /**
   * Fetch threat data and convert to standard format
   */
  public async fetchThreats(options: {
    ips?: string[];
    includeSmoke?: boolean;
    maxResults?: number;
  } = {}): Promise<ThreatFeedResult> {
    const { ips = [], includeSmoke = true, maxResults = 100 } = options;
    const indicators: ThreatIndicator[] = [];
    const errors: string[] = [];

    // If no specific IPs provided, we can't fetch random threats from CrowdSec
    // This is different from URLhaus which provides a feed
    if (ips.length === 0) {
      console.warn('CrowdSec requires specific IP addresses to check');
      return {
        source: this.config.name,
        timestamp: new Date(),
        indicators: [],
        metadata: {
          totalCount: 0,
          totalIndicators: 0,
          hasMore: false,
          errors: ['No IP addresses provided for CrowdSec lookup']
        }
      };
    }

    // Process each IP
    for (const ip of ips.slice(0, maxResults)) {
      try {
        let crowdSecData: CrowdSecIPInfo | CrowdSecSmokeResponse;

        if (this.apiKey && !includeSmoke) {
          crowdSecData = await this.fetchIPInfo(ip);
        } else {
          crowdSecData = await this.fetchSmokeData(ip);
        }

        const indicator = this.mapToThreatIndicator(ip, crowdSecData);
        if (indicator) {
          indicators.push(indicator);
        }
      } catch (error: any) {
        errors.push(`${ip}: ${error.message}`);
        console.warn(`Failed to fetch CrowdSec data for ${ip}:`, error.message);
      }

      // Respect rate limits
      if (this.rateLimitRemaining <= 1) {
        console.warn('CrowdSec rate limit approaching, stopping batch processing');
        break;
      }
    }

    return {
      source: this.config.name,
      timestamp: new Date(),
      indicators,
      metadata: {
        totalCount: indicators.length,
        totalIndicators: indicators.length,
        hasMore: false,
        requestsProcessed: ips.length,
        errors: errors.length > 0 ? errors : undefined,
        rateLimit: {
          remaining: this.rateLimitRemaining,
          resetTime: this.rateLimitReset,
          limit: 1000 // Default daily limit for free tier
        }
      }
    };
  }

  /**
   * Map CrowdSec data to our ThreatIndicator format
   */
  private mapToThreatIndicator(
    ip: string, 
    data: CrowdSecIPInfo | CrowdSecSmokeResponse
  ): ThreatIndicator | null {
    // Determine if this IP is malicious based on CrowdSec scores and behaviors
    const isMalicious = this.calculateThreatLevel(data);
    
    if (!isMalicious) {
      return null; // Skip clean IPs unless explicitly requested
    }

    const confidence = this.calculateConfidence(data);
    const behaviors = data.behaviors || [];
    const attackDetails = data.attack_details || [];

    return {
      type: 'ip',
      value: ip,
      confidence,
      severity: this.mapSeverity(data.scores?.overall?.threat || 0),
      firstSeen: data.history?.first_seen ? new Date(data.history.first_seen) : new Date(),
      lastSeen: data.history?.last_seen ? new Date(data.history.last_seen) : new Date(),
      source: this.config.name,
      tags: [
        ...behaviors.map(b => b.name),
        ...attackDetails.map(a => a.name),
        'crowdsec-cti'
      ].filter(Boolean),
      metadata: {
        crowdsec: {
          scores: data.scores,
          country: 'location' in data ? data.location?.country : data.country,
          city: 'location' in data ? data.location?.city : data.city,
          asn: data.as_num,
          asName: data.as_name,
          behaviors: behaviors.map(b => ({
            name: b.name,
            label: b.label,
            description: b.description
          })),
          attackDetails: attackDetails.map(a => ({
            name: a.name,
            label: a.label,
            description: a.description,
            references: a.references
          })),
          backgroundNoise: 'background_noise' in data ? data.background_noise : false,
          ipRange: 'ip_range' in data ? data.ip_range : undefined,
          ipRangeScore: 'ip_range_score' in data ? data.ip_range_score : undefined
        }
      },
      description: this.generateDescription(behaviors, attackDetails),
      malwareFamily: attackDetails.length > 0 ? attackDetails[0].name : undefined
    };
  }

  /**
   * Calculate if IP is malicious based on CrowdSec data
   */
  private calculateThreatLevel(data: CrowdSecIPInfo | CrowdSecSmokeResponse): boolean {
    const scores = data.scores?.overall;
    
    if (!scores) {
      return false;
    }

    // Consider malicious if:
    // - High threat score (> 3)
    // - High aggressiveness (> 3) 
    // - Has attack behaviors
    // - Low trust score (< 2)
    const hasHighThreat = scores.threat > 3;
    const hasHighAggression = scores.aggressiveness > 3;
    const hasAttackBehaviors = (data.attack_details?.length || 0) > 0;
    const hasLowTrust = scores.trust < 2;
    const hasOverallHighScore = scores.total > 3;

    return hasHighThreat || hasHighAggression || hasAttackBehaviors || (hasLowTrust && hasOverallHighScore);
  }

  /**
   * Calculate confidence score (0-1)
   */
  private calculateConfidence(data: CrowdSecIPInfo | CrowdSecSmokeResponse): number {
    const scores = data.scores?.overall;
    
    if (!scores) {
      return 0.3; // Low confidence without scores
    }

    let confidence = 0.5; // Base confidence

    // Higher threat score increases confidence
    confidence += (scores.threat / 10) * 0.3;
    
    // Multiple attack details increase confidence
    const attackCount = data.attack_details?.length || 0;
    confidence += Math.min(attackCount * 0.1, 0.2);

    // Recent activity increases confidence
    if (data.history) {
      const daysOld = data.history.days_age || 0;
      if (daysOld < 7) {
        confidence += 0.1;
      } else if (daysOld < 30) {
        confidence += 0.05;
      }
    }

    // Background noise decreases confidence
    if ('background_noise' in data && data.background_noise) {
      confidence -= 0.2;
    }

    // High anomaly score increases confidence
    confidence += (scores.anomaly / 10) * 0.1;

    return Math.max(0.1, Math.min(confidence, 1.0));
  }

  /**
   * Map CrowdSec threat scores to severity levels
   */
  private mapSeverity(threatScore: number): 'low' | 'medium' | 'high' | 'critical' {
    if (threatScore >= 4) {
      return 'critical';
    }
    if (threatScore >= 3) {
      return 'high';
    }
    if (threatScore >= 2) {
      return 'medium';
    }
    return 'low';
  }

  /**
   * Generate human-readable description
   */
  private generateDescription(
    behaviors: Array<{ name: string; label: string; description: string }>,
    attackDetails: Array<{ name: string; label: string; description: string }>
  ): string {
    const parts: string[] = [];

    if (behaviors.length > 0) {
      const behaviorNames = behaviors.map(b => b.label || b.name).join(', ');
      parts.push(`Observed behaviors: ${behaviorNames}`);
    }

    if (attackDetails.length > 0) {
      const attackNames = attackDetails.map(a => a.label || a.name).join(', ');
      parts.push(`Attack patterns: ${attackNames}`);
    }

    return parts.join('. ') || 'Malicious IP identified by CrowdSec CTI';
  }

  /**
   * Check rate limit before making requests
   */
  private async checkRateLimit(): Promise<void> {
    const now = new Date();
    
    // Reset daily counter if needed
    if (now.getTime() - this.rateLimitReset.getTime() > 24 * 60 * 60 * 1000) {
      this.requestCount = 0;
      this.rateLimitReset = new Date(now.getTime() + 24 * 60 * 60 * 1000);
    }

    // Check daily limit
    if (this.requestCount >= this.dailyLimit) {
      const resetTime = this.rateLimitReset.getTime() - now.getTime();
      throw new Error(`Daily rate limit exceeded. Resets in ${Math.ceil(resetTime / 1000 / 60)} minutes`);
    }

    // Check burst limit
    if (this.rateLimitRemaining <= 0) {
      throw new Error('Rate limit exceeded. Please wait before making more requests');
    }
  }

  /**
   * Update rate limit information from response headers
   */
  private updateRateLimitInfo(headers: any): void {
    const remaining = headers['x-ratelimit-remaining'];
    const reset = headers['x-ratelimit-reset'];

    if (remaining !== undefined) {
      this.rateLimitRemaining = parseInt(remaining);
    }

    if (reset !== undefined) {
      this.rateLimitReset = new Date(parseInt(reset) * 1000);
    }
  }

  /**
   * Get current statistics
   */
  public getStats(): {
    requestCount: number;
    rateLimitRemaining: number;
    rateLimitReset: Date;
    dailyLimit: number;
    isEnabled: boolean;
    hasApiKey: boolean;
    rateLimit: FeedConfiguration['rateLimit'];
    } {
    return {
      requestCount: this.requestCount,
      rateLimitRemaining: this.rateLimitRemaining,
      rateLimitReset: this.rateLimitReset,
      dailyLimit: this.dailyLimit,
      isEnabled: this.config.enabled || false,
      hasApiKey: !!this.apiKey,
      rateLimit: this.config.rateLimit
    };
  }

  /**
   * Test API connectivity and authentication
   */
  public async testConnection(): Promise<{ success: boolean; message: string; details?: any }> {
    try {
      // Test with a known IP (Google DNS)
      const testIP = '8.8.8.8';
      
      if (this.apiKey) {
        await this.fetchIPInfo(testIP);
        return {
          success: true,
          message: 'CrowdSec CTI API connection successful (authenticated)'
        };
      } else {
        await this.fetchSmokeData(testIP);
        return {
          success: true,
          message: 'CrowdSec Smoke API connection successful (anonymous)'
        };
      }
    } catch (error: any) {
      return {
        success: false,
        message: `CrowdSec API connection failed: ${error.message}`,
        details: {
          hasApiKey: !!this.apiKey,
          endpoint: this.baseUrl,
          error: error.message
        }
      };
    }
  }
} 
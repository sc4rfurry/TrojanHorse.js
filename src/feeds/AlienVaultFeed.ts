/**
 * AlienVault OTX Feed Integration
 * 
 * Provides secure integration with AlienVault Open Threat Exchange (OTX)
 * - Fetches subscribed pulses with threat indicators
 * - Supports optional API key authentication for higher rate limits
 * - Converts OTX pulse data to standardized ThreatIndicator format
 * - Implements secure rate limiting and error handling
 */

import axios, { AxiosInstance } from 'axios';
import { 
  ThreatIndicator, 
  ThreatFeedResult, 
  FeedConfiguration, 
  TrojanHorseError, 
  RateLimitError 
} from '../types';

export interface OTXPulse {
  id: string;
  name: string;
  description: string;
  author_name: string;
  public: boolean;
  created: string;
  modified: string;
  TLP: 'white' | 'green' | 'amber' | 'red';
  tags: string[];
  targeted_countries: string[];
  adversary: string;
  indicators: OTXIndicator[];
}

export interface OTXIndicator {
  id: number;
  indicator: string;
  type: string;
  title: string;
  description: string;
  created: string;
  is_active: boolean | number;
  access_type: 'public' | 'private' | 'redacted';
  content: string;
  role: string | null;
  expiration: string | null;
  observations: number;
}

export interface OTXResponse {
  count: number;
  next: string | null;
  previous: string | null;
  results: OTXPulse[];
}

export class AlienVaultFeed {
  private config: FeedConfiguration;
  private httpClient: AxiosInstance;
  private lastFetch: Date | null = null;
  private rateLimit: {
    requestsPerHour: number;
    requestCount: number;
    resetTime: Date;
  };

  constructor(config: Partial<FeedConfiguration> = {}) {
    this.config = {
      name: 'AlienVault OTX',
      endpoint: 'https://otx.alienvault.com/api/v1/pulses/subscribed',
      rateLimit: {
        requestsPerHour: config.apiKey ? 1000 : 100, // Higher with API key
        burstLimit: 5,
        retryAfter: 5000
      },
      timeout: 30000,
      retries: 3,
      ...config
    };

    // Initialize rate limiting
    this.rateLimit = {
      requestsPerHour: this.config.rateLimit?.requestsPerHour || 100,
      requestCount: 0,
      resetTime: new Date(Date.now() + 60 * 60 * 1000) // 1 hour from now
    };

    // Configure HTTP client with security headers
    this.httpClient = axios.create({
      baseURL: 'https://otx.alienvault.com/api/v1',
      timeout: this.config.timeout || 30000,
      headers: {
        'User-Agent': 'TrojanHorse.js/1.0.0 (Security Research)',
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        ...(this.config.apiKey && {
          'X-OTX-API-KEY': this.config.apiKey
        })
      },
      validateStatus: (status) => status < 500, // Allow client errors for handling
      maxRedirects: 5
      // Remove httpsAgent configuration that's causing issues
    });

    // Set up response interceptors for rate limiting
    this.httpClient.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response?.status === 429) {
          const retryAfter = parseInt(error.response.headers['retry-after'] || '60');
          throw new RateLimitError(
            'AlienVault OTX rate limit exceeded',
            retryAfter * 1000,
            { 
              provider: 'AlienVault OTX',
              endpoint: error.config?.url,
              resetTime: new Date(Date.now() + retryAfter * 1000)
            }
          );
        }
        return Promise.reject(error);
      }
    );
  }

  /**
   * Fetch threat intelligence data (main interface method)
   */
  public async fetchThreatData(): Promise<ThreatFeedResult> {
    return this.fetchThreats({
      modifiedSince: this.lastFetch || new Date(Date.now() - 24 * 60 * 60 * 1000), // Last 24 hours
      limit: 100,
      minimumConfidence: 0.5
    });
  }

  /**
   * Fetch threat intelligence from AlienVault OTX subscribed pulses
   */
  public async fetchThreats(options: {
    modifiedSince?: Date;
    limit?: number;
    minimumConfidence?: number;
  } = {}): Promise<ThreatFeedResult> {
    try {
      await this.checkRateLimit();
      
      const { modifiedSince, limit = 100, minimumConfidence = 0.5 } = options;
      
      // Build query parameters
      const params: Record<string, string> = {
        limit: limit.toString(),
        page: '1'
      };

      if (modifiedSince) {
        params.modified_since = modifiedSince.toISOString();
      }

      const response = await this.httpClient.get<OTXResponse>('/pulses/subscribed', {
        params
      });

      if (response.status !== 200) {
        throw new TrojanHorseError(
          `AlienVault OTX API returned status ${response.status}`,
          'FEED_API_ERROR',
          response.status
        );
      }

      const otxData = response.data;
      const indicators: ThreatIndicator[] = [];

      // Process each pulse and its indicators
      for (const pulse of otxData.results) {
        for (const otxIndicator of pulse.indicators) {
          // Skip inactive indicators
          if (!otxIndicator.is_active) {
            continue;
          }

          // Convert OTX indicator to standardized format
          const indicator = this.convertOTXIndicator(otxIndicator, pulse, minimumConfidence);
          if (indicator) {
            indicators.push(indicator);
          }
        }
      }

      this.lastFetch = new Date();
      
      return {
        source: this.config.name,
        timestamp: new Date(),
        indicators,
        metadata: {
          totalPulses: otxData.count,
          totalIndicators: indicators.length,
          hasMore: !!otxData.next,
          nextPage: otxData.next,
          rateLimit: {
            remaining: this.rateLimit.requestsPerHour - this.rateLimit.requestCount,
            resetTime: this.rateLimit.resetTime,
            limit: this.rateLimit.requestsPerHour
          }
        }
      };

    } catch (error) {
      if (error instanceof RateLimitError || error instanceof TrojanHorseError) {
        throw error;
      }

      throw new TrojanHorseError(
        `Failed to fetch from AlienVault OTX: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'FEED_FETCH_FAILED',
        500,
        { 
          originalError: error instanceof Error ? error.message : String(error),
          provider: 'AlienVault OTX'
        }
      );
    }
  }

  /**
   * Convert OTX indicator to standardized ThreatIndicator format
   */
  private convertOTXIndicator(
    otxIndicator: OTXIndicator, 
    pulse: OTXPulse, 
    minimumConfidence: number
  ): ThreatIndicator | null {
    try {
      // Map OTX indicator types to our standard types
      const typeMapping: Record<string, ThreatIndicator['type']> = {
        'IPv4': 'ip',
        'IPv6': 'ip',
        'domain': 'domain',
        'hostname': 'domain',
        'URL': 'url',
        'email': 'email',
        'FileHash-MD5': 'hash',
        'FileHash-SHA1': 'hash',
        'FileHash-SHA256': 'hash',
        'FileHash-PEHASH': 'hash',
        'FileHash-IMPHASH': 'hash',
        'FilePath': 'file_path'
      };

      const indicatorType = typeMapping[otxIndicator.type];
      if (!indicatorType) {
        // Skip unsupported indicator types
        return null;
      }

      // Calculate confidence based on OTX factors
      const confidence = this.calculateConfidence(otxIndicator, pulse);
      
      if (confidence < minimumConfidence) {
        return null;
      }

      // Determine severity based on TLP and pulse metadata
      const severity = this.determineSeverity(pulse, otxIndicator);

      return {
        type: indicatorType,
        value: otxIndicator.indicator,
        confidence,
        firstSeen: new Date(otxIndicator.created),
        lastSeen: new Date(pulse.modified),
        source: `AlienVault OTX - ${pulse.author_name}`,
        tags: [
          ...pulse.tags,
          ...(otxIndicator.role ? [otxIndicator.role] : []),
          ...(pulse.adversary ? [pulse.adversary] : [])
        ].filter(Boolean),
        malwareFamily: this.extractMalwareFamily(pulse),
        severity
      };

    } catch (error) {
      // Log parsing error but don't fail the entire operation
      console.warn(`Failed to parse OTX indicator ${otxIndicator.id}:`, error);
      return null;
    }
  }

  /**
   * Calculate confidence score based on OTX indicator quality signals
   */
  private calculateConfidence(indicator: OTXIndicator, pulse: OTXPulse): number {
    let confidence = 0.5; // Base confidence

    // Boost confidence for active indicators
    if (indicator.is_active) {
      confidence += 0.1;
    }

    // Boost for public access (more validated)
    if (indicator.access_type === 'public') {
      confidence += 0.1;
    }

    // Boost for observations/votes
    if (indicator.observations > 0) {
      confidence += Math.min(indicator.observations * 0.05, 0.2);
    }

    // Boost for detailed description
    if (indicator.description && indicator.description.length > 10) {
      confidence += 0.05;
    }

    // Boost for recent indicators
    const daysSinceCreated = (Date.now() - new Date(indicator.created).getTime()) / (1000 * 60 * 60 * 24);
    if (daysSinceCreated < 7) {
      confidence += 0.1;
    } else if (daysSinceCreated < 30) {
      confidence += 0.05;
    }

    // TLP-based confidence adjustment
    const tlpBoost = {
      'red': 0.3,
      'amber': 0.2,
      'green': 0.1,
      'white': 0.05
    };
    confidence += tlpBoost[pulse.TLP] || 0;

    return Math.min(confidence, 1.0);
  }

  /**
   * Determine severity based on pulse and indicator metadata
   */
  private determineSeverity(pulse: OTXPulse, indicator: OTXIndicator): ThreatIndicator['severity'] {
    // High severity for red TLP
    if (pulse.TLP === 'red') {
      return 'critical';
    }
    if (pulse.TLP === 'amber') {
      return 'high';
    }

    // Check for high-risk roles
    const highRiskRoles = [
      'command_and_control',
      'malware_hosting',
      'exploit_kit',
      'ransomware',
      'trojan',
      'backdoor'
    ];

    if (indicator.role && highRiskRoles.includes(indicator.role)) {
      return 'high';
    }

    // Check for medium-risk roles
    const mediumRiskRoles = [
      'phishing',
      'bruteforce',
      'web_attack',
      'scanning_host'
    ];

    if (indicator.role && mediumRiskRoles.includes(indicator.role)) {
      return 'medium';
    }

    // Default based on activity and observations
    if (indicator.observations > 10) {
      return 'medium';
    }
    
    return 'low';
  }

  /**
   * Extract malware family from pulse metadata
   */
  private extractMalwareFamily(pulse: OTXPulse): string | undefined {
    // Check pulse name for common malware families
    const malwareFamilies = [
      'emotet', 'trickbot', 'dridex', 'qakbot', 'cobalt strike',
      'ransomware', 'trojan', 'backdoor', 'rootkit', 'worm'
    ];

    const pulseName = pulse.name.toLowerCase();
    const malwareFamily = malwareFamilies.find(family => 
      pulseName.includes(family.toLowerCase())
    );

    return malwareFamily || pulse.adversary || undefined;
  }

  /**
   * Check rate limiting before making requests
   */
  private async checkRateLimit(): Promise<void> {
    const now = new Date();
    
    // Reset rate limit counter if an hour has passed
    if (now > this.rateLimit.resetTime) {
      this.rateLimit.requestCount = 0;
      this.rateLimit.resetTime = new Date(now.getTime() + 60 * 60 * 1000);
    }

    // Check if we've exceeded the rate limit
    if (this.rateLimit.requestCount >= this.rateLimit.requestsPerHour) {
      const resetIn = this.rateLimit.resetTime.getTime() - now.getTime();
      throw new RateLimitError(
        'AlienVault OTX rate limit exceeded',
        resetIn,
        {
          provider: 'AlienVault OTX',
          requestsPerHour: this.rateLimit.requestsPerHour,
          resetTime: this.rateLimit.resetTime
        }
      );
    }

    this.rateLimit.requestCount++;
  }

  /**
   * Test the feed connection and API key validity
   */
  public async testConnection(): Promise<boolean> {
    try {
      // Test with a simple API call
      const response = await this.httpClient.get('/pulses/subscribed', {
        params: { limit: '1' }
      });
      
      return response.status === 200;
    } catch (error) {
      return false;
    }
  }

  /**
   * Get feed statistics and health information
   */
  public getStats(): {
    lastFetch: Date | null;
    nextAllowedFetch: Date;
    rateLimit: FeedConfiguration['rateLimit'];
    hasApiKey: boolean;
    } {
    const nextAllowedFetch = new Date(
      Math.max(
        Date.now() + (this.config.rateLimit?.retryAfter || 5000),
        this.rateLimit.resetTime.getTime()
      )
    );

    return {
      lastFetch: this.lastFetch,
      nextAllowedFetch,
      rateLimit: this.config.rateLimit!,
      hasApiKey: !!this.config.apiKey
    };
  }

  /**
   * Get configuration information
   */
  public getConfig(): FeedConfiguration {
    // Return config without exposing sensitive API key
    return {
      ...this.config,
      apiKey: this.config.apiKey ? '***masked***' : undefined
    };
  }
} 
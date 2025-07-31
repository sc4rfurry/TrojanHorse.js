/**
 * AbuseIPDB Feed Integration
 * 
 * Integrates with AbuseIPDB's IP reputation and abuse database
 * - IP reputation scoring and confidence ratings
 * - Abuse category classifications
 * - Country and ISP information
 * - Free tier: 1000 requests/day, Premium: higher limits
 */

import axios, { AxiosResponse } from 'axios';
import { FeedConfiguration, ThreatIndicator, ThreatFeedResult } from '../types';

// AbuseIPDB API response interfaces
interface AbuseIPDBResponse {
  data: {
    ipAddress: string;
    isPublic: boolean;
    ipVersion: number;
    isWhitelisted: boolean;
    abuseConfidencePercentage: number;
    countryCode: string | null;
    countryName: string | null;
    usageType: string;
    isp: string | null;
    domain: string | null;
    hostnames: string[];
    totalReports: number;
    numDistinctUsers: number;
    lastReportedAt: string | null;
  };
}

interface AbuseIPDBBulkResponse {
  data: Array<{
    ipAddress: string;
    abuseConfidencePercentage: number;
    lastReportedAt: string;
  }>;
}

interface AbuseIPDBReportsResponse {
  data: {
    ipAddress: string;
    reports: Array<{
      reportedAt: string;
      comment: string;
      categories: number[];
      reporterId: number;
      reporterCountryCode: string;
      reporterCountryName: string;
    }>;
  };
}

interface AbuseIPDBError {
  errors: Array<{
    detail: string;
    status: number;
    source?: {
      parameter?: string;
    };
  }>;
}

// AbuseIPDB abuse categories mapping
const ABUSE_CATEGORIES = {
  1: 'DNS Compromise',
  2: 'DNS Poisoning',
  3: 'Fraud Orders',
  4: 'DDoS Attack',
  5: 'FTP Brute-Force',
  6: 'Ping of Death',
  7: 'Phishing',
  8: 'Fraud VoIP',
  9: 'Open Proxy',
  10: 'Web Spam',
  11: 'Email Spam',
  12: 'Blog Spam',
  13: 'VPN IP',
  14: 'Port Scan',
  15: 'Hacking',
  16: 'SQL Injection',
  17: 'Spoofing',
  18: 'Brute-Force',
  19: 'Bad Web Bot',
  20: 'Exploited Host',
  21: 'Web App Attack',
  22: 'SSH',
  23: 'IoT Targeted'
} as const;

export class AbuseIPDBFeed {
  private config: FeedConfiguration;
  private apiKey: string;
  private baseUrl: string = 'https://api.abuseipdb.com/api/v2';
  private rateLimitRemaining: number = 1000;
  private rateLimitReset: Date = new Date();
  private requestCount: number = 0;
  private dailyLimit: number = 1000; // Free tier default

  constructor(config: Partial<FeedConfiguration> = {}) {
    this.config = {
      name: 'AbuseIPDB',
      type: 'api',
      endpoint: 'https://api.abuseipdb.com/api/v2',
      authentication: {
        type: 'api_key',
        required: true,
        header: 'Key',
        credentials: {}
      },
      rateLimit: {
        requestsPerHour: 1000, // Conservative for free tier
        burstLimit: 5,
        retryAfter: 1000
      },
      enabled: true,
      priority: 'high',
      sslPinning: true,
      timeout: 30000,
      retries: 3,
      ...config
    };

    this.apiKey = config.apiKey || process.env.ABUSEIPDB_API_KEY || '';
    
    if (!this.apiKey) {
      throw new Error('AbuseIPDB API key is required. Set ABUSEIPDB_API_KEY environment variable or provide apiKey in config.');
    }

    // Detect premium tier based on rate limits
    // Premium users typically have higher limits
    this.dailyLimit = 1000; // Default to free tier
  }

  /**
   * Check a single IP address for abuse reports
   */
  public async checkIP(ip: string, options: {
    maxAgeInDays?: number;
    verbose?: boolean;
  } = {}): Promise<AbuseIPDBResponse> {
    const { maxAgeInDays = 90, verbose = false } = options;

    await this.checkRateLimit();

    try {
      const params = new URLSearchParams({
        ipAddress: ip,
        maxAgeInDays: maxAgeInDays.toString(),
        verbose: verbose.toString()
      });

      const response: AxiosResponse<AbuseIPDBResponse> = await axios.get(
        `${this.baseUrl}/check`,
        {
          headers: {
            'Key': this.apiKey,
            'Accept': 'application/json'
          },
          params,
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
      
      if (error.response?.status === 422) {
        const abuseError = error.response.data as AbuseIPDBError;
        const detail = abuseError.errors?.[0]?.detail || 'Invalid parameter';
        throw new Error(`AbuseIPDB validation error: ${detail}`);
      }

      if (error.response?.status === 401) {
        throw new Error('Invalid AbuseIPDB API key');
      }

      throw new Error(`AbuseIPDB API error: ${error.message}`);
    }
  }

  /**
   * Get detailed reports for an IP address
   */
  public async getReports(ip: string, options: {
    maxAgeInDays?: number;
    perPage?: number;
    page?: number;
  } = {}): Promise<AbuseIPDBReportsResponse> {
    const { maxAgeInDays = 90, perPage = 25, page = 1 } = options;

    await this.checkRateLimit();

    try {
      const params = new URLSearchParams({
        ipAddress: ip,
        maxAgeInDays: maxAgeInDays.toString(),
        perPage: perPage.toString(),
        page: page.toString()
      });

      const response: AxiosResponse<AbuseIPDBReportsResponse> = await axios.get(
        `${this.baseUrl}/reports`,
        {
          headers: {
            'Key': this.apiKey,
            'Accept': 'application/json'
          },
          params,
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

      throw new Error(`AbuseIPDB reports API error: ${error.message}`);
    }
  }

  /**
   * Fetch threat intelligence data (main interface method)
   * Since AbuseIPDB requires specific IPs, this uses a sample of known bad IPs
   */
  public async fetchThreatData(): Promise<ThreatFeedResult> {
    // Use a sample of commonly reported malicious IPs for demonstration
    // In production, you'd typically have your own list of IPs to check
    const sampleIPs = [
      '185.220.101.32', // Tor exit node (often flagged)
      '192.42.116.16',  // Known scanner
      '194.147.102.87', // Known malicious IP
      '45.148.10.62',   // VPN/proxy commonly flagged
      '89.248.174.241'  // Scanner/bot
    ];

    return this.fetchThreats({
      ips: sampleIPs,
      maxAgeInDays: 30,
      confidenceThreshold: 50,
      includeReports: false,
      maxResults: 50
    });
  }

  /**
   * Fetch threat data and convert to standard format
   */
  public async fetchThreats(options: {
    ips?: string[];
    maxAgeInDays?: number;
    confidenceThreshold?: number;
    includeReports?: boolean;
    maxResults?: number;
  } = {}): Promise<ThreatFeedResult> {
    const { 
      ips = [], 
      maxAgeInDays = 90, 
      confidenceThreshold = 25,
      includeReports = false,
      maxResults = 100 
    } = options;
    
    const indicators: ThreatIndicator[] = [];
    const errors: string[] = [];

    // AbuseIPDB requires specific IP addresses to check
    if (ips.length === 0) {
      console.warn('AbuseIPDB requires specific IP addresses to check');
      return {
        source: this.config.name,
        timestamp: new Date(),
        indicators: [],
        metadata: {
          totalCount: 0,
          totalIndicators: 0,
          hasMore: false,
          errors: ['No IP addresses provided for AbuseIPDB lookup']
        }
      };
    }

    // Process each IP
    for (const ip of ips.slice(0, maxResults)) {
      try {
        const abuseData = await this.checkIP(ip, { 
          maxAgeInDays,
          verbose: true 
        });

        // Only include IPs that meet confidence threshold
        if (abuseData.data.abuseConfidencePercentage >= confidenceThreshold) {
          let reports: AbuseIPDBReportsResponse['data']['reports'] | undefined = undefined;
          
          // Optionally fetch detailed reports
          if (includeReports && abuseData.data.totalReports > 0) {
            try {
              const reportsData = await this.getReports(ip, { maxAgeInDays });
              reports = reportsData.data.reports;
            } catch (error: any) {
              console.warn(`Failed to fetch reports for ${ip}:`, error.message);
            }
          }

          const indicator = this.mapToThreatIndicator(ip, abuseData.data, reports);
          if (indicator) {
            indicators.push(indicator);
          }
        }
      } catch (error: any) {
        errors.push(`${ip}: ${error.message}`);
        console.warn(`Failed to fetch AbuseIPDB data for ${ip}:`, error.message);
      }

      // Respect rate limits
      if (this.rateLimitRemaining <= 1) {
        console.warn('AbuseIPDB rate limit approaching, stopping batch processing');
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
        confidenceThreshold,
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
   * Map AbuseIPDB data to our ThreatIndicator format
   */
  private mapToThreatIndicator(
    ip: string, 
    data: AbuseIPDBResponse['data'],
    reports?: AbuseIPDBReportsResponse['data']['reports']
  ): ThreatIndicator | null {
    // Skip if confidence is too low or whitelisted
    if (data.abuseConfidencePercentage < 25 || data.isWhitelisted) {
      return null;
    }

    // Extract abuse categories from reports
    const abuseCategories = new Set<number>();
    if (reports) {
      reports.forEach(report => {
        report.categories.forEach(cat => abuseCategories.add(cat));
      });
    }

    const confidence = this.calculateConfidence(data, reports);
    const severity = this.mapSeverity(data.abuseConfidencePercentage);

    return {
      type: 'ip',
      value: ip,
      confidence,
      severity,
      firstSeen: reports && reports.length > 0 
        ? new Date(Math.min(...reports.map(r => new Date(r.reportedAt).getTime())))
        : new Date(),
      lastSeen: data.lastReportedAt ? new Date(data.lastReportedAt) : new Date(),
      source: this.config.name,
      tags: [
        ...Array.from(abuseCategories).map(cat => 
          ABUSE_CATEGORIES[cat as keyof typeof ABUSE_CATEGORIES] || `category-${cat}`
        ),
        data.usageType,
        'abuseipdb'
      ].filter(Boolean),
      metadata: {
        abuseipdb: {
          abuseConfidencePercentage: data.abuseConfidencePercentage,
          totalReports: data.totalReports,
          numDistinctUsers: data.numDistinctUsers,
          isPublic: data.isPublic,
          isWhitelisted: data.isWhitelisted,
          ipVersion: data.ipVersion,
          country: {
            code: data.countryCode,
            name: data.countryName
          },
          usageType: data.usageType,
          isp: data.isp,
          domain: data.domain,
          hostnames: data.hostnames,
          categories: Array.from(abuseCategories),
          reports: reports?.slice(0, 10)?.map(report => ({
            reportedAt: report.reportedAt,
            comment: report.comment?.substring(0, 200), // Truncate long comments
            categories: report.categories,
            reporterCountry: report.reporterCountryName
          }))
        }
      },
      description: this.generateDescription(data, Array.from(abuseCategories)),
      malwareFamily: this.extractMalwareFamily(Array.from(abuseCategories))
    };
  }

  /**
   * Calculate confidence score based on AbuseIPDB data
   */
  private calculateConfidence(
    data: AbuseIPDBResponse['data'], 
    reports?: AbuseIPDBReportsResponse['data']['reports']
  ): number {
    let confidence = data.abuseConfidencePercentage / 100; // Base on AbuseIPDB confidence

    // Adjust based on report volume
    if (data.totalReports > 50) {
      confidence += 0.1;
    } else if (data.totalReports > 10) {
      confidence += 0.05;
    }

    // Adjust based on distinct reporters
    if (data.numDistinctUsers > 10) {
      confidence += 0.1;
    } else if (data.numDistinctUsers > 5) {
      confidence += 0.05;
    }

    // Recent activity increases confidence
    if (data.lastReportedAt) {
      const daysSinceLastReport = (Date.now() - new Date(data.lastReportedAt).getTime()) / (1000 * 60 * 60 * 24);
      if (daysSinceLastReport < 7) {
        confidence += 0.1;
      } else if (daysSinceLastReport < 30) {
        confidence += 0.05;
      }
    }

    // Multiple distinct abuse categories increase confidence
    if (reports) {
      const categories = new Set();
      reports.forEach(r => r.categories.forEach(c => categories.add(c)));
      if (categories.size > 3) {
        confidence += 0.1;
      } else if (categories.size > 1) {
        confidence += 0.05;
      }
    }

    return Math.max(0.1, Math.min(confidence, 1.0));
  }

  /**
   * Map AbuseIPDB confidence percentage to severity levels
   */
  private mapSeverity(confidencePercentage: number): 'low' | 'medium' | 'high' | 'critical' {
    if (confidencePercentage >= 75) {
      return 'critical';
    }
    if (confidencePercentage >= 50) {
      return 'high';
    }
    if (confidencePercentage >= 25) {
      return 'medium';
    }
    return 'low';
  }

  /**
   * Generate human-readable description
   */
  private generateDescription(
    data: AbuseIPDBResponse['data'],
    categories: number[]
  ): string {
    const parts: string[] = [];

    parts.push(`IP reported with ${data.abuseConfidencePercentage}% confidence`);
    
    if (data.totalReports > 0) {
      parts.push(`${data.totalReports} reports from ${data.numDistinctUsers} users`);
    }

    if (categories.length > 0) {
      const categoryNames = categories
        .map(cat => ABUSE_CATEGORIES[cat as keyof typeof ABUSE_CATEGORIES])
        .filter(Boolean)
        .slice(0, 3);
      
      if (categoryNames.length > 0) {
        parts.push(`Categories: ${categoryNames.join(', ')}`);
      }
    }

    if (data.countryName) {
      parts.push(`Location: ${data.countryName}`);
    }

    return parts.join('. ');
  }

  /**
   * Extract potential malware family from abuse categories
   */
  private extractMalwareFamily(categories: number[]): string | undefined {
    // Map certain categories to malware families
    for (const cat of categories) {
      switch (cat) {
      case 4: return 'DDoS Botnet';
      case 15: return 'Hacking Tools';
      case 19: return 'Malicious Bot';
      case 20: return 'Compromised Host';
      case 21: return 'Web Attack Tools';
      case 23: return 'IoT Malware';
      }
    }
    return undefined;
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
      // Test with a known malicious IP (if available) or a safe test IP
      const testIP = '127.0.0.1'; // localhost - should be safe to test
      
      await this.checkIP(testIP, { maxAgeInDays: 30 });
      
      return {
        success: true,
        message: 'AbuseIPDB API connection successful',
        details: {
          endpoint: this.baseUrl,
          rateLimitRemaining: this.rateLimitRemaining,
          dailyLimit: this.dailyLimit
        }
      };
    } catch (error: any) {
      return {
        success: false,
        message: `AbuseIPDB API connection failed: ${error.message}`,
        details: {
          hasApiKey: !!this.apiKey,
          endpoint: this.baseUrl,
          error: error.message
        }
      };
    }
  }
} 
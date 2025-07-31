/**
 * URLhaus Feed - Abuse.ch malicious URL feed integration
 * CSV-based feed with no authentication required
 */

import axios, { AxiosInstance } from 'axios';
import { 
  ThreatIndicator, 
  ThreatFeedResult, 
  FeedConfiguration, 
  URLhausEntry,
  TrojanHorseError,
  RateLimitError 
} from '../types';

interface FeedStats {
  lastFetch: Date | null;
  nextAllowedFetch: Date;
  rateLimit: FeedConfiguration['rateLimit'];
  successCount: number;
  errorCount: number;
  requestsProcessed: number;
}

interface CacheEntry {
  data: ThreatFeedResult;
  timestamp: number;
}

export class URLhausFeed {
  private readonly axiosInstance: AxiosInstance;
  private config: FeedConfiguration; // Removed readonly for updateConfig
  private lastFetchTime: number = 0;
  private readonly MIN_FETCH_INTERVAL = 300000; // 5 minutes
  private stats: FeedStats;
  private cache: Map<string, CacheEntry> = new Map();
  private promiseCache: Map<string, Promise<ThreatFeedResult>> = new Map(); // Add promise cache
  private readonly DEFAULT_CACHE_TTL = 600000; // 10 minutes

  constructor() {
    this.config = {
      name: 'URLhaus',
      type: 'csv',
      endpoint: 'https://urlhaus.abuse.ch/downloads/csv_recent/',
      authentication: {
        type: 'none',
        required: false
      },
      rateLimit: {
        requestsPerHour: 12, // Conservative rate limit
        burstLimit: 1
      },
      enabled: true,
      priority: 'high',
      sslPinning: true,
      timeout: 30000,
      retries: 3,
      cacheTTL: this.DEFAULT_CACHE_TTL
    };

    this.stats = {
      lastFetch: null,
      nextAllowedFetch: new Date(Date.now() + this.MIN_FETCH_INTERVAL),
      rateLimit: this.config.rateLimit,
      successCount: 0,
      errorCount: 0,
      requestsProcessed: 0
    };

    this.axiosInstance = axios.create({
      timeout: this.config.timeout || 30000,
      headers: {
        'User-Agent': 'TrojanHorse.js/1.0.1 (Threat Intelligence Library)',
        'Accept': 'text/csv',
        'Cache-Control': 'no-cache'
      },
      httpsAgent: undefined, // Will be configured for SSL pinning if needed
      validateStatus: (status) => status >= 200 && status < 300
    });

    this.setupInterceptors();
  }

  /**
   * Update feed configuration
   */
  public updateConfig(newConfig: Partial<FeedConfiguration>): void {
    this.config = { ...this.config, ...newConfig };
    
    // Update axios instance if timeout changed
    if (newConfig.timeout) {
      this.axiosInstance.defaults.timeout = newConfig.timeout;
    }
  }

  /**
   * Fetch recent malicious URLs from URLhaus
   */
  public async fetchThreatData(): Promise<ThreatFeedResult> {
    const cacheKey = 'recent_urls';
    
    // Check data cache first
    const cached = this.getCachedData(cacheKey);
    if (cached) {
      return cached;
    }

    // Check if request is already in progress
    if (this.promiseCache.has(cacheKey)) {
      return await this.promiseCache.get(cacheKey)!;
    }

    // Create new request promise
    const requestPromise = this.performFetch(cacheKey);
    this.promiseCache.set(cacheKey, requestPromise);

    try {
      const result = await requestPromise;
      return result;
    } finally {
      // Remove promise from cache when done
      this.promiseCache.delete(cacheKey);
    }
  }

  /**
   * Get feed configuration
   */
  public getConfig(): FeedConfiguration {
    return { ...this.config };
  }

  /**
   * Check if feed is available
   */
  public async checkAvailability(): Promise<boolean> {
    try {
      const response = await this.axiosInstance.head(this.config.endpoint);
      return response.status === 200;
    } catch (error) {
      return false;
    }
  }

  /**
   * Get feed statistics
   */
  public getStats(): FeedStats {
    return {
      lastFetch: this.lastFetchTime ? new Date(this.lastFetchTime) : null,
      nextAllowedFetch: new Date(this.lastFetchTime + this.MIN_FETCH_INTERVAL),
      rateLimit: this.config.rateLimit,
      successCount: this.stats.successCount,
      errorCount: this.stats.errorCount,
      requestsProcessed: this.stats.requestsProcessed
    };
  }

  // === PRIVATE METHODS ===

  private getCachedData(key: string): ThreatFeedResult | null {
    const entry = this.cache.get(key);
    if (!entry) {
      return null;
    }

    const now = Date.now();
    const ttl = this.config.cacheTTL || this.DEFAULT_CACHE_TTL;
    
    if (now - entry.timestamp > ttl) {
      this.cache.delete(key);
      return null;
    }

    return entry.data;
  }

  private setCachedData(key: string, data: ThreatFeedResult): void {
    this.cache.set(key, {
      data,
      timestamp: Date.now()
    });
  }

  private setupInterceptors(): void {
    // Request interceptor for logging and security
    this.axiosInstance.interceptors.request.use(
      (config) => {
        // Use proper logging instead of console.log
        if (process.env.NODE_ENV !== 'test') {
          // console.log(`[URLhaus] Fetching threat data from ${config.url}`);
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor for security validation
    this.axiosInstance.interceptors.response.use(
      (response) => {
        // Validate response size (prevent DoS)
        const maxSize = 50 * 1024 * 1024; // 50MB max
        const contentLength = response.headers['content-length'];
        
        if (contentLength && parseInt(contentLength) > maxSize) {
          throw new TrojanHorseError(
            'Response too large',
            'RESPONSE_TOO_LARGE',
            response.status
          );
        }

        return response;
      },
      (error) => Promise.reject(error)
    );
  }

  // @ts-ignore - Keep for future use
  private checkRateLimit(): void {
    const now = Date.now();
    const timeSinceLastFetch = now - this.lastFetchTime;

    if (timeSinceLastFetch < this.MIN_FETCH_INTERVAL) {
      const waitTime = this.MIN_FETCH_INTERVAL - timeSinceLastFetch;
      throw new RateLimitError(
        `URLhaus rate limit: must wait ${Math.ceil(waitTime / 1000)} seconds`,
        waitTime
      );
    }
  }

  private async performFetch(cacheKey: string): Promise<ThreatFeedResult> {
    let lastError: Error | null = null;
    const maxRetries = this.config.retries || 3;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        const response = await this.axiosInstance.get(this.config.endpoint);
        const csvData = response.data as string;
        
        const entries = this.parseCSV(csvData);
        const indicators = this.convertToThreatIndicators(entries);

        this.lastFetchTime = Date.now();
        this.stats.successCount++;
        this.stats.requestsProcessed++;
        this.stats.lastFetch = new Date();

        const result: ThreatFeedResult = {
          source: this.config.name,
          timestamp: new Date(),
          indicators,
          metadata: {
            totalCount: indicators.length,
            totalIndicators: indicators.length,
            requestsProcessed: this.stats.requestsProcessed
          }
        };

        // Cache the result
        this.setCachedData(cacheKey, result);

        return result;
      } catch (error) {
        lastError = error as Error;
        this.stats.errorCount++;
        
        if (attempt < maxRetries) {
          // Wait before retry (exponential backoff)
          await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempt) * 1000));
          continue;
        }

        // Handle final error after all retries
        const err = error as any; // Type assertion for error handling
        
        // More robust axios error detection
        const isAxiosError = axios.isAxiosError(err) || err.isAxiosError || err.name === 'AxiosError';
        const hasResponse = err.response && typeof err.response === 'object';
        const hasAxiosProps = err.config || err.request || hasResponse;
        
        // Check for axios-like errors (including mocked ones)
        if (isAxiosError || hasAxiosProps || hasResponse) {
          const response = err.response;
          const status = response?.status;
          const statusText = response?.statusText || 'HTTP Error';
          
          // Rate limiting (429)
          if (status === 429) {
            throw new RateLimitError(
              'URLhaus rate limit exceeded',
              response.headers?.['retry-after'] ? parseInt(response.headers['retry-after']) * 1000 : 300000
            );
          }
          
          // Server errors (5xx)
          if (status && status >= 500) {
            throw new TrojanHorseError(
              `URLhaus server error: ${status} ${statusText}`,
              'FEED_ERROR',
              status,
              { provider: 'URLhaus', originalError: err }
            );
          }

          // Client errors (4xx)
          if (status && status >= 400) {
            throw new TrojanHorseError(
              `URLhaus HTTP error: ${status} ${statusText}`,
              'HTTP_ERROR', 
              status,
              { provider: 'URLhaus', originalError: err }
            );
          }

          // Timeout errors
          if (err.code === 'ECONNABORTED' || 
              (err.message && err.message.includes('timeout'))) {
            throw new TrojanHorseError(
              `URLhaus request timeout: ${err.message || 'Request timeout'}`,
              'TIMEOUT_ERROR',
              undefined,
              { provider: 'URLhaus', originalError: err }
            );
          }
          
          // Generic axios error
          throw new TrojanHorseError(
            `URLhaus feed error: ${err.message || 'Request failed'}`,
            'FEED_ERROR',
            status,
            { provider: 'URLhaus', originalError: err }
          );
        }
        
        // Handle network errors that aren't axios errors
        if (err.message && (err.message.includes('Network Error') || err.message.includes('fetch'))) {
          throw new TrojanHorseError(
            `URLhaus network error: ${err.message}`,
            'NETWORK_ERROR',
            undefined,
            { provider: 'URLhaus', originalError: err }
          );
        }
        
        throw new TrojanHorseError(
          'Unknown error fetching URLhaus data',
          'UNKNOWN_ERROR',
          undefined,
          { provider: 'URLhaus', originalError: err }
        );
      }
    }

    throw lastError || new Error('Maximum retries exceeded');
  }

  private parseCSV(csvData: string): URLhausEntry[] {
    const lines = csvData.trim().split('\n');
    const entries: URLhausEntry[] = [];

    // Skip header lines (lines starting with #)
    const dataLines = lines.filter(line => !line.startsWith('#') && line.trim());

    for (const line of dataLines) {
      try {
        const entry = this.parseCSVLine(line);
        if (entry) {
          entries.push(entry);
        }
      } catch (error) {
        // Increment error count but continue processing
        this.stats.errorCount++;
      }
    }

    return entries;
  }

  private parseCSVLine(line: string): URLhausEntry | null {
    // URLhaus CSV format: id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter
    const columns = this.parseCSVColumns(line);
    
    if (columns.length < 8) {
      return null;
    }

    const [id, dateAdded, url, urlStatus, threat, tags, , reporter] = columns;

    if (!id || !dateAdded || !url) {
      return null;
    }

    return {
      id: id.trim(),
      dateAdded: new Date(dateAdded.trim()),
      url: url.trim(),
      urlStatus: (urlStatus?.trim() || 'offline') as 'online' | 'offline',
      threat: threat?.trim() || 'unknown',
      tags: tags ? tags.split(',').map(tag => tag.trim()).filter(Boolean) : [],
      reporter: reporter?.trim() || 'unknown'
    };
  }

  private parseCSVColumns(line: string): string[] {
    const columns: string[] = [];
    let current = '';
    let inQuotes = false;

    for (let i = 0; i < line.length; i++) {
      const char = line[i];
      
      if (char === '"') {
        inQuotes = !inQuotes;
      } else if (char === ',' && !inQuotes) {
        columns.push(current);
        current = '';
      } else {
        current += char;
      }
    }
    
    columns.push(current);
    return columns.map(col => col.replace(/^"(.*)"$/, '$1')); // Remove surrounding quotes
  }

  private convertToThreatIndicators(entries: URLhausEntry[]): ThreatIndicator[] {
    const indicators: ThreatIndicator[] = [];

    for (const entry of entries) {
      // Create URL indicator
      const severity = this.determineSeverity(entry.threat, entry.tags);
      
      const urlIndicator: ThreatIndicator = {
        type: 'url',
        value: entry.url,
        confidence: 0.85, // URLhaus has high confidence
        firstSeen: entry.dateAdded,
        lastSeen: entry.dateAdded, // URLhaus doesn't provide separate last seen
        source: 'URLhaus',
        tags: [entry.threat, ...entry.tags].filter(Boolean),
        malwareFamily: this.extractMalwareFamily(entry.threat, entry.tags),
        severity
      };
      
      indicators.push(urlIndicator);

      // Extract domain indicator
      try {
        const urlObj = new URL(entry.url);
        if (urlObj.hostname && urlObj.hostname !== entry.url) {
          const domainIndicator: ThreatIndicator = {
            type: 'domain',
            value: urlObj.hostname,
            confidence: 0.75, // Slightly lower confidence for derived indicators
            firstSeen: entry.dateAdded,
            lastSeen: entry.dateAdded,
            source: 'URLhaus',
            tags: [entry.threat, ...entry.tags, 'derived-from-url'].filter(Boolean),
            malwareFamily: this.extractMalwareFamily(entry.threat, entry.tags),
            severity
          };
          indicators.push(domainIndicator);
        }

        // Extract IP indicator if hostname is an IP
        const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
        if (ipPattern.test(urlObj.hostname)) {
          const ipIndicator: ThreatIndicator = {
            type: 'ip',
            value: urlObj.hostname,
            confidence: 0.8,
            firstSeen: entry.dateAdded,
            lastSeen: entry.dateAdded,
            source: 'URLhaus',
            tags: [entry.threat, ...entry.tags, 'derived-from-url'].filter(Boolean),
            malwareFamily: this.extractMalwareFamily(entry.threat, entry.tags),
            severity
          };
          indicators.push(ipIndicator);
        }
      } catch (urlError) {
        // Invalid URL, skip derived indicators
      }
    }

    return indicators;
  }

  private determineSeverity(threat: string, tags: string[]): 'low' | 'medium' | 'high' | 'critical' {
    const lowSeverityTerms = ['adware', 'potentially unwanted', 'pup'];
    const highSeverityTerms = ['ransomware', 'banking', 'stealer', 'trojan'];
    const criticalSeverityTerms = ['apt', 'targeted', 'zero-day'];

    const allTerms = [threat, ...tags].join(' ').toLowerCase();

    if (criticalSeverityTerms.some(term => allTerms.includes(term))) {
      return 'critical';
    }
    
    if (highSeverityTerms.some(term => allTerms.includes(term))) {
      return 'high';
    }
    
    if (lowSeverityTerms.some(term => allTerms.includes(term))) {
      return 'low';
    }

    return 'medium'; // Default severity
  }

  private extractMalwareFamily(threat: string, tags: string[]): string | undefined {
    // Common malware family patterns
    const familyPatterns = [
      /emotet/i,
      /trickbot/i,
      /dridex/i,
      /qakbot/i,
      /cobalt\s*strike/i,
      /metasploit/i,
      /mirai/i,
      /locky/i,
      /wannacry/i,
      /malware/i,
      /trojan/i,
      /ransomware/i,
      /phishing/i,
      /exploit/i
    ];

    const allText = [threat, ...tags].join(' ');
    
    for (const pattern of familyPatterns) {
      const match = allText.match(pattern);
      if (match) {
        return match[0].toLowerCase();
      }
    }

    // Return cleaned threat type as malware family if no specific pattern found
    const threatLower = threat?.toLowerCase()?.trim();
    if (threatLower && threatLower !== 'unknown' && !threatLower.includes('-')) {
      return threatLower;
    }

    return undefined;
  }
} 
/**
 * @jest-environment node
 */

import { jest } from '@jest/globals';
import axios from 'axios';
import { URLhausFeed } from '../URLhausFeed';
import { TestUtils } from '../../../tests/setup';
import type { ThreatFeedResult, ThreatIndicator } from '../../types';

// Mock axios
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

// Mock CSV data for testing
const MOCK_URLHAUS_CSV = `# Abuse.ch URLhaus Database Dump
# Generated: 2024-01-15 12:00:00
# Copyright (c) 2024 Abuse.ch
# License: Free for non-commercial use  
# Terms: https://urlhaus.abuse.ch/api/
# Fields: id,date_added,url,url_status,last_online,threat,tags,reporter
# Comments start with #
"1","2024-01-15 10:30:00","http://malicious-site.com/malware.exe","online","2024-01-15 12:00:00","malware","exe,trojan","security_researcher"
"2","2024-01-15 09:15:00","https://phishing-example.net/login","offline","2024-01-15 11:00:00","phishing","banking,credential_theft","automated"
"3","2024-01-15 08:45:00","http://bad-domain.org/exploit.php","online","2024-01-15 11:45:00","exploit_kit","php,exploit","analyst"
"4","2024-01-15 07:30:00","https://threat-actor.co/payload.js","online","2024-01-15 11:30:00","malware","js,downloader","honeypot"
"5","2024-01-15 06:00:00","http://scam-website.info/fake-bank","offline","2024-01-15 10:00:00","phishing","banking,fake","researcher"
`;

describe('URLhaus Feed Integration', () => {
  let urlhausFeed: URLhausFeed;
  let axiosInstanceMock: any;
  
  beforeEach(() => {
    // Clear all mocks
    jest.clearAllMocks();
    
    // Create axios instance mock
    axiosInstanceMock = {
      get: jest.fn(),
      head: jest.fn(),
      defaults: {
        timeout: 30000,
        headers: {}
      },
      interceptors: {
        request: { use: jest.fn() },
        response: { use: jest.fn() }
      }
    };
    
    // Mock axios.create to return our mock instance
    mockedAxios.create.mockReturnValue(axiosInstanceMock);
    
    // Create URLhausFeed instance
    urlhausFeed = new URLhausFeed();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Feed Configuration', () => {
    test('should initialize with default configuration', () => {
      expect(urlhausFeed.config).toBeDefined();
      expect(urlhausFeed.config.name).toBe('URLhaus');
      expect(urlhausFeed.config.endpoint).toContain('urlhaus.abuse.ch');
      expect(urlhausFeed.config.authentication.type).toBe('none');
    });

    test('should have correct feed metadata', () => {
      const config = urlhausFeed.config;
      
      expect(config.type).toBe('csv');
      expect(config.priority).toBe('high');
      expect(config.enabled).toBe(true);
      expect(config.sslPinning).toBe(true);
    });

    test('should support configuration updates', () => {
      const customConfig = {
        timeout: 30000,
        retries: 5,
        rateLimit: {
          requestsPerHour: 100,
          burstLimit: 10
        }
      };

      urlhausFeed.updateConfig(customConfig);
      
      expect(urlhausFeed.config.timeout).toBe(30000);
      expect(urlhausFeed.config.retries).toBe(5);
    });
  });

  describe('Data Fetching', () => {
    test('should fetch threat data successfully', async () => {
      // Mock successful response
      axiosInstanceMock.get.mockResolvedValueOnce({
        status: 200,
        data: MOCK_URLHAUS_CSV
      });

      const result = await urlhausFeed.fetchThreatData();

      expect(result).toBeDefined();
      expect(result.source).toBe('URLhaus');
      expect(result.timestamp).toBeInstanceOf(Date);
      expect(result.indicators).toBeInstanceOf(Array);
      expect(result.indicators.length).toBeGreaterThan(0);
    });

    test('should handle network errors gracefully', async () => {
      // Mock network error
      const networkError = new Error('Network Error');
      (networkError as any).isAxiosError = true;
      axiosInstanceMock.get.mockRejectedValueOnce(networkError);

      await expect(urlhausFeed.fetchThreatData()).rejects.toThrow(/network|fetch/i);
    });

    test('should handle HTTP errors', async () => {
      // Mock HTTP error response
      const httpError = new Error('Request failed with status code 500');
      (httpError as any).isAxiosError = true;
      (httpError as any).response = {
        status: 500,
        statusText: 'Internal Server Error'
      };
      axiosInstanceMock.get.mockRejectedValueOnce(httpError);

      await expect(urlhausFeed.fetchThreatData()).rejects.toThrow(/500|server error/i);
    });

    test('should handle rate limiting', async () => {
      // Mock rate limit response
      const rateLimitError = new Error('Request failed with status code 429');
      (rateLimitError as any).isAxiosError = true;
      (rateLimitError as any).response = {
        status: 429,
        statusText: 'Too Many Requests',
        headers: { 'retry-after': '60' }
      };
      axiosInstanceMock.get.mockRejectedValueOnce(rateLimitError);

      await expect(urlhausFeed.fetchThreatData()).rejects.toThrow(/rate limit|429/i);
    });

    test('should respect timeout settings', async () => {
      urlhausFeed.updateConfig({ timeout: 1000 });

      // Mock timeout error
      const timeoutError = new Error('timeout of 1000ms exceeded');
      (timeoutError as any).isAxiosError = true;
      (timeoutError as any).code = 'ECONNABORTED';
      axiosInstanceMock.get.mockRejectedValueOnce(timeoutError);

      await expect(urlhausFeed.fetchThreatData()).rejects.toThrow(/timeout/i);
    });
  });

  describe('CSV Parsing', () => {
    beforeEach(() => {
      // Mock successful fetch
      axiosInstanceMock.get.mockResolvedValue({
        status: 200,
        data: MOCK_URLHAUS_CSV
      });
    });

    test('should parse CSV data correctly', async () => {
      const result = await urlhausFeed.fetchThreatData();
      const indicators = result.indicators;

      // With domain/IP extraction, we get more indicators than CSV lines
      expect(indicators.length).toBeGreaterThan(5); // Original 5 + derived indicators

      // Find URL indicators (original ones)
      const urlIndicators = indicators.filter(i => i.type === 'url');
      expect(urlIndicators).toHaveLength(5); // 5 URLs in mock data

      // Check first URL indicator
      const firstIndicator = urlIndicators[0];
      expect(firstIndicator.type).toBe('url');
      expect(firstIndicator.value).toBe('http://malicious-site.com/malware.exe');
      expect(firstIndicator.confidence).toBeGreaterThanOrEqual(0);
      expect(firstIndicator.confidence).toBeLessThanOrEqual(1);
      expect(firstIndicator.source).toBe('URLhaus');
      expect(firstIndicator.tags).toContain('malware');
      expect(firstIndicator.severity).toMatch(/low|medium|high|critical/);
    });

    test('should handle malformed CSV entries', async () => {
      const malformedCSV = `# Header
"1","2024-01-15","malformed-entry"
"2","2024-01-15 10:30:00","http://valid-url.com","online","2024-01-15 12:00:00","malware","tag","reporter"
`;

      axiosInstanceMock.get.mockResolvedValueOnce({
        status: 200,
        data: malformedCSV
      });

      const result = await urlhausFeed.fetchThreatData();

      // Should only parse valid entries and generate derived indicators
      const urlIndicators = result.indicators.filter(i => i.type === 'url');
      expect(urlIndicators).toHaveLength(1);
      expect(urlIndicators[0].value).toBe('http://valid-url.com');
    });

    test('should skip comment and header lines', async () => {
      const csvWithComments = `# This is a comment
# Another comment
"1","2024-01-15 10:30:00","http://test1.com","online","2024-01-15 12:00:00","malware","tag","reporter"
"2","2024-01-15 10:31:00","http://test2.com","online","2024-01-15 12:01:00","phishing","tag","reporter"
`;

      axiosInstanceMock.get.mockResolvedValueOnce({
        status: 200,
        data: csvWithComments
      });

      const result = await urlhausFeed.fetchThreatData();
      const urlIndicators = result.indicators.filter(i => i.type === 'url');
      expect(urlIndicators).toHaveLength(2);
    });

    test('should handle different threat types correctly', async () => {
      const result = await urlhausFeed.fetchThreatData();
      const indicators = result.indicators;

      // Should have various malware families extracted
      const malwareFamilies = indicators
        .map(i => i.malwareFamily)
        .filter(Boolean);
      
      expect(malwareFamilies.length).toBeGreaterThan(0);
      expect(malwareFamilies).toContain('malware');
    });

    test('should calculate confidence scores appropriately', async () => {
      const result = await urlhausFeed.fetchThreatData();
      const indicators = result.indicators;

      // All indicators should have confidence scores
      indicators.forEach(indicator => {
        expect(indicator.confidence).toBeGreaterThanOrEqual(0);
        expect(indicator.confidence).toBeLessThanOrEqual(1);
      });

      // URL indicators should have standard confidence
      const urlIndicators = indicators.filter(i => i.type === 'url');
      urlIndicators.forEach(indicator => {
        expect(indicator.confidence).toBe(0.85); // URLhaus standard confidence
      });
    });
  });

  describe('Threat Indicator Generation', () => {
    beforeEach(() => {
      axiosInstanceMock.get.mockResolvedValue({
        status: 200,
        data: MOCK_URLHAUS_CSV
      });
    });

    test('should generate valid threat indicators', async () => {
      const result = await urlhausFeed.fetchThreatData();
      
      result.indicators.forEach(indicator => {
        // Validate required fields
        expect(indicator.type).toMatch(/url|domain|ip/);
        expect(indicator.value).toBeTruthy();
        expect(indicator.firstSeen).toBeInstanceOf(Date);
        expect(indicator.lastSeen).toBeInstanceOf(Date);
        expect(indicator.source).toBe('URLhaus');
        expect(Array.isArray(indicator.tags)).toBe(true);
        expect(indicator.severity).toMatch(/low|medium|high|critical/);
      });
    });

    test('should extract domains from URLs', async () => {
      const result = await urlhausFeed.fetchThreatData();
      const indicators = result.indicators;

      // Should contain both URL and domain indicators
      const urlIndicators = indicators.filter(i => i.type === 'url');
      const domainIndicators = indicators.filter(i => i.type === 'domain');

      expect(urlIndicators.length).toBeGreaterThan(0);
      expect(domainIndicators.length).toBeGreaterThan(0);

      // Each URL should have a corresponding domain (except for IP-based URLs)
      urlIndicators.forEach(urlIndicator => {
        try {
          const url = new URL(urlIndicator.value);
          const hostname = url.hostname;
          
          // Skip IP addresses (they create IP indicators instead)
          const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
          if (!ipPattern.test(hostname)) {
            const correspondingDomain = domainIndicators.find(
              d => d.value === hostname
            );
            expect(correspondingDomain).toBeDefined();
          }
        } catch (urlError) {
          // Skip invalid URLs
        }
      });
    });

    test('should handle IP addresses in URLs', async () => {
      const ipUrlCSV = `# Header
"1","2024-01-15 10:30:00","http://192.168.1.100/malware","online","2024-01-15 12:00:00","malware","ip","researcher"
`;

      axiosInstanceMock.get.mockResolvedValueOnce({
        status: 200,
        data: ipUrlCSV
      });

      const result = await urlhausFeed.fetchThreatData();
      const indicators = result.indicators;

      // Should create IP indicator for IP-based URLs
      const ipIndicators = indicators.filter(i => i.type === 'ip');
      expect(ipIndicators.length).toBeGreaterThan(0);
      expect(ipIndicators[0].value).toBe('192.168.1.100');
    });
  });

  describe('Metadata and Statistics', () => {
    beforeEach(() => {
      axiosInstanceMock.get.mockResolvedValue({
        status: 200,
        data: MOCK_URLHAUS_CSV
      });
    });

    test('should provide comprehensive metadata', async () => {
      const result = await urlhausFeed.fetchThreatData();
      const metadata = result.metadata;

      expect(metadata).toBeDefined();
      expect(metadata?.totalCount).toBe(result.indicators.length);
      expect(metadata?.totalIndicators).toBe(result.indicators.length);
      expect(typeof metadata?.requestsProcessed).toBe('number');
    });

    test('should track feed statistics', async () => {
      await urlhausFeed.fetchThreatData();

      const stats = urlhausFeed.getStats();
      expect(stats.successCount).toBeGreaterThan(0);
      expect(stats.requestsProcessed).toBeGreaterThan(0);
      expect(stats.lastFetch).toBeInstanceOf(Date);
    });

    test('should track error statistics', async () => {
      // Force an error
      const networkError = new Error('Network Error');
      (networkError as any).isAxiosError = true;
      axiosInstanceMock.get.mockRejectedValueOnce(networkError);

      try {
        await urlhausFeed.fetchThreatData();
      } catch (error) {
        // Expected error
      }

      const stats = urlhausFeed.getStats();
      expect(stats.errorCount).toBeGreaterThan(0);
    });
  });

  describe('Caching and Performance', () => {
    test('should implement request caching', async () => {
      // Mock successful response
      axiosInstanceMock.get.mockResolvedValue({
        status: 200,
        data: MOCK_URLHAUS_CSV
      });

      // First call should make HTTP request
      await urlhausFeed.fetchThreatData();
      expect(axiosInstanceMock.get).toHaveBeenCalledTimes(1);

      // Second call should use cache
      await urlhausFeed.fetchThreatData();
      expect(axiosInstanceMock.get).toHaveBeenCalledTimes(1); // Still 1, not 2
    });

    test('should handle cache expiration', async () => {
      urlhausFeed.updateConfig({ cacheTTL: 100 }); // 100ms cache

      axiosInstanceMock.get.mockResolvedValue({
        status: 200,
        data: MOCK_URLHAUS_CSV
      });

      // First call
      await urlhausFeed.fetchThreatData();
      expect(axiosInstanceMock.get).toHaveBeenCalledTimes(1);

      // Wait for cache to expire
      await new Promise(resolve => setTimeout(resolve, 150));

      // Second call should make new request
      await urlhausFeed.fetchThreatData();
      expect(axiosInstanceMock.get).toHaveBeenCalledTimes(2);
    });

    test('should handle concurrent requests efficiently', async () => {
      axiosInstanceMock.get.mockResolvedValue({
        status: 200,
        data: MOCK_URLHAUS_CSV
      });

      const startTime = Date.now();

      // Make multiple concurrent requests
      const promises = Array(5).fill(null).map(() => urlhausFeed.fetchThreatData());
      await Promise.all(promises);

      const endTime = Date.now();

      // Should complete efficiently with caching
      expect(endTime - startTime).toBeLessThan(5000);

      // Should have made only one HTTP request due to caching
      expect(axiosInstanceMock.get).toHaveBeenCalledTimes(1);
    });
  });

  describe('Error Recovery', () => {
    test('should implement retry logic', async () => {
      urlhausFeed.updateConfig({ retries: 3 });

      // Mock failure then success
      const networkError = new Error('Network Error');
      (networkError as any).isAxiosError = true;
      
      axiosInstanceMock.get
        .mockRejectedValueOnce(networkError)
        .mockRejectedValueOnce(networkError)
        .mockResolvedValueOnce({
          status: 200,
          data: MOCK_URLHAUS_CSV
        });

      const result = await urlhausFeed.fetchThreatData();
      expect(result.indicators).toBeInstanceOf(Array);
      expect(axiosInstanceMock.get).toHaveBeenCalledTimes(3); // 2 failures + 1 success
    });

    test('should fail after max retries', async () => {
      urlhausFeed.updateConfig({ retries: 2 });

      // Mock persistent failures
      const persistentError = new Error('Persistent Error');
      (persistentError as any).isAxiosError = true;
      axiosInstanceMock.get.mockRejectedValue(persistentError);

      await expect(urlhausFeed.fetchThreatData()).rejects.toThrow(/persistent error/i);
      expect(axiosInstanceMock.get).toHaveBeenCalledTimes(3); // Initial + 2 retries
    });

    test('should handle partial data corruption', async () => {
      const corruptedCSV = `# Header
"1","2024-01-15 10:30:00","http://valid1.com","online","2024-01-15 12:00:00","malware","tag","reporter"
this-is-corrupted-data
"2","2024-01-15 10:31:00","http://valid2.com","online","2024-01-15 12:01:00","phishing","tag","reporter"
`;

      axiosInstanceMock.get.mockResolvedValueOnce({
        status: 200,
        data: corruptedCSV
      });

      const result = await urlhausFeed.fetchThreatData();

      // Should successfully parse valid entries and skip corrupt ones
      const urlIndicators = result.indicators.filter(i => i.type === 'url');
      expect(urlIndicators).toHaveLength(2);
      expect(urlIndicators[0].value).toBe('http://valid1.com');
      expect(urlIndicators[1].value).toBe('http://valid2.com');
    });
  });
}); 
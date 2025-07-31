/**
 * @jest-environment node
 */

import { jest } from '@jest/globals';
import { TrojanHorse, createVault } from '../../src/index';
import { TestUtils } from '../setup';
import type { TrojanHorseConfig } from '../../src/types';

describe('TrojanHorse.js End-to-End Integration Tests', () => {
  let trojan: TrojanHorse;
  
  // Mock network requests for integration testing
  beforeAll(() => {
    global.fetch = jest.fn();
  });

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Mock URLhaus CSV response
    (global.fetch as jest.Mock).mockResolvedValue({
      ok: true,
      status: 200,
      text: () => Promise.resolve(`
# URLhaus CSV Header
"1","2024-01-15 10:30:00","http://malicious-test.com/malware.exe","online","2024-01-15 12:00:00","malware","exe,trojan","researcher"
"2","2024-01-15 09:15:00","https://phishing-test.net/login","offline","2024-01-15 11:00:00","phishing","banking","automated"
"3","2024-01-15 08:45:00","http://test-threat.org/exploit.php","online","2024-01-15 11:45:00","exploit_kit","php","analyst"
      `.trim())
    });
  });

  afterEach(async () => {
    if (trojan) {
      await trojan.destroy?.();
    }
  });

  describe('Complete Threat Intelligence Workflow', () => {
    test('should perform full threat detection workflow', async () => {
      // Initialize TrojanHorse with test configuration
      const config: TrojanHorseConfig = {
        sources: ['urlhaus'],
        strategy: 'defensive',
        security: {
          enforceHttps: false, // Disabled for testing
          autoLock: false
        }
      };

      trojan = new TrojanHorse(config);

      // Test 1: Scout for threats
      const scoutResult = await trojan.scout('malicious-test.com');
      
      expect(scoutResult).toBeDefined();
      expect(scoutResult.indicators).toBeInstanceOf(Array);
      expect(scoutResult.correlationScore).toBeGreaterThanOrEqual(0);
      expect(scoutResult.sources).toContain('URLhaus');

      // Test 2: Verify threat indicators are properly formed
      if (scoutResult.indicators.length > 0) {
        const indicator = scoutResult.indicators[0];
        expect(indicator.type).toMatch(/domain|url|ip/);
        expect(indicator.value).toBeTruthy();
        expect(indicator.source).toBeTruthy();
        expect(indicator.confidence).toBeGreaterThanOrEqual(0);
        expect(indicator.confidence).toBeLessThanOrEqual(1);
      }

      // Test 3: Export threat data
      const jsonExport = await trojan.plunder('json');
      expect(jsonExport).toBeTruthy();
      expect(() => JSON.parse(jsonExport)).not.toThrow();

      const csvExport = await trojan.plunder('csv');
      expect(csvExport).toBeTruthy();
      expect(csvExport).toMatch(/[,\n]/);
    });

    test('should handle multiple threat sources integration', async () => {
      const config: TrojanHorseConfig = {
        apiKeys: {
          alienVault: TestUtils.generateTestApiKey(),
          crowdsec: TestUtils.generateTestApiKey(),
          abuseipdb: TestUtils.generateTestApiKey()
        },
        sources: ['urlhaus', 'alienvault', 'crowdsec', 'abuseipdb'],
        strategy: 'balanced'
      };

      trojan = new TrojanHorse(config);

      // Mock additional API responses
      (global.fetch as jest.Mock)
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          text: () => Promise.resolve('# URLhaus data\n"1","2024-01-15","http://test.com","online","2024-01-15","malware","tag","reporter"')
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: () => Promise.resolve({
            results: [
              {
                pulse: { id: '123', name: 'Test Pulse' },
                indicator: { value: 'test.com', type: 'domain' },
                confidence: 85
              }
            ]
          })
        });

      const result = await trojan.scout('test.com');
      
      expect(result.sources.length).toBeGreaterThan(0);
      expect(result.correlationScore).toBeGreaterThanOrEqual(0);
    });

    test('should integrate with secure storage', async () => {
      const config: TrojanHorseConfig = {
        sources: ['urlhaus'],
        strategy: 'defensive',
        storage: {
          enabled: true,
          dbName: 'test-integration-db',
          encryptionKey: TestUtils.generateTestApiKey()
        }
      };

      trojan = new TrojanHorse(config);

      // Perform threat detection (should cache results)
      const firstResult = await trojan.scout('test-domain.com');
      
      // Second request should use cached data
      const secondResult = await trojan.scout('test-domain.com');
      
      expect(firstResult).toEqual(secondResult);
      expect(global.fetch).toHaveBeenCalledTimes(1); // Only one API call due to caching
    });
  });

  describe('Security Integration Tests', () => {
    test('should integrate vault creation and usage', async () => {
      const vaultPassword = 'test-vault-password-123';
      const apiKeys = {
        alienVault: TestUtils.generateTestApiKey(),
        crowdsec: TestUtils.generateTestApiKey()
      };

      // Create secure vault
      const vault = await createVault({
        password: vaultPassword,
        keys: apiKeys,
        options: {
          iterations: 1000, // Lower for testing
          autoLock: false
        }
      });

      expect(vault).toBeDefined();
      expect(vault.encrypted).toBeTruthy();

      // Use vault with TrojanHorse
      const config: TrojanHorseConfig = {
        vault: vault,
        sources: ['alienvault', 'crowdsec'],
        strategy: 'defensive'
      };

      trojan = new TrojanHorse(config);
      
      // Should be able to perform operations with vault-stored keys
      await expect(trojan.scout('test.com')).resolves.toBeDefined();
    });

    test('should handle API key rotation', async () => {
      const initialKey = TestUtils.generateTestApiKey();
      const rotatedKey = TestUtils.generateTestApiKey();

      const config: TrojanHorseConfig = {
        apiKeys: {
          alienVault: initialKey
        },
        sources: ['alienvault'],
        strategy: 'defensive'
      };

      trojan = new TrojanHorse(config);

      // Simulate key rotation
      await trojan.security.rotateKey('alienVault', {
        newKey: rotatedKey,
        gracePeriod: 1000 // 1 second for testing
      });

      // Should still work with rotated key
      await expect(trojan.scout('test.com')).resolves.toBeDefined();
    });

    test('should enforce security policies', async () => {
      const config: TrojanHorseConfig = {
        sources: ['urlhaus'],
        strategy: 'fort-knox',
        security: {
          enforceHttps: true,
          autoLock: true,
          lockTimeout: 1000,
          certificatePinning: ['pin-sha256="test-pin"'],
          contentSecurityPolicy: "default-src 'self'"
        }
      };

      trojan = new TrojanHorse(config);

      // Security policies should be enforced
      expect(trojan.config.security.enforceHttps).toBe(true);
      expect(trojan.config.security.autoLock).toBe(true);
    });
  });

  describe('Performance Integration Tests', () => {
    test('should handle concurrent threat detection efficiently', async () => {
      const config: TrojanHorseConfig = {
        sources: ['urlhaus'],
        strategy: 'defensive'
      };

      trojan = new TrojanHorse(config);

      const targets = [
        'concurrent1.com',
        'concurrent2.com',
        'concurrent3.com',
        'concurrent4.com',
        'concurrent5.com'
      ];

      const startTime = Date.now();
      
      // Run concurrent threat detection
      const promises = targets.map(target => trojan.scout(target));
      const results = await Promise.all(promises);
      
      const endTime = Date.now();
      const duration = endTime - startTime;

      // All requests should complete successfully
      expect(results).toHaveLength(targets.length);
      results.forEach(result => {
        expect(result).toBeDefined();
        expect(result.indicators).toBeInstanceOf(Array);
      });

      // Should complete in reasonable time
      expect(duration).toBeLessThan(10000); // 10 seconds
    });

    test('should optimize memory usage during bulk operations', async () => {
      const config: TrojanHorseConfig = {
        sources: ['urlhaus'],
        strategy: 'defensive'
      };

      trojan = new TrojanHorse(config);

      const initialMemory = process.memoryUsage().heapUsed;

      // Perform bulk operations
      const bulkTargets = Array(50).fill(0).map((_, i) => `bulk-test-${i}.com`);
      
      for (const target of bulkTargets) {
        await trojan.scout(target);
      }

      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;

      // Memory increase should be reasonable (less than 100MB)
      expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024);
    });

    test('should implement intelligent caching across modules', async () => {
      const config: TrojanHorseConfig = {
        sources: ['urlhaus'],
        strategy: 'defensive',
        caching: {
          enabled: true,
          ttl: 60000, // 1 minute
          maxSize: 1000
        }
      };

      trojan = new TrojanHorse(config);

      const target = 'cached-test.com';

      // First request
      const start1 = Date.now();
      await trojan.scout(target);
      const duration1 = Date.now() - start1;

      // Second request (should be faster due to caching)
      const start2 = Date.now();
      await trojan.scout(target);
      const duration2 = Date.now() - start2;

      // Should only make one network request
      expect(global.fetch).toHaveBeenCalledTimes(1);
      
      // Second request should be significantly faster
      expect(duration2).toBeLessThan(duration1 * 0.5);
    });
  });

  describe('Error Handling Integration', () => {
    test('should gracefully handle feed failures', async () => {
      const config: TrojanHorseConfig = {
        sources: ['urlhaus'],
        strategy: 'defensive',
        retries: 2
      };

      trojan = new TrojanHorse(config);

      // Mock network failure
      (global.fetch as jest.Mock).mockRejectedValue(new Error('Network Error'));

      // Should handle failure gracefully
      const result = await trojan.scout('error-test.com');
      
      expect(result).toBeDefined();
      expect(result.indicators).toBeInstanceOf(Array);
      expect(result.metadata?.errors).toBeDefined();
    });

    test('should implement circuit breaker pattern', async () => {
      const config: TrojanHorseConfig = {
        sources: ['urlhaus'],
        strategy: 'defensive',
        circuitBreaker: {
          enabled: true,
          failureThreshold: 3,
          recoveryTime: 5000
        }
      };

      trojan = new TrojanHorse(config);

      // Mock multiple failures
      (global.fetch as jest.Mock).mockRejectedValue(new Error('Service Unavailable'));

      // Multiple failed requests should trigger circuit breaker
      for (let i = 0; i < 5; i++) {
        try {
          await trojan.scout(`circuit-test-${i}.com`);
        } catch (error) {
          // Expected to fail
        }
      }

      // Circuit should be open, preventing further requests
      expect(trojan.getCircuitBreakerState?.()).toBe('open');
    });

    test('should handle malformed API responses', async () => {
      const config: TrojanHorseConfig = {
        sources: ['urlhaus'],
        strategy: 'defensive'
      };

      trojan = new TrojanHorse(config);

      // Mock malformed response
      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        status: 200,
        text: () => Promise.resolve('invalid-csv-data-here')
      });

      // Should handle malformed data gracefully
      const result = await trojan.scout('malformed-test.com');
      
      expect(result).toBeDefined();
      expect(result.indicators).toBeInstanceOf(Array);
      // May be empty due to parsing failure, but shouldn't crash
    });
  });

  describe('Event System Integration', () => {
    test('should emit events throughout threat detection workflow', async () => {
      const config: TrojanHorseConfig = {
        sources: ['urlhaus'],
        strategy: 'defensive'
      };

      trojan = new TrojanHorse(config);

      const events: Array<{ type: string; data: any }> = [];

      // Listen to various events
      trojan.on('feed:updated', (source, data) => {
        events.push({ type: 'feed:updated', data: { source, data } });
      });

      trojan.on('threat:detected', (indicator) => {
        events.push({ type: 'threat:detected', data: indicator });
      });

      trojan.on('correlation:completed', (result) => {
        events.push({ type: 'correlation:completed', data: result });
      });

      // Perform threat detection
      await trojan.scout('event-test.com');

      // Should have emitted events
      expect(events.length).toBeGreaterThan(0);
      
      const eventTypes = events.map(e => e.type);
      expect(eventTypes).toContain('feed:updated');
    });

    test('should support event filtering and middleware', async () => {
      const config: TrojanHorseConfig = {
        sources: ['urlhaus'],
        strategy: 'defensive'
      };

      trojan = new TrojanHorse(config);

      const highSeverityEvents: any[] = [];

      // Filter events by severity
      trojan.on('threat:detected', (indicator) => {
        if (indicator.severity === 'high' || indicator.severity === 'critical') {
          highSeverityEvents.push(indicator);
        }
      });

      await trojan.scout('filter-test.com');

      // Should filter events appropriately
      highSeverityEvents.forEach(indicator => {
        expect(['high', 'critical']).toContain(indicator.severity);
      });
    });
  });

  describe('Browser Integration Compatibility', () => {
    test('should work with browser-compatible configuration', async () => {
      const browserConfig: TrojanHorseConfig = {
        sources: ['urlhaus'], // Only browser-compatible sources
        strategy: 'defensive',
        browser: {
          corsProxy: 'https://proxy.example.com',
          fallbackMode: 'demo',
          secureContext: false
        }
      };

      trojan = new TrojanHorse(browserConfig);

      // Should initialize without Node.js-specific dependencies
      await expect(trojan.scout('browser-test.com')).resolves.toBeDefined();
    });

    test('should handle CORS proxy integration', async () => {
      const config: TrojanHorseConfig = {
        sources: ['urlhaus'],
        strategy: 'defensive',
        corsProxy: 'https://still-water-daf2.zeeahanm900.workers.dev'
      };

      trojan = new TrojanHorse(config);

      // Mock proxy response
      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        status: 200,
        text: () => Promise.resolve('# URLhaus data via proxy\n"1","2024-01-15","http://proxy-test.com","online","2024-01-15","malware","tag","reporter"')
      });

      const result = await trojan.scout('proxy-test.com');
      
      expect(result).toBeDefined();
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('still-water-daf2.zeeahanm900.workers.dev'),
        expect.any(Object)
      );
    });
  });
}); 
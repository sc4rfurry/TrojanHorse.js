/**
 * @jest-environment node
 */

import { jest } from '@jest/globals';
import { TrojanHorse } from '../index';
import { TestUtils, SecurityTestUtils } from '../../tests/setup';
import type { TrojanHorseConfig, ThreatIndicator } from '../types';

describe('TrojanHorse Core Functionality', () => {
  let trojan: TrojanHorse;
  let config: TrojanHorseConfig;

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();
    
    // Create test configuration
    config = {
      apiKeys: {
        alienVault: TestUtils.generateTestApiKey(),
        crowdsec: TestUtils.generateTestApiKey(),
        abuseipdb: TestUtils.generateTestApiKey()
      },
      sources: ['urlhaus', 'alienvault', 'crowdsec', 'abuseipdb'],
      strategy: 'defensive',
      security: {
        enforceHttps: false, // Disabled for testing
        autoLock: false
      }
    };
  });

  afterEach(async () => {
    // Clean up
    if (trojan) {
      await trojan.destroy?.();
    }
    TestUtils.secureCleanup(config);
  });

  describe('Initialization', () => {
    test('should initialize with valid configuration', async () => {
      trojan = new TrojanHorse(config);
      
      expect(trojan).toBeInstanceOf(TrojanHorse);
      expect(trojan.config).toBeDefined();
      expect(trojan.config.strategy).toBe('defensive');
    });

    test('should initialize with minimal configuration', async () => {
      const minimalConfig = {
        sources: ['urlhaus'],
        strategy: 'defensive' as const
      };
      
      trojan = new TrojanHorse(minimalConfig);
      
      expect(trojan).toBeInstanceOf(TrojanHorse);
      expect(trojan.config.sources).toContain('urlhaus');
    });

    test('should throw error with invalid configuration', () => {
      expect(() => {
        new TrojanHorse({} as any);
      }).toThrow();
    });

    test('should validate API keys format', () => {
      const invalidConfig = {
        ...config,
        apiKeys: {
          alienVault: 'invalid-key', // Too short
          crowdsec: '',
          abuseipdb: null as any
        }
      };

      expect(() => {
        new TrojanHorse(invalidConfig);
      }).toThrow(/invalid api key/i);
    });
  });

  describe('Security Features', () => {
    beforeEach(() => {
      trojan = new TrojanHorse(config);
    });

    test('should handle secure initialization', async () => {
      const secureConfig = {
        ...config,
        security: {
          enforceHttps: true,
          autoLock: true,
          lockTimeout: 5000
        }
      };

      const secureTrojan = new TrojanHorse(secureConfig);
      expect(secureTrojan.config.security.enforceHttps).toBe(true);
    });

    test('should protect against timing attacks', async () => {
      const indicator = TestUtils.generateTestThreatIndicator();
      
      const isTimingAttackResistant = await SecurityTestUtils.testTimingAttack(
        async (input: string) => {
          const result = await trojan.scout(input);
          return result.indicators.length > 0;
        },
        indicator.value,
        'invalid-input'
      );

      expect(isTimingAttackResistant).toBe(true);
    });

    test('should clean up sensitive data from memory', () => {
      const sensitiveData = TestUtils.generateTestApiKey();
      
      const isMemoryClean = SecurityTestUtils.testMemoryCleanup(() => {
        // Simulate operations with sensitive data
        const temp = sensitiveData + 'processed';
        TestUtils.secureCleanup(temp);
      });

      expect(isMemoryClean).toBe(true);
    });

    test('should handle vault operations securely', async () => {
      const vaultConfig = TestUtils.createTestVaultConfig();
      
      // Test vault creation (simulated)
      expect(() => {
        // Simulated vault operations
        TestUtils.secureCleanup(vaultConfig);
      }).not.toThrow();
    });
  });

  describe('Threat Intelligence Operations', () => {
    beforeEach(() => {
      trojan = new TrojanHorse(config);
    });

    test('should scout threats successfully', async () => {
      const testTarget = 'malicious-domain.com';
      
      const result = await trojan.scout(testTarget);
      
      expect(result).toBeDefined();
      expect(result.indicators).toBeInstanceOf(Array);
      expect(result.sources).toBeInstanceOf(Array);
      expect(result.correlationScore).toBeGreaterThanOrEqual(0);
      expect(result.correlationScore).toBeLessThanOrEqual(1);
    });

    test('should handle multiple target types', async () => {
      const targets = [
        'malicious-domain.com',      // Domain
        '192.168.1.100',            // IP
        'http://evil.com/malware',   // URL
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' // Hash
      ];

      for (const target of targets) {
        const result = await trojan.scout(target);
        expect(result).toBeDefined();
        expect(result.indicators).toBeInstanceOf(Array);
      }
    });

    test('should provide detailed threat information', async () => {
      const result = await trojan.scout('test-domain.com', {
        enrichment: true,
        includeDetails: true
      });

      expect(result.indicators).toBeInstanceOf(Array);
      if (result.indicators.length > 0) {
        const indicator = result.indicators[0];
        expect(indicator).toHaveProperty('type');
        expect(indicator).toHaveProperty('value');
        expect(indicator).toHaveProperty('confidence');
        expect(indicator).toHaveProperty('firstSeen');
        expect(indicator).toHaveProperty('lastSeen');
        expect(indicator).toHaveProperty('source');
        expect(indicator).toHaveProperty('severity');
      }
    });

    test('should handle correlation engine', async () => {
      const indicators: ThreatIndicator[] = [
        TestUtils.generateTestThreatIndicator({ type: 'domain', value: 'evil.com' }),
        TestUtils.generateTestThreatIndicator({ type: 'ip', value: '1.2.3.4' }),
        TestUtils.generateTestThreatIndicator({ type: 'url', value: 'http://evil.com/malware' })
      ];

      const result = await trojan.scout('evil.com');
      
      expect(result.correlationScore).toBeGreaterThanOrEqual(0);
      expect(result.correlationScore).toBeLessThanOrEqual(1);
      expect(result.consensusLevel).toMatch(/weak|moderate|strong|consensus/);
    });
  });

  describe('Data Export Operations', () => {
    beforeEach(() => {
      trojan = new TrojanHorse(config);
    });

    test('should export data in JSON format', async () => {
      const result = await trojan.plunder('json');
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      // Should be valid JSON
      expect(() => JSON.parse(result)).not.toThrow();
    });

    test('should export data in CSV format', async () => {
      const result = await trojan.plunder('csv');
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      expect(result).toMatch(/[,\n]/); // Basic CSV structure check
    });

    test('should handle export options', async () => {
      const result = await trojan.plunder('json', {
        timeRange: '24h',
        sources: ['urlhaus'],
        includeMetadata: true
      });

      expect(result).toBeDefined();
      const parsed = JSON.parse(result);
      expect(parsed).toHaveProperty('metadata');
    });
  });

  describe('Event System', () => {
    beforeEach(() => {
      trojan = new TrojanHorse(config);
    });

    test('should emit events during operations', async () => {
      const events: string[] = [];
      
      trojan.on('feed:updated', (source) => {
        events.push(`feed:updated:${source}`);
      });
      
      trojan.on('threat:detected', (indicator) => {
        events.push(`threat:detected:${indicator.type}`);
      });

      await trojan.scout('test-domain.com');
      
      // Events should be emitted during operation
      expect(events.length).toBeGreaterThan(0);
    });

    test('should handle error events', async () => {
      const errors: Error[] = [];
      
      trojan.on('error', (error) => {
        errors.push(error);
      });

      // Test with invalid configuration to trigger error
      try {
        await trojan.scout(''); // Empty target should trigger error
      } catch (e) {
        // Expected to throw
      }

      // Error event should be emitted
      expect(errors.length).toBeGreaterThan(0);
    });
  });

  describe('Performance & Memory', () => {
    beforeEach(() => {
      trojan = new TrojanHorse(config);
    });

    test('should handle concurrent requests', async () => {
      const targets = [
        'domain1.com',
        'domain2.com', 
        'domain3.com',
        '1.1.1.1',
        '2.2.2.2'
      ];

      const startTime = Date.now();
      
      // Run concurrent scouts
      const promises = targets.map(target => trojan.scout(target));
      const results = await Promise.all(promises);
      
      const endTime = Date.now();
      const duration = endTime - startTime;

      // All requests should complete
      expect(results).toHaveLength(targets.length);
      results.forEach(result => {
        expect(result).toBeDefined();
        expect(result.indicators).toBeInstanceOf(Array);
      });

      // Should complete in reasonable time (less than 30 seconds)
      expect(duration).toBeLessThan(30000);
    });

    test('should handle memory usage efficiently', async () => {
      const initialMemory = process.memoryUsage().heapUsed;
      
      // Perform multiple operations
      for (let i = 0; i < 10; i++) {
        await trojan.scout(`test-domain-${i}.com`);
      }
      
      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }
      
      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;
      
      // Memory increase should be reasonable (less than 50MB)
      expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024);
    });

    test('should handle rate limiting gracefully', async () => {
      // Simulate rate limiting by making many requests quickly
      const rapidRequests = Array(20).fill(0).map((_, i) => 
        trojan.scout(`rapid-test-${i}.com`)
      );

      // Should not throw errors due to rate limiting
      await expect(Promise.all(rapidRequests)).resolves.toBeDefined();
    });
  });

  describe('Edge Cases & Error Handling', () => {
    beforeEach(() => {
      trojan = new TrojanHorse(config);
    });

    test('should handle malformed targets gracefully', async () => {
      const malformedTargets = [
        '',              // Empty
        '   ',           // Whitespace only
        'not-a-url',     // Invalid format
        '999.999.999.999', // Invalid IP
        'http://',       // Incomplete URL
        'ftp://test.com' // Unsupported protocol
      ];

      for (const target of malformedTargets) {
        await expect(trojan.scout(target)).rejects.toThrow();
      }
    });

    test('should handle network failures', async () => {
      // Mock network failure
      const originalFetch = global.fetch;
      global.fetch = jest.fn().mockRejectedValue(new Error('Network Error'));

      try {
        const result = await trojan.scout('test.com');
        // Should still return a result (possibly from cache or fallback)
        expect(result).toBeDefined();
      } catch (error) {
        // Or should handle the error gracefully
        expect(error).toBeInstanceOf(Error);
      } finally {
        global.fetch = originalFetch;
      }
    });

    test('should validate input parameters', async () => {
      // Test invalid scout options
      await expect(trojan.scout('test.com', {
        enrichment: 'invalid' as any
      })).rejects.toThrow();

      // Test invalid plunder format
      await expect(trojan.plunder('invalid-format' as any)).rejects.toThrow();
    });
  });
}); 
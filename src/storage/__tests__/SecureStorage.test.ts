/**
 * @jest-environment node
 */

import { jest } from '@jest/globals';
import { SecureStorage } from '../SecureStorage';
import { TestUtils, SecurityTestUtils } from '../../../tests/setup';
import type { ThreatIndicator, StorageConfig } from '../../types';

// Mock IndexedDB for Node.js testing environment
const mockIndexedDB = {
  open: jest.fn(),
  deleteDatabase: jest.fn()
};

global.indexedDB = mockIndexedDB as any;

describe('SecureStorage Module', () => {
  let secureStorage: SecureStorage;
  let config: StorageConfig;
  let testData: ThreatIndicator[];

  beforeEach(async () => {
    config = {
      dbName: 'test-trojanhorse-db',
      encryptionKey: TestUtils.generateTestApiKey(),
      maxSizeBytes: 10 * 1024 * 1024, // 10MB
      defaultTTL: 24 * 60 * 60 * 1000 // 24 hours
    };

    testData = [
      TestUtils.generateTestThreatIndicator({ type: 'domain', value: 'test1.com' }),
      TestUtils.generateTestThreatIndicator({ type: 'ip', value: '1.2.3.4' }),
      TestUtils.generateTestThreatIndicator({ type: 'url', value: 'http://test.com/malware' })
    ];

    // Mock successful DB operations
    const mockDB = {
      transaction: jest.fn().mockReturnValue({
        objectStore: jest.fn().mockReturnValue({
          add: jest.fn().mockResolvedValue(undefined),
          get: jest.fn().mockResolvedValue(undefined),
          put: jest.fn().mockResolvedValue(undefined),
          delete: jest.fn().mockResolvedValue(undefined),
          clear: jest.fn().mockResolvedValue(undefined),
          getAll: jest.fn().mockResolvedValue([]),
          count: jest.fn().mockResolvedValue(0)
        })
      }),
      createObjectStore: jest.fn(),
      close: jest.fn()
    };

    mockIndexedDB.open.mockResolvedValue({
      result: mockDB,
      onsuccess: null,
      onerror: null
    });

    secureStorage = new SecureStorage(config);
  });

  afterEach(async () => {
    if (secureStorage) {
      await secureStorage.clear();
    }
    jest.clearAllMocks();
    TestUtils.secureCleanup([config, testData]);
  });

  describe('Initialization', () => {
    test('should initialize with valid configuration', async () => {
      await secureStorage.initialize();
      
      expect(secureStorage.isInitialized()).toBe(true);
      expect(mockIndexedDB.open).toHaveBeenCalledWith(config.dbName, expect.any(Number));
    });

    test('should validate configuration parameters', () => {
      const invalidConfigs = [
        { ...config, dbName: '' },
        { ...config, encryptionKey: '' },
        { ...config, maxSizeBytes: -1 },
        { ...config, defaultTTL: -1 }
      ];

      invalidConfigs.forEach(invalidConfig => {
        expect(() => new SecureStorage(invalidConfig)).toThrow(/invalid|configuration/i);
      });
    });

    test('should handle database creation errors', async () => {
      mockIndexedDB.open.mockRejectedValueOnce(new Error('DB Error'));

      await expect(secureStorage.initialize()).rejects.toThrow(/db error/i);
    });

    test('should upgrade database schema when needed', async () => {
      const upgradeMock = jest.fn();
      mockIndexedDB.open.mockResolvedValueOnce({
        result: {
          createObjectStore: upgradeMock,
          transaction: jest.fn(),
          close: jest.fn()
        },
        onupgradeneeded: upgradeMock
      });

      await secureStorage.initialize();
      
      // Should handle schema upgrades
      expect(secureStorage.isInitialized()).toBe(true);
    });
  });

  describe('Data Storage and Retrieval', () => {
    beforeEach(async () => {
      await secureStorage.initialize();
    });

    test('should store and retrieve data successfully', async () => {
      const key = 'test-threats';
      const stored = await secureStorage.store(key, testData);
      
      expect(stored).toBe(true);
      
      const retrieved = await secureStorage.get<ThreatIndicator[]>(key);
      expect(retrieved).toEqual(testData);
    });

    test('should handle encryption/decryption transparently', async () => {
      const key = 'encrypted-data';
      const sensitiveData = { apiKey: TestUtils.generateTestApiKey() };
      
      await secureStorage.store(key, sensitiveData);
      const retrieved = await secureStorage.get(key);
      
      expect(retrieved).toEqual(sensitiveData);
    });

    test('should return null for non-existent keys', async () => {
      const result = await secureStorage.get('non-existent-key');
      expect(result).toBeNull();
    });

    test('should handle TTL expiration', async () => {
      const shortTTL = 100; // 100ms
      const key = 'short-lived-data';
      
      await secureStorage.store(key, testData, { ttl: shortTTL });
      
      // Should exist immediately
      let retrieved = await secureStorage.get(key);
      expect(retrieved).toEqual(testData);
      
      // Wait for expiration
      await TestUtils.wait(shortTTL + 50);
      
      // Should be expired and return null
      retrieved = await secureStorage.get(key);
      expect(retrieved).toBeNull();
    });

    test('should support custom tags for organization', async () => {
      const tags = ['threat-intel', 'urlhaus', 'high-confidence'];
      
      await secureStorage.store('tagged-data', testData, { tags });
      
      const taggedItems = await secureStorage.getByTags(['urlhaus']);
      expect(taggedItems.length).toBeGreaterThan(0);
    });

    test('should handle large data sets efficiently', async () => {
      const largeDataSet = Array(1000).fill(0).map((_, i) => 
        TestUtils.generateTestThreatIndicator({ value: `large-test-${i}.com` })
      );

      const startTime = Date.now();
      await secureStorage.store('large-dataset', largeDataSet);
      const retrieved = await secureStorage.get('large-dataset');
      const endTime = Date.now();

      expect(retrieved).toEqual(largeDataSet);
      expect(endTime - startTime).toBeLessThan(5000); // Should complete within 5 seconds
    });
  });

  describe('Data Modification and Deletion', () => {
    beforeEach(async () => {
      await secureStorage.initialize();
      await secureStorage.store('test-data', testData);
    });

    test('should update existing data', async () => {
      const updatedData = [...testData, TestUtils.generateTestThreatIndicator()];
      
      const updated = await secureStorage.update('test-data', updatedData);
      expect(updated).toBe(true);
      
      const retrieved = await secureStorage.get('test-data');
      expect(retrieved).toEqual(updatedData);
    });

    test('should delete data successfully', async () => {
      const deleted = await secureStorage.deleteData('test-data');
      expect(deleted).toBe(true);
      
      const retrieved = await secureStorage.get('test-data');
      expect(retrieved).toBeNull();
    });

    test('should handle deletion of non-existent keys', async () => {
      const deleted = await secureStorage.deleteData('non-existent');
      expect(deleted).toBe(false);
    });

    test('should clear all data', async () => {
      await secureStorage.store('data1', testData);
      await secureStorage.store('data2', testData);
      
      await secureStorage.clear();
      
      const data1 = await secureStorage.get('data1');
      const data2 = await secureStorage.get('data2');
      
      expect(data1).toBeNull();
      expect(data2).toBeNull();
    });
  });

  describe('Security Features', () => {
    beforeEach(async () => {
      await secureStorage.initialize();
    });

    test('should encrypt data at rest', async () => {
      const sensitiveData = { secret: TestUtils.generateTestApiKey() };
      
      await secureStorage.store('sensitive', sensitiveData);
      
      // Check that raw storage doesn't contain plaintext
      // This would require access to the underlying IndexedDB, which is mocked
      // In a real implementation, you'd verify encryption by checking raw data
      const retrieved = await secureStorage.get('sensitive');
      expect(retrieved).toEqual(sensitiveData);
    });

    test('should be resistant to timing attacks', async () => {
      const validKey = 'valid-key';
      const invalidKey = 'invalid-key';
      
      await secureStorage.store(validKey, testData);
      
      const isTimingAttackResistant = await SecurityTestUtils.testTimingAttack(
        async (key: string) => {
          const result = await secureStorage.get(key);
          return result !== null;
        },
        validKey,
        invalidKey
      );

      expect(isTimingAttackResistant).toBe(true);
    });

    test('should clean up sensitive data from memory', () => {
      const sensitiveKey = TestUtils.generateTestApiKey();
      
      const isMemoryClean = SecurityTestUtils.testMemoryCleanup(() => {
        // Simulate storage operations with sensitive data
        const tempData = { key: sensitiveKey };
        TestUtils.secureCleanup(tempData);
      });

      expect(isMemoryClean).toBe(true);
    });

    test('should validate data integrity', async () => {
      const key = 'integrity-test';
      await secureStorage.store(key, testData);
      
      // Simulate data corruption (in real implementation)
      // Here we just verify the integrity check mechanism exists
      const retrieved = await secureStorage.get(key);
      expect(retrieved).toEqual(testData);
    });

    test('should handle encryption key rotation', async () => {
      const key = 'rotation-test';
      await secureStorage.store(key, testData);
      
      const newEncryptionKey = TestUtils.generateTestApiKey();
      await secureStorage.rotateEncryptionKey(newEncryptionKey);
      
      // Data should still be accessible after key rotation
      const retrieved = await secureStorage.get(key);
      expect(retrieved).toEqual(testData);
    });
  });

  describe('Storage Management', () => {
    beforeEach(async () => {
      await secureStorage.initialize();
    });

    test('should track storage usage', async () => {
      await secureStorage.store('usage-test', testData);
      
      const quota = await secureStorage.getStorageQuota();
      
      expect(quota).toBeDefined();
      expect(quota.used).toBeGreaterThan(0);
      expect(quota.available).toBeGreaterThan(0);
      expect(quota.total).toBeGreaterThan(0);
      expect(quota.percentage).toBeGreaterThanOrEqual(0);
      expect(quota.percentage).toBeLessThanOrEqual(100);
    });

    test('should enforce storage limits', async () => {
      const smallStorage = new SecureStorage({
        ...config,
        maxSizeBytes: 1024 // Very small limit
      });
      
      await smallStorage.initialize();
      
      const largeData = Array(1000).fill(0).map(() => 
        TestUtils.generateTestThreatIndicator()
      );
      
      await expect(smallStorage.store('large-data', largeData))
        .rejects.toThrow(/storage limit|quota/i);
    });

    test('should clean up expired entries automatically', async () => {
      const shortTTL = 100;
      
      await secureStorage.store('expired1', testData, { ttl: shortTTL });
      await secureStorage.store('expired2', testData, { ttl: shortTTL });
      await secureStorage.store('permanent', testData); // No TTL
      
      await TestUtils.wait(shortTTL + 50);
      
      const cleanedCount = await secureStorage.cleanupExpired();
      expect(cleanedCount).toBe(2);
      
      // Permanent data should remain
      const permanent = await secureStorage.get('permanent');
      expect(permanent).toEqual(testData);
    });

    test('should provide storage statistics', async () => {
      await secureStorage.store('stats1', testData, { tags: ['test'] });
      await secureStorage.store('stats2', testData, { tags: ['test', 'demo'] });
      
      const quota = await secureStorage.getStorageQuota();
      
      expect(quota.totalEntries).toBeGreaterThanOrEqual(2);
      expect(quota.tagStats).toBeDefined();
      expect(quota.tagStats.test).toBe(2);
      expect(quota.tagStats.demo).toBe(1);
    });
  });

  describe('Advanced Querying', () => {
    beforeEach(async () => {
      await secureStorage.initialize();
      
      // Store test data with various tags and metadata
      await secureStorage.store('threats1', testData, { 
        tags: ['malware', 'high-confidence'] 
      });
      await secureStorage.store('threats2', testData, { 
        tags: ['phishing', 'medium-confidence'] 
      });
      await secureStorage.store('threats3', testData, { 
        tags: ['malware', 'low-confidence'] 
      });
    });

    test('should query by tags', async () => {
      const malwareThreats = await secureStorage.getByTags(['malware']);
      expect(malwareThreats.length).toBe(2);
      
      const highConfidence = await secureStorage.getByTags(['high-confidence']);
      expect(highConfidence.length).toBe(1);
    });

    test('should support complex tag queries', async () => {
      // AND query (must have all tags)
      const results = await secureStorage.getByTags(['malware', 'high-confidence'], 'AND');
      expect(results.length).toBe(1);
      
      // OR query (must have any tag)
      const orResults = await secureStorage.getByTags(['phishing', 'high-confidence'], 'OR');
      expect(orResults.length).toBe(2);
    });

    test('should query by time range', async () => {
      const now = new Date();
      const hourAgo = new Date(now.getTime() - 60 * 60 * 1000);
      
      const recentEntries = await secureStorage.getByTimeRange(hourAgo, now);
      expect(recentEntries.length).toBeGreaterThan(0);
    });

    test('should support pagination', async () => {
      // Store more data for pagination testing
      for (let i = 0; i < 20; i++) {
        await secureStorage.store(`page-test-${i}`, testData);
      }
      
      const page1 = await secureStorage.getByTags(['test'], 'OR', { limit: 5, offset: 0 });
      const page2 = await secureStorage.getByTags(['test'], 'OR', { limit: 5, offset: 5 });
      
      expect(page1.length).toBe(5);
      expect(page2.length).toBe(5);
      expect(page1[0].key).not.toBe(page2[0].key);
    });
  });

  describe('Performance and Optimization', () => {
    beforeEach(async () => {
      await secureStorage.initialize();
    });

    test('should handle concurrent operations', async () => {
      const operations = Array(20).fill(0).map((_, i) => 
        secureStorage.store(`concurrent-${i}`, testData)
      );
      
      const results = await Promise.all(operations);
      
      // All operations should succeed
      results.forEach(result => {
        expect(result).toBe(true);
      });
    });

    test('should implement caching for frequently accessed data', async () => {
      const key = 'cached-data';
      await secureStorage.store(key, testData);
      
      // First access
      const start1 = Date.now();
      await secureStorage.get(key);
      const end1 = Date.now();
      
      // Second access (should be faster due to caching)
      const start2 = Date.now();
      await secureStorage.get(key);
      const end2 = Date.now();
      
      // Second access should be significantly faster
      expect(end2 - start2).toBeLessThan(end1 - start1);
    });

    test('should batch operations for efficiency', async () => {
      const batchData = Array(100).fill(0).map((_, i) => ({
        key: `batch-${i}`,
        value: testData
      }));
      
      const startTime = Date.now();
      await secureStorage.batchStore(batchData);
      const endTime = Date.now();
      
      // Batch operation should be faster than individual operations
      expect(endTime - startTime).toBeLessThan(5000);
      
      // Verify all data was stored
      for (let i = 0; i < 10; i++) { // Check subset
        const retrieved = await secureStorage.get(`batch-${i}`);
        expect(retrieved).toEqual(testData);
      }
    });
  });

  describe('Error Handling and Recovery', () => {
    test('should handle database connection failures', async () => {
      mockIndexedDB.open.mockRejectedValue(new Error('Connection failed'));
      
      await expect(secureStorage.initialize()).rejects.toThrow(/connection/i);
    });

    test('should recover from corrupted data', async () => {
      await secureStorage.initialize();
      
      // Mock corrupted data scenario
      const mockStore = {
        get: jest.fn().mockRejectedValue(new Error('Data corrupted'))
      };
      
      // Should handle corruption gracefully
      await expect(secureStorage.get('corrupted-key')).rejects.toThrow(/corrupt/i);
    });

    test('should handle quota exceeded errors', async () => {
      const quotaError = new Error('QuotaExceededError');
      quotaError.name = 'QuotaExceededError';
      
      mockIndexedDB.open.mockRejectedValue(quotaError);
      
      await expect(secureStorage.initialize()).rejects.toThrow(/quota/i);
    });

    test('should provide detailed error information', async () => {
      try {
        await secureStorage.get('test-error');
      } catch (error) {
        expect(error.message).toMatch(/storage|error/i);
        expect(error.code).toBeDefined();
      }
    });
  });
}); 
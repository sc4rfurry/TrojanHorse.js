/**
 * @jest-environment node
 */

import { jest } from '@jest/globals';
import { CryptoEngine } from '../CryptoEngine';
import { TestUtils, SecurityTestUtils } from '../../../tests/setup';

describe('CryptoEngine Security Module', () => {
  let cryptoEngine: CryptoEngine;
  let testPassword: string;
  let testData: string;

  beforeEach(() => {
    cryptoEngine = new CryptoEngine();
    testPassword = TestUtils.generateTestApiKey();
    testData = 'sensitive test data for encryption';
  });

  afterEach(() => {
    // Secure cleanup
    TestUtils.secureCleanup([testPassword, testData]);
  });

  describe('Encryption/Decryption', () => {
    test('should encrypt and decrypt data successfully', async () => {
      const encrypted = await cryptoEngine.encrypt(testData, testPassword);
      
      expect(encrypted).toBeDefined();
      expect(encrypted).not.toBe(testData); // Should be different from original
      expect(encrypted.length).toBeGreaterThan(testData.length); // Should be longer due to encoding
      
      const decrypted = await cryptoEngine.decrypt(encrypted, testPassword);
      
      expect(decrypted).toBe(testData); // Should match original exactly
    });

    test('should produce different outputs for same input', async () => {
      const encrypted1 = await cryptoEngine.encrypt(testData, testPassword);
      const encrypted2 = await cryptoEngine.encrypt(testData, testPassword);
      
      expect(encrypted1).not.toBe(encrypted2); // Should use random IV/salt
      
      // But both should decrypt to same original
      const decrypted1 = await cryptoEngine.decrypt(encrypted1, testPassword);
      const decrypted2 = await cryptoEngine.decrypt(encrypted2, testPassword);
      
      expect(decrypted1).toBe(testData);
      expect(decrypted2).toBe(testData);
    });

    test('should fail with wrong password', async () => {
      const encrypted = await cryptoEngine.encrypt(testData, testPassword);
      const wrongPassword = TestUtils.generateTestApiKey();
      
      await expect(cryptoEngine.decrypt(encrypted, wrongPassword))
        .rejects.toThrow(/decryption|password|invalid/i);
    });

    test('should handle empty data', async () => {
      const emptyData = '';
      const encrypted = await cryptoEngine.encrypt(emptyData, testPassword);
      const decrypted = await cryptoEngine.decrypt(encrypted, testPassword);
      
      expect(decrypted).toBe(emptyData);
    });

    test('should handle large data', async () => {
      const largeData = 'x'.repeat(100000); // 100KB of data
      
      const startTime = Date.now();
      const encrypted = await cryptoEngine.encrypt(largeData, testPassword);
      const decrypted = await cryptoEngine.decrypt(encrypted, testPassword);
      const endTime = Date.now();
      
      expect(decrypted).toBe(largeData);
      expect(endTime - startTime).toBeLessThan(5000); // Should complete within 5 seconds
    });

    test('should handle unicode data correctly', async () => {
      const unicodeData = '🏰🛡️ TrojanHorse.js ⚔️ Τροία 中文 العربية 🎯';
      
      const encrypted = await cryptoEngine.encrypt(unicodeData, testPassword);
      const decrypted = await cryptoEngine.decrypt(encrypted, testPassword);
      
      expect(decrypted).toBe(unicodeData);
    });
  });

  describe('Key Derivation (PBKDF2)', () => {
    test('should derive keys consistently', async () => {
      const salt = 'test-salt';
      const iterations = 1000;
      
      const key1 = await cryptoEngine.deriveKey(testPassword, salt, iterations);
      const key2 = await cryptoEngine.deriveKey(testPassword, salt, iterations);
      
      expect(key1).toBe(key2); // Same inputs should produce same output
      expect(key1.length).toBeGreaterThan(0);
    });

    test('should produce different keys with different salts', async () => {
      const salt1 = 'salt1';
      const salt2 = 'salt2';
      const iterations = 1000;
      
      const key1 = await cryptoEngine.deriveKey(testPassword, salt1, iterations);
      const key2 = await cryptoEngine.deriveKey(testPassword, salt2, iterations);
      
      expect(key1).not.toBe(key2);
    });

    test('should produce different keys with different iterations', async () => {
      const salt = 'test-salt';
      
      const key1 = await cryptoEngine.deriveKey(testPassword, salt, 1000);
      const key2 = await cryptoEngine.deriveKey(testPassword, salt, 2000);
      
      expect(key1).not.toBe(key2);
    });

    test('should handle minimum security requirements', async () => {
      const salt = 'test-salt';
      const minIterations = 10000; // OWASP minimum
      
      const key = await cryptoEngine.deriveKey(testPassword, salt, minIterations);
      
      expect(key).toBeDefined();
      expect(key.length).toBeGreaterThanOrEqual(32); // At least 256 bits
    });
  });

  describe('Hash Functions', () => {
    test('should generate consistent hashes', async () => {
      const hash1 = await cryptoEngine.hash(testData);
      const hash2 = await cryptoEngine.hash(testData);
      
      expect(hash1).toBe(hash2);
      expect(hash1.length).toBeGreaterThan(0);
    });

    test('should generate different hashes for different inputs', async () => {
      const data1 = 'test data 1';
      const data2 = 'test data 2';
      
      const hash1 = await cryptoEngine.hash(data1);
      const hash2 = await cryptoEngine.hash(data2);
      
      expect(hash1).not.toBe(hash2);
    });

    test('should support different hash algorithms', async () => {
      const algorithms = ['SHA-256', 'SHA-512'];
      
      for (const algorithm of algorithms) {
        const hash = await cryptoEngine.hash(testData, algorithm);
        expect(hash).toBeDefined();
        expect(hash.length).toBeGreaterThan(0);
      }
    });

    test('should handle large data for hashing', async () => {
      const largeData = 'x'.repeat(1000000); // 1MB of data
      
      const startTime = Date.now();
      const hash = await cryptoEngine.hash(largeData);
      const endTime = Date.now();
      
      expect(hash).toBeDefined();
      expect(endTime - startTime).toBeLessThan(3000); // Should complete within 3 seconds
    });
  });

  describe('Random Generation', () => {
    test('should generate cryptographically secure random values', async () => {
      const random1 = await cryptoEngine.generateRandomBytes(32);
      const random2 = await cryptoEngine.generateRandomBytes(32);
      
      expect(random1).not.toBe(random2); // Should be different
      expect(random1.length).toBe(64); // 32 bytes = 64 hex chars
      expect(random2.length).toBe(64);
      
      // Should be valid hex
      expect(random1).toMatch(/^[0-9a-f]+$/i);
      expect(random2).toMatch(/^[0-9a-f]+$/i);
    });

    test('should generate random values of different lengths', async () => {
      const lengths = [16, 32, 64, 128];
      
      for (const length of lengths) {
        const random = await cryptoEngine.generateRandomBytes(length);
        expect(random.length).toBe(length * 2); // Hex encoding doubles length
      }
    });

    test('should pass basic randomness tests', async () => {
      const samples = [];
      
      // Generate multiple samples
      for (let i = 0; i < 100; i++) {
        const random = await cryptoEngine.generateRandomBytes(4);
        samples.push(parseInt(random, 16));
      }
      
      // Check for basic randomness properties
      const unique = new Set(samples);
      expect(unique.size).toBeGreaterThan(80); // Should have high uniqueness
      
      const average = samples.reduce((a, b) => a + b, 0) / samples.length;
      const expectedAverage = 0x7FFFFFFF; // Rough middle value for 32-bit
      const tolerance = expectedAverage * 0.2; // 20% tolerance
      
      expect(Math.abs(average - expectedAverage)).toBeLessThan(tolerance);
    });
  });

  describe('Security Properties', () => {
    test('should be resistant to timing attacks', async () => {
      const correctPassword = testPassword;
      const incorrectPassword = TestUtils.generateTestApiKey();
      
      const isTimingAttackResistant = await SecurityTestUtils.testTimingAttack(
        async (password: string) => {
          try {
            const encrypted = await cryptoEngine.encrypt(testData, correctPassword);
            await cryptoEngine.decrypt(encrypted, password);
            return true;
          } catch {
            return false;
          }
        },
        correctPassword,
        incorrectPassword
      );

      expect(isTimingAttackResistant).toBe(true);
    });

    test('should clean up sensitive data from memory', () => {
      const sensitiveKey = TestUtils.generateTestApiKey();
      
      const isMemoryClean = SecurityTestUtils.testMemoryCleanup(() => {
        // Simulate cryptographic operations
        const derived = cryptoEngine.deriveKey(sensitiveKey, 'salt', 1000);
        TestUtils.secureCleanup([sensitiveKey, derived]);
      });

      expect(isMemoryClean).toBe(true);
    });

    test('should validate input parameters', async () => {
      // Test with invalid passwords
      await expect(cryptoEngine.encrypt(testData, '')).rejects.toThrow();
      await expect(cryptoEngine.encrypt(testData, null as any)).rejects.toThrow();
      
      // Test with invalid data
      await expect(cryptoEngine.encrypt(null as any, testPassword)).rejects.toThrow();
      
      // Test with invalid encrypted data
      await expect(cryptoEngine.decrypt('invalid-encrypted-data', testPassword))
        .rejects.toThrow();
      
      // Test with malformed base64
      await expect(cryptoEngine.decrypt('not-base64!@#', testPassword))
        .rejects.toThrow();
    });

    test('should handle concurrent operations safely', async () => {
      const operations = [];
      
      // Create multiple concurrent encryption/decryption operations
      for (let i = 0; i < 10; i++) {
        operations.push(
          cryptoEngine.encrypt(`test data ${i}`, testPassword)
            .then(encrypted => cryptoEngine.decrypt(encrypted, testPassword))
        );
      }
      
      const results = await Promise.all(operations);
      
      // All operations should complete successfully
      results.forEach((result, index) => {
        expect(result).toBe(`test data ${index}`);
      });
    });
  });

  describe('Error Handling', () => {
    test('should handle corrupted encrypted data', async () => {
      const encrypted = await cryptoEngine.encrypt(testData, testPassword);
      
      // Corrupt the encrypted data
      const corrupted = encrypted.slice(0, -10) + 'corrupted!';
      
      await expect(cryptoEngine.decrypt(corrupted, testPassword))
        .rejects.toThrow(/corrupt|invalid|decrypt/i);
    });

    test('should handle unsupported algorithms gracefully', async () => {
      await expect(cryptoEngine.hash(testData, 'INVALID-ALGO'))
        .rejects.toThrow(/algorithm|supported/i);
    });

    test('should provide helpful error messages', async () => {
      try {
        await cryptoEngine.decrypt('invalid', testPassword);
      } catch (error) {
        expect(error.message).toMatch(/decrypt|invalid|format/i);
        expect(error.message.length).toBeGreaterThan(10); // Should be descriptive
      }
    });
  });

  describe('Performance Benchmarks', () => {
    test('should encrypt/decrypt within performance limits', async () => {
      const testSizes = [1024, 10240, 102400]; // 1KB, 10KB, 100KB
      
      for (const size of testSizes) {
        const data = 'x'.repeat(size);
        
        const startTime = Date.now();
        const encrypted = await cryptoEngine.encrypt(data, testPassword);
        const decrypted = await cryptoEngine.decrypt(encrypted, testPassword);
        const endTime = Date.now();
        
        expect(decrypted).toBe(data);
        
        // Performance expectations (adjust based on requirements)
        const timeLimit = size < 10000 ? 1000 : 5000; // 1s for small, 5s for large
        expect(endTime - startTime).toBeLessThan(timeLimit);
      }
    });

    test('should handle key derivation performance', async () => {
      const iterations = 100000; // Production-level iterations
      
      const startTime = Date.now();
      const key = await cryptoEngine.deriveKey(testPassword, 'salt', iterations);
      const endTime = Date.now();
      
      expect(key).toBeDefined();
      expect(endTime - startTime).toBeLessThan(10000); // Should complete within 10 seconds
    });
  });
}); 
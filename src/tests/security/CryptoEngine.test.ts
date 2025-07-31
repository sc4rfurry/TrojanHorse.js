/**
 * CryptoEngine Security Tests
 * 
 * Comprehensive security testing for cryptographic operations
 * - Tests encryption/decryption functionality
 * - Validates timing attack resistance
 * - Checks for memory leaks in crypto operations
 * - Ensures proper key derivation and IV generation
 */

import { CryptoEngine } from '../../security/CryptoEngine';
import { TestUtils, SecurityTestUtils, TEST_CONSTANTS } from '../../../tests/setup';

describe('CryptoEngine Security Tests', () => {
  let cryptoEngine: CryptoEngine;

  beforeEach(() => {
    cryptoEngine = new CryptoEngine();
  });

  afterEach(() => {
    // Secure cleanup
    TestUtils.secureCleanup(cryptoEngine);
  });

  describe('Encryption/Decryption Operations', () => {
    test('should encrypt and decrypt data successfully', async () => {
      const testData = { apiKey: 'test-api-key-12345', sensitive: true };
      const password = TEST_CONSTANTS.TEST_PASSWORD;
      
      // Generate key and IV
      const key = await cryptoEngine.deriveKey(password, 'test-salt');
      const iv = cryptoEngine.generateIV();
      
      // Encrypt
      const encrypted = await cryptoEngine.encrypt(testData, key, iv);
      
      expect(encrypted).toBeDefined();
      expect(encrypted.encrypted).toBeTruthy();
      expect(encrypted.iv).toBe(iv);
      expect(encrypted.algorithm).toBe('AES-256-CBC');
      
      // Decrypt
      const decrypted = await cryptoEngine.decrypt(encrypted, key);
      
      expect(decrypted).toEqual(testData);
    });

    test('should fail gracefully with wrong key', async () => {
      const testData = { secret: 'confidential-data' };
      const password = TEST_CONSTANTS.TEST_PASSWORD;
      const wrongPassword = 'wrong-password';
      
      const key = await cryptoEngine.deriveKey(password, 'test-salt');
      const wrongKey = await cryptoEngine.deriveKey(wrongPassword, 'test-salt');
      const iv = cryptoEngine.generateIV();
      
      const encrypted = await cryptoEngine.encrypt(testData, key, iv);
      
      await expect(cryptoEngine.decrypt(encrypted, wrongKey))
        .rejects
        .toThrow();
    });

    test('should generate unique IVs', () => {
      const ivs = new Set();
      
      for (let i = 0; i < 100; i++) {
        const iv = cryptoEngine.generateIV();
        expect(iv).toHaveLength(24); // Base64 encoded 16-byte IV
        expect(ivs.has(iv)).toBe(false);
        ivs.add(iv);
      }
    });

    test('should derive deterministic keys from same input', async () => {
      const password = TEST_CONSTANTS.TEST_PASSWORD;
      const salt = 'consistent-salt';
      
      const key1 = await cryptoEngine.deriveKey(password, salt);
      const key2 = await cryptoEngine.deriveKey(password, salt);
      
      expect(key1).toBe(key2);
    });

    test('should derive different keys from different salts', async () => {
      const password = TEST_CONSTANTS.TEST_PASSWORD;
      
      const key1 = await cryptoEngine.deriveKey(password, 'salt1');
      const key2 = await cryptoEngine.deriveKey(password, 'salt2');
      
      expect(key1).not.toBe(key2);
    });
  });

  describe('Security Properties', () => {
    test('should be resistant to timing attacks', async () => {
      const validPassword = TEST_CONSTANTS.TEST_PASSWORD;
      const invalidPassword = 'invalid-password-with-same-length';
      
      // Create a test function that simulates authentication
      const testAuthentication = async (password: string): Promise<boolean> => {
        try {
          const salt = 'test-salt';
          const key = await cryptoEngine.deriveKey(password, salt);
          
          // Simulate some work with the key
          const testData = { test: 'data' };
          const iv = cryptoEngine.generateIV();
          await cryptoEngine.encrypt(testData, key, iv);
          
          return password === validPassword;
        } catch {
          return false;
        }
      };

      const isTimingSecure = await SecurityTestUtils.testTimingAttack(
        testAuthentication,
        validPassword,
        invalidPassword,
        50 // Reduced iterations for faster tests
      );

      expect(isTimingSecure).toBe(true);
    }, 30000);

    test('should not leak memory during operations', () => {
      const isMemorySecure = SecurityTestUtils.testMemoryCleanup(() => {
        // Perform memory-intensive crypto operations
        for (let i = 0; i < 100; i++) {
          const iv = cryptoEngine.generateIV();
          cryptoEngine.deriveKey(`password-${i}`, `salt-${i}`);
        }
      });

      expect(isMemorySecure).toBe(true);
    });

    test('should handle large data encryption/decryption', async () => {
      // Create a large test object (1MB)
      const largeData = {
        data: 'x'.repeat(1024 * 1024),
        timestamp: Date.now(),
        metadata: { size: 'large', test: true }
      };

      const password = TEST_CONSTANTS.TEST_PASSWORD;
      const key = await cryptoEngine.deriveKey(password, 'large-data-salt');
      const iv = cryptoEngine.generateIV();

      const encrypted = await cryptoEngine.encrypt(largeData, key, iv);
      expect(encrypted.encrypted).toBeTruthy();

      const decrypted = await cryptoEngine.decrypt(encrypted, key);
      expect(decrypted).toEqual(largeData);
    }, 15000);

    test('should handle edge cases gracefully', async () => {
      const password = TEST_CONSTANTS.TEST_PASSWORD;
      const key = await cryptoEngine.deriveKey(password, 'edge-case-salt');
      const iv = cryptoEngine.generateIV();

      // Empty object
      const emptyData = {};
      const encrypted1 = await cryptoEngine.encrypt(emptyData, key, iv);
      const decrypted1 = await cryptoEngine.decrypt(encrypted1, key);
      expect(decrypted1).toEqual(emptyData);

      // Null values
      const nullData = { value: null, undefined: undefined };
      const encrypted2 = await cryptoEngine.encrypt(nullData, key, iv);
      const decrypted2 = await cryptoEngine.decrypt(encrypted2, key);
      expect(decrypted2).toEqual({ value: null });

      // Arrays
      const arrayData = [1, 'string', { nested: true }, null];
      const encrypted3 = await cryptoEngine.encrypt(arrayData, key, iv);
      const decrypted3 = await cryptoEngine.decrypt(encrypted3, key);
      expect(decrypted3).toEqual([1, 'string', { nested: true }, null]);
    });
  });

  describe('Error Handling', () => {
    test('should throw on invalid encrypted data', async () => {
      const password = TEST_CONSTANTS.TEST_PASSWORD;
      const key = await cryptoEngine.deriveKey(password, 'test-salt');
      
      const invalidEncrypted = {
        encrypted: 'invalid-base64-data!!!',
        iv: cryptoEngine.generateIV(),
        algorithm: 'AES-256-CBC' as const,
        keyDerivation: 'PBKDF2' as const,
        iterations: 100000,
        salt: 'test-salt'
      };

      await expect(cryptoEngine.decrypt(invalidEncrypted, key))
        .rejects
        .toThrow();
    });

    test('should throw on invalid IV', async () => {
      const testData = { test: 'data' };
      const password = TEST_CONSTANTS.TEST_PASSWORD;
      const key = await cryptoEngine.deriveKey(password, 'test-salt');
      const invalidIV = 'invalid-iv';

      await expect(cryptoEngine.encrypt(testData, key, invalidIV))
        .rejects
        .toThrow();
    });

    test('should validate key derivation parameters', async () => {
      const password = TEST_CONSTANTS.TEST_PASSWORD;

      // Empty password
      await expect(cryptoEngine.deriveKey('', 'salt'))
        .rejects
        .toThrow();

      // Empty salt
      await expect(cryptoEngine.deriveKey(password, ''))
        .rejects
        .toThrow();
    });
  });

  describe('Algorithm Compatibility', () => {
    test('should use AES-256-CBC algorithm', async () => {
      const testData = { algorithm: 'test' };
      const password = TEST_CONSTANTS.TEST_PASSWORD;
      const key = await cryptoEngine.deriveKey(password, 'algo-salt');
      const iv = cryptoEngine.generateIV();

      const encrypted = await cryptoEngine.encrypt(testData, key, iv);
      
      expect(encrypted.algorithm).toBe('AES-256-CBC');
      expect(encrypted.keyDerivation).toBe('PBKDF2');
      expect(encrypted.iterations).toBe(100000);
    });

    test('should produce consistent encryption format', async () => {
      const testData = { consistency: 'test' };
      const password = TEST_CONSTANTS.TEST_PASSWORD;
      const key = await cryptoEngine.deriveKey(password, 'format-salt');
      const iv = cryptoEngine.generateIV();

      const encrypted = await cryptoEngine.encrypt(testData, key, iv);
      
      // Check that the encrypted object has all required fields
      expect(encrypted).toHaveProperty('encrypted');
      expect(encrypted).toHaveProperty('iv');
      expect(encrypted).toHaveProperty('algorithm');
      expect(encrypted).toHaveProperty('keyDerivation');
      expect(encrypted).toHaveProperty('iterations');
      expect(encrypted).toHaveProperty('salt');
      
      // Verify types
      expect(typeof encrypted.encrypted).toBe('string');
      expect(typeof encrypted.iv).toBe('string');
      expect(typeof encrypted.algorithm).toBe('string');
      expect(typeof encrypted.keyDerivation).toBe('string');
      expect(typeof encrypted.iterations).toBe('number');
      expect(typeof encrypted.salt).toBe('string');
    });
  });
}); 
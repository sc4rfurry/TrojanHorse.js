/**
 * Jest Test Setup for TrojanHorse.js
 * Security-focused testing utilities and mocks
 */

import { jest } from '@jest/globals';

// Global test timeout for async operations
jest.setTimeout(30000);

// Mock console methods for cleaner test output
const originalConsole = { ...console };

beforeEach(() => {
  // Reset console mocks
  console.log = jest.fn();
  console.info = jest.fn();
  console.warn = jest.fn();
  console.error = jest.fn();
});

afterEach(() => {
  // Restore console
  Object.assign(console, originalConsole);
  
  // Clear all mocks
  jest.clearAllMocks();
});

// Mock Web Crypto API for Node.js environment
global.crypto = {
  getRandomValues: (arr: Uint8Array) => {
    for (let i = 0; i < arr.length; i++) {
      arr[i] = Math.floor(Math.random() * 256);
    }
    return arr;
  },
  subtle: {
    digest: jest.fn(),
    encrypt: jest.fn(),
    decrypt: jest.fn(),
    generateKey: jest.fn(),
    deriveKey: jest.fn(),
    sign: jest.fn(),
    verify: jest.fn()
  }
} as any;

// Mock window object for browser compatibility tests
global.window = {
  crypto: global.crypto,
  isSecureContext: true,
  location: {
    protocol: 'https:',
    hostname: 'localhost'
  }
} as any;

// Test utilities
export const TestUtils = {
  /**
   * Generate test API key
   */
  generateTestApiKey: (length: number = 32): string => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  },

  /**
   * Generate test threat indicator
   */
  generateTestThreatIndicator: (overrides = {}) => ({
    type: 'domain' as const,
    value: 'malicious-test-domain.com',
    confidence: 0.85,
    firstSeen: new Date('2023-01-01'),
    lastSeen: new Date(),
    source: 'test-feed',
    tags: ['test', 'malware'],
    severity: 'medium' as const,
    ...overrides
  }),

  /**
   * Create test vault configuration
   */
  createTestVaultConfig: () => ({
    algorithm: 'AES-GCM' as const,
    keyDerivation: 'PBKDF2' as const,
    iterations: 10000, // Lower for faster tests
    saltBytes: 16,
    autoLock: false, // Disable for tests
    lockTimeout: 0
  }),

  /**
   * Mock axios response
   */
  mockAxiosResponse: (data: any, status: number = 200) => ({
    data,
    status,
    statusText: 'OK',
    headers: {},
    config: {}
  }),

  /**
   * Wait for async operations
   */
  wait: (ms: number): Promise<void> => 
    new Promise(resolve => setTimeout(resolve, ms)),

  /**
   * Secure test data cleanup
   */
  secureCleanup: (data: any): void => {
    if (typeof data === 'string') {
      // Overwrite string data
      data = '\0'.repeat(data.length);
    } else if (data && typeof data === 'object') {
      Object.keys(data).forEach(key => {
        if (typeof data[key] === 'string') {
          data[key] = '\0'.repeat(data[key].length);
        }
        delete data[key];
      });
    }
  }
};

// Export test constants
export const TEST_CONSTANTS = {
  TEST_PASSWORD: 'TestPassword123!',
  TEST_API_KEYS: {
    alienVault: TestUtils.generateTestApiKey(),
    crowdsec: TestUtils.generateTestApiKey(),
    abuseipdb: TestUtils.generateTestApiKey()
  },
  TEST_VAULT_CONFIG: TestUtils.createTestVaultConfig(),
  TEST_THREAT: TestUtils.generateTestThreatIndicator()
};

// Security test helpers
export const SecurityTestUtils = {
  /**
   * Test for timing attacks
   */
  async testTimingAttack(
    operation: (input: string) => Promise<boolean>,
    validInput: string,
    invalidInput: string,
    iterations: number = 100
  ): Promise<boolean> {
    const validTimes: number[] = [];
    const invalidTimes: number[] = [];

    for (let i = 0; i < iterations; i++) {
      // Test valid input
      const validStart = process.hrtime.bigint();
      await operation(validInput);
      const validEnd = process.hrtime.bigint();
      validTimes.push(Number(validEnd - validStart));

      // Test invalid input
      const invalidStart = process.hrtime.bigint();
      await operation(invalidInput);
      const invalidEnd = process.hrtime.bigint();
      invalidTimes.push(Number(invalidEnd - invalidStart));
    }

    const validAvg = validTimes.reduce((a, b) => a + b) / validTimes.length;
    const invalidAvg = invalidTimes.reduce((a, b) => a + b) / invalidTimes.length;
    
    // If timing difference is less than 5%, consider it secure
    const timingDifference = Math.abs(validAvg - invalidAvg) / Math.max(validAvg, invalidAvg);
    return timingDifference < 0.05;
  },

  /**
   * Test for memory leaks
   */
  testMemoryCleanup: (operation: () => void): boolean => {
    const beforeHeap = process.memoryUsage().heapUsed;
    operation();
    
    // Force garbage collection if available
    if (global.gc) {
      global.gc();
    }
    
    const afterHeap = process.memoryUsage().heapUsed;
    const memoryIncrease = afterHeap - beforeHeap;
    
    // Allow for some memory increase but flag significant leaks
    return memoryIncrease < 1024 * 1024; // 1MB threshold
  }
};

// Global error handler for unhandled promises
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  // Don't exit the process in tests, just log
});

export default TestUtils; 
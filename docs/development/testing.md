# Testing Guide

Comprehensive testing strategies, frameworks, and best practices for TrojanHorse.js development and quality assurance.

## Overview

TrojanHorse.js uses a multi-layered testing approach including unit tests, integration tests, end-to-end tests, and performance testing to ensure reliability and security in production environments.

```mermaid
graph TB
    A[Testing Strategy] --> B[Unit Tests]
    A --> C[Integration Tests]
    A --> D[E2E Tests]
    A --> E[Performance Tests]
    A --> F[Security Tests]
    
    B --> B1[Jest Framework]
    B --> B2[Mock Services]
    B --> B3[Coverage Reports]
    
    C --> C1[API Testing]
    C --> C2[Database Testing]
    C --> C3[Feed Integration]
    
    D --> D1[User Workflows]
    D --> D2[System Integration]
    D --> D3[Browser Testing]
    
    E --> E1[Load Testing]
    E --> E2[Stress Testing]
    E --> E3[Benchmarking]
    
    F --> F1[Penetration Testing]
    F --> F2[Vulnerability Scanning]
    F --> F3[Security Audits]
```

## Testing Framework Setup

### Jest Configuration

```javascript
// jest.config.js
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  
  // Test file patterns
  testMatch: [
    '**/src/**/__tests__/**/*.test.ts',
    '**/tests/**/*.test.ts'
  ],
  
  // Coverage configuration
  collectCoverage: true,
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80
    }
  },
  
  // Setup files
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
  
  // Module path mapping
  moduleNameMapping: {
    '^@/(.*)$': '<rootDir>/src/$1',
    '^@tests/(.*)$': '<rootDir>/tests/$1'
  },
  
  // Test timeout
  testTimeout: 10000,
  
  // Parallel testing
  maxWorkers: '50%'
};
```

## Unit Testing

### Core Component Testing

```typescript
// tests/core/TrojanHorse.test.ts
import { TrojanHorse } from '@/core/TrojanHorse';
import { MockFeedRegistry } from '@tests/mocks/MockFeedRegistry';
import { MockKeyVault } from '@tests/mocks/MockKeyVault';

describe('TrojanHorse Core', () => {
  let trojan: TrojanHorse;
  let mockFeedRegistry: MockFeedRegistry;
  let mockKeyVault: MockKeyVault;
  
  beforeEach(() => {
    mockFeedRegistry = new MockFeedRegistry();
    mockKeyVault = new MockKeyVault();
    
    trojan = new TrojanHorse({
      sources: ['urlhaus', 'virustotal'],
      testing: true,
      feedRegistry: mockFeedRegistry,
      keyVault: mockKeyVault
    });
  });
  
  describe('scout method', () => {
    it('should detect malicious domains', async () => {
      // Arrange
      const maliciousDomain = 'malicious-site.com';
      mockFeedRegistry.mockResponse('urlhaus', {
        indicator: maliciousDomain,
        threat: true,
        confidence: 95,
        sources: ['urlhaus']
      });
      
      // Act
      const results = await trojan.scout(maliciousDomain);
      
      // Assert
      expect(results).toHaveLength(1);
      expect(results[0].threat).toBe(true);
      expect(results[0].confidence).toBeGreaterThan(90);
      expect(results[0].sources).toContain('urlhaus');
    });
    
    it('should handle feed timeouts gracefully', async () => {
      // Arrange
      const indicator = 'timeout-test.com';
      mockFeedRegistry.mockTimeout('virustotal', 5000);
      
      // Act & Assert
      await expect(trojan.scout(indicator, { timeout: 1000 }))
        .resolves.not.toThrow();
    });
    
    it('should validate input parameters', async () => {
      // Test invalid indicators
      await expect(trojan.scout('')).rejects.toThrow('Invalid indicator');
      await expect(trojan.scout(null as any)).rejects.toThrow('Invalid indicator');
      await expect(trojan.scout('x'.repeat(3000))).rejects.toThrow('Indicator too long');
    });
    
    it('should emit threatDetected events', async () => {
      // Arrange
      const threatHandler = jest.fn();
      trojan.on('threatDetected', threatHandler);
      
      mockFeedRegistry.mockResponse('urlhaus', {
        indicator: 'evil.com',
        threat: true,
        confidence: 90
      });
      
      // Act
      await trojan.scout('evil.com');
      
      // Assert
      expect(threatHandler).toHaveBeenCalledWith(
        expect.objectContaining({
          indicator: 'evil.com',
          threat: true,
          confidence: 90
        })
      );
    });
  });
  
  describe('correlation', () => {
    it('should correlate related threats', async () => {
      // Arrange
      const indicators = ['domain1.com', 'domain2.com', 'related-ip.com'];
      
      indicators.forEach(indicator => {
        mockFeedRegistry.mockResponse('urlhaus', {
          indicator,
          threat: true,
          confidence: 85,
          metadata: { campaign: 'test-campaign' }
        });
      });
      
      // Act
      const correlation = await trojan.correlate(indicators[0]);
      
      // Assert
      expect(correlation.relatedThreats).toHaveLength(2);
      expect(correlation.correlationScore).toBeGreaterThan(70);
    });
  });
});
```

### Feed Testing

```typescript
// tests/feeds/URLhausFeed.test.ts
import { URLhausFeed } from '@/feeds/URLhausFeed';
import { MockHTTPClient } from '@tests/mocks/MockHTTPClient';

describe('URLhaus Feed', () => {
  let feed: URLhausFeed;
  let mockClient: MockHTTPClient;
  
  beforeEach(() => {
    mockClient = new MockHTTPClient();
    feed = new URLhausFeed({
      baseUrl: 'https://urlhaus-api.abuse.ch',
      httpClient: mockClient
    });
  });
  
  describe('fetchThreatData', () => {
    it('should fetch threat data for domains', async () => {
      // Arrange
      const domain = 'malicious-domain.com';
      mockClient.mockResponse('/api/host/', {
        query_status: 'ok',
        urlhaus_reference: 'https://urlhaus.abuse.ch/host/malicious-domain.com/',
        host: domain,
        firstseen: '2025-01-15',
        url_count: 5,
        blacklists: {
          spamhaus_dbl: 'not listed',
          surbl: 'listed'
        }
      });
      
      // Act
      const result = await feed.fetchThreatData(domain);
      
      // Assert
      expect(result.indicator).toBe(domain);
      expect(result.type).toBe('domain');
      expect(result.threat).toBe(true);
      expect(result.sources).toContain('URLhaus');
      expect(result.metadata.url_count).toBe(5);
    });
    
    it('should handle API errors gracefully', async () => {
      // Arrange
      mockClient.mockError('/api/host/', new Error('API rate limit exceeded'));
      
      // Act & Assert
      const result = await feed.fetchThreatData('test-domain.com');
      expect(result.threat).toBe(false);
      expect(result.confidence).toBe(0);
      expect(result.metadata.error).toBeDefined();
    });
    
    it('should cache responses', async () => {
      // Arrange
      const domain = 'cached-domain.com';
      mockClient.mockResponse('/api/host/', { query_status: 'ok' });
      
      // Act
      await feed.fetchThreatData(domain);
      await feed.fetchThreatData(domain); // Second call should use cache
      
      // Assert
      expect(mockClient.getCallCount('/api/host/')).toBe(1);
    });
  });
  
  describe('batchQuery', () => {
    it('should handle batch queries efficiently', async () => {
      // Arrange
      const domains = Array.from({ length: 100 }, (_, i) => `domain${i}.com`);
      mockClient.mockBatchResponse('/api/host/', domains.map(domain => ({
        query_status: 'ok',
        host: domain
      })));
      
      // Act
      const startTime = Date.now();
      const results = await feed.batchQuery(domains);
      const duration = Date.now() - startTime;
      
      // Assert
      expect(results).toHaveLength(100);
      expect(duration).toBeLessThan(5000); // Should complete within 5 seconds
    });
  });
});
```

### Security Component Testing

```typescript
// tests/security/CryptoEngine.test.ts
import { CryptoEngine } from '@/security/CryptoEngine';

describe('CryptoEngine', () => {
  let crypto: CryptoEngine;
  
  beforeEach(() => {
    crypto = new CryptoEngine({
      algorithm: 'aes-256-gcm',
      keyDerivation: 'argon2id'
    });
  });
  
  describe('encryption/decryption', () => {
    it('should encrypt and decrypt data correctly', async () => {
      // Arrange
      const plaintext = 'sensitive data';
      const password = 'strong-password-123';
      
      // Act
      const encrypted = await crypto.encrypt(plaintext, { password });
      const decrypted = await crypto.decrypt(encrypted, { password });
      
      // Assert
      expect(decrypted).toBe(plaintext);
      expect(encrypted.data).not.toBe(plaintext);
      expect(encrypted.iv).toBeDefined();
      expect(encrypted.tag).toBeDefined();
      expect(encrypted.salt).toBeDefined();
    });
    
    it('should fail with wrong password', async () => {
      // Arrange
      const plaintext = 'secret data';
      const correctPassword = 'correct-password';
      const wrongPassword = 'wrong-password';
      
      const encrypted = await crypto.encrypt(plaintext, { password: correctPassword });
      
      // Act & Assert
      await expect(crypto.decrypt(encrypted, { password: wrongPassword }))
        .rejects.toThrow('Decryption failed');
    });
    
    it('should use different salts for same password', async () => {
      // Arrange
      const plaintext = 'data';
      const password = 'password';
      
      // Act
      const encrypted1 = await crypto.encrypt(plaintext, { password });
      const encrypted2 = await crypto.encrypt(plaintext, { password });
      
      // Assert
      expect(encrypted1.salt).not.toBe(encrypted2.salt);
      expect(encrypted1.data).not.toBe(encrypted2.data);
    });
  });
  
  describe('key derivation', () => {
    it('should derive consistent keys from same password and salt', async () => {
      // Arrange
      const password = 'test-password';
      const salt = 'fixed-salt-for-testing';
      
      // Act
      const key1 = await crypto.deriveKey(password, { salt });
      const key2 = await crypto.deriveKey(password, { salt });
      
      // Assert
      expect(key1.key).toBe(key2.key);
    });
    
    it('should derive different keys with different salts', async () => {
      // Arrange
      const password = 'test-password';
      
      // Act
      const key1 = await crypto.deriveKey(password);
      const key2 = await crypto.deriveKey(password);
      
      // Assert
      expect(key1.key).not.toBe(key2.key);
      expect(key1.salt).not.toBe(key2.salt);
    });
  });
});
```

## Integration Testing

### API Integration Tests

```typescript
// tests/integration/api.test.ts
import request from 'supertest';
import { createTestApp } from '@tests/helpers/testApp';
import { TestDatabase } from '@tests/helpers/TestDatabase';

describe('API Integration Tests', () => {
  let app: Express.Application;
  let database: TestDatabase;
  
  beforeAll(async () => {
    database = new TestDatabase();
    await database.setup();
    
    app = createTestApp({
      database: database.connection,
      testing: true
    });
  });
  
  afterAll(async () => {
    await database.teardown();
  });
  
  describe('POST /api/threats/scan', () => {
    it('should scan a single indicator', async () => {
      const response = await request(app)
        .post('/api/threats/scan')
        .send({
          indicator: 'malicious-domain.com',
          sources: ['urlhaus', 'virustotal']
        })
        .expect(200);
      
      expect(response.body).toMatchObject({
        indicator: 'malicious-domain.com',
        results: expect.any(Array),
        timestamp: expect.any(String)
      });
    });
    
    it('should require authentication', async () => {
      await request(app)
        .post('/api/threats/scan')
        .send({ indicator: 'test.com' })
        .expect(401);
    });
    
    it('should validate input parameters', async () => {
      const response = await request(app)
        .post('/api/threats/scan')
        .set('Authorization', 'Bearer valid-token')
        .send({ indicator: '' })
        .expect(400);
      
      expect(response.body.error).toContain('Invalid indicator');
    });
  });
  
  describe('GET /api/threats/history', () => {
    it('should return threat history', async () => {
      // First, create some threat history
      await request(app)
        .post('/api/threats/scan')
        .set('Authorization', 'Bearer valid-token')
        .send({ indicator: 'history-test.com' });
      
      const response = await request(app)
        .get('/api/threats/history')
        .set('Authorization', 'Bearer valid-token')
        .expect(200);
      
      expect(response.body.threats).toBeDefined();
      expect(Array.isArray(response.body.threats)).toBe(true);
    });
  });
});
```

### Database Integration Tests

```typescript
// tests/integration/database.test.ts
import { DatabaseManager } from '@/storage/DatabaseManager';
import { TestDatabase } from '@tests/helpers/TestDatabase';

describe('Database Integration', () => {
  let db: DatabaseManager;
  let testDb: TestDatabase;
  
  beforeAll(async () => {
    testDb = new TestDatabase();
    await testDb.setup();
    db = new DatabaseManager(testDb.config);
  });
  
  afterAll(async () => {
    await testDb.teardown();
  });
  
  describe('threat storage', () => {
    it('should store and retrieve threats', async () => {
      // Arrange
      const threat = {
        indicator: 'test-domain.com',
        type: 'domain',
        threat: true,
        confidence: 85,
        sources: ['test-feed'],
        timestamp: new Date().toISOString()
      };
      
      // Act
      const id = await db.storeThreat(threat);
      const retrieved = await db.getThreat(id);
      
      // Assert
      expect(retrieved).toMatchObject(threat);
    });
    
    it('should handle duplicate threats', async () => {
      // Arrange
      const threat = {
        indicator: 'duplicate-test.com',
        type: 'domain',
        threat: true,
        confidence: 80
      };
      
      // Act
      const id1 = await db.storeThreat(threat);
      const id2 = await db.storeThreat({ ...threat, confidence: 90 });
      
      // Assert
      expect(id1).toBe(id2); // Should update existing record
      const retrieved = await db.getThreat(id1);
      expect(retrieved.confidence).toBe(90); // Should have updated confidence
    });
  });
  
  describe('search functionality', () => {
    it('should search threats by indicator pattern', async () => {
      // Arrange
      await db.storeThreat({
        indicator: 'search-test-1.com',
        type: 'domain',
        threat: true
      });
      await db.storeThreat({
        indicator: 'search-test-2.com',
        type: 'domain',
        threat: true
      });
      
      // Act
      const results = await db.searchThreats({
        pattern: 'search-test-*.com',
        limit: 10
      });
      
      // Assert
      expect(results).toHaveLength(2);
      expect(results.every(r => r.indicator.includes('search-test'))).toBe(true);
    });
  });
});
```

## End-to-End Testing

### User Workflow Testing

```typescript
// tests/e2e/user-workflows.test.ts
import { Browser, Page } from 'puppeteer';
import { launchBrowser, createTestUser } from '@tests/helpers/e2e';

describe('User Workflows', () => {
  let browser: Browser;
  let page: Page;
  
  beforeAll(async () => {
    browser = await launchBrowser();
    page = await browser.newPage();
  });
  
  afterAll(async () => {
    await browser.close();
  });
  
  describe('Threat Analysis Workflow', () => {
    it('should allow user to scan threats end-to-end', async () => {
      // Login
      await page.goto('http://localhost:3000/login');
      await page.type('#username', 'test-user@example.com');
      await page.type('#password', 'test-password');
      await page.click('#login-button');
      await page.waitForNavigation();
      
      // Navigate to threat scanner
      await page.click('[data-testid="threat-scanner-link"]');
      await page.waitForSelector('#threat-input');
      
      // Input threat indicator
      await page.type('#threat-input', 'malicious-domain.com');
      await page.click('#scan-button');
      
      // Wait for results
      await page.waitForSelector('[data-testid="scan-results"]', { timeout: 10000 });
      
      // Verify results are displayed
      const results = await page.$eval('[data-testid="scan-results"]', el => el.textContent);
      expect(results).toContain('malicious-domain.com');
      
      // Check threat details
      await page.click('[data-testid="threat-details-button"]');
      await page.waitForSelector('[data-testid="threat-metadata"]');
      
      const metadata = await page.$eval('[data-testid="threat-metadata"]', el => el.textContent);
      expect(metadata).toContain('Confidence');
      expect(metadata).toContain('Sources');
    });
    
    it('should handle bulk threat scanning', async () => {
      await page.goto('http://localhost:3000/bulk-scan');
      
      // Upload CSV file
      const fileInput = await page.$('#file-input');
      await fileInput!.uploadFile('./tests/fixtures/threat-indicators.csv');
      
      await page.click('#upload-button');
      
      // Wait for processing
      await page.waitForSelector('[data-testid="processing-complete"]', { timeout: 30000 });
      
      // Verify results
      const resultsCount = await page.$eval('[data-testid="results-count"]', el => 
        parseInt(el.textContent || '0')
      );
      expect(resultsCount).toBeGreaterThan(0);
    });
  });
  
  describe('Dashboard Workflow', () => {
    it('should display real-time threat metrics', async () => {
      await page.goto('http://localhost:3000/dashboard');
      
      // Wait for metrics to load
      await page.waitForSelector('[data-testid="threat-metrics"]');
      
      // Check metric values
      const metricsElements = await page.$$('[data-testid="metric-value"]');
      expect(metricsElements.length).toBeGreaterThan(0);
      
      // Verify charts are rendered
      const charts = await page.$$('canvas');
      expect(charts.length).toBeGreaterThan(0);
    });
  });
});
```

## Performance Testing

### Load Testing

```typescript
// tests/performance/load.test.ts
import { performance } from 'perf_hooks';
import { TrojanHorse } from '@/core/TrojanHorse';

describe('Performance Tests', () => {
  let trojan: TrojanHorse;
  
  beforeAll(async () => {
    trojan = new TrojanHorse({
      sources: ['urlhaus', 'virustotal'],
      performance: {
        workers: 8,
        batchSize: 100
      }
    });
  });
  
  describe('Single Request Performance', () => {
    it('should complete threat scan within acceptable time', async () => {
      const start = performance.now();
      
      await trojan.scout('performance-test.com');
      
      const duration = performance.now() - start;
      expect(duration).toBeLessThan(5000); // 5 second SLA
    });
  });
  
  describe('Concurrent Request Performance', () => {
    it('should handle concurrent requests efficiently', async () => {
      const concurrentRequests = 50;
      const indicators = Array.from({ length: concurrentRequests }, 
        (_, i) => `concurrent-test-${i}.com`
      );
      
      const start = performance.now();
      
      const promises = indicators.map(indicator => trojan.scout(indicator));
      const results = await Promise.all(promises);
      
      const duration = performance.now() - start;
      const avgDuration = duration / concurrentRequests;
      
      expect(results).toHaveLength(concurrentRequests);
      expect(avgDuration).toBeLessThan(1000); // 1 second average
    });
  });
  
  describe('Batch Processing Performance', () => {
    it('should process large batches efficiently', async () => {
      const batchSize = 1000;
      const indicators = Array.from({ length: batchSize }, 
        (_, i) => `batch-test-${i}.com`
      );
      
      const start = performance.now();
      
      const results = await trojan.scoutBatch(indicators);
      
      const duration = performance.now() - start;
      const throughput = batchSize / (duration / 1000); // requests per second
      
      expect(results).toHaveLength(batchSize);
      expect(throughput).toBeGreaterThan(10); // Minimum 10 RPS
    });
  });
  
  describe('Memory Usage', () => {
    it('should not have memory leaks during extended operation', async () => {
      const initialMemory = process.memoryUsage().heapUsed;
      
      // Perform many operations
      for (let i = 0; i < 100; i++) {
        await trojan.scout(`memory-test-${i}.com`);
      }
      
      // Force garbage collection
      if (global.gc) {
        global.gc();
      }
      
      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = (finalMemory - initialMemory) / 1024 / 1024; // MB
      
      expect(memoryIncrease).toBeLessThan(50); // Less than 50MB increase
    });
  });
});
```

### Benchmark Testing

```typescript
// tests/performance/benchmark.test.ts
import Benchmark from 'benchmark';
import { TrojanHorse } from '@/core/TrojanHorse';

describe('Benchmark Tests', () => {
  let trojan: TrojanHorse;
  
  beforeAll(async () => {
    trojan = new TrojanHorse({ sources: ['mock-feed'] });
  });
  
  it('should benchmark threat scanning performance', (done) => {
    const suite = new Benchmark.Suite();
    
    suite
      .add('Single threat scan', {
        defer: true,
        fn: async (deferred: any) => {
          await trojan.scout('benchmark-test.com');
          deferred.resolve();
        }
      })
      .add('Batch threat scan (10)', {
        defer: true,
        fn: async (deferred: any) => {
          const indicators = Array.from({ length: 10 }, (_, i) => `batch-${i}.com`);
          await trojan.scoutBatch(indicators);
          deferred.resolve();
        }
      })
      .on('cycle', (event: any) => {
        console.log(String(event.target));
      })
      .on('complete', function(this: any) {
        console.log('Fastest is ' + this.filter('fastest').map('name'));
        done();
      })
      .run({ async: true });
  });
});
```

## Security Testing

### Penetration Testing

```typescript
// tests/security/penetration.test.ts
import request from 'supertest';
import { createTestApp } from '@tests/helpers/testApp';

describe('Security Penetration Tests', () => {
  let app: Express.Application;
  
  beforeAll(async () => {
    app = createTestApp({ security: true });
  });
  
  describe('Input Validation', () => {
    it('should prevent SQL injection attacks', async () => {
      const maliciousPayloads = [
        "'; DROP TABLE threats; --",
        "' OR '1'='1",
        "'; SELECT * FROM users; --"
      ];
      
      for (const payload of maliciousPayloads) {
        const response = await request(app)
          .post('/api/threats/scan')
          .send({ indicator: payload })
          .expect(400);
        
        expect(response.body.error).toContain('Invalid indicator');
      }
    });
    
    it('should prevent XSS attacks', async () => {
      const xssPayloads = [
        '<script>alert("xss")</script>',
        'javascript:alert("xss")',
        '<img src="x" onerror="alert(1)">'
      ];
      
      for (const payload of xssPayloads) {
        const response = await request(app)
          .post('/api/threats/scan')
          .send({ indicator: payload });
        
        expect(response.body).not.toContain('<script>');
        expect(response.body).not.toContain('javascript:');
      }
    });
  });
  
  describe('Authentication Security', () => {
    it('should prevent brute force attacks', async () => {
      const invalidCredentials = {
        username: 'test@example.com',
        password: 'wrong-password'
      };
      
      // Attempt multiple failed logins
      for (let i = 0; i < 6; i++) {
        await request(app)
          .post('/api/auth/login')
          .send(invalidCredentials);
      }
      
      // Next attempt should be rate limited
      const response = await request(app)
        .post('/api/auth/login')
        .send(invalidCredentials)
        .expect(429);
      
      expect(response.body.error).toContain('rate limit');
    });
  });
  
  describe('Authorization Security', () => {
    it('should prevent privilege escalation', async () => {
      // Create user with limited privileges
      const userToken = await createUserToken({ role: 'viewer' });
      
      // Attempt to access admin endpoint
      const response = await request(app)
        .delete('/api/admin/users/123')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(403);
      
      expect(response.body.error).toContain('Insufficient permissions');
    });
  });
});
```

## Test Automation

### CI/CD Pipeline Testing

```yaml
# .github/workflows/test.yml
name: Test Suite

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        node-version: [18.x, 20.x]
    
    steps:
    - uses: actions/checkout@v4
    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: ${{ matrix.node-version }}
        cache: 'npm'
    
    - name: Install dependencies
      run: npm ci
    
    - name: Run unit tests
      run: npm run test:unit
    
    - name: Generate coverage report
      run: npm run test:coverage
    
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage/lcov.info

  integration-tests:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    
    steps:
    - uses: actions/checkout@v4
    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: '20.x'
        cache: 'npm'
    
    - name: Install dependencies
      run: npm ci
    
    - name: Run integration tests
      run: npm run test:integration
      env:
        DATABASE_URL: postgresql://postgres:test@localhost:5432/test
        REDIS_URL: redis://localhost:6379

  security-tests:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Run security scan
      uses: securecodewarrior/github-action-add-sarif@v1
      with:
        sarif-file: security-scan-results.sarif
    
    - name: Run dependency check
      run: npm audit --audit-level moderate
```

---

**Next Steps**:
- Review [Architecture Guide](architecture.md) for system design
- Check [Building Guide](building.md) for build processes  
- Explore [Contributing Guide](contributing.md) for development guidelines
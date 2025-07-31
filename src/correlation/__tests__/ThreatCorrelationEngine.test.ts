/**
 * @jest-environment node
 */

import { jest } from '@jest/globals';
import { ThreatCorrelationEngine } from '../ThreatCorrelationEngine';
import { TestUtils } from '../../../tests/setup';
import type { ThreatIndicator, ThreatCorrelationResult } from '../../types';

describe('ThreatCorrelationEngine', () => {
  let correlationEngine: ThreatCorrelationEngine;
  let sampleIndicators: ThreatIndicator[];

  beforeEach(() => {
    correlationEngine = new ThreatCorrelationEngine({
      minimumSources: 2,
      confidenceThreshold: 0.5,
      consensusThreshold: 0.7,
      enablePatternDetection: true,
      enableRiskAssessment: true
    });

    // Create sample threat indicators from different sources
    sampleIndicators = [
      TestUtils.generateTestThreatIndicator({
        type: 'domain',
        value: 'malicious-site.com',
        source: 'URLhaus',
        confidence: 0.8,
        severity: 'high',
        tags: ['malware', 'trojan']
      }),
      TestUtils.generateTestThreatIndicator({
        type: 'domain',
        value: 'malicious-site.com',
        source: 'AlienVault',
        confidence: 0.9,
        severity: 'critical',
        tags: ['malware', 'apt']
      }),
      TestUtils.generateTestThreatIndicator({
        type: 'ip',
        value: '192.168.1.100',
        source: 'AbuseIPDB',
        confidence: 0.7,
        severity: 'medium',
        tags: ['bruteforce', 'ssh']
      }),
      TestUtils.generateTestThreatIndicator({
        type: 'url',
        value: 'http://malicious-site.com/payload.exe',
        source: 'URLhaus',
        confidence: 0.95,
        severity: 'critical',
        tags: ['malware', 'downloader']
      })
    ];
  });

  afterEach(() => {
    TestUtils.secureCleanup(sampleIndicators);
  });

  describe('Basic Correlation', () => {
    test('should correlate indicators from multiple sources', async () => {
      const result = await correlationEngine.correlate(sampleIndicators);

      expect(result).toBeDefined();
      expect(result.correlationScore).toBeGreaterThanOrEqual(0);
      expect(result.correlationScore).toBeLessThanOrEqual(1);
      expect(result.sources).toBeInstanceOf(Array);
      expect(result.sources.length).toBeGreaterThan(0);
      expect(result.consensusLevel).toMatch(/weak|moderate|strong|consensus/);
    });

    test('should handle single source indicators', async () => {
      const singleSourceIndicators = [sampleIndicators[0]];
      
      const result = await correlationEngine.correlate(singleSourceIndicators);
      
      expect(result.correlationScore).toBeLessThan(0.5); // Lower confidence for single source
      expect(result.consensusLevel).toBe('weak');
      expect(result.sources).toHaveLength(1);
    });

    test('should handle empty indicator list', async () => {
      const result = await correlationEngine.correlate([]);
      
      expect(result.correlationScore).toBe(0);
      expect(result.sources).toHaveLength(0);
      expect(result.consensusLevel).toBe('weak');
    });

    test('should calculate weighted confidence scores', async () => {
      // High confidence indicators from multiple sources
      const highConfidenceIndicators = sampleIndicators.filter(i => i.confidence > 0.8);
      const highResult = await correlationEngine.correlate(highConfidenceIndicators);

      // Low confidence indicators
      const lowConfidenceIndicators = sampleIndicators.map(i => ({
        ...i,
        confidence: 0.3
      }));
      const lowResult = await correlationEngine.correlate(lowConfidenceIndicators);

      expect(highResult.correlationScore).toBeGreaterThan(lowResult.correlationScore);
    });
  });

  describe('Pattern Detection', () => {
    test('should detect related domain patterns', async () => {
      const relatedDomains = [
        TestUtils.generateTestThreatIndicator({
          type: 'domain',
          value: 'malicious-site.com',
          source: 'URLhaus'
        }),
        TestUtils.generateTestThreatIndicator({
          type: 'domain',
          value: 'sub.malicious-site.com',
          source: 'AlienVault'
        }),
        TestUtils.generateTestThreatIndicator({
          type: 'url',
          value: 'http://malicious-site.com/path',
          source: 'CrowdSec'
        })
      ];

      const result = await correlationEngine.correlate(relatedDomains);
      
      expect(result.patterns).toContain('domain-hierarchy');
      expect(result.correlationScore).toBeGreaterThan(0.7);
    });

    test('should detect malware family patterns', async () => {
      const malwareFamilyIndicators = [
        TestUtils.generateTestThreatIndicator({
          malwareFamily: 'trojan.banker',
          tags: ['banking', 'stealer'],
          source: 'URLhaus'
        }),
        TestUtils.generateTestThreatIndicator({
          malwareFamily: 'trojan.banker',
          tags: ['financial', 'credential'],
          source: 'AlienVault'
        })
      ];

      const result = await correlationEngine.correlate(malwareFamilyIndicators);
      
      expect(result.patterns).toContain('malware-family');
      expect(result.correlationScore).toBeGreaterThan(0.6);
    });

    test('should detect attack campaign patterns', async () => {
      const campaignIndicators = [
        TestUtils.generateTestThreatIndicator({
          tags: ['apt29', 'cozy-bear'],
          source: 'AlienVault'
        }),
        TestUtils.generateTestThreatIndicator({
          tags: ['apt29', 'russia'],
          source: 'CrowdSec'
        }),
        TestUtils.generateTestThreatIndicator({
          tags: ['cozy-bear', 'government'],
          source: 'URLhaus'
        })
      ];

      const result = await correlationEngine.correlate(campaignIndicators);
      
      expect(result.patterns).toContain('attack-campaign');
    });

    test('should detect temporal patterns', async () => {
      const now = new Date();
      const recentIndicators = [
        TestUtils.generateTestThreatIndicator({
          firstSeen: new Date(now.getTime() - 60000), // 1 minute ago
          lastSeen: now,
          source: 'URLhaus'
        }),
        TestUtils.generateTestThreatIndicator({
          firstSeen: new Date(now.getTime() - 120000), // 2 minutes ago
          lastSeen: now,
          source: 'AlienVault'
        })
      ];

      const result = await correlationEngine.correlate(recentIndicators);
      
      expect(result.patterns).toContain('temporal-clustering');
    });
  });

  describe('Consensus Building', () => {
    test('should build consensus from multiple sources', async () => {
      // Multiple sources agree on severity
      const consensusIndicators = [
        TestUtils.generateTestThreatIndicator({
          value: 'consensus-test.com',
          severity: 'high',
          source: 'URLhaus'
        }),
        TestUtils.generateTestThreatIndicator({
          value: 'consensus-test.com',
          severity: 'high',
          source: 'AlienVault'
        }),
        TestUtils.generateTestThreatIndicator({
          value: 'consensus-test.com',
          severity: 'critical',
          source: 'CrowdSec'
        })
      ];

      const result = await correlationEngine.correlate(consensusIndicators);
      
      expect(result.consensusLevel).toMatch(/strong|consensus/);
      expect(result.indicator?.severity).toBe('high'); // Most common severity
    });

    test('should handle conflicting information', async () => {
      const conflictingIndicators = [
        TestUtils.generateTestThreatIndicator({
          value: 'conflict-test.com',
          severity: 'low',
          confidence: 0.3,
          source: 'Source1'
        }),
        TestUtils.generateTestThreatIndicator({
          value: 'conflict-test.com',
          severity: 'critical',
          confidence: 0.9,
          source: 'Source2'
        })
      ];

      const result = await correlationEngine.correlate(conflictingIndicators);
      
      expect(result.consensusLevel).toBe('weak');
      expect(result.correlationScore).toBeLessThan(0.6);
    });

    test('should weight trusted sources higher', async () => {
      const trustedSourceConfig = {
        ...correlationEngine.config,
        sourceWeights: {
          'TrustedSource': 2.0,
          'RegularSource': 1.0
        }
      };
      
      const weightedEngine = new ThreatCorrelationEngine(trustedSourceConfig);
      
      const indicators = [
        TestUtils.generateTestThreatIndicator({
          value: 'weighted-test.com',
          confidence: 0.5,
          source: 'TrustedSource'
        }),
        TestUtils.generateTestThreatIndicator({
          value: 'weighted-test.com',
          confidence: 0.5,
          source: 'RegularSource'
        })
      ];

      const result = await weightedEngine.correlate(indicators);
      
      expect(result.correlationScore).toBeGreaterThan(0.5);
    });
  });

  describe('Risk Assessment', () => {
    test('should calculate risk scores based on severity and confidence', async () => {
      const highRiskIndicators = [
        TestUtils.generateTestThreatIndicator({
          severity: 'critical',
          confidence: 0.9,
          source: 'URLhaus'
        }),
        TestUtils.generateTestThreatIndicator({
          severity: 'high',
          confidence: 0.8,
          source: 'AlienVault'
        })
      ];

      const result = await correlationEngine.correlate(highRiskIndicators);
      
      expect(result.riskScore).toBeGreaterThan(0.7);
      expect(result.riskScore).toBeLessThanOrEqual(1.0);
    });

    test('should factor in temporal relevance', async () => {
      const now = new Date();
      const oldIndicator = TestUtils.generateTestThreatIndicator({
        lastSeen: new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000), // 30 days ago
        severity: 'critical',
        source: 'URLhaus'
      });

      const recentIndicator = TestUtils.generateTestThreatIndicator({
        lastSeen: now,
        severity: 'critical',
        source: 'AlienVault'
      });

      const oldResult = await correlationEngine.correlate([oldIndicator]);
      const recentResult = await correlationEngine.correlate([recentIndicator]);

      expect(recentResult.riskScore).toBeGreaterThan(oldResult.riskScore);
    });

    test('should consider indicator breadth', async () => {
      // Wide spread across different types
      const broadIndicators = [
        TestUtils.generateTestThreatIndicator({ type: 'domain' }),
        TestUtils.generateTestThreatIndicator({ type: 'ip' }),
        TestUtils.generateTestThreatIndicator({ type: 'url' }),
        TestUtils.generateTestThreatIndicator({ type: 'hash' })
      ];

      // Narrow (single type)
      const narrowIndicators = [
        TestUtils.generateTestThreatIndicator({ type: 'domain' }),
        TestUtils.generateTestThreatIndicator({ type: 'domain' })
      ];

      const broadResult = await correlationEngine.correlate(broadIndicators);
      const narrowResult = await correlationEngine.correlate(narrowIndicators);

      expect(broadResult.riskScore).toBeGreaterThan(narrowResult.riskScore);
    });
  });

  describe('Performance and Scalability', () => {
    test('should handle large indicator sets efficiently', async () => {
      const largeIndicatorSet = Array(1000).fill(0).map((_, i) => 
        TestUtils.generateTestThreatIndicator({
          value: `test-domain-${i}.com`,
          source: `Source${i % 5}` // 5 different sources
        })
      );

      const startTime = Date.now();
      const result = await correlationEngine.correlate(largeIndicatorSet);
      const endTime = Date.now();

      expect(result).toBeDefined();
      expect(endTime - startTime).toBeLessThan(10000); // Should complete within 10 seconds
    });

    test('should handle concurrent correlation requests', async () => {
      const requests = Array(10).fill(0).map(() => 
        correlationEngine.correlate(sampleIndicators)
      );

      const results = await Promise.all(requests);
      
      results.forEach(result => {
        expect(result).toBeDefined();
        expect(result.correlationScore).toBeGreaterThanOrEqual(0);
      });
    });

    test('should implement caching for repeated correlations', async () => {
      const firstResult = await correlationEngine.correlate(sampleIndicators);
      
      const startTime = Date.now();
      const secondResult = await correlationEngine.correlate(sampleIndicators);
      const endTime = Date.now();

      expect(secondResult).toEqual(firstResult);
      expect(endTime - startTime).toBeLessThan(100); // Should be much faster due to caching
    });
  });

  describe('Configuration and Customization', () => {
    test('should respect minimum sources threshold', async () => {
      const strictEngine = new ThreatCorrelationEngine({
        minimumSources: 3,
        confidenceThreshold: 0.5
      });

      // Only 2 sources (below threshold)
      const twoSourceIndicators = sampleIndicators.slice(0, 2);
      const result = await strictEngine.correlate(twoSourceIndicators);
      
      expect(result.consensusLevel).toBe('weak');
      expect(result.correlationScore).toBeLessThan(0.5);
    });

    test('should apply confidence threshold filtering', async () => {
      const highThresholdEngine = new ThreatCorrelationEngine({
        confidenceThreshold: 0.9
      });

      const mixedConfidenceIndicators = [
        TestUtils.generateTestThreatIndicator({ confidence: 0.8 }), // Below threshold
        TestUtils.generateTestThreatIndicator({ confidence: 0.95 }) // Above threshold
      ];

      const result = await highThresholdEngine.correlate(mixedConfidenceIndicators);
      
      // Should only consider the high-confidence indicator
      expect(result.sources).toHaveLength(1);
    });

    test('should allow custom pattern detection rules', async () => {
      const customEngine = new ThreatCorrelationEngine({
        customPatterns: {
          'custom-pattern': (indicators: ThreatIndicator[]) => {
            return indicators.some(i => i.tags.includes('custom-tag'));
          }
        }
      });

      const customIndicators = [
        TestUtils.generateTestThreatIndicator({
          tags: ['custom-tag', 'test']
        })
      ];

      const result = await customEngine.correlate(customIndicators);
      
      expect(result.patterns).toContain('custom-pattern');
    });
  });

  describe('Edge Cases and Error Handling', () => {
    test('should handle malformed indicators gracefully', async () => {
      const malformedIndicators = [
        {
          ...TestUtils.generateTestThreatIndicator(),
          confidence: 'invalid' as any
        },
        {
          ...TestUtils.generateTestThreatIndicator(),
          firstSeen: 'not-a-date' as any
        }
      ];

      // Should not throw error, but filter out malformed indicators
      const result = await correlationEngine.correlate(malformedIndicators);
      
      expect(result).toBeDefined();
      expect(result.correlationScore).toBeGreaterThanOrEqual(0);
    });

    test('should handle null and undefined values', async () => {
      const invalidIndicators = [
        null,
        undefined,
        TestUtils.generateTestThreatIndicator()
      ] as any[];

      const result = await correlationEngine.correlate(invalidIndicators);
      
      expect(result).toBeDefined();
      expect(result.sources).toHaveLength(1); // Only the valid indicator
    });

    test('should validate correlation configuration', () => {
      expect(() => {
        new ThreatCorrelationEngine({
          minimumSources: -1 // Invalid
        });
      }).toThrow(/invalid|configuration/i);

      expect(() => {
        new ThreatCorrelationEngine({
          confidenceThreshold: 1.5 // Invalid (> 1)
        });
      }).toThrow(/threshold|range/i);
    });

    test('should handle memory cleanup for large datasets', async () => {
      const largeDataset = Array(10000).fill(0).map(() => 
        TestUtils.generateTestThreatIndicator()
      );

      const initialMemory = process.memoryUsage().heapUsed;
      
      await correlationEngine.correlate(largeDataset);
      
      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }
      
      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;
      
      // Memory increase should be reasonable
      expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024); // Less than 100MB
    });
  });

  describe('Integration with External Systems', () => {
    test('should export correlation results in standard format', async () => {
      const result = await correlationEngine.correlate(sampleIndicators);
      
      const exported = correlationEngine.exportResult(result, 'json');
      const parsed = JSON.parse(exported);
      
      expect(parsed).toHaveProperty('correlationScore');
      expect(parsed).toHaveProperty('consensusLevel');
      expect(parsed).toHaveProperty('sources');
      expect(parsed).toHaveProperty('timestamp');
    });

    test('should support STIX format export', async () => {
      const result = await correlationEngine.correlate(sampleIndicators);
      
      const stixExport = correlationEngine.exportResult(result, 'stix');
      const stixObject = JSON.parse(stixExport);
      
      expect(stixObject).toHaveProperty('type');
      expect(stixObject).toHaveProperty('spec_version');
      expect(stixObject.type).toBe('bundle');
    });

    test('should integrate with threat intelligence platforms', async () => {
      const platformConnector = {
        submitCorrelation: jest.fn().mockResolvedValue({ status: 'accepted' })
      };

      correlationEngine.addIntegration('tip', platformConnector);
      
      const result = await correlationEngine.correlate(sampleIndicators);
      await correlationEngine.shareResult(result, 'tip');
      
      expect(platformConnector.submitCorrelation).toHaveBeenCalledWith(result);
    });
  });
}); 
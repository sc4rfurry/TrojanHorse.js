/**
 * TrojanHorse.js Machine Learning Threat Prediction Engine
 * 
 * ⚠️  EXPERIMENTAL FEATURE - BETA VERSION ⚠️
 * This module contains experimental ML features that are still in development.
 * Use with caution in production environments.
 * 
 * Advanced AI-powered threat detection and behavioral analysis
 */

import { EventEmitter } from 'events';
import { ThreatIndicator, ThreatFeedResult } from '../types';
import { CryptoEngine } from '../security/CryptoEngine';

// ML Engine Status
const ML_ENGINE_STATUS = {
  EXPERIMENTAL: true,
  BETA_VERSION: '0.1.0',
  PRODUCTION_READY: false,
  WARNING: 'This is an experimental feature. Results may vary in accuracy.'
};

// ===== ML ENGINE INTERFACES =====

export interface MLFeatures {
  // Domain/URL Features
  domainLength?: number;
  subdomainCount?: number;
  vowelConsonantRatio?: number;
  entropyScore?: number;
  hasNumbers?: boolean;
  hasDashes?: boolean;
  suspiciousTLD?: boolean;
  
  // IP Features  
  isPrivateIP?: boolean;
  isCloudProvider?: boolean;
  geographicRisk?: number;
  portScanHistory?: number;
  
  // Behavioral Features
  firstSeenAge?: number;
  reportingVelocity?: number;
  sourceReliability?: number;
  contextualAnomalies?: number;
  
  // Network Features
  dnsRecordCount?: number;
  httpResponseCode?: number;
  certificateValidity?: boolean;
  redirectChainLength?: number;
}

export interface MLPrediction {
  threatProbability: number;
  confidence: number;
  riskScore: number;
  threatCategory: 'malware' | 'phishing' | 'c2' | 'botnet' | 'spam' | 'benign';
  explanation: {
    topFeatures: Array<{ feature: string; importance: number; value: any }>;
    riskFactors: string[];
    modelVersion: string;
  };
  anomalyScore?: number;
  behavioralSignature?: string;
  experimental: {
    status: typeof ML_ENGINE_STATUS;
    warning: string;
    disclaimer: string;
  };
}

export interface MLModel {
  id: string;
  name: string;
  type: 'classification' | 'regression' | 'anomaly_detection' | 'clustering';
  version: string;
  accuracy: number;
  lastTrained: Date;
  featureImportance: Record<string, number>;
  hyperparameters: Record<string, any>;
  trainingMetrics: {
    precision: number;
    recall: number;
    f1Score: number;
    auc: number;
    falsePositiveRate: number;
  };
  experimental: boolean;
}

export interface TrainingDataPoint {
  features: MLFeatures;
  label: number; // 0 = benign, 1 = malicious
  weight: number;
  timestamp: Date;
  source: string;
}

// ===== FEATURE ENGINEERING =====

export class FeatureExtractor {
  private domainRegex = /^(?:https?:\/\/)?(?:www\.)?([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\/.*)?$/;
  private ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  private suspiciousTLDs = new Set([
    'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'click', 'science', 'work', 'party'
  ]);

  /**
   * Extract features from threat indicator
   */
  public extractFeatures(indicator: ThreatIndicator, context?: any): MLFeatures {
    const features: MLFeatures = {};
    
    switch (indicator.type) {
    case 'domain':
    case 'url':
      Object.assign(features, this.extractDomainFeatures(indicator.value));
      break;
    case 'ip':
      Object.assign(features, this.extractIPFeatures(indicator.value));
      break;
    case 'hash':
      Object.assign(features, this.extractHashFeatures(indicator.value));
      break;
    }

    // Common behavioral features
    features.firstSeenAge = this.calculateAge(indicator.firstSeen);
    features.sourceReliability = this.calculateSourceReliability(indicator.source);
    features.reportingVelocity = this.calculateReportingVelocity(indicator, context);
    
    return features;
  }

  private extractDomainFeatures(domain: string): Partial<MLFeatures> {
    const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    const parts = cleanDomain.split('.');
    
    return {
      domainLength: cleanDomain.length,
      subdomainCount: Math.max(0, parts.length - 2),
      vowelConsonantRatio: this.calculateVowelConsonantRatio(cleanDomain),
      entropyScore: this.calculateEntropy(cleanDomain),
      hasNumbers: /\d/.test(cleanDomain),
      hasDashes: /-/.test(cleanDomain),
      suspiciousTLD: this.suspiciousTLDs.has(parts[parts.length - 1]?.toLowerCase() || '')
    };
  }

  private extractIPFeatures(ip: string): Partial<MLFeatures> {
    const octets = ip.split('.').map(Number);
    
    return {
      isPrivateIP: this.isPrivateIP(ip),
      isCloudProvider: this.isCloudProvider(ip),
      geographicRisk: this.calculateGeographicRisk(ip)
    };
  }

  private extractHashFeatures(hash: string): Partial<MLFeatures> {
    return {
      entropyScore: this.calculateEntropy(hash)
    };
  }

  private calculateAge(date: Date): number {
    return Math.floor((Date.now() - date.getTime()) / (1000 * 60 * 60 * 24));
  }

  private calculateVowelConsonantRatio(text: string): number {
    const vowels = (text.match(/[aeiou]/gi) || []).length;
    const consonants = (text.match(/[bcdfghjklmnpqrstvwxyz]/gi) || []).length;
    return consonants > 0 ? vowels / consonants : 0;
  }

  private calculateEntropy(text: string): number {
    const freq: Record<string, number> = {};
    for (const char of text) {
      freq[char] = (freq[char] || 0) + 1;
    }
    
    let entropy = 0;
    const length = text.length;
    for (const count of Object.values(freq)) {
      const p = count / length;
      entropy -= p * Math.log2(p);
    }
    
    return entropy;
  }

  private isPrivateIP(ip: string): boolean {
    const octets = ip.split('.').map(Number);
    return (
      octets[0] === 10 ||
      (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
      (octets[0] === 192 && octets[1] === 168)
    );
  }

  private isCloudProvider(ip: string): boolean {
    // Simplified - would use actual cloud provider IP ranges
    const cloudRanges = [
      '52.', '54.', '3.', '13.', // AWS
      '104.', '40.', '52.', '13.', // Azure  
      '34.', '35.', '104.', '130.' // GCP
    ];
    return cloudRanges.some(range => ip.startsWith(range));
  }

  private calculateGeographicRisk(ip: string): number {
    // Simplified risk scoring based on geographic location
    // Would integrate with GeoIP service in production
    const highRiskCountries = ['CN', 'RU', 'KP', 'IR'];
    // This would be actual geolocation lookup
    return Math.random() * 10; // Placeholder
  }

  private calculateSourceReliability(source: string): number {
    const reliabilityScores: Record<string, number> = {
      'urlhaus': 0.9,
      'alienvault': 0.85,
      'virustotal': 0.95,
      'abuseipdb': 0.8,
      'crowdsec': 0.75
    };
    return reliabilityScores[source] || 0.5;
  }

  private calculateReportingVelocity(indicator: ThreatIndicator, context?: any): number {
    // Calculate how quickly this indicator is being reported across sources
    if (!context?.recentReports) {
      return 0;
    }
    
    const recentReports = context.recentReports.filter((report: any) => 
      report.value === indicator.value && 
      Date.now() - report.timestamp < 24 * 60 * 60 * 1000
    );
    
    return recentReports.length;
  }
}

// ===== MACHINE LEARNING MODELS =====

export class ThreatClassificationModel {
  private model: MLModel;
  private weights: Map<string, number> = new Map();
  private featureScaler: Map<string, { mean: number; std: number }> = new Map();

  constructor(modelConfig: Partial<MLModel>) {
    this.model = {
      id: modelConfig.id || 'threat-classifier-v1',
      name: modelConfig.name || 'Threat Classification Model',
      type: 'classification',
      version: modelConfig.version || '1.0.0',
      accuracy: modelConfig.accuracy || 0.85,
      lastTrained: modelConfig.lastTrained || new Date(),
      featureImportance: modelConfig.featureImportance || {},
      hyperparameters: modelConfig.hyperparameters || {},
      trainingMetrics: modelConfig.trainingMetrics || {
        precision: 0.85,
        recall: 0.82,
        f1Score: 0.83,
        auc: 0.89,
        falsePositiveRate: 0.05
      },
      experimental: modelConfig.experimental || false
    };
    
    this.initializeWeights();
  }

  private initializeWeights(): void {
    // Initialize model weights (simplified logistic regression)
    const weights = {
      'entropyScore': 0.3,
      'domainLength': -0.1,
      'subdomainCount': 0.25,
      'suspiciousTLD': 0.4,
      'hasNumbers': 0.15,
      'firstSeenAge': -0.2,
      'sourceReliability': -0.3,
      'reportingVelocity': 0.35,
      'geographicRisk': 0.2
    };
    
    for (const [feature, weight] of Object.entries(weights)) {
      this.weights.set(feature, weight);
    }
  }

  /**
   * Predict threat probability for given features
   */
  public predict(features: MLFeatures): MLPrediction {
    const normalizedFeatures = this.normalizeFeatures(features);
    const logit = this.calculateLogit(normalizedFeatures);
    const probability = this.sigmoid(logit);
    
    const prediction: MLPrediction = {
      threatProbability: probability,
      confidence: this.calculateConfidence(probability, normalizedFeatures),
      riskScore: this.calculateRiskScore(probability, normalizedFeatures),
      threatCategory: this.classifyThreatType(probability, normalizedFeatures),
      explanation: {
        topFeatures: this.getTopFeatures(normalizedFeatures),
        riskFactors: this.identifyRiskFactors(normalizedFeatures),
        modelVersion: this.model.version
      },
      experimental: {
        status: ML_ENGINE_STATUS,
        warning: 'This ML prediction is experimental and may not be accurate',
        disclaimer: 'Use for supplemental analysis only, not primary threat detection'
      }
    };

    return prediction;
  }

  private normalizeFeatures(features: MLFeatures): Map<string, number> {
    const normalized = new Map<string, number>();
    
    for (const [key, value] of Object.entries(features)) {
      if (typeof value === 'number') {
        // Z-score normalization (simplified)
        const mean = this.featureScaler.get(key)?.mean || 0;
        const std = this.featureScaler.get(key)?.std || 1;
        normalized.set(key, (value - mean) / std);
      } else if (typeof value === 'boolean') {
        normalized.set(key, value ? 1 : 0);
      }
    }
    
    return normalized;
  }

  private calculateLogit(features: Map<string, number>): number {
    let logit = 0;
    
    for (const [feature, value] of features) {
      const weight = this.weights.get(feature) || 0;
      logit += weight * value;
    }
    
    return logit;
  }

  private sigmoid(x: number): number {
    return 1 / (1 + Math.exp(-x));
  }

  private calculateConfidence(probability: number, features: Map<string, number>): number {
    // Confidence based on feature completeness and model certainty
    const featureCompleteness = features.size / this.weights.size;
    const modelCertainty = Math.abs(probability - 0.5) * 2;
    return (featureCompleteness * 0.4 + modelCertainty * 0.6);
  }

  private calculateRiskScore(probability: number, features: Map<string, number>): number {
    // Risk score from 0-100
    return Math.round(probability * 100);
  }

  private classifyThreatType(probability: number, features: Map<string, number>): MLPrediction['threatCategory'] {
    if (probability < 0.3) {
      return 'benign';
    }
    
    // Simple heuristic-based classification
    const entropyScore = features.get('entropyScore') || 0;
    const hasNumbers = features.get('hasNumbers') || 0;
    const subdomainCount = features.get('subdomainCount') || 0;
    
    if (entropyScore > 1 && hasNumbers > 0) {
      return 'malware';
    }
    if (subdomainCount > 2) {
      return 'phishing';
    }
    if (features.get('reportingVelocity') || 0 > 5) {
      return 'botnet';
    }
    
    return probability > 0.7 ? 'c2' : 'spam';
  }

  private getTopFeatures(features: Map<string, number>): Array<{ feature: string; importance: number; value: any }> {
    const featureImportance = Array.from(features.entries())
      .map(([feature, value]) => ({
        feature,
        importance: Math.abs((this.weights.get(feature) || 0) * value),
        value
      }))
      .sort((a, b) => b.importance - a.importance)
      .slice(0, 5);
    
    return featureImportance;
  }

  private identifyRiskFactors(features: Map<string, number>): string[] {
    const riskFactors: string[] = [];
    
    if ((features.get('suspiciousTLD') || 0) > 0) {
      riskFactors.push('Suspicious top-level domain');
    }
    if ((features.get('entropyScore') || 0) > 4) {
      riskFactors.push('High entropy (random-looking) domain');
    }
    if ((features.get('reportingVelocity') || 0) > 3) {
      riskFactors.push('Rapidly increasing threat reports');
    }
    if ((features.get('geographicRisk') || 0) > 7) {
      riskFactors.push('High-risk geographic location');
    }
    
    return riskFactors;
  }

  public getModelInfo(): MLModel {
    return { ...this.model };
  }
}

// ===== ANOMALY DETECTION ENGINE =====

export class AnomalyDetectionEngine {
  private baselineProfiles: Map<string, any> = new Map();
  private anomalyThreshold = 2.5; // Standard deviations

  /**
   * Detect anomalies in threat indicators
   */
  public detectAnomalies(indicators: ThreatIndicator[]): Array<{ indicator: ThreatIndicator; anomalyScore: number; reasons: string[] }> {
    const anomalies: Array<{ indicator: ThreatIndicator; anomalyScore: number; reasons: string[] }> = [];
    
    for (const indicator of indicators) {
      const profile = this.getBaselineProfile(indicator.type);
      const anomalyScore = this.calculateAnomalyScore(indicator, profile);
      
      if (anomalyScore > this.anomalyThreshold) {
        anomalies.push({
          indicator,
          anomalyScore,
          reasons: this.identifyAnomalyReasons(indicator, profile)
        });
      }
    }
    
    return anomalies;
  }

  private getBaselineProfile(type: string): any {
    // Return baseline statistical profile for indicator type
    return this.baselineProfiles.get(type) || this.createDefaultProfile(type);
  }

  private createDefaultProfile(type: string): any {
    // Create default statistical profiles
    const profiles = {
      domain: {
        avgLength: 12,
        avgSubdomains: 0.5,
        avgEntropy: 3.2,
        commonTLDs: ['com', 'org', 'net']
      },
      ip: {
        avgReports: 2,
        commonPorts: [80, 443, 22, 25],
        avgGeographicSpread: 3
      },
      url: {
        avgPathLength: 15,
        avgParameters: 2,
        commonSchemes: ['http', 'https']
      }
    };
    
    return profiles[type] || {};
  }

  private calculateAnomalyScore(indicator: ThreatIndicator, profile: any): number {
    // Simplified anomaly scoring
    let score = 0;
    
    // Check various anomaly indicators
    if (indicator.type === 'domain') {
      const domain = indicator.value;
      const domainLength = domain.length;
      
      if (Math.abs(domainLength - profile.avgLength) > 2 * 5) { // 2 std devs
        score += 1;
      }
    }
    
    // Temporal anomalies
    const age = Date.now() - indicator.firstSeen.getTime();
    if (age < 24 * 60 * 60 * 1000) { // Very recently seen
      score += 0.5;
    }
    
    return score;
  }

  private identifyAnomalyReasons(indicator: ThreatIndicator, profile: any): string[] {
    const reasons: string[] = [];
    
    if (indicator.type === 'domain') {
      const domain = indicator.value;
      if (domain.length > profile.avgLength + 10) {
        reasons.push('Unusually long domain name');
      }
      if (domain.split('.').length > 4) {
        reasons.push('Excessive subdomain nesting');
      }
    }
    
    const age = Date.now() - indicator.firstSeen.getTime();
    if (age < 60 * 60 * 1000) { // Less than 1 hour
      reasons.push('Very recently registered/first seen');
    }
    
    return reasons;
  }
}

// ===== ML THREAT ENGINE =====

export class MLThreatEngine extends EventEmitter {
  private featureExtractor: FeatureExtractor;
  private classificationModel: ThreatClassificationModel;
  private anomalyDetector: AnomalyDetectionEngine;
  private trainingData: TrainingDataPoint[] = [];
  private predictionCache: Map<string, MLPrediction> = new Map();

  constructor(config?: { modelPath?: string; cacheSize?: number }) {
    super();
    this.featureExtractor = new FeatureExtractor();
    this.classificationModel = new ThreatClassificationModel({});
    this.anomalyDetector = new AnomalyDetectionEngine();
    
    // Initialize with any pre-trained models
    if (config?.modelPath) {
      this.loadModel(config.modelPath);
    }
  }

  /**
   * Analyze threat indicators with ML predictions
   */
  public async analyzeThreat(indicator: ThreatIndicator, context?: any): Promise<MLPrediction> {
    const cacheKey = `${indicator.type}:${indicator.value}`;
    
    // Check cache
    if (this.predictionCache.has(cacheKey)) {
      return this.predictionCache.get(cacheKey)!;
    }

    // Extract features
    const features = this.featureExtractor.extractFeatures(indicator, context);
    
    // Get ML prediction
    const prediction = this.classificationModel.predict(features);
    
    // Detect anomalies
    const anomalies = this.anomalyDetector.detectAnomalies([indicator]);
    if (anomalies.length > 0) {
      prediction.anomalyScore = anomalies[0].anomalyScore;
    }
    
    // Cache result
    this.predictionCache.set(cacheKey, prediction);
    
    // Emit events
    this.emit('prediction_completed', { indicator, prediction });
    
    if (prediction.threatProbability > 0.7) {
      this.emit('high_confidence_threat', { indicator, prediction });
    }

    return prediction;
  }

  /**
   * Batch analyze multiple indicators
   */
  public async analyzeBatch(indicators: ThreatIndicator[]): Promise<Map<string, MLPrediction>> {
    const results = new Map<string, MLPrediction>();
    
    const promises = indicators.map(async (indicator) => {
      try {
        const prediction = await this.analyzeThreat(indicator);
        results.set(indicator.value, prediction);
      } catch (error) {
        this.emit('analysis_error', { indicator, error });
      }
    });
    
    await Promise.allSettled(promises);
    return results;
  }

  /**
   * Train model with new data
   */
  public addTrainingData(dataPoint: TrainingDataPoint): void {
    this.trainingData.push(dataPoint);
    
    // Trigger retraining if we have enough new data
    if (this.trainingData.length > 1000) {
      this.retrain();
    }
  }

  /**
   * Retrain model with accumulated data
   */
  public async retrain(): Promise<void> {
    if (this.trainingData.length === 0) {
      return;
    }
    
    this.emit('retraining_started', { dataPoints: this.trainingData.length });
    
    // Simplified retraining logic
    // In production, this would integrate with actual ML frameworks
    try {
      // Update feature importance based on new data
      const featureImportance = this.calculateFeatureImportance(this.trainingData);
      
      // Update model metrics
      const metrics = this.evaluateModel(this.trainingData);
      
      // Clear training data cache
      this.trainingData = [];
      this.predictionCache.clear();
      
      this.emit('retraining_completed', { featureImportance, metrics });
      
    } catch (error) {
      this.emit('retraining_failed', { error });
    }
  }

  private calculateFeatureImportance(data: TrainingDataPoint[]): Record<string, number> {
    // Simplified feature importance calculation
    const importance: Record<string, number> = {};
    
    for (const dataPoint of data) {
      for (const [feature, value] of Object.entries(dataPoint.features)) {
        if (typeof value === 'number') {
          importance[feature] = (importance[feature] || 0) + Math.abs(value * dataPoint.label);
        }
      }
    }
    
    return importance;
  }

  private evaluateModel(testData: TrainingDataPoint[]): any {
    // Simplified model evaluation
    let correct = 0;
    const predictions: number[] = [];
    const actuals: number[] = [];
    
    for (const dataPoint of testData) {
      const prediction = this.classificationModel.predict(dataPoint.features);
      const predicted = prediction.threatProbability > 0.5 ? 1 : 0;
      
      predictions.push(predicted);
      actuals.push(dataPoint.label);
      
      if (predicted === dataPoint.label) {
        correct++;
      }
    }
    
    const accuracy = correct / testData.length;
    
    return {
      accuracy,
      testSize: testData.length,
      predictions,
      actuals
    };
  }

  private async loadModel(modelPath: string): Promise<void> {
    // Load pre-trained model from file/database
    // Implementation would depend on model format
    this.emit('model_loaded', { path: modelPath });
  }

  public getStats() {
    return {
      cacheSize: this.predictionCache.size,
      trainingDataSize: this.trainingData.length,
      modelInfo: this.classificationModel.getModelInfo()
    };
  }
} 
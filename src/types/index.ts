/**
 * TrojanHorse.js Type Definitions
 * Security-focused threat intelligence library types
 */

// ===== CORE SECURITY TYPES =====
export interface SecureVaultOptions {
  algorithm?: 'AES-256-GCM' | 'AES-GCM' | 'AES-CBC';
  keyDerivation?: 'Argon2id' | 'PBKDF2';
  iterations?: number;
  saltBytes?: number;
  autoLock?: boolean;
  lockTimeout?: number;
  requireMFA?: boolean;
}

export interface EncryptedVault {
  encrypted: string;
  salt: string;
  iv: string;
  algorithm: string;
  iterations: number;
  timestamp: number;
}

export interface ApiKeyConfig {
  [provider: string]: string | ApiKeyObject | undefined;
  alienVault?: string | ApiKeyObject;
  crowdsec?: string | ApiKeyObject;
  abuseipdb?: string | ApiKeyObject;
  urlhaus?: string | ApiKeyObject;
  virustotal?: string | ApiKeyObject;
}

export interface ApiKeyObject {
  key?: string;
  secret?: string;
  token?: string;
  endpoint?: string;
  timeout?: number;
}

// ===== THREAT INTELLIGENCE TYPES =====
export interface ThreatIndicator {
  type: 'ip' | 'domain' | 'url' | 'hash' | 'email' | 'file_path';
  value: string;
  confidence: number;
  firstSeen: Date;
  lastSeen: Date;
  source: string;
  tags: string[];
  malwareFamily?: string | undefined;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description?: string;
  metadata?: Record<string, any>;
}

export interface ThreatFeedResult {
  source: string;
  timestamp: Date;
  indicators: ThreatIndicator[];
  sources?: string[]; // Sources that contributed to this result
  correlationScore?: number; // Correlation confidence score (0-1)
  consensusLevel?: 'weak' | 'moderate' | 'strong' | 'consensus'; // Consensus level
  metadata: {
    totalCount?: number;
    totalPulses?: number;
    totalIndicators?: number;
    hasMore?: boolean;
    nextPage?: string | null;
    rateLimit?: {
      remaining: number;
      resetTime: Date;
      limit: number;
    };
    requestsProcessed?: number;
    confidenceThreshold?: number;
    errors?: string[];
    processingStats?: ProcessingStats;
    streamingConfig?: StreamProcessingOptions;
    correlationScore?: number; // Also allow in metadata for backward compatibility
    consensusLevel?: 'weak' | 'moderate' | 'strong' | 'consensus';
    sources?: string[];
  };
}

export interface FeedConfiguration {
  name: string;
  type?: 'api' | 'csv' | 'json' | 'rss';
  endpoint: string;
  authentication?: {
    type: 'none' | 'api_key' | 'oauth' | 'basic';
    required: boolean;
    header?: string;
    credentials?: Record<string, string>;
  };
  rateLimit?: {
    requestsPerHour: number;
    burstLimit: number;
    retryAfter?: number;
    limit?: number; // Add limit property for compatibility
  };
  enabled?: boolean;
  priority?: 'low' | 'medium' | 'high' | 'critical';
  sslPinning?: boolean;
  apiKey?: string;
  timeout?: number;
  retries?: number;
  cacheTTL?: number; // Add cacheTTL property
}

// ===== CONFIGURATION TYPES =====
export interface TrojanHorseConfig {
  apiKeys?: ApiKeyConfig;
  vault?: SecureVaultOptions;
  security?: SecurityConfig;
  sources?: string[];
  strategy?: 'defensive' | 'offensive' | 'balanced' | 'fort-knox';
  audit?: AuditConfig;
}

export interface SecurityConfig {
  mode?: 'standard' | 'enhanced' | 'fort-knox';
  httpsOnly?: boolean;
  certificatePinning?: boolean;
  minTlsVersion?: '1.2' | '1.3';
  validateCertificates?: boolean;
  secureMemory?: boolean;
  autoLock?: boolean;
  lockTimeout?: number;
  requestTimeout?: number;
  maxConcurrentRequests?: number;
}

export interface AuditConfig {
  enabled: boolean;
  logLevel: 'error' | 'warn' | 'info' | 'debug';
  destinations: ('console' | 'file' | 'remote')[];
  retention: string;
  piiMasking: boolean;
  encryptLogs: boolean;
}

// ===== STORAGE TYPES =====
export interface StorageAdapter {
  get<T>(key: string): Promise<T | null>;
  set<T>(key: string, value: T, ttl?: number): Promise<void>;
  delete(key: string): Promise<void>;
  clear(): Promise<void>;
  encrypt(data: any): Promise<string>;
  decrypt(data: string): Promise<any>;
}

export interface CacheEntry<T> {
  data: T;
  timestamp: number;
  ttl?: number;
  expiresAt?: number;
  encrypted?: boolean;
  source?: string;
  hash?: string;
}

// ===== RATE LIMITING TYPES =====
export interface RateLimitConfig {
  maxRequests: number;
  windowMs: number;
  strategy: 'token-bucket' | 'sliding-window' | 'fixed-window';
  backoffMultiplier?: number;
  maxBackoffMs?: number;
}

export interface RateLimitState {
  tokens: number;
  lastRefill: number;
  requestHistory: number[];
}

// ===== ERROR TYPES =====
export class TrojanHorseError extends Error {
  public readonly code: string;
  public readonly statusCode?: number;
  public readonly details?: Record<string, any>;

  constructor(message: string, code: string, statusCode?: number, details?: Record<string, any>) {
    super(message);
    this.name = 'TrojanHorseError';
    this.code = code;
    this.statusCode = statusCode || 500;
    this.details = details || {};
    Error.captureStackTrace(this, TrojanHorseError);
  }
}

export class SecurityError extends TrojanHorseError {
  constructor(message: string, details?: Record<string, any>) {
    super(message, 'SECURITY_ERROR', 403, details);
    this.name = 'SecurityError';
  }
}

export class AuthenticationError extends TrojanHorseError {
  constructor(message: string, details?: Record<string, any>) {
    super(message, 'AUTH_ERROR', 401, details);
    this.name = 'AuthenticationError';
  }
}

export class RateLimitError extends TrojanHorseError {
  public readonly retryAfter?: number;

  constructor(message: string, retryAfter?: number, details?: Record<string, any>) {
    super(message, 'RATE_LIMIT_ERROR', 429, details);
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter || 60;
  }
}

// ===== EVENT TYPES =====
export interface TrojanHorseEvents {
  'vault:locked': () => void;
  'vault:unlocked': () => void;
  'security:alert': (alert: SecurityAlert) => void;
  'threat:detected': (threat: ThreatIndicator) => void;
  'feed:updated': (feedName: string, count: number) => void;
  'error': (error: TrojanHorseError) => void;
  'rate-limit': (provider: string, retryAfter: number) => void;
}

export interface SecurityAlert {
  level: 'info' | 'warning' | 'critical';
  type: string;
  message: string;
  timestamp: Date;
  source: string;
  details?: Record<string, any>;
}

// ===== UTILITY TYPES =====
export type DeepReadonly<T> = {
  readonly [P in keyof T]: T[P] extends object ? DeepReadonly<T[P]> : T[P];
};

export type RequireAtLeastOne<T> = {
  [K in keyof T]-?: Required<Pick<T, K>> & Partial<Pick<T, Exclude<keyof T, K>>>;
}[keyof T];

export type SecureString = string & { readonly __brand: unique symbol };

// ===== FEED-SPECIFIC TYPES =====
export interface URLhausEntry {
  id: string;
  dateAdded: Date;
  url: string;
  urlStatus: 'online' | 'offline';
  threat: string;
  tags: string[];
  payloadType?: string;
  reporter: string;
}

export interface AlienVaultPulse {
  id: string;
  name: string;
  description: string;
  authorName: string;
  created: Date;
  modified: Date;
  indicators: Array<{
    type: string;
    indicator: string;
    description?: string;
  }>;
}

export interface CrowdSecDecision {
  duration: string;
  scope: string;
  value: string;
  type: string;
  scenario: string;
  origin: string;
}

// ===== STREAMING PROCESSOR TYPES =====
export interface ProcessingStats {
  startTime: Date;
  endTime?: Date;
  itemsProcessed: number;
  errorsEncountered: number;
  totalSize: number;
  avgProcessingTimeMs: number;
  memoryUsageMB: number;
}

export interface StreamProcessingOptions {
  chunkSize: number;
  maxConcurrency: number;
  bufferSize: number;
  processorType?: string;
}

export interface StreamProcessingResult {
  source: string;
  timestamp: Date;
  indicators: ThreatIndicator[];
  metadata: {
    totalCount: number;
    processingStats: ProcessingStats;
    streamingConfig?: StreamProcessingOptions;
  };
}

// ===== EXPORT COLLECTIONS =====
export * from './feeds';
export * from './security';
export * from './storage'; 
/**
 * Security-specific type definitions for TrojanHorse.js
 */

export interface SecurityPolicy {
  version: string;
  rules: SecurityRule[];
  lastUpdated: Date;
}

export interface SecurityRule {
  id: string;
  name: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  action: 'allow' | 'block' | 'warn' | 'audit';
  conditions: SecurityCondition[];
}

export interface SecurityCondition {
  field: string;
  operator: 'equals' | 'contains' | 'regex' | 'range';
  value: any;
  caseSensitive?: boolean;
}

export interface AccessLog {
  timestamp: Date;
  userId?: string;
  action: string;
  resource: string;
  outcome: 'success' | 'failure';
  details?: Record<string, any>;
}

export interface EncryptionMetadata {
  algorithm: string;
  keySize: number;
  mode: string;
  iv: string;
  salt: string;
  iterations: number;
} 
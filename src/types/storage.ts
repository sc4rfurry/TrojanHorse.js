/**
 * Storage-specific type definitions for TrojanHorse.js
 */

export interface StorageEngine {
  name: string;
  version: string;
  encrypted: boolean;
  persistent: boolean;
}

export interface StorageQuota {
  used: number;
  available: number;
  total: number;
  percentage: number;
}

export interface StorageTransaction {
  id: string;
  operations: StorageOperation[];
  timestamp: Date;
  status: 'pending' | 'committed' | 'rollback';
}

export interface StorageOperation {
  type: 'create' | 'read' | 'update' | 'delete';
  key: string;
  value?: any;
  previousValue?: any;
}

export interface CachePolicy {
  maxAge: number;
  maxSize: number;
  evictionStrategy: 'lru' | 'fifo' | 'random';
  compressData: boolean;
} 
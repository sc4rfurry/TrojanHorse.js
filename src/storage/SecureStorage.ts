/**
 * Secure Storage Layer for TrojanHorse.js
 * 
 * Provides encrypted storage using IndexedDB via Dexie
 * - Secure storage for threat indicators and API keys
 * - Automatic encryption at rest using CryptoJS
 * - TTL (Time To Live) support for temporary data
 * - Compression for large datasets
 * - Transaction support for atomic operations
 */

import Dexie, { Table } from 'dexie';
import CryptoJS from 'crypto-js';
import { CacheEntry, StorageQuota, EncryptedVault, ThreatIndicator, TrojanHorseError } from '../types';

export interface StorageEntry {
  id?: number;
  key: string;
  encryptedData: string;
  iv: string;
  timestamp: number;
  expiresAt?: number;
  tags?: string[];
  size: number;
}

export interface StorageConfig {
  dbName: string;
  encryptionKey: string;
  maxSizeBytes?: number;
  defaultTTL?: number; // Time to live in milliseconds
  compressionEnabled?: boolean;
}

export class SecureStorage extends Dexie {
  private storage!: Table<StorageEntry>;
  private config: StorageConfig;
  private isInitialized = false;

  constructor(config: StorageConfig) {
    super(config.dbName);
    
    this.config = {
      maxSizeBytes: 50 * 1024 * 1024, // 50MB default
      defaultTTL: 24 * 60 * 60 * 1000, // 24 hours default
      compressionEnabled: true,
      ...config
    };

    this.version(1).stores({
      storage: '++id, key, timestamp, expiresAt, *tags'
    });

    this.storage = this.table('storage');
  }

  /**
   * Initialize the storage database and perform cleanup
   */
  public async initialize(): Promise<void> {
    try {
      await this.open();
      await this.cleanup();
      this.isInitialized = true;
    } catch (error) {
      throw new TrojanHorseError(
        `Failed to initialize secure storage: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'STORAGE_INIT_FAILED'
      );
    }
  }

  /**
   * Store encrypted data with optional TTL
   */
  public async store(
    key: string, 
    data: any, 
    options: {
      ttl?: number;
      tags?: string[];
      compress?: boolean;
    } = {}
  ): Promise<void> {
    this.ensureInitialized();

    try {
      // Serialize the data
      let serializedData = JSON.stringify(data);

      // Optionally compress the data
      if (options.compress ?? this.config.compressionEnabled) {
        serializedData = this.compress(serializedData);
      }

      // Generate a random IV for this encryption
      const iv = CryptoJS.lib.WordArray.random(16).toString();

      // Encrypt the data
      const encrypted = CryptoJS.AES.encrypt(serializedData, this.config.encryptionKey, {
        iv: CryptoJS.enc.Utf8.parse(iv),
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      }).toString();

      // Calculate expiration time
      const ttl = options.ttl ?? this.config.defaultTTL;
      const expiresAt = ttl ? Date.now() + ttl : undefined;

      // Check storage quota
      await this.checkStorageQuota(encrypted.length);

      // Store in IndexedDB
      const entry = {
        key,
        encryptedData: encrypted,
        iv,
        timestamp: Date.now(),
        tags: options.tags || [],
        size: encrypted.length,
        ...(expiresAt && { expiresAt })
      };
      await this.storage.put(entry);

    } catch (error) {
      throw new TrojanHorseError(
        `Failed to store data: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'STORAGE_WRITE_FAILED',
        500,
        { key }
      );
    }
  }

  /**
   * Retrieve and decrypt data by key
   */
  public async retrieve<T = any>(key: string): Promise<T | null> {
    this.ensureInitialized();

    try {
      const entry = await this.storage.where('key').equals(key).first();
      
      if (!entry) {
        return null;
      }

      // Check if data has expired
      if (entry.expiresAt && Date.now() > entry.expiresAt) {
        await this.deleteData(key);
        return null;
      }

      // Decrypt the data
      const decrypted = CryptoJS.AES.decrypt(entry.encryptedData, this.config.encryptionKey, {
        iv: CryptoJS.enc.Utf8.parse(entry.iv),
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      }).toString(CryptoJS.enc.Utf8);

      // Decompress if needed
      let decompressedData = decrypted;
      if (this.config.compressionEnabled && this.isCompressed(decrypted)) {
        decompressedData = this.decompress(decrypted);
      }

      return JSON.parse(decompressedData);

    } catch (error) {
      throw new TrojanHorseError(
        `Failed to retrieve data: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'STORAGE_READ_FAILED',
        500,
        { key }
      );
    }
  }

  /**
   * Delete data by key
   */
  public async deleteData(key: string): Promise<boolean> {
    this.ensureInitialized();

    try {
      const deleteCount = await this.storage.where('key').equals(key).delete();
      return deleteCount > 0;
    } catch (error) {
      throw new TrojanHorseError(
        `Failed to delete data: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'STORAGE_DELETE_FAILED',
        500,
        { key }
      );
    }
  }

  /**
   * Store threat indicators with caching metadata
   */
  public async storeThreatIndicators(
    indicators: ThreatIndicator[], 
    source: string,
    ttl?: number
  ): Promise<void> {
    const cacheEntry = {
      data: indicators,
      timestamp: Date.now(),
      source,
      hash: this.calculateHash(indicators),
      ...(ttl && { expiresAt: Date.now() + ttl })
    } as CacheEntry<ThreatIndicator[]>;

    const storeOptions = {
      tags: ['threats', source],
      compress: true,
      ...(ttl && { ttl })
    };
    await this.store(`threats:${source}`, cacheEntry, storeOptions);
  }

  /**
   * Retrieve cached threat indicators
   */
  public async getThreatIndicators(source: string): Promise<ThreatIndicator[] | null> {
    const cacheEntry = await this.retrieve<CacheEntry<ThreatIndicator[]>>(`threats:${source}`);
    
    if (!cacheEntry || (cacheEntry.expiresAt && Date.now() > cacheEntry.expiresAt)) {
      return null;
    }

    return cacheEntry.data;
  }

  /**
   * Store encrypted vault
   */
  public async storeVault(vault: EncryptedVault, key: string = 'default'): Promise<void> {
    await this.store(`vault:${key}`, vault, {
      tags: ['vault', 'sensitive'],
      compress: false // Already encrypted
    });
  }

  /**
   * Retrieve encrypted vault
   */
  public async getVault(key: string = 'default'): Promise<EncryptedVault | null> {
    return await this.retrieve<EncryptedVault>(`vault:${key}`);
  }

  /**
   * Search for entries by tags
   */
  public async findByTags(tags: string[]): Promise<StorageEntry[]> {
    this.ensureInitialized();

    try {
      return await this.storage
        .where('tags')
        .anyOf(tags)
        .and(entry => !entry.expiresAt || Date.now() <= entry.expiresAt)
        .toArray();
    } catch (error) {
      throw new TrojanHorseError(
        `Failed to search by tags: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'STORAGE_SEARCH_FAILED'
      );
    }
  }

  /**
   * Get storage statistics
   */
  public async getStorageStats(): Promise<StorageQuota & {
    totalEntries: number;
    expiredEntries: number;
    tagStats: Record<string, number>;
  }> {
    this.ensureInitialized();

    try {
      const allEntries = await this.storage.toArray();
      const now = Date.now();
      
      let totalSize = 0;
      let expiredEntries = 0;
      const tagStats: Record<string, number> = {};

      for (const entry of allEntries) {
        totalSize += entry.size;
        
        if (entry.expiresAt && now > entry.expiresAt) {
          expiredEntries++;
        }

        if (entry.tags) {
          for (const tag of entry.tags) {
            tagStats[tag] = (tagStats[tag] || 0) + 1;
          }
        }
      }

      const total = this.config.maxSizeBytes || totalSize;
      const available = Math.max(0, total - totalSize);
      
      return {
        used: totalSize,
        available,
        total,
        percentage: total > 0 ? (totalSize / total) * 100 : 0,
        totalEntries: allEntries.length,
        expiredEntries,
        tagStats
      };

    } catch (error) {
      throw new TrojanHorseError(
        `Failed to get storage stats: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'STORAGE_STATS_FAILED'
      );
    }
  }

  /**
   * Clean up expired entries and optimize storage
   */
  public async cleanup(): Promise<{ deletedEntries: number; freedBytes: number }> {
    this.ensureInitialized();

    try {
      const now = Date.now();
      const expiredEntries = await this.storage
        .where('expiresAt')
        .below(now)
        .toArray();

      const freedBytes = expiredEntries.reduce((total, entry) => total + entry.size, 0);
      
      await this.storage
        .where('expiresAt')
        .below(now)
        .delete();

      return {
        deletedEntries: expiredEntries.length,
        freedBytes
      };

    } catch (error) {
      throw new TrojanHorseError(
        `Failed to cleanup storage: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'STORAGE_CLEANUP_FAILED'
      );
    }
  }

  /**
   * Clear all data (use with caution!)
   */
  public async clear(): Promise<void> {
    this.ensureInitialized();

    try {
      await this.storage.clear();
    } catch (error) {
      throw new TrojanHorseError(
        `Failed to clear storage: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'STORAGE_CLEAR_FAILED'
      );
    }
  }

  /**
   * Create a secure backup of all data
   */
  public async createBackup(): Promise<string> {
    this.ensureInitialized();

    try {
      const allData = await this.storage.toArray();
      const backup = {
        version: '1.0.1',
        timestamp: Date.now(),
        entries: allData
      };

      // Encrypt the backup itself
      const backupString = JSON.stringify(backup);
      const iv = CryptoJS.lib.WordArray.random(16).toString();
      
      const encrypted = CryptoJS.AES.encrypt(backupString, this.config.encryptionKey, {
        iv: CryptoJS.enc.Utf8.parse(iv),
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      }).toString();

      return `${iv}:${encrypted}`;

    } catch (error) {
      throw new TrojanHorseError(
        `Failed to create backup: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'STORAGE_BACKUP_FAILED'
      );
    }
  }

  /**
   * Restore from a secure backup
   */
  public async restoreBackup(encryptedBackup: string): Promise<void> {
    this.ensureInitialized();

    try {
      const [iv, encrypted] = encryptedBackup.split(':');
      
      if (!encrypted || !iv) {
        throw new TrojanHorseError('Invalid encrypted backup format', 'DECRYPTION_ERROR');
      }
      
      const decrypted = CryptoJS.AES.decrypt(encrypted, this.config.encryptionKey, {
        iv: CryptoJS.enc.Utf8.parse(iv),
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      }).toString(CryptoJS.enc.Utf8);

      const backup = JSON.parse(decrypted);
      
      // Validate backup format
      if (!backup.version || !backup.entries) {
        throw new Error('Invalid backup format');
      }

      // Clear existing data and restore
      await this.clear();
      await this.storage.bulkAdd(backup.entries);

    } catch (error) {
      throw new TrojanHorseError(
        `Failed to restore backup: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'STORAGE_RESTORE_FAILED'
      );
    }
  }

  /**
   * Private helper methods
   */

  private ensureInitialized(): void {
    if (!this.isInitialized) {
      throw new TrojanHorseError(
        'Storage not initialized. Call initialize() first.',
        'STORAGE_NOT_INITIALIZED'
      );
    }
  }

  private async checkStorageQuota(dataSize: number): Promise<void> {
    if (!this.config.maxSizeBytes) {
      return;
    }

    const stats = await this.getStorageStats();
    
    if (stats.used + dataSize > this.config.maxSizeBytes) {
      // Try to free up space by cleaning expired entries
      await this.cleanup();
      
      const newStats = await this.getStorageStats();
      if (newStats.used + dataSize > this.config.maxSizeBytes) {
        throw new TrojanHorseError(
          'Storage quota exceeded',
          'STORAGE_QUOTA_EXCEEDED',
          507,
          { 
            required: dataSize,
            available: newStats.available,
            used: newStats.used,
            total: newStats.total
          }
        );
      }
    }
  }

  private compress(data: string): string {
    // Simple compression - in production, consider using a proper compression library
    return `COMPRESSED:${data}`;
  }

  private decompress(data: string): string {
    if (data.startsWith('COMPRESSED:')) {
      return data.substring(11);
    }
    return data;
  }

  private isCompressed(data: string): boolean {
    return data.startsWith('COMPRESSED:');
  }

  private calculateHash(data: any): string {
    const dataString = JSON.stringify(data);
    return CryptoJS.SHA256(dataString).toString();
  }
} 
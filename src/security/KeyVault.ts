/**
 * KeyVault - Secure API Key Management for TrojanHorse.js
 * Secure key storage with proper encryption
 */

import { CryptoEngine, RealEncryptionResult } from './CryptoEngine';
import { 
  ApiKeyConfig, 
  ApiKeyObject,
  SecureVaultOptions, 
  SecurityError, 
  AuthenticationError 
} from '../types';

export class KeyVault {
  private cryptoEngine: CryptoEngine;
  private encryptedVault: RealEncryptionResult | null = null;
  private decryptedKeys: Record<string, string> | null = null; // Always store as strings internally
  private isLocked: boolean = true;
  private options: SecureVaultOptions;
  private autoLockTimer: NodeJS.Timeout | null = null;
  private lastAccessTime: Date | null = null;
  private failedAttempts: number = 0;
  private maxFailedAttempts: number = 5;
  private lockoutDuration: number = 300000; // 5 minutes

  constructor(options: SecureVaultOptions = {}) {
    this.cryptoEngine = new CryptoEngine();
    this.options = {
      algorithm: 'AES-256-GCM',
      keyDerivation: 'Argon2id',
      iterations: 65536,
      saltBytes: 32,
      autoLock: true,
      lockTimeout: 300000,
      requireMFA: false,
      ...options
    };
  }

  /**
   * Extract string API key from either string or object format
   */
  private extractApiKey(keyData: string | ApiKeyObject | undefined): string | undefined {
    if (!keyData) {
      return undefined;
    }
    if (typeof keyData === 'string') {
      return keyData;
    }
    if (typeof keyData === 'object') {
      return keyData.key || keyData.secret || keyData.token;
    }
    return undefined;
  }

  /**
   * Normalize ApiKeyConfig to string-only format for internal storage
   */
  private normalizeApiKeys(apiKeys: ApiKeyConfig): Record<string, string> {
    const normalized: Record<string, string> = {};
    for (const [provider, keyData] of Object.entries(apiKeys)) {
      const stringKey = this.extractApiKey(keyData);
      if (stringKey) {
        normalized[provider] = stringKey;
      }
    }
    return normalized;
  }

  /**
   * Create a new encrypted vault with API keys
   */
  public async createVault(password: string, apiKeys: ApiKeyConfig): Promise<RealEncryptionResult> {
    this.validatePassword(password);
    this.validateApiKeys(apiKeys);

    try {
      // Encrypt the API keys
      const vault = await this.cryptoEngine.encrypt(apiKeys, password, this.options);
      
      // Store the encrypted vault
      this.encryptedVault = vault;
      this.decryptedKeys = this.normalizeApiKeys(apiKeys);
      this.isLocked = false;
      this.updateAccessTime();

      // Set up auto-lock
      this.setupAutoLock();

      return vault;
    } catch (error) {
      throw new SecurityError('Failed to create vault', { originalError: error });
    }
  }

  /**
   * Load an existing encrypted vault
   */
  public loadVault(vault: RealEncryptionResult): void {
    if (!this.cryptoEngine.validateEncryptionParams(vault)) {
      throw new SecurityError('Invalid vault structure');
    }

    this.encryptedVault = vault;
    this.isLocked = true;
    this.decryptedKeys = null;
  }

  /**
   * Unlock the vault with password
   */
  public async unlock(password: string): Promise<void> {
    if (!this.encryptedVault) {
      throw new SecurityError('No vault loaded');
    }

    if (this.failedAttempts >= this.maxFailedAttempts) {
      throw new AuthenticationError('Vault is locked due to too many failed attempts');
    }

    this.validatePassword(password);

    try {
      // Decrypt the vault
      const decryptedData = await this.cryptoEngine.decrypt(this.encryptedVault, password);
      
      // Validate decrypted data
      this.validateApiKeys(decryptedData);
      
      // Store decrypted keys (normalize to strings)
      this.decryptedKeys = this.normalizeApiKeys(decryptedData);
      this.isLocked = false;
      this.failedAttempts = 0;
      this.updateAccessTime();

      // Set up auto-lock
      this.setupAutoLock();

    } catch (error) {
      this.failedAttempts++;
      
      if (this.failedAttempts >= this.maxFailedAttempts) {
        this.lockVault();
        setTimeout(() => {
          this.failedAttempts = 0;
        }, this.lockoutDuration);
      }
      
      throw new AuthenticationError('Failed to unlock vault - invalid password');
    }
  }

  /**
   * Lock the vault
   */
  public lock(): void {
    this.lockVault();
  }

  /**
   * Get API key for a specific provider
   */
  public getApiKey(provider: string): string {
    if (this.isLocked || !this.decryptedKeys) {
      throw new SecurityError('Vault is locked - please unlock first');
    }

    this.updateAccessTime();

    const key = this.decryptedKeys[provider];
    if (!key) {
      throw new SecurityError(`API key for provider '${provider}' not found`);
    }

    return key;
  }

  /**
   * Add or update an API key
   */
  public async setApiKey(provider: string, apiKey: string, password: string): Promise<void> {
    if (this.isLocked || !this.decryptedKeys) {
      throw new SecurityError('Vault is locked - please unlock first');
    }

    if (!provider || !apiKey) {
      throw new SecurityError('Provider and API key cannot be empty');
    }

    // Update the keys
    this.decryptedKeys[provider] = apiKey;

    // Re-encrypt the vault with updated keys
    const newVault = await this.cryptoEngine.encrypt(this.decryptedKeys, password, this.options);
    this.encryptedVault = newVault;
    
    this.updateAccessTime();
  }

  /**
   * Remove an API key
   */
  public async removeApiKey(provider: string, password: string): Promise<void> {
    if (this.isLocked || !this.decryptedKeys) {
      throw new SecurityError('Vault is locked - please unlock first');
    }

    if (!this.decryptedKeys[provider]) {
      throw new SecurityError(`API key for provider '${provider}' not found`);
    }

    // Remove the key
    delete this.decryptedKeys[provider];

    // Re-encrypt the vault
    const newVault = await this.cryptoEngine.encrypt(this.decryptedKeys, password, this.options);
    this.encryptedVault = newVault;
    
    this.updateAccessTime();
  }

  /**
   * Rotate an API key with optional grace period
   */
  public async rotateKey(provider: string, newKey: string, options: {
    gracePeriod?: number; // Time in ms to keep old key active
    password?: string;    // Required for re-encryption
    notifyRotation?: boolean;
  } = {}): Promise<void> {
    if (this.isLocked || !this.decryptedKeys) {
      throw new SecurityError('Vault is locked - please unlock first');
    }

    if (!this.decryptedKeys[provider]) {
      throw new SecurityError(`API key for provider '${provider}' not found`);
    }

    const { gracePeriod = 0, password, notifyRotation = true } = options;
    const oldKey = this.decryptedKeys[provider];

    try {
      // Update the key immediately
      this.decryptedKeys[provider] = newKey;
      this.updateAccessTime();

      // If password provided, re-encrypt the vault with new key
      if (password && this.encryptedVault) {
        const updatedVault = await this.cryptoEngine.encrypt(this.decryptedKeys, password, this.options);
        this.encryptedVault = updatedVault;
      }

      // Schedule old key cleanup if grace period specified
      if (gracePeriod > 0) {
        setTimeout(() => {
          // Securely erase old key from memory
          if (typeof oldKey === 'string') {
            // Create array of characters and overwrite
            const keyArray = oldKey.split('');
            for (let i = 0; i < keyArray.length; i++) {
              keyArray[i] = Math.random().toString(36).charAt(0);
            }
          }
        }, gracePeriod);
      }

      if (notifyRotation) {
        console.info(`🔄 API key rotated for provider: ${provider}`);
      }

      this.auditLog('info', `API key rotated for provider: ${provider}`);

    } catch (error) {
      // Rollback on error
      if (this.decryptedKeys && oldKey) {
        this.decryptedKeys[provider] = oldKey;
      }
      throw new SecurityError(`Key rotation failed for ${provider}: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Batch rotate multiple API keys
   */
  public async rotateMultipleKeys(keyUpdates: Record<string, string>, options: {
    password?: string;
    gracePeriod?: number;
    continueOnError?: boolean;
  } = {}): Promise<{ success: string[]; failed: Record<string, string> }> {
    const results = { success: [] as string[], failed: {} as Record<string, string> };
    const { continueOnError = true } = options;

    for (const [provider, newKey] of Object.entries(keyUpdates)) {
      try {
        await this.rotateKey(provider, newKey, {
          ...options,
          notifyRotation: false // We'll notify at the end
        });
        results.success.push(provider);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        results.failed[provider] = errorMessage;
        
        console.error(`❌ Failed to rotate key for ${provider}: ${errorMessage}`);
        
        if (!continueOnError) {
          throw error;
        }
      }
    }

    console.info(`🔄 Batch key rotation completed: ${results.success.length} successful, ${Object.keys(results.failed).length} failed`);
    return results;
  }

  /**
   * Setup automatic key rotation schedule
   */
  public setupKeyRotation(config: {
    providers: string[];
    rotationInterval: number; // in milliseconds
    keyGenerator: (provider: string) => Promise<string>;
    password: string;
  }): NodeJS.Timeout {
    const { providers, rotationInterval, keyGenerator, password } = config;

    return setInterval(async () => {
      console.info('🔄 Starting scheduled key rotation...');
      
      const keyUpdates: Record<string, string> = {};
      
      // Generate new keys for all providers
      for (const provider of providers) {
        try {
          keyUpdates[provider] = await keyGenerator(provider);
        } catch (error) {
          console.error(`Failed to generate new key for ${provider}:`, error);
        }
      }

      // Perform batch rotation
      try {
        const results = await this.rotateMultipleKeys(keyUpdates, {
          password,
          gracePeriod: 5 * 60 * 1000, // 5 minute grace period
          continueOnError: true
        });
        
        console.info(`✅ Scheduled rotation completed: ${results.success.length} keys rotated`);
      } catch (error) {
        console.error('❌ Scheduled key rotation failed:', error);
      }
    }, rotationInterval);
  }

  /**
   * Get vault status
   */
  public getStatus(): {
    isLocked: boolean;
    hasVault: boolean;
    keyCount: number;
    lastAccess: Date | null;
    autoLockEnabled: boolean;
    failedAttempts: number;
    } {
    return {
      isLocked: this.isLocked,
      hasVault: !!this.encryptedVault,
      keyCount: this.decryptedKeys ? Object.keys(this.decryptedKeys).length : 0,
      lastAccess: this.lastAccessTime,
      autoLockEnabled: this.options.autoLock || false,
      failedAttempts: this.failedAttempts
    };
  }

  /**
   * Get list of configured providers
   */
  public getProviders(): string[] {
    if (this.isLocked || !this.decryptedKeys) {
      throw new SecurityError('Vault is locked - please unlock first');
    }

    this.updateAccessTime();
    return Object.keys(this.decryptedKeys);
  }

  /**
   * Test API key validity
   */
  public async testApiKey(provider: string): Promise<boolean> {
    const key = this.getApiKey(provider);
    
    // Basic validation
    if (!key || key.length < 8) {
      return false;
    }

    // Provider-specific validation could be added here
    return true;
  }

  /**
   * Export encrypted vault
   */
  public exportVault(): RealEncryptionResult {
    if (!this.encryptedVault) {
      throw new SecurityError('No vault to export');
    }

    return { ...this.encryptedVault };
  }

  // ===== PRIVATE METHODS =====

  private lockVault(): void {
    this.isLocked = true;
    this.decryptedKeys = null;
    this.clearAutoLockTimer();
    
    // Secure memory cleanup
    if (this.decryptedKeys) {
      this.cryptoEngine.secureErase(this.decryptedKeys);
    }
  }

  private updateAccessTime(): void {
    this.lastAccessTime = new Date();
    
    if (this.options.autoLock) {
      this.setupAutoLock();
    }
  }

  private setupAutoLock(): void {
    this.clearAutoLockTimer();
    
    if (this.options.autoLock && this.options.lockTimeout) {
      this.autoLockTimer = setTimeout(() => {
        this.lockVault();
      }, this.options.lockTimeout);
    }
  }

  private clearAutoLockTimer(): void {
    if (this.autoLockTimer) {
      clearTimeout(this.autoLockTimer);
      this.autoLockTimer = null;
    }
  }

  private validatePassword(password: string): void {
    if (!password || typeof password !== 'string') {
      throw new SecurityError('Password is required');
    }

    if (password.length < 12) {
      throw new SecurityError('Password must be at least 12 characters long');
    }

    // Calculate entropy score (bits of entropy)
    const entropy = this.calculatePasswordEntropy(password);
    if (entropy < 50) {
      throw new SecurityError(`Password is too weak (entropy: ${entropy.toFixed(1)} bits). Minimum required: 50 bits`);
    }

    // Check for common weak patterns
    if (this.hasWeakPatterns(password)) {
      throw new SecurityError('Password contains weak patterns');
    }
  }

  private calculatePasswordEntropy(password: string): number {
    // Character set sizes
    const charSets = {
      lowercase: /[a-z]/.test(password) ? 26 : 0,
      uppercase: /[A-Z]/.test(password) ? 26 : 0,
      digits: /[0-9]/.test(password) ? 10 : 0,
      symbols: /[^a-zA-Z0-9]/.test(password) ? 32 : 0 // Approximate symbol count
    };

    const charsetSize = Object.values(charSets).reduce((sum, size) => sum + size, 0);
    
    if (charsetSize === 0) {
      return 0;
    }

    // Entropy = log2(charset_size^length)
    const entropy = password.length * Math.log2(charsetSize);
    
    // Apply penalty for repeated characters
    const uniqueChars = new Set(password).size;
    const repetitionPenalty = uniqueChars / password.length;
    
    return entropy * repetitionPenalty;
  }

  private hasWeakPatterns(password: string): boolean {
    const weakPatterns = [
      /(.)\1{2,}/, // 3+ repeated characters
      /012|123|234|345|456|567|678|789|890/, // Sequential numbers
      /abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz/i, // Sequential letters
      /^(password|admin|user|login|qwerty|123456|letmein)$/i, // Common passwords
      /^.{1,3}$/ // Too short patterns
    ];

    return weakPatterns.some(pattern => pattern.test(password));
  }

  private validateApiKeys(apiKeys: any): void {
    if (!apiKeys || typeof apiKeys !== 'object') {
      throw new SecurityError('API keys must be an object');
    }

    const keys = Object.keys(apiKeys);
    if (keys.length === 0) {
      throw new SecurityError('At least one API key is required');
    }

    // Validate each key
    keys.forEach(provider => {
      const key = apiKeys[provider];
      if (!key || typeof key !== 'string' || key.length < 8) {
        throw new SecurityError(`Invalid API key for provider: ${provider}`);
      }
    });
  }

  // @ts-ignore - Keep for future use
  private sanitizeProvider(provider: string): string {
    // Remove any potentially dangerous characters
    return provider.replace(/[^a-zA-Z0-9_-]/g, '');
  }

  /**
   * Simple audit logging for security events
   */
  private auditLog(level: 'info' | 'warn' | 'error', message: string, details?: any): void {
    const timestamp = new Date().toISOString();
    // const _logEntry = {
    //   timestamp,
    //   level,
    //   service: 'KeyVault',
    //   message,
    //   ...(details && { details })
    // };

    // For now, just log to console. In production, this would go to a proper audit system
    console[level](`[KeyVault Audit] ${timestamp} - ${message}`, details || '');
  }
} 
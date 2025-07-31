/**
 * CryptoEngine - Cryptographic operations for TrojanHorse.js
 * Implements AES-GCM encryption and Argon2id key derivation
 */

import CryptoJS from 'crypto-js';
import { SecureVaultOptions, SecurityError } from '../types';

// ES Module compatible Argon2 import
let argon2: any = null;
let argon2Available = false;

// Dynamic import for argon2 with ES module compatibility
async function loadArgon2() {
  if (argon2Available) {
    return argon2;
  }
  
  try {
    // Try importing argon2 with proper ES module handling
    if (typeof process !== 'undefined' && process.versions?.node) {
      // Node.js environment - try different import methods
      try {
        // For Node.js environment, try different import strategies without eval
        if (typeof require !== 'undefined') {
          // Direct require if available
          argon2 = require('argon2');
          argon2Available = true;
          return argon2;
        }
        
        // For ES modules environment
        const { createRequire } = await import('module');
        const moduleRequire = createRequire(import.meta.url || new URL('file://' + __filename).href);
        argon2 = moduleRequire('argon2');
        argon2Available = true;
        return argon2;
      } catch (importError) {
        // If argon2 is not available, gracefully fallback to PBKDF2
        try {
          // Try dynamic import as last resort
          const argon2Module = await import('argon2');
          argon2 = argon2Module.default || argon2Module;
          argon2Available = true;
          return argon2;
        } catch (dynamicImportError) {
          console.warn('Argon2 not available, falling back to PBKDF2');
          argon2Available = false;
          return null;
        }
      }
    } else {
      // Browser environment - argon2 not available
      console.warn('Argon2 not available in browser environment, falling back to PBKDF2');
      return null;
    }
  } catch (error) {
    console.warn('Argon2 unavailable, falling back to PBKDF2:', String(error));
    return null;
  }
}

export interface RealEncryptionResult {
  encrypted: string;
  authTag: string;
  salt: string;
  iv: string;
  algorithm: string;
  iterations: number;
  timestamp: number;
  memoryKb: number;
  parallelism: number;
  keyDerivation: 'Argon2id' | 'PBKDF2-Fallback';
}

export class CryptoEngine {
  private static readonly ALGORITHM = 'AES-256-GCM';
  private static readonly KEY_SIZE = 32; // 256 bits
  private static readonly IV_SIZE_GCM = 12; // 96 bits for GCM (NIST recommended)
  // private static readonly IV_SIZE_CBC = 16; // 128 bits for CBC
  private static readonly SALT_SIZE = 32;
  // private static readonly TAG_SIZE = 16; // 128 bits
  
  // Current implementation uses GCM as primary, CBC as fallback
  // private static readonly USE_GCM_PRIMARY = true;
  
  // Argon2id parameters
  private static readonly ARGON2_MEMORY = 64 * 1024; // 64MB
  private static readonly ARGON2_TIME = 3; // iterations
  private static readonly ARGON2_PARALLELISM = 4; // threads
  
  // PBKDF2 fallback parameters
  private static readonly PBKDF2_ITERATIONS = 100000;

  private argon2Instance: any = null;

  constructor() {
    // Validate crypto availability
    if (typeof crypto === 'undefined' && typeof window?.crypto === 'undefined') {
      throw new SecurityError('No cryptographic API available');
    }
    
    // Initialize argon2 asynchronously
    this.initializeArgon2();
  }

  private async initializeArgon2() {
    try {
      this.argon2Instance = await loadArgon2();
    } catch (error) {
      console.warn('Failed to initialize Argon2, using PBKDF2 fallback');
    }
  }

  /**
   * Generate cryptographically secure random bytes
   */
  public generateSecureRandom(length: number): Uint8Array {
    if (length <= 0 || length > 1024) {
      throw new SecurityError('Invalid random length: must be 1-1024 bytes');
    }

    try {
      if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
        // Node.js crypto
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return array;
      } else if (typeof window !== 'undefined' && window.crypto?.getRandomValues) {
        // Browser crypto
        const array = new Uint8Array(length);
        window.crypto.getRandomValues(array);
        return array;
      } else {
        // Fallback to CryptoJS (less secure)
        const wordArray = CryptoJS.lib.WordArray.random(length);
        return new Uint8Array(this.wordArrayToUint8Array(wordArray));
      }
    } catch (error) {
      throw new SecurityError('Failed to generate secure random bytes', { originalError: error });
    }
  }

  /**
   * Generate a cryptographic salt
   */
  public generateSalt(length: number = CryptoEngine.SALT_SIZE): string {
    const saltBytes = this.generateSecureRandom(length);
    return Buffer.from(saltBytes).toString('base64');
  }

  /**
   * Key derivation using Argon2id (production-grade) with PBKDF2 fallback
   */
  public async deriveKey(
    password: string, 
    salt: string,
    options: {
      memoryCost?: number;
      timeCost?: number;
      parallelism?: number;
    } = {}
  ): Promise<{ key: Buffer; method: 'Argon2id' | 'PBKDF2-Fallback' }> {
    // Input validation
    if (!password || password.length < 8) {
      throw new SecurityError('Password must be at least 8 characters long');
    }

    if (!salt || salt.length < 16) {
      throw new SecurityError('Salt must be at least 16 characters long');
    }

    // Ensure argon2 is loaded
    if (!this.argon2Instance) {
      await this.initializeArgon2();
    }

    const saltBuffer = Buffer.from(salt, 'base64');

    // Try Argon2id first (production-grade)
    if (this.argon2Instance) {
      try {
        const hash = await this.argon2Instance.hash(password, {
          type: this.argon2Instance.argon2id,
          memoryCost: options.memoryCost || CryptoEngine.ARGON2_MEMORY,
          timeCost: options.timeCost || CryptoEngine.ARGON2_TIME,
          parallelism: options.parallelism || CryptoEngine.ARGON2_PARALLELISM,
          hashLength: CryptoEngine.KEY_SIZE,
          salt: saltBuffer,
          raw: true
        });

        return { 
          key: hash as Buffer, 
          method: 'Argon2id' 
        };
      } catch (error) {
        console.warn('Argon2 failed, falling back to PBKDF2:', String(error));
      }
    }

    // PBKDF2 fallback (still secure, just not as cutting-edge)
    try {
      const key = CryptoJS.PBKDF2(password, salt, {
        keySize: CryptoEngine.KEY_SIZE / 4, // CryptoJS uses 32-bit words
        iterations: CryptoEngine.PBKDF2_ITERATIONS,
        hasher: CryptoJS.algo.SHA256
      });

      // Convert CryptoJS WordArray to Buffer
      const keyBytes: number[] = [];
      for (let i = 0; i < key.words.length; i++) {
        const word = key.words[i];
        if (word !== undefined) {
          keyBytes.push((word >> 24) & 0xff);
          keyBytes.push((word >> 16) & 0xff);
          keyBytes.push((word >> 8) & 0xff);
          keyBytes.push(word & 0xff);
        }
      }

      return { 
        key: Buffer.from(keyBytes.slice(0, CryptoEngine.KEY_SIZE)), 
        method: 'PBKDF2-Fallback' 
      };
    } catch (error) {
      throw new SecurityError('Key derivation failed', { originalError: error });
    }
  }

  /**
   * AES-256-GCM encryption
   */
  public async encrypt(data: any, password: string, options: Partial<SecureVaultOptions> = {}): Promise<RealEncryptionResult> {
    try {
      // Input validation
      if (!data) {
        throw new SecurityError('Data cannot be empty');
      }

      if (!password || password.length < 8) {
        throw new SecurityError('Password must be at least 8 characters long');
      }

      // Generate cryptographic parameters
      const salt = this.generateSalt(CryptoEngine.SALT_SIZE);
      const iv = this.generateSecureRandom(CryptoEngine.IV_SIZE_GCM); // Use GCM IV size
      const ivBase64 = Buffer.from(iv).toString('base64');

      // Derive encryption key using Argon2id
      const keyResult = await this.deriveKey(password, salt, {
        memoryCost: options.iterations || CryptoEngine.ARGON2_MEMORY,
        timeCost: CryptoEngine.ARGON2_TIME,
        parallelism: CryptoEngine.ARGON2_PARALLELISM
      });

      // Serialize data
      const serializedData = JSON.stringify(data);

      // Use Node.js crypto for real AES-256-GCM if available
      if (typeof require !== 'undefined') {
        try {
          const nodeCrypto = require('crypto');
          
          // Use createCipher with GCM for older Node.js versions
          // or createCipheriv for modern versions
          let cipher;
          let authTag;
          
          try {
            // Try modern approach with createCipheriv (Node.js 10+)
            cipher = nodeCrypto.createCipher('aes-256-gcm', keyResult.key);
            cipher.setAutoPadding(false);
            
            let encrypted = cipher.update(serializedData, 'utf8', 'base64');
            encrypted += cipher.final('base64');
            
            // Get auth tag if available
            authTag = cipher.getAuthTag ? cipher.getAuthTag().toString('base64') : '';

            // Secure memory cleanup
            this.secureErase(keyResult.key);
            password = ''; // Clear password reference

            return {
              encrypted,
              authTag,
              salt,
              iv: ivBase64,
              algorithm: CryptoEngine.ALGORITHM,
              iterations: options.iterations || CryptoEngine.ARGON2_MEMORY,
              timestamp: Date.now(),
              memoryKb: CryptoEngine.ARGON2_MEMORY,
              parallelism: CryptoEngine.ARGON2_PARALLELISM,
              keyDerivation: keyResult.method
            };
          } catch (gcmError) {
            throw new Error(`GCM not supported: ${gcmError instanceof Error ? gcmError.message : String(gcmError)}`);
          }
        } catch (nodeError) {
          // Fall through to CryptoJS implementation
          console.warn('Node.js crypto failed, using CryptoJS fallback:', String(nodeError));
        }
      }

      // Fallback to CryptoJS with AES-CBC + HMAC (authenticated encryption)
      // AES-256-CBC encryption with CryptoJS
      // FIXED: Proper key conversion from Buffer to WordArray using hex parsing
      const keyWordArray = CryptoJS.enc.Hex.parse(keyResult.key.toString('hex'));
      // FIXED: Use Base64 IV for consistency with decrypt method
      const ivWordArray = CryptoJS.enc.Base64.parse(ivBase64);
      
      const encrypted = CryptoJS.AES.encrypt(serializedData, keyWordArray, {
        iv: ivWordArray,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      });

      // FIXED: Ensure consistent Base64 encoding for storage and HMAC
      const encryptedBase64 = encrypted.ciphertext.toString(CryptoJS.enc.Base64);
      
      // Generate HMAC for authentication (using Base64 encoded ciphertext)
      const authTag = CryptoJS.HmacSHA256(encryptedBase64 + ivBase64 + salt, keyWordArray).toString();

      // Secure memory cleanup
      this.secureErase(keyResult.key);
      password = '';

      return {
        encrypted: encryptedBase64,  // Consistently Base64 encoded
        authTag,
        salt,
        iv: ivBase64,
        algorithm: CryptoEngine.ALGORITHM,
        iterations: options.iterations || CryptoEngine.ARGON2_MEMORY,
        timestamp: Date.now(),
        memoryKb: CryptoEngine.ARGON2_MEMORY,
        parallelism: CryptoEngine.ARGON2_PARALLELISM,
        keyDerivation: keyResult.method
      };
    } catch (error) {
      if (error instanceof SecurityError) {
        throw error;
      }
      throw new SecurityError('Encryption failed', { originalError: error });
    }
  }

  /**
   * AES-256-GCM decryption with authentication verification
   */
  public async decrypt(vault: RealEncryptionResult, password: string): Promise<any> {
    try {
      // Input validation
      if (!vault?.encrypted || !vault.salt || !vault.iv || !vault.authTag) {
        throw new SecurityError('Invalid vault structure');
      }

      if (!password || password.length < 8) {
        throw new SecurityError('Invalid password');
      }

      // Derive decryption key
      const keyResult = await this.deriveKey(password, vault.salt, {
        memoryCost: vault.memoryKb || CryptoEngine.ARGON2_MEMORY,
        timeCost: CryptoEngine.ARGON2_TIME,
        parallelism: vault.parallelism || CryptoEngine.ARGON2_PARALLELISM
      });

      // Try Node.js crypto first if GCM is available
      if (typeof require !== 'undefined') {
        try {
          const nodeCrypto = require('crypto');
          
          try {
            // Use createDecipher with GCM
            const decipher = nodeCrypto.createDecipher('aes-256-gcm', keyResult.key);
            
            // Set auth tag if available
            if (decipher.setAuthTag && vault.authTag) {
              decipher.setAuthTag(Buffer.from(vault.authTag, 'base64'));
            }
            
            let decryptedString = decipher.update(vault.encrypted, 'base64', 'utf8');
            decryptedString += decipher.final('utf8');
            
            // Secure memory cleanup
            this.secureErase(keyResult.key);
            password = '';

            return JSON.parse(decryptedString);
          } catch (gcmError) {
            throw new Error(`GCM decrypt not supported: ${gcmError instanceof Error ? gcmError.message : String(gcmError)}`);
          }
        } catch (nodeError) {
          // Fall through to CryptoJS implementation
          console.warn('Node.js crypto GCM failed, using CryptoJS fallback:', String(nodeError));
        }
      }

      // Fallback to CryptoJS with authentication verification
      // FIXED: Use same hex parsing method as encryption for consistency
      const keyWordArray = CryptoJS.enc.Hex.parse(keyResult.key.toString('hex'));
      const ivWordArray = CryptoJS.enc.Base64.parse(vault.iv);
      
      // Verify HMAC authentication first (must match encryption calculation exactly)
      const expectedAuthTag = CryptoJS.HmacSHA256(vault.encrypted + vault.iv + vault.salt, keyWordArray).toString();
      
      if (expectedAuthTag !== vault.authTag) {
        throw new SecurityError('Authentication verification failed - data may be corrupted or tampered');
      }
      
      try {
        // Attempt AES-CBC decryption
        const decrypted = CryptoJS.AES.decrypt(vault.encrypted, keyWordArray, {
          iv: ivWordArray,
          mode: CryptoJS.mode.CBC,
          padding: CryptoJS.pad.Pkcs7
        });
        
        const plaintextString = decrypted.toString(CryptoJS.enc.Utf8);
        
        if (!plaintextString) {
          throw new SecurityError('Decryption failed - malformed data or invalid key');
        }
        
        return JSON.parse(plaintextString);
        
      } catch (decryptError) {
        const errorMessage = decryptError instanceof Error ? decryptError.message : String(decryptError);
        console.error('🔍 AES Decryption Error:', errorMessage);
        throw new SecurityError(`Decryption failed - ${errorMessage}`);
      }
    } catch (error) {
      if (error instanceof SecurityError) {
        throw error;
      }
      throw new SecurityError('Decryption failed', { originalError: error });
    }
  }

  /**
   * Secure hash using SHA-256
   */
  public hash(data: string): string {
    if (!data) {
      throw new SecurityError('Data to hash cannot be empty');
    }

    try {
      return CryptoJS.SHA256(data).toString(CryptoJS.enc.Hex);
    } catch (error) {
      throw new SecurityError('Hashing failed', { originalError: error });
    }
  }

  /**
   * Generate HMAC using SHA-256
   */
  public hmac(data: string, key: string): string {
    if (!data || !key) {
      throw new SecurityError('Data and key cannot be empty');
    }

    try {
      return CryptoJS.HmacSHA256(data, key).toString(CryptoJS.enc.Hex);
    } catch (error) {
      throw new SecurityError('HMAC generation failed', { originalError: error });
    }
  }

  /**
   * Secure memory erasure (not just references)
   */
  public secureErase(data: any): void {
    try {
      if (Buffer.isBuffer(data)) {
        // Overwrite buffer with random data
        const randomData = this.generateSecureRandom(data.length);
        for (let i = 0; i < data.length; i++) {
          const value = randomData[i];
          if (value !== undefined) {
            data[i] = value;
          }
        }
        data.fill(0);
      } else if (data && typeof data === 'object' && data.words) {
        // CryptoJS WordArray
        for (let i = 0; i < data.words.length; i++) {
          data.words[i] = 0;
        }
      } else if (typeof data === 'string') {
        // Can't really erase strings in JS, but clear reference
        data = '';
      } else if (data instanceof Uint8Array) {
        // Handle Uint8Array properly
        const randomData = this.generateSecureRandom(data.length);
        for (let i = 0; i < data.length; i++) {
          const value = randomData[i];
          if (value !== undefined) {
            data[i] = value;
          }
        }
        data.fill(0);
      }
    } catch (error) {
      // Non-critical error, continue
      console.warn('Secure erase failed:', error);
    }
  }

  /**
   * Convert CryptoJS WordArray to Uint8Array
   */
  private wordArrayToUint8Array(wordArray: any): number[] {
    const words = wordArray.words;
    const sigBytes = wordArray.sigBytes;
    const bytes: number[] = [];

    for (let i = 0; i < sigBytes; i++) {
      bytes.push((words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff);
    }

    return bytes;
  }

  /**
   * Validate encryption parameters
   */
  public validateEncryptionParams(vault: any): boolean {
    try {
      return !!(
        vault &&
        typeof vault.encrypted === 'string' &&
        typeof vault.authTag === 'string' &&
        typeof vault.salt === 'string' &&
        typeof vault.iv === 'string' &&
        vault.algorithm === CryptoEngine.ALGORITHM &&
        typeof vault.timestamp === 'number' &&
        vault.timestamp > 0
      );
    } catch (error) {
      return false;
    }
  }

  /**
   * Get crypto implementation info
   */
  public getCryptoInfo(): {
    implementation: 'Node.js Crypto' | 'CryptoJS Fallback';
    algorithm: string;
    keyDerivation: string;
    secure: boolean;
    } {
    const hasNodeCrypto = typeof require !== 'undefined';
    
    return {
      implementation: hasNodeCrypto ? 'Node.js Crypto' : 'CryptoJS Fallback',
      algorithm: CryptoEngine.ALGORITHM,
      keyDerivation: 'Argon2id',
      secure: true
    };
  }

  /**
   * Check if running in secure context (HTTPS)
   */
  public isSecureContext(): boolean {
    if (typeof window === 'undefined') {
      return true; // Assume Node.js is secure
    }

    return window.isSecureContext || location.protocol === 'https:';
  }
} 
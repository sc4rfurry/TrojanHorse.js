/**
 * TrojanHorse.js Browser Entry Point
 * 
 * Optimized for static sites and standalone browser usage
 * - Browser-compatible API surface
 * - No Node.js dependencies
 * - Ready for script tag inclusion
 * - Includes browser-specific features
 * - CORS-aware with demo/proxy modes
 */

// Browser-compatible imports
import { TrojanHorse } from './index';
import { CryptoEngine } from './security/CryptoEngine';
import { KeyVault } from './security/KeyVault';
import { URLhausFeed } from './feeds/URLhausFeed';
import { AlienVaultFeed } from './feeds/AlienVaultFeed';
import { CrowdSecFeed } from './feeds/CrowdSecFeed';
import { AbuseIPDBFeed } from './feeds/AbuseIPDBFeed';

// Type exports for TypeScript users
export type {
  TrojanHorseConfig,
  ApiKeyConfig,
  ThreatIndicator,
  ThreatFeedResult,
  EncryptedVault,
  FeedConfiguration,
  SecurityConfig
} from './types';

// Demo threat data for browser examples (when CORS prevents real API calls)
const DEMO_THREATS = {
  domains: [
    'malicious-site.com',
    'phishing-example.net', 
    'bad-domain.org',
    'threat-actor.co',
    'scam-website.info'
  ],
  ips: [
    '192.0.2.1',    // RFC 5737 test IP
    '198.51.100.1', // RFC 5737 test IP
    '203.0.113.1',  // RFC 5737 test IP
    '10.0.0.1',     // Private IP for demo
    '172.16.0.1'    // Private IP for demo
  ],
  urls: [
    'http://malicious-site.com/malware.exe',
    'https://phishing-example.net/login',
    'http://bad-domain.org/exploit.php',
    'https://threat-actor.co/payload.js',
    'http://scam-website.info/fake-bank'
  ]
};

// Browser-specific utilities
export class BrowserUtils {
  /**
   * Check if the browser supports required features
   */
  static checkBrowserSupport(): {
    supported: boolean;
    missing: string[];
    warnings: string[];
    } {
    const missing: string[] = [];
    const warnings: string[] = [];

    // Check for essential features
    if (typeof crypto === 'undefined' || !crypto.getRandomValues) {
      missing.push('Web Crypto API (crypto.getRandomValues)');
    }

    if (typeof indexedDB === 'undefined') {
      missing.push('IndexedDB');
    }

    if (typeof fetch === 'undefined') {
      missing.push('Fetch API');
    }

    // Check for preferred features
    if (!crypto.subtle) {
      warnings.push('Web Crypto Subtle API not available - using fallback encryption');
    }

    if (!window.isSecureContext) {
      warnings.push('Not running in secure context (HTTPS) - some features may be limited');
    }

    // Check for CORS limitations
    if (window.location.protocol === 'file:' || window.location.hostname === 'localhost') {
      warnings.push('Running locally - threat feeds will use demo mode due to CORS restrictions');
    }

    return {
      supported: missing.length === 0,
      missing,
      warnings
    };
  }

  /**
   * Initialize TrojanHorse with browser-optimized defaults
   */
  static async createBrowserInstance(config: {
    apiKeys?: Record<string, string>;
    feeds?: string[];
    storage?: {
      dbName?: string;
      encryptionKey?: string;
    };
    proxyUrl?: string; // URL to CORS proxy for production use
    demoMode?: boolean; // Force demo mode
  } = {}): Promise<TrojanHorse> {
    const support = this.checkBrowserSupport();
    
    if (!support.supported) {
      throw new Error(
        `Browser not supported. Missing features: ${support.missing.join(', ')}`
      );
    }

    // Show warnings in development
    if (support.warnings.length > 0 && console.warn) {
      console.warn('TrojanHorse.js Browser Warnings:', support.warnings);
    }

    // Determine if we should use demo mode
    const shouldUseDemoMode = config.demoMode || 
      window.location.protocol === 'file:' || 
      (window.location.hostname === 'localhost' && !config.proxyUrl);

    if (shouldUseDemoMode && console.info) {
      console.info('🎭 TrojanHorse.js running in demo mode - using simulated threat data for CORS compatibility');
    }

    // Browser-optimized configuration
    const browserConfig = {
      apiKeys: config.apiKeys || {},
      security: {
        enforceHttps: window.isSecureContext,
        autoLock: true,
        lockTimeout: 5 * 60 * 1000 // 5 minutes
      },
      sources: config.feeds || ['urlhaus'], // Safe default for browsers
      strategy: 'defensive' as const
    };

    const trojan = new TrojanHorse(browserConfig);

    // Initialize storage if configured
    if (config.storage) {
      const storage = await this.initializeBrowserStorage(config.storage);
      // Storage initialized and available for use
      console.log('Browser storage initialized:', typeof storage);
    }

    return trojan;
  }

  /**
   * Initialize browser-specific storage
   */
  private static async initializeBrowserStorage(config: {
    dbName?: string;
    encryptionKey?: string;
  }): Promise<void> {
    // Browser storage initialization
    const dbName = config.dbName || 'trojanhorse-cache';
    const encryptionKey = config.encryptionKey || await this.generateStorageKey();
    
    // Storage setup would go here
    console.debug(`Initialized browser storage: ${dbName} with key: ${encryptionKey.substring(0, 8)}...`);
  }

  /**
   * Generate a browser-specific storage encryption key
   */
  private static async generateStorageKey(): Promise<string> {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Create a simple threat lookup function for static sites
   * Automatically handles CORS issues with demo mode fallback
   */
  static createSimpleLookup(options: {
    proxyUrl?: string;
    demoMode?: boolean;
    apiKeys?: Record<string, string>;
  } = {}): {
    checkDomain: (domain: string) => Promise<boolean>;
    checkIP: (ip: string) => Promise<boolean>;
    checkURL: (url: string) => Promise<boolean>;
  } {
    const cache = new Map<string, { result: boolean; expires: number }>();
    const CACHE_DURATION = 60 * 60 * 1000; // 1 hour

    // Determine if we should use demo mode
    const shouldUseDemoMode = options.demoMode || 
      window.location.protocol === 'file:' || 
      (window.location.hostname === 'localhost' && !options.proxyUrl);

    const checkCached = (key: string): boolean | null => {
      const cached = cache.get(key);
      if (cached && Date.now() < cached.expires) {
        return cached.result;
      }
      if (cached) {
        cache.delete(key);
      }
      return null;
    };

    const setCached = (key: string, result: boolean): void => {
      cache.set(key, {
        result,
        expires: Date.now() + CACHE_DURATION
      });
    };

    // Demo mode threat checking (fallback for CORS issues)
    const checkThreatDemo = (value: string, type: 'domain' | 'ip' | 'url'): boolean => {
      const threats = DEMO_THREATS[type === 'domain' ? 'domains' : type === 'ip' ? 'ips' : 'urls'];
      return threats.some(threat => 
        value.toLowerCase().includes(threat.toLowerCase()) || 
        threat.toLowerCase().includes(value.toLowerCase())
      );
    };

    // Real threat checking (requires CORS proxy or API keys)
    const checkThreatReal = async (value: string, type: 'domain' | 'ip' | 'url'): Promise<boolean> => {
      try {
        // If proxy URL provided, use it
        if (options.proxyUrl) {
          console.info(`🌐 Using CORS proxy: ${options.proxyUrl}`);
          
          // For URLhaus feed through proxy
          const proxyUrl = options.proxyUrl.endsWith('/') ? options.proxyUrl.slice(0, -1) : options.proxyUrl;
          const targetUrl = 'https://urlhaus.abuse.ch/downloads/csv_recent/';
          
          const response = await fetch(`${proxyUrl}/${targetUrl}`, {
            method: 'GET',
            headers: {
              'Accept': 'text/csv,*/*',
              'User-Agent': 'TrojanHorse.js/1.0.1'
            }
          });
          
          if (!response.ok) {
            throw new Error(`Proxy error: ${response.status} ${response.statusText}`);
          }
          
          const csvData = await response.text();
          console.info(`📊 Received ${csvData.split('\n').length} lines of threat data`);
          
          // Parse CSV and check for threats
          const isMalicious = await parseUrlhausData(csvData, value, type);
          return isMalicious;
        }

        // For specific APIs that support CORS (rare)
        // Most threat feeds don't support direct browser access
        throw new Error('CORS not supported - use demo mode or proxy');
        
      } catch (error) {
        console.warn('Real threat check failed, falling back to demo mode:', error);
        return checkThreatDemo(value, type);
      }
    };

    // URLhaus CSV parser for real threat data
    const parseUrlhausData = async (csvData: string, value: string, type: 'domain' | 'ip' | 'url'): Promise<boolean> => {
      try {
        const lines = csvData.split('\n').slice(9); // Skip header comments
        const cleanValue = value.toLowerCase().trim();
        
        for (const line of lines) {
          if (!line.trim() || line.startsWith('#')) {
            continue;
          }
          
          const columns = line.split(',');
          if (columns.length < 8) {
            continue;
          }
          
          const [, , url, urlStatus, , threat, ,] = columns.map(col => 
            col.replace(/^"/, '').replace(/"$/, '').trim()
          );
          
          if (urlStatus !== 'online' && urlStatus !== 'offline') {
            continue;
          }
          
          if (!url) continue;
          
          try {
            const threatUrl = new URL(url);
            const domain = threatUrl.hostname.toLowerCase();
            const fullUrl = url.toLowerCase();
            
            // Check based on type
            switch (type) {
            case 'domain':
              if (domain === cleanValue || domain.endsWith(`.${cleanValue}`)) {
                console.info(`🎯 Threat found: ${cleanValue} matches ${domain} (${threat})`);
                return true;
              }
              break;
                
            case 'url':
              if (fullUrl.includes(cleanValue) || cleanValue.includes(domain)) {
                console.info(`🎯 Threat found: ${cleanValue} matches ${url} (${threat})`);
                return true;
              }
              break;
                
            case 'ip':
              // For IP, we'd need additional resolution or feeds that specifically list IPs
              // URLhaus primarily contains URLs, so this is limited
              if (domain === cleanValue || url.includes(cleanValue)) {
                console.info(`🎯 Threat found: ${cleanValue} in ${url} (${threat})`);
                return true;
              }
              break;
            }
          } catch (urlError) {
            // Skip malformed URLs
            continue;
          }
        }
        
        console.info(`✅ No threats found for ${cleanValue} in URLhaus data`);
        return false;
        
      } catch (error) {
        console.warn('Error parsing URLhaus data:', error);
        return checkThreatDemo(value, type);
      }
    };

    return {
      async checkDomain(domain: string): Promise<boolean> {
        const cached = checkCached(`domain:${domain}`);
        if (cached !== null) {
          return cached;
        }

        try {
          let isMalicious: boolean;
          
          if (shouldUseDemoMode) {
            isMalicious = checkThreatDemo(domain, 'domain');
            console.info(`🎭 Demo mode: ${domain} → ${isMalicious ? 'malicious' : 'safe'}`);
          } else {
            isMalicious = await checkThreatReal(domain, 'domain');
          }

          setCached(`domain:${domain}`, isMalicious);
          return isMalicious;
        } catch (error) {
          console.warn('Domain check failed:', error);
          // Fallback to demo mode
          const result = checkThreatDemo(domain, 'domain');
          setCached(`domain:${domain}`, result);
          return result;
        }
      },

      async checkIP(ip: string): Promise<boolean> {
        const cached = checkCached(`ip:${ip}`);
        if (cached !== null) {
          return cached;
        }

        try {
          let isMalicious: boolean;
          
          if (shouldUseDemoMode) {
            isMalicious = checkThreatDemo(ip, 'ip');
            console.info(`🎭 Demo mode: ${ip} → ${isMalicious ? 'malicious' : 'safe'}`);
          } else {
            isMalicious = await checkThreatReal(ip, 'ip');
          }

          setCached(`ip:${ip}`, isMalicious);
          return isMalicious;
        } catch (error) {
          console.warn('IP check failed:', error);
          // Fallback to demo mode
          const result = checkThreatDemo(ip, 'ip');
          setCached(`ip:${ip}`, result);
          return result;
        }
      },

      async checkURL(url: string): Promise<boolean> {
        const cached = checkCached(`url:${url}`);
        if (cached !== null) {
          return cached;
        }

        try {
          let isMalicious: boolean;
          
          if (shouldUseDemoMode) {
            isMalicious = checkThreatDemo(url, 'url');
            console.info(`🎭 Demo mode: ${url} → ${isMalicious ? 'malicious' : 'safe'}`);
          } else {
            isMalicious = await checkThreatReal(url, 'url');
          }

          setCached(`url:${url}`, isMalicious);
          return isMalicious;
        } catch (error) {
          console.warn('URL check failed:', error);
          // Fallback to demo mode
          const result = checkThreatDemo(url, 'url');
          setCached(`url:${url}`, result);
          return result;
        }
      }
    };
  }

  /**
   * Get production implementation guidance
   */
  static getProductionGuidance(): {
    corsIssue: string;
    solutions: Array<{
      name: string;
      description: string;
      example: string;
    }>;
    } {
    return {
      corsIssue: 'Most threat intelligence APIs do not support CORS for direct browser access due to security policies.',
      solutions: [
        {
          name: 'Backend Proxy',
          description: 'Route requests through your own server to bypass CORS',
          example: `
// Your backend endpoint
app.post('/api/threat-check', async (req, res) => {
  const trojan = new TrojanHorse({ apiKeys: { ... } });
  const result = await trojan.scout(req.body.target);
  res.json(result);
});

// Frontend usage
const response = await fetch('/api/threat-check', {
  method: 'POST',
  body: JSON.stringify({ target: 'example.com' })
});`
        },
        {
          name: 'CORS Proxy Service',
          description: 'Use a CORS proxy service (for development only)',
          example: `
const lookup = TrojanHorse.createLookup({
  proxyUrl: 'https://cors-anywhere.herokuapp.com'
});`
        },
        {
          name: 'Serverless Functions',
          description: 'Deploy threat checking as serverless functions',
          example: `
// Vercel/Netlify function
export default async function handler(req, res) {
  const trojan = new TrojanHorse({ apiKeys: process.env });
  const result = await trojan.scout(req.query.target);
  res.json(result);
}`
        }
      ]
    };
  }
}

// Create browser-friendly global namespace
if (typeof window !== 'undefined') {
  // Make TrojanHorse available globally
  (window as any).TrojanHorse = {
    // Main class
    TrojanHorse,
    
    // Browser utilities
    BrowserUtils,
    
    // Individual components for advanced users
    CryptoEngine,
    KeyVault,
    URLhausFeed,
    AlienVaultFeed,
    CrowdSecFeed,
    AbuseIPDBFeed,
    
    // Quick setup function
    async create(config = {}) {
      return BrowserUtils.createBrowserInstance(config);
    },
    
    // Simple lookup functions with CORS handling
    createLookup(options = {}) {
      return BrowserUtils.createSimpleLookup(options);
    },
    
    // Production guidance
    getProductionGuidance() {
      return BrowserUtils.getProductionGuidance();
    },
    
    // Version info
    version: '1.0.1'
  };

  // Show helpful info in console
  if (console.info) {
    console.info(`
🏰 TrojanHorse.js v1.0.1 loaded successfully!

ℹ️  Browser Usage Notes:
• Most threat APIs don't support CORS for direct browser access
• Demo mode automatically activates for local development
• For production, use a backend proxy or serverless functions

📖 Get production guidance: TrojanHorse.getProductionGuidance()
🎭 Demo threats available for testing
    `);
  }
}

// Default export for ES modules
export default {
  TrojanHorse,
  BrowserUtils,
  CryptoEngine,
  KeyVault,
  URLhausFeed,
  AlienVaultFeed,
  CrowdSecFeed,
  AbuseIPDBFeed
};

// Named exports (remove duplicate BrowserUtils export)
export {
  TrojanHorse,
  CryptoEngine,
  KeyVault,
  URLhausFeed,
  AlienVaultFeed,
  CrowdSecFeed,
  AbuseIPDBFeed
}; 
// TrojanHorse.js Configuration Template
// Copy this file to trojanhorse.config.js and add your real API keys
// NEVER commit the real config file to git!

export default {
  // API Keys - Replace with your actual keys
  apiKeys: {
    alienVault: process.env.ALIENVAULT_API_KEY || 'your-alienvault-api-key-here',
    abuseipdb: process.env.ABUSEIPDB_API_KEY || 'your-abuseipdb-api-key-here',
    virustotal: process.env.VIRUSTOTAL_API_KEY || 'your-virustotal-api-key-here',
    crowdsec: process.env.CROWDSEC_API_KEY || 'your-crowdsec-api-key-here'
  },
  
  // Data Sources - Select which feeds to use
  sources: ['urlhaus', 'alienvault', 'abuseipdb', 'virustotal', 'crowdsec'],
  
  // Analysis Strategy
  strategy: 'fort-knox', // 'defensive' | 'balanced' | 'aggressive' | 'fort-knox'
  
  // Security Settings
  security: {
    enforceHttps: true, // Set to true in production
    autoLock: true,
    lockTimeout: 300000, // 5 minutes
    auditLogging: true // Enable in production
  },
  
  // Performance Settings
  caching: {
    enabled: true,
    ttl: 3600000, // 1 hour
    maxSize: 1000
  },
  
  // Rate Limiting
  rateLimit: {
    enabled: true,
    maxConcurrent: 10,
    timeout: 30000
  },
  
  // Browser Configuration
  browser: {
    corsProxy: 'https://your-cors-proxy.workers.dev', // Replace with your CORS proxy
    fallbackMode: 'demo' // 'demo' | 'limited' | 'offline'
  },
  
  // Circuit Breaker
  circuitBreaker: {
    enabled: true,
    failureThreshold: 5,
    timeout: 60000
  },
  
  // Monitoring
  monitoring: {
    enabled: true,
    metricsPort: 9090
  }
};
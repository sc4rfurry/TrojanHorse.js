# Browser Usage Guide

Complete guide for using TrojanHorse.js in browser environments, including static sites, SPAs, and production deployments.

## Overview

TrojanHorse.js provides robust browser support with multiple integration methods:

- **CDN Integration**: Simple script tag inclusion
- **ES Modules**: Modern browser module support  
- **Build Tools**: Webpack, Rollup, Vite integration
- **CORS Solutions**: Production-ready proxy patterns
- **Demo Mode**: Development without API keys

## Quick Start

### Simple Script Tag

```html
<!DOCTYPE html>
<html>
<head>
    <title>Threat Detection</title>
</head>
<body>
    <!-- Load TrojanHorse.js -->
    <script src="https://unpkg.com/trojanhorse-js@latest/dist/trojanhorse.browser.min.js"></script>
    
    <script>
        // Check browser support
        const support = TrojanHorse.BrowserUtils.checkBrowserSupport();
        if (!support.supported) {
            console.error('Browser not supported:', support.missing);
        }
        
        // Create simple lookup (demo mode)
        const lookup = TrojanHorse.createLookup({ demoMode: true });
        
        // Check threats
        async function checkDomain(domain) {
            const isMalicious = await lookup.checkDomain(domain);
            console.log(`${domain}:`, isMalicious ? '🚨 Malicious' : '✅ Safe');
        }
        
        // Example usage
        checkDomain('test-malware.com');
        checkDomain('google.com');
    </script>
</body>
</html>
```

### ES Modules (Modern)

```html
<script type="module">
    import { TrojanHorse, BrowserUtils } from 'https://unpkg.com/trojanhorse-js@latest/dist/trojanhorse.browser.esm.js';
    
    // Browser-optimized instance
    const trojan = await BrowserUtils.createBrowserInstance({
        feeds: ['urlhaus'],
        storage: {
            dbName: 'threat-cache',
            encryptionKey: 'user-generated-key'
        },
        demoMode: true // For development
    });
    
    // Use the instance
    const threats = await trojan.scout('suspicious-domain.com');
    console.log(`Found ${threats.length} threats`);
</script>
```

## Production Integration

### 1. Backend Proxy (Recommended)

**Backend (Express.js example):**

```javascript
// server.js
const express = require('express');
const { TrojanHorse } = require('trojanhorse-js');

const app = express();
app.use(express.json());

// Initialize TrojanHorse with API keys
const trojan = new TrojanHorse({
  apiKeys: {
    alienVault: process.env.ALIENVAULT_API_KEY,
    abuseipdb: process.env.ABUSEIPDB_API_KEY,
    virustotal: process.env.VIRUSTOTAL_API_KEY
  },
  sources: ['urlhaus', 'alienvault', 'abuseipdb', 'virustotal']
});

// Threat check endpoint
app.post('/api/threat-check', async (req, res) => {
  try {
    const { target, type = 'domain' } = req.body;
    
    if (!target) {
      return res.status(400).json({ error: 'Target required' });
    }
    
    const threats = await trojan.scout(target);
    
    res.json({
      target,
      safe: threats.length === 0,
      threatCount: threats.length,
      threats: threats.slice(0, 10), // Limit response size
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Threat check error:', error);
    res.status(500).json({ error: 'Threat check failed' });
  }
});

app.listen(3000, () => {
  console.log('Threat API server running on port 3000');
});
```

**Frontend:**

```javascript
// frontend.js
class ThreatChecker {
  constructor(apiUrl = '/api/threat-check') {
    this.apiUrl = apiUrl;
  }
  
  async checkThreat(target) {
    try {
      const response = await fetch(this.apiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ target })
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('Threat check failed:', error);
      throw error;
    }
  }
}

// Usage
const checker = new ThreatChecker();

document.getElementById('check-button').addEventListener('click', async () => {
  const domain = document.getElementById('domain-input').value;
  const result = await checker.checkThreat(domain);
  
  document.getElementById('result').innerHTML = result.safe 
    ? '✅ Domain appears safe'
    : `🚨 ${result.threatCount} threats detected`;
});
```

### 2. CORS Proxy Service

!!! warning "Development Only"
    CORS proxy services should only be used for development. Use a backend proxy for production.

```javascript
// Using a CORS proxy service
const lookup = TrojanHorse.createLookup({
  proxyUrl: 'https://still-water-daf2.zeeahanm900.workers.dev' // Example Cloudflare Worker
});

// This will route requests through the proxy
const isMalicious = await lookup.checkDomain('suspicious-site.com');
```

### 3. Serverless Functions

**Vercel Function (`api/threat-check.js`):**

```javascript
import { TrojanHorse } from 'trojanhorse-js';

const trojan = new TrojanHorse({
  apiKeys: {
    alienVault: process.env.ALIENVAULT_API_KEY,
    abuseipdb: process.env.ABUSEIPDB_API_KEY
  }
});

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }
  
  try {
    const { target } = req.body;
    const threats = await trojan.scout(target);
    
    res.json({
      safe: threats.length === 0,
      threats: threats.length
    });
  } catch (error) {
    res.status(500).json({ error: 'Threat check failed' });
  }
}
```

**Netlify Function (`netlify/functions/threat-check.js`):**

```javascript
const { TrojanHorse } = require('trojanhorse-js');

const trojan = new TrojanHorse({
  apiKeys: {
    alienVault: process.env.ALIENVAULT_API_KEY
  }
});

exports.handler = async (event, context) => {
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }
  
  try {
    const { target } = JSON.parse(event.body);
    const threats = await trojan.scout(target);
    
    return {
      statusCode: 200,
      body: JSON.stringify({
        safe: threats.length === 0,
        threats: threats.length
      })
    };
  } catch (error) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Threat check failed' })
    };
  }
};
```

## Advanced Browser Features

### 1. Storage Management

```javascript
// IndexedDB storage for caching
const trojan = await BrowserUtils.createBrowserInstance({
  storage: {
    dbName: 'trojanhorse-cache',
    version: 1,
    encryptionKey: 'user-provided-key',
    ttl: 3600000 // 1 hour cache
  }
});

// Manual cache management
await trojan.clearCache();
const cacheStats = await trojan.getCacheStats();
console.log('Cache entries:', cacheStats.count);
```

### 2. Service Worker Integration

```javascript
// service-worker.js
importScripts('https://unpkg.com/trojanhorse-js@latest/dist/trojanhorse.browser.min.js');

const lookup = TrojanHorse.createLookup({ demoMode: true });

self.addEventListener('message', async (event) => {
  if (event.data.type === 'THREAT_CHECK') {
    const { target, id } = event.data;
    
    try {
      const isMalicious = await lookup.checkDomain(target);
      
      event.ports[0].postMessage({
        id,
        result: { safe: !isMalicious }
      });
    } catch (error) {
      event.ports[0].postMessage({
        id,
        error: error.message
      });
    }
  }
});
```

```javascript
// main.js
navigator.serviceWorker.register('/service-worker.js');

async function checkThreatInWorker(target) {
  return new Promise((resolve, reject) => {
    const channel = new MessageChannel();
    const id = Math.random().toString(36);
    
    channel.port1.onmessage = (event) => {
      if (event.data.error) {
        reject(new Error(event.data.error));
      } else {
        resolve(event.data.result);
      }
    };
    
    navigator.serviceWorker.controller.postMessage({
      type: 'THREAT_CHECK',
      target,
      id
    }, [channel.port2]);
  });
}
```

### 3. Web Workers

```javascript
// threat-worker.js
importScripts('https://unpkg.com/trojanhorse-js@latest/dist/trojanhorse.browser.min.js');

const lookup = TrojanHorse.createLookup({ demoMode: true });

self.onmessage = async function(e) {
  const { targets, jobId } = e.data;
  const results = [];
  
  for (const target of targets) {
    try {
      const isMalicious = await lookup.checkDomain(target);
      results.push({ target, safe: !isMalicious });
    } catch (error) {
      results.push({ target, error: error.message });
    }
    
    // Report progress
    self.postMessage({
      type: 'progress',
      jobId,
      completed: results.length,
      total: targets.length
    });
  }
  
  self.postMessage({
    type: 'complete',
    jobId,
    results
  });
};
```

```javascript
// main.js
class ThreatWorkerPool {
  constructor(workerCount = 4) {
    this.workers = [];
    this.jobQueue = [];
    this.activeJobs = new Map();
    
    for (let i = 0; i < workerCount; i++) {
      const worker = new Worker('/threat-worker.js');
      worker.onmessage = this.handleWorkerMessage.bind(this);
      this.workers.push(worker);
    }
  }
  
  async checkThreats(targets) {
    return new Promise((resolve, reject) => {
      const jobId = Math.random().toString(36);
      
      this.activeJobs.set(jobId, { resolve, reject, results: [] });
      
      // Find available worker
      const worker = this.workers[0]; // Simple assignment
      worker.postMessage({ targets, jobId });
    });
  }
  
  handleWorkerMessage(e) {
    const { type, jobId, results } = e.data;
    
    if (type === 'complete') {
      const job = this.activeJobs.get(jobId);
      if (job) {
        job.resolve(results);
        this.activeJobs.delete(jobId);
      }
    }
  }
}

// Usage
const pool = new ThreatWorkerPool();
const results = await pool.checkThreats([
  'site1.com', 'site2.com', 'site3.com'
]);
```

## React Integration

### Hook Implementation

```jsx
// useThreatCheck.js
import { useState, useEffect, useCallback } from 'react';

export function useThreatChecker(apiUrl = '/api/threat-check') {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  
  const checkThreat = useCallback(async (target) => {
    setIsLoading(true);
    setError(null);
    
    try {
      const response = await fetch(apiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target })
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      
      const result = await response.json();
      return result;
    } catch (err) {
      setError(err.message);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [apiUrl]);
  
  return { checkThreat, isLoading, error };
}
```

```jsx
// ThreatChecker.jsx
import React, { useState } from 'react';
import { useThreatChecker } from './useThreatCheck';

export function ThreatChecker() {
  const [domain, setDomain] = useState('');
  const [result, setResult] = useState(null);
  const { checkThreat, isLoading, error } = useThreatChecker();
  
  const handleCheck = async (e) => {
    e.preventDefault();
    
    try {
      const result = await checkThreat(domain);
      setResult(result);
    } catch (err) {
      console.error('Check failed:', err);
    }
  };
  
  return (
    <div className="threat-checker">
      <form onSubmit={handleCheck}>
        <input
          type="text"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="Enter domain to check"
          disabled={isLoading}
        />
        <button type="submit" disabled={isLoading || !domain}>
          {isLoading ? 'Checking...' : 'Check Threat'}
        </button>
      </form>
      
      {error && (
        <div className="error">Error: {error}</div>
      )}
      
      {result && (
        <div className={`result ${result.safe ? 'safe' : 'threat'}`}>
          {result.safe ? (
            <span>✅ Domain appears safe</span>
          ) : (
            <span>🚨 {result.threatCount} threats detected</span>
          )}
        </div>
      )}
    </div>
  );
}
```

## Vue.js Integration

```vue
<!-- ThreatChecker.vue -->
<template>
  <div class="threat-checker">
    <form @submit.prevent="checkThreat">
      <input
        v-model="domain"
        type="text"
        placeholder="Enter domain to check"
        :disabled="loading"
      />
      <button type="submit" :disabled="loading || !domain">
        {{ loading ? 'Checking...' : 'Check Threat' }}
      </button>
    </form>
    
    <div v-if="error" class="error">
      Error: {{ error }}
    </div>
    
    <div v-if="result" :class="['result', result.safe ? 'safe' : 'threat']">
      {{ result.safe ? '✅ Domain appears safe' : `🚨 ${result.threatCount} threats detected` }}
    </div>
  </div>
</template>

<script>
export default {
  name: 'ThreatChecker',
  data() {
    return {
      domain: '',
      result: null,
      loading: false,
      error: null
    };
  },
  methods: {
    async checkThreat() {
      this.loading = true;
      this.error = null;
      
      try {
        const response = await fetch('/api/threat-check', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target: this.domain })
        });
        
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        
        this.result = await response.json();
      } catch (err) {
        this.error = err.message;
      } finally {
        this.loading = false;
      }
    }
  }
};
</script>
```

## Build Tool Integration

### Webpack Configuration

```javascript
// webpack.config.js
module.exports = {
  // ... other config
  resolve: {
    fallback: {
      "crypto": require.resolve("crypto-browserify"),
      "stream": require.resolve("stream-browserify"),
      "util": require.resolve("util/"),
      "buffer": require.resolve("buffer/")
    }
  },
  plugins: [
    new webpack.ProvidePlugin({
      Buffer: ['buffer', 'Buffer'],
    }),
  ]
};
```

### Vite Configuration

```javascript
// vite.config.js
import { defineConfig } from 'vite';

export default defineConfig({
  define: {
    global: 'globalThis',
  },
  resolve: {
    alias: {
      crypto: 'crypto-browserify',
      stream: 'stream-browserify',
      util: 'util',
    }
  }
});
```

## Performance Optimization

### 1. Lazy Loading

```javascript
// Lazy load TrojanHorse only when needed
async function loadThreatChecker() {
  const { TrojanHorse } = await import('trojanhorse-js/browser');
  return TrojanHorse.createLookup({ demoMode: true });
}

// Use when needed
document.getElementById('check-button').addEventListener('click', async () => {
  const lookup = await loadThreatChecker();
  const result = await lookup.checkDomain('example.com');
});
```

### 2. Request Batching

```javascript
class BatchedThreatChecker {
  constructor() {
    this.queue = [];
    this.batchTimeout = null;
  }
  
  checkDomain(domain) {
    return new Promise((resolve, reject) => {
      this.queue.push({ domain, resolve, reject });
      
      if (!this.batchTimeout) {
        this.batchTimeout = setTimeout(() => this.processBatch(), 100);
      }
    });
  }
  
  async processBatch() {
    const batch = this.queue.splice(0);
    this.batchTimeout = null;
    
    try {
      const domains = batch.map(item => item.domain);
      const response = await fetch('/api/threat-check-batch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targets: domains })
      });
      
      const results = await response.json();
      
      batch.forEach((item, index) => {
        item.resolve(results[index]);
      });
    } catch (error) {
      batch.forEach(item => item.reject(error));
    }
  }
}
```

## Security Considerations

### Content Security Policy

```html
<meta http-equiv="Content-Security-Policy" content="
  default-src 'self';
  script-src 'self' 'unsafe-inline' https://unpkg.com;
  connect-src 'self' https://your-api.com;
  worker-src 'self';
">
```

### Subresource Integrity

```html
<script 
  src="https://unpkg.com/trojanhorse-js@1.0.0/dist/trojanhorse.browser.min.js"
  integrity="sha384-[HASH]"
  crossorigin="anonymous">
</script>
```

## Troubleshooting

### Common Issues

**CORS Errors**
```javascript
// Use demo mode for development
const lookup = TrojanHorse.createLookup({ demoMode: true });

// Or implement backend proxy for production
```

**Memory Issues**
```javascript
// Clear cache periodically
setInterval(() => {
  trojan.clearCache();
}, 300000); // Every 5 minutes
```

**Service Worker Issues**
```javascript
// Check if service workers are supported
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js');
}
```

### Browser Support

| Feature | Chrome | Firefox | Safari | Edge |
|---------|--------|---------|---------|------|
| Basic API | 60+ | 55+ | 12+ | 79+ |
| IndexedDB | 24+ | 16+ | 10+ | 12+ |
| Web Workers | 4+ | 3.5+ | 4+ | 12+ |
| Service Workers | 45+ | 44+ | 11.1+ | 17+ |

## Production Checklist

- [ ] Implement backend proxy or serverless functions
- [ ] Configure proper CORS headers
- [ ] Set up error monitoring
- [ ] Implement rate limiting
- [ ] Add security headers (CSP, etc.)
- [ ] Test across target browsers
- [ ] Optimize bundle size
- [ ] Set up caching strategy
- [ ] Add loading states and error handling
- [ ] Monitor performance metrics

## Next Steps

- **[Production Deployment](production.md)** - Deploy to production
- **[Configuration Guide](../user-guide/configuration.md)** - Advanced settings
- **[API Reference](../api/core.md)** - Complete API docs
- **[Examples](../examples/basic.md)** - More usage examples

---

**Need help?** Check our [troubleshooting guide](production.md#troubleshooting) or join the [community discussions](https://github.com/sc4rfurry/TrojanHorse.js/discussions).
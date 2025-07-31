# 🌐 TrojanHorse.js Browser Examples

Complete examples for using TrojanHorse.js in static sites, CDN deployments, and browser environments.

## 🚀 Quick Start for Static Sites

### Option 1: CDN (Recommended)

```html
<!DOCTYPE html>
<html>
<head>
    <title>My Secure Site</title>
</head>
<body>
    <!-- Include TrojanHorse.js -->
    <script src="https://cdn.jsdelivr.net/npm/trojanhorse-js@latest/dist/trojanhorse.browser.min.js"></script>
    
    <script>
        // Simple threat checking
        async function checkURL(url) {
            const lookup = TrojanHorse.createLookup();
            const isMalicious = await lookup.checkURL(url);
            return !isMalicious; // Returns true if safe
        }
        
        // Use it
        checkURL('https://example.com').then(isSafe => {
            console.log('URL is safe:', isSafe);
        });
    </script>
</body>
</html>
```

### Option 2: Download and Host

1. Download the browser build:
   - Development: `trojanhorse.browser.js`
   - Production: `trojanhorse.browser.min.js`

2. Include in your HTML:

```html
<script src="path/to/trojanhorse.browser.min.js"></script>
```

## 📁 Available Builds

| Build | Size | Use Case |
|-------|------|----------|
| `trojanhorse.browser.js` | ~200KB | Development, debugging |
| `trojanhorse.browser.min.js` | ~80KB | Production CDN |
| `trojanhorse.browser.esm.js` | ~190KB | ES Modules |
| `trojanhorse.browser.iife.js` | ~200KB | Self-executing |

## 🛠️ Browser Compatibility

### ✅ Supported Browsers

- **Chrome/Edge**: Version 60+
- **Firefox**: Version 55+
- **Safari**: Version 11+
- **Mobile**: iOS 11+, Android 7+

### Required Features

- **Web Crypto API** (for encryption)
- **IndexedDB** (for caching)
- **Fetch API** (for network requests)
- **ES2018** (async/await, object spread)

### Compatibility Check

```javascript
// Check if browser is supported
const support = TrojanHorse.BrowserUtils.checkBrowserSupport();

if (support.supported) {
    console.log('✅ Browser fully supported');
} else {
    console.error('❌ Missing features:', support.missing);
}

if (support.warnings.length > 0) {
    console.warn('⚠️ Warnings:', support.warnings);
}
```

## 🎯 Usage Examples

### Basic Threat Lookup

```javascript
// Create lookup functions
const lookup = TrojanHorse.createLookup();

// Check different types
const isDomainMalicious = await lookup.checkDomain('example.com');
const isIPMalicious = await lookup.checkIP('192.168.1.1');
const isURLMalicious = await lookup.checkURL('https://example.com');
```

### Advanced Configuration

```javascript
// Create full TrojanHorse instance
const trojan = await TrojanHorse.create({
    // Optional: API keys for enhanced feeds
    apiKeys: {
        alienVault: 'your-api-key'
    },
    
    // Configure threat feeds
    feeds: ['urlhaus', 'alienvault'],
    
    // Storage configuration
    storage: {
        dbName: 'my-threat-cache',
        encryptionKey: 'your-encryption-key'
    }
});

// Use advanced features
const threats = await trojan.scout('suspicious-domain.com');
console.log('Threat analysis:', threats);
```

### Form Integration

```html
<form id="url-checker">
    <input type="url" id="url-input" placeholder="Enter URL to check">
    <button type="submit">Check Safety</button>
    <div id="result"></div>
</form>

<script>
document.getElementById('url-checker').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const url = document.getElementById('url-input').value;
    const resultDiv = document.getElementById('result');
    
    try {
        const lookup = TrojanHorse.createLookup();
        const isMalicious = await lookup.checkURL(url);
        
        if (isMalicious) {
            resultDiv.innerHTML = '⚠️ This URL appears to be malicious!';
            resultDiv.style.color = 'red';
        } else {
            resultDiv.innerHTML = '✅ This URL appears to be safe';
            resultDiv.style.color = 'green';
        }
    } catch (error) {
        resultDiv.innerHTML = `❌ Error: ${error.message}`;
        resultDiv.style.color = 'orange';
    }
});
</script>
```

### Link Scanner

```javascript
// Automatically scan all links on page
async function scanPageLinks() {
    const lookup = TrojanHorse.createLookup();
    const links = document.querySelectorAll('a[href]');
    
    for (const link of links) {
        try {
            const isMalicious = await lookup.checkURL(link.href);
            
            if (isMalicious) {
                link.style.border = '2px solid red';
                link.title = 'Warning: This link may be malicious';
                link.addEventListener('click', (e) => {
                    if (!confirm('This link appears to be malicious. Continue?')) {
                        e.preventDefault();
                    }
                });
            }
        } catch (error) {
            console.warn('Failed to check link:', link.href, error);
        }
    }
}

// Run on page load
document.addEventListener('DOMContentLoaded', scanPageLinks);
```

## 🔧 Configuration Options

### Basic Configuration

```javascript
const trojan = await TrojanHorse.create({
    // Which feeds to use
    feeds: ['urlhaus', 'alienvault'],
    
    // Storage settings
    storage: {
        dbName: 'threat-cache',
        maxSizeBytes: 10 * 1024 * 1024, // 10MB
        defaultTTL: 24 * 60 * 60 * 1000  // 24 hours
    }
});
```

### Security Settings

```javascript
const trojan = await TrojanHorse.create({
    security: {
        enforceHttps: true,
        autoLock: true,
        lockTimeout: 5 * 60 * 1000 // 5 minutes
    }
});
```

## 🚫 Error Handling

```javascript
try {
    const lookup = TrojanHorse.createLookup();
    const result = await lookup.checkDomain('example.com');
    console.log('Domain is safe:', !result);
} catch (error) {
    if (error.name === 'SecurityError') {
        console.error('Security error:', error.message);
    } else if (error.name === 'RateLimitError') {
        console.error('Rate limited, retry after:', error.retryAfter);
    } else {
        console.error('General error:', error.message);
    }
}
```

## 📱 Mobile Considerations

### Responsive Design

```css
/* Ensure inputs work well on mobile */
input[type="text"], input[type="url"] {
    font-size: 16px; /* Prevents zoom on iOS */
    padding: 12px;
}

button {
    min-height: 44px; /* iOS touch target minimum */
    font-size: 16px;
}
```

### Performance

```javascript
// Debounce user input for better performance
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

const debouncedCheck = debounce(async (value) => {
    const lookup = TrojanHorse.createLookup();
    const result = await lookup.checkDomain(value);
    // Update UI with result
}, 500);

// Use with input events
document.getElementById('domain-input').addEventListener('input', (e) => {
    debouncedCheck(e.target.value);
});
```

## 🔒 Security Best Practices

### 1. HTTPS Only

Always serve your static site over HTTPS when using TrojanHorse.js:

```javascript
// Check if running on HTTPS
if (!window.isSecureContext) {
    console.warn('TrojanHorse.js works best with HTTPS');
}
```

### 2. Content Security Policy

Add CSP headers to allow threat intelligence fetching:

```html
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; 
               connect-src 'self' https://urlhaus.abuse.ch https://otx.alienvault.com;
               script-src 'self' https://cdn.jsdelivr.net;">
```

### 3. API Key Protection

Never expose API keys in client-side code:

```javascript
// ❌ Don't do this
const trojan = await TrojanHorse.create({
    apiKeys: {
        alienVault: 'exposed-api-key' // Visible to users!
    }
});

// ✅ Instead, proxy through your backend
const response = await fetch('/api/check-threat', {
    method: 'POST',
    body: JSON.stringify({ url: 'example.com' })
});
```

## 📦 Building from Source

If you want to customize the browser build:

1. Clone the repository
2. Install dependencies: `npm install`
3. Build browser version: `npm run build:browser`
4. Find outputs in `dist/` directory

## 🎨 Styling the UI

The examples include responsive CSS. Customize the appearance:

```css
/* Threat result styling */
.threat-safe {
    background: #d4edda;
    color: #155724;
    border: 1px solid #c3e6cb;
    padding: 12px;
    border-radius: 6px;
}

.threat-danger {
    background: #f8d7da;
    color: #721c24;
    border: 1px solid #f5c6cb;
    padding: 12px;
    border-radius: 6px;
}
```

## 🐛 Debugging

### Enable Debug Mode

```javascript
// Enable detailed logging
localStorage.setItem('trojan-debug', 'true');

// Check browser console for detailed logs
const trojan = await TrojanHorse.create();
```

### Common Issues

1. **CORS Errors**: Some threat feeds may not work due to CORS. Use a proxy.
2. **Storage Quota**: IndexedDB has limits. Monitor usage.
3. **Rate Limiting**: Don't make too many requests too quickly.

## 📄 License

TrojanHorse.js is MIT licensed. See [LICENSE](../../LICENSE) for details.

---

**Need help?** Check out the [main documentation](../../README.md) or [open an issue](https://github.com/sc4rfurry/TrojanHorse.js/issues). 
# 🚨 CRITICAL SECURITY WARNING

## API Keys and Sensitive Data

**NEVER commit API keys or sensitive configuration to version control!**

### ❌ What NOT to commit:
- `trojanhorse.config.js` (contains your real API keys)
- `.env` files with secrets
- Any files with real API keys, passwords, or tokens

### ✅ What TO commit:
- `trojanhorse.config.example.js` (template with placeholder values)
- Documentation and source code
- Example configurations without real credentials

### Safe Configuration:

1. **Copy the example config:**
```bash
cp trojanhorse.config.example.js trojanhorse.config.js
```

2. **Add your real API keys to the copy:**
```javascript
// trojanhorse.config.js (DO NOT COMMIT THIS FILE!)
export default {
  apiKeys: {
    alienVault: 'your-real-api-key-here',
    abuseipdb: 'your-real-api-key-here',
    // ... other keys
  }
}
```

3. **Verify .gitignore excludes it:**
```bash
# Check that trojanhorse.config.js is ignored
git status
# Should NOT show trojanhorse.config.js as a new file
```

### Environment Variables (Recommended):

```bash
# .env file (also ignored by git)
ALIENVAULT_API_KEY=your-real-key
ABUSEIPDB_API_KEY=your-real-key
VIRUSTOTAL_API_KEY=your-real-key
CROWDSEC_API_KEY=your-real-key
```

### Production Deployment:

Use environment variables or secure secret management:

```bash
# Docker
docker run -e ALIENVAULT_API_KEY=real-key sc4rfurry/trojanhorse-js

# Kubernetes
kubectl create secret generic api-keys \
  --from-literal=alienvault-key=real-key \
  --from-literal=abuseipdb-key=real-key

# Cloud providers
# AWS: Parameter Store / Secrets Manager
# Azure: Key Vault
# GCP: Secret Manager
```

## Recovery if Keys Were Committed:

If you accidentally committed API keys:

1. **Immediately rotate all exposed keys**
2. **Remove from git history:**
```bash
# Remove file from git history
git filter-branch --force --index-filter \
  'git rm --cached --ignore-unmatch trojanhorse.config.js' \
  --prune-empty --tag-name-filter cat -- --all

# Force push (WARNING: destructive)
git push --force-with-lease origin main
```

3. **Notify your team about the security incident**

---

**Remember: Security is not optional! Protect your API keys like passwords.** 🔐
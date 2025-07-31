# Vault Management

Complete guide to secure API key storage, management, and rotation using TrojanHorse.js enterprise-grade vault system.

## Overview

The TrojanHorse.js vault system provides zero-knowledge encrypted storage for API keys and sensitive configuration data, with support for automatic rotation, enterprise authentication, and audit logging.

```mermaid
graph TB
    A[Vault Management] --> B[Encrypted Storage]
    A --> C[Key Rotation]
    A --> D[Access Control]
    A --> E[Audit Logging]
    
    B --> B1[AES-256-GCM]
    B --> B2[Argon2id KDF]
    B --> B3[Zero-Knowledge]
    
    C --> C1[Automatic Rotation]
    C --> C2[Graceful Transitions]
    C --> C3[Rollback Support]
    
    D --> D1[RBAC]
    D --> D2[MFA Required]
    D --> D3[Time-based Access]
    
    E --> E1[Access Logs]
    E --> E2[Change History]
    E --> E3[Compliance Reports]
```

## Getting Started

### Creating Your First Vault

```javascript
import { createVault, TrojanHorse } from 'trojanhorse-js';

// Create a new encrypted vault
const vault = await createVault({
  password: 'your-strong-master-password',
  
  encryption: {
    algorithm: 'aes-256-gcm',
    keyDerivation: 'argon2id',
    iterations: 100000
  },
  
  security: {
    autoLock: true,
    lockTimeout: 3600, // 1 hour
    maxAttempts: 3
  }
});

// Add API keys to vault
await vault.store('urlhaus', 'your-urlhaus-api-key');
await vault.store('virustotal', 'your-virustotal-api-key');
await vault.store('alienvault', 'your-alienvault-api-key');

// Save encrypted vault to file
await vault.save('./secure-vault.enc');
console.log('✅ Vault created and saved securely!');
```

### Loading and Using Existing Vault

```javascript
// Load existing vault
const trojan = new TrojanHorse();

// Load vault from encrypted file
await trojan.loadVault('./secure-vault.enc', 'your-master-password');

// Vault is now automatically used for API authentication
const threats = await trojan.scout('suspicious-domain.com');
console.log('Threats detected:', threats.length);
```

## Vault Configuration

### Advanced Vault Creation

```javascript
// Create vault with advanced configuration
const advancedVault = await createVault({
  // Master password configuration
  password: {
    value: 'your-complex-master-password',
    strength: 'enforced', // Check password strength
    rotation: {
      enabled: true,
      interval: '90d', // Rotate every 90 days
      notifyBefore: '7d' // Notify 7 days before rotation
    }
  },
  
  // Encryption settings
  encryption: {
    algorithm: 'aes-256-gcm',
    keySize: 256,
    ivSize: 96, // 12 bytes for GCM
    tagSize: 128, // 16 bytes auth tag
    
    keyDerivation: {
      algorithm: 'argon2id',
      memory: 65536, // 64 MB
      iterations: 3,
      parallelism: 4,
      saltSize: 32
    }
  },
  
  // Security policies
  security: {
    autoLock: true,
    lockTimeout: 1800, // 30 minutes
    maxAttempts: 5,
    lockoutDuration: 900, // 15 minutes
    
    authentication: {
      mfa: true,
      biometric: false,
      sessionTimeout: 3600
    },
    
    audit: {
      enabled: true,
      logAccess: true,
      logChanges: true,
      retention: '1y'
    }
  },
  
  // Backup and recovery
  backup: {
    enabled: true,
    frequency: 'daily',
    retention: 30, // Keep 30 backups
    encryption: true,
    offsite: {
      enabled: true,
      provider: 'aws-s3',
      bucket: 'trojanhorse-vault-backups'
    }
  }
});
```

### Environment-Specific Configuration

```javascript
// Development vault configuration
const devVault = await createVault({
  password: 'dev-password-123',
  security: {
    autoLock: false, // Disabled for development
    maxAttempts: 10,
    audit: { enabled: false }
  }
});

// Production vault configuration
const prodVault = await createVault({
  password: process.env.VAULT_MASTER_PASSWORD,
  security: {
    autoLock: true,
    lockTimeout: 900, // 15 minutes in production
    maxAttempts: 3,
    authentication: { mfa: true },
    audit: { 
      enabled: true,
      logAccess: true,
      compliance: 'SOC2'
    }
  },
  
  // Hardware Security Module support
  hsm: {
    enabled: true,
    provider: 'aws-cloudhsm',
    keyId: 'vault-master-key'
  }
});
```

## API Key Management

### Storing Different Key Types

```javascript
// Store various API key formats
await vault.store('urlhaus', 'simple-api-key-string');

// Store structured API keys
await vault.store('enterprise_service', {
  apiKey: 'complex-api-key',
  secretKey: 'secret-key',
  endpoint: 'https://api.enterprise.com',
  region: 'us-east-1'
});

// Store OAuth credentials
await vault.store('oauth_service', {
  clientId: 'oauth-client-id',
  clientSecret: 'oauth-client-secret',
  refreshToken: 'oauth-refresh-token',
  tokenUrl: 'https://oauth.provider.com/token'
});

// Store certificate-based authentication
await vault.store('cert_service', {
  certificate: '-----BEGIN CERTIFICATE-----\n...',
  privateKey: '-----BEGIN PRIVATE KEY-----\n...',
  passphrase: 'cert-passphrase'
});
```

### Retrieving and Using Keys

```javascript
// Retrieve simple API key
const apiKey = await vault.retrieve('urlhaus');
console.log('URLhaus API Key:', apiKey);

// Retrieve structured keys
const enterpriseConfig = await vault.retrieve('enterprise_service');
const client = new EnterpriseClient({
  apiKey: enterpriseConfig.apiKey,
  endpoint: enterpriseConfig.endpoint
});

// Batch retrieval for multiple services
const keys = await vault.retrieveBatch(['urlhaus', 'virustotal', 'alienvault']);
console.log('Retrieved keys:', Object.keys(keys));
```

### Key Validation

```javascript
// Validate API keys before storage
await vault.store('virustotal', 'vt-api-key', {
  validation: {
    enabled: true,
    testEndpoint: 'https://www.virustotal.com/vtapi/v2/file/report',
    testRequest: { apikey: '{API_KEY}', resource: 'test' },
    expectedResponse: { responseCode: 1 },
    timeout: 5000
  }
});

// Periodic key validation
vault.enablePeriodicValidation({
  interval: '24h',
  onFailure: 'notify', // 'disable', 'rotate', 'notify'
  notifications: ['email', 'slack', 'webhook']
});
```

## Key Rotation

### Automatic Key Rotation

```javascript
// Enable automatic key rotation
await vault.setupKeyRotation({
  services: {
    urlhaus: {
      enabled: true,
      interval: '30d',
      method: 'api', // 'manual', 'api', 'webhook'
      endpoint: 'https://urlhaus.abuse.ch/api/rotate',
      gracePeriod: '24h' // Keep old key for 24h
    },
    
    virustotal: {
      enabled: true,
      interval: '60d',
      method: 'manual',
      notifyBefore: '7d',
      contacts: ['admin@company.com']
    }
  },
  
  global: {
    maxAge: '90d', // Force rotation after 90 days
    warningPeriod: '7d',
    emergencyRotation: true
  }
});

// Handle rotation events
vault.on('keyRotationRequired', async (event) => {
  console.log(`Key rotation required for: ${event.service}`);
  await handleKeyRotation(event);
});

vault.on('keyRotationComplete', (event) => {
  console.log(`Key rotation completed for: ${event.service}`);
  logAuditEvent('key_rotation', event);
});
```

### Manual Key Rotation

```javascript
// Manual key rotation
const rotationResult = await vault.rotateKey('virustotal', {
  newKey: 'new-virustotal-api-key',
  
  validation: {
    testBeforeSwitch: true,
    fallbackOnFailure: true
  },
  
  transition: {
    gracePeriod: '24h',
    notifyUsers: true,
    updateDependentServices: true
  }
});

if (rotationResult.success) {
  console.log('✅ Key rotation successful');
} else {
  console.error('❌ Key rotation failed:', rotationResult.error);
}
```

### Batch Rotation

```javascript
// Rotate multiple keys at once
const batchRotation = await vault.rotateMultipleKeys({
  keys: {
    urlhaus: 'new-urlhaus-key',
    abuseipdb: 'new-abuseipdb-key',
    crowdsec: 'new-crowdsec-key'
  },
  
  options: {
    sequential: true, // Rotate one at a time
    rollbackOnFailure: true,
    maxConcurrency: 3,
    timeout: 300000 // 5 minutes total timeout
  }
});

console.log('Batch rotation results:', batchRotation);
```

## Access Control

### Role-Based Access Control (RBAC)

```javascript
// Configure RBAC for vault access
await vault.configureRBAC({
  roles: {
    admin: {
      permissions: ['read', 'write', 'delete', 'rotate', 'audit'],
      keys: ['*'], // Access to all keys
      conditions: {
        mfa: true,
        ipWhitelist: ['10.0.0.0/8', '192.168.0.0/16']
      }
    },
    
    analyst: {
      permissions: ['read'],
      keys: ['urlhaus', 'virustotal', 'alienvault'], // Limited key access
      conditions: {
        timeRestriction: '09:00-17:00',
        sessionTimeout: 3600
      }
    },
    
    service: {
      permissions: ['read'],
      keys: ['specific-service-key'],
      conditions: {
        certificateAuth: true,
        ipWhitelist: ['service-ip-range']
      }
    }
  },
  
  // User assignments
  users: {
    'admin@company.com': ['admin'],
    'analyst@company.com': ['analyst'],
    'service-account': ['service']
  }
});
```

### Multi-Factor Authentication

```javascript
// Enable MFA for vault access
await vault.configureMFA({
  methods: {
    totp: {
      enabled: true,
      issuer: 'TrojanHorse.js',
      algorithm: 'SHA256',
      digits: 6,
      period: 30
    },
    
    webauthn: {
      enabled: true,
      requireResidentKey: false,
      userVerification: 'required'
    },
    
    sms: {
      enabled: false, // Not recommended for production
      provider: 'twilio'
    }
  },
  
  policy: {
    required: true,
    backupCodes: 10,
    recoveryMethods: ['email', 'admin-override']
  }
});

// Setup MFA for user
const mfaSetup = await vault.setupMFA('admin@company.com');
console.log('MFA QR Code:', mfaSetup.qrCode);
console.log('Backup codes:', mfaSetup.backupCodes);
```

## Audit and Compliance

### Audit Logging

```javascript
// Configure comprehensive audit logging
await vault.configureAuditLogging({
  events: {
    access: true,
    modifications: true,
    authentication: true,
    errors: true,
    rotations: true
  },
  
  details: {
    userId: true,
    ipAddress: true,
    userAgent: true,
    timestamp: true,
    actionDetails: true,
    affectedKeys: true
  },
  
  storage: {
    local: {
      enabled: true,
      path: './vault-audit.log',
      rotation: 'daily',
      retention: '1y'
    },
    
    siem: {
      enabled: true,
      endpoint: 'https://siem.company.com/api/events',
      format: 'cef'
    },
    
    cloud: {
      enabled: true,
      provider: 'aws-cloudwatch',
      logGroup: 'trojanhorse-vault-audit'
    }
  }
});
```

### Compliance Reporting

```javascript
// Generate compliance reports
const complianceReport = await vault.generateComplianceReport({
  period: {
    start: '2025-01-01',
    end: '2025-01-31'
  },
  
  standards: ['SOC2', 'ISO27001', 'GDPR'],
  
  sections: {
    accessControl: true,
    dataProtection: true,
    auditTrail: true,
    incidentResponse: true,
    keyManagement: true
  },
  
  format: 'pdf',
  includeEvidence: true
});

console.log('Compliance report generated:', complianceReport.path);
```

## Enterprise Features

### High Availability Configuration

```javascript
// Configure vault for high availability
const haVault = await createVault({
  password: 'master-password',
  
  highAvailability: {
    enabled: true,
    
    clustering: {
      nodes: [
        'vault-node-1.company.com',
        'vault-node-2.company.com',
        'vault-node-3.company.com'
      ],
      consensus: 'raft',
      autoFailover: true
    },
    
    replication: {
      enabled: true,
      mode: 'synchronous',
      regions: ['us-east-1', 'us-west-2', 'eu-west-1']
    },
    
    backup: {
      continuous: true,
      crossRegion: true,
      encryption: true
    }
  }
});
```

### Integration with External Key Management

```javascript
// Integrate with external key management systems
await vault.integrateExternalKMS({
  providers: {
    aws_kms: {
      enabled: true,
      region: 'us-east-1',
      keyId: 'vault-master-key-id',
      role: 'vault-access-role'
    },
    
    azure_keyvault: {
      enabled: false,
      vaultUrl: 'https://company-vault.vault.azure.net/',
      keyName: 'vault-master-key'
    },
    
    hashicorp_vault: {
      enabled: true,
      endpoint: 'https://vault.company.com:8200',
      path: 'secret/trojanhorse',
      token: process.env.VAULT_TOKEN
    }
  },
  
  strategy: 'primary_external', // 'local_only', 'external_only', 'hybrid'
  fallback: 'local'
});
```

## Best Practices

### Security Recommendations

```javascript
// Implement security best practices
const secureVault = await createVault({
  password: generateStrongPassword(32),
  
  security: {
    // Strong encryption
    encryption: {
      algorithm: 'aes-256-gcm',
      keyDerivation: 'argon2id',
      iterations: 100000
    },
    
    // Strict access controls
    access: {
      autoLock: true,
      lockTimeout: 900, // 15 minutes
      maxAttempts: 3,
      sessionTimeout: 1800, // 30 minutes
      mfa: true
    },
    
    // Network security
    network: {
      tlsOnly: true,
      certificatePinning: true,
      ipWhitelist: true
    },
    
    // Monitoring
    monitoring: {
      failedAttempts: true,
      suspiciousActivity: true,
      dataExfiltration: true
    }
  }
});
```

### Operational Guidelines

1. **Regular Backups**: Ensure encrypted backups are created regularly
2. **Key Rotation**: Implement automatic key rotation for all services
3. **Access Reviews**: Conduct quarterly access reviews
4. **Monitoring**: Set up real-time monitoring and alerting
5. **Incident Response**: Have a plan for vault compromise scenarios

## Troubleshooting

### Common Issues

```javascript
// Handle common vault issues
vault.on('error', (error) => {
  switch (error.code) {
    case 'VAULT_LOCKED':
      console.log('Vault is locked. Please unlock with master password.');
      break;
      
    case 'INVALID_PASSWORD':
      console.error('Invalid master password provided.');
      break;
      
    case 'KEY_NOT_FOUND':
      console.error(`API key not found: ${error.keyName}`);
      break;
      
    case 'ROTATION_FAILED':
      console.error(`Key rotation failed: ${error.details}`);
      await handleRotationFailure(error);
      break;
      
    case 'VAULT_CORRUPTED':
      console.error('Vault file appears corrupted. Restoring from backup...');
      await restoreFromBackup();
      break;
  }
});
```

### Recovery Procedures

```javascript
// Vault recovery procedures
const recovery = {
  // Recover from backup
  restoreFromBackup: async (backupPath) => {
    const restoredVault = await vault.restore(backupPath, {
      verifyIntegrity: true,
      decryptionKey: 'backup-encryption-key'
    });
    return restoredVault;
  },
  
  // Emergency access
  emergencyAccess: async (recoveryCode) => {
    const emergency = await vault.emergencyUnlock(recoveryCode);
    return emergency;
  },
  
  // Reset master password
  resetMasterPassword: async (recoveryKeys) => {
    const reset = await vault.resetMasterPassword(recoveryKeys, {
      newPassword: generateStrongPassword(32),
      requireMFA: true
    });
    return reset;
  }
};
```

---

**Next Steps**:
- Learn about [Threat Detection](threat-detection.md) capabilities
- Configure [Event System](events.md) for real-time notifications  
- Review [Security Best Practices](../security/best-practices.md) for production deployment
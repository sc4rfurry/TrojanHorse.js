#!/usr/bin/env node

/**
 * TrojanHorse.js Basic Usage Example
 * 
 * This example demonstrates:
 * - Basic threat detection
 * - Secure vault creation and management
 * - Event handling
 * - Error handling best practices
 */

import { TrojanHorse, createVault } from '../dist/trojanhorse.esm.js';

async function basicThreatDetection() {
  console.log('🏰 TrojanHorse.js Basic Usage Example\n');

  try {
    // Initialize TrojanHorse with basic configuration
    const trojan = new TrojanHorse({
      sources: ['urlhaus'], // Free source, no API key required
      strategy: 'defensive',
      audit: {
        enabled: true,
        logLevel: 'info'
      }
    });

    console.log('✅ TrojanHorse initialized successfully\n');

    // Example 1: Basic threat detection
    console.log('🔍 Example 1: Basic Threat Detection');
    console.log('Scanning test domains...\n');

    const testTargets = [
      'google.com',           // Should be clean
      'example.com',          // Should be clean
      'test-malware.com'      // May have historical threats
    ];

    for (const target of testTargets) {
      try {
        console.log(`Scanning: ${target}`);
        const threats = await trojan.scout(target);
        
        if (threats.length > 0) {
          console.log(`  ⚠️  Found ${threats.length} threat(s):`);
          threats.forEach((threat, index) => {
            console.log(`    ${index + 1}. ${threat.type}: ${threat.value}`);
            console.log(`       Confidence: ${threat.confidence.toFixed(2)}`);
            console.log(`       Severity: ${threat.severity}`);
            console.log(`       Source: ${threat.source}`);
          });
        } else {
          console.log(`  ✅ No threats detected`);
        }
        console.log('');
      } catch (error) {
        console.error(`  ❌ Error scanning ${target}: ${error.message}\n`);
      }
    }

    // Example 2: Event handling
    console.log('🔊 Example 2: Event Handling');
    
    trojan.on('threat:detected', (threat) => {
      console.log(`🚨 Real-time threat detected: ${threat.value} (${threat.severity})`);
    });

    trojan.on('feed:updated', (source, count) => {
      console.log(`📊 Feed updated: ${source} - ${count} new indicators`);
    });

    // Example 3: System status
    console.log('📊 Example 3: System Status');
    const status = trojan.getStatus();
    console.log('System Status:');
    console.log(`  Vault Status: ${status.vault.isLocked ? '🔒 Locked' : '🔓 Unlocked'}`);
    console.log(`  Available Feeds: ${status.feeds.length}`);
    console.log(`  Crypto Implementation: ${status.crypto.implementation}`);
    console.log(`  Secure Context: ${status.security.secureContext ? '✅' : '⚠️'}\n`);

    // Example 4: Data export
    console.log('📤 Example 4: Data Export');
    const exportData = await trojan.plunder('json');
    console.log(`Exported data: ${exportData.length} characters\n`);

  } catch (error) {
    console.error('❌ Error in basic example:', error.message);
    console.error('Stack trace:', error.stack);
  }
}

async function vaultManagementExample() {
  console.log('🔐 Vault Management Example\n');

  try {
    // Create a secure vault for API keys
    console.log('Creating secure vault...');
    
    const apiKeys = {
      // These are example keys - use your real API keys
      alienVault: 'your-alienvault-otx-api-key-here',
      abuseipdb: 'your-abuseipdb-api-key-here'
    };

    const password = 'MySecurePassword123!@#';
    
    const { vault, trojan } = await createVault(password, apiKeys, {
      sources: ['urlhaus', 'alienvault', 'abuseipdb'],
      strategy: 'balanced'
    });

    console.log('✅ Vault created successfully');
    console.log(`Algorithm: ${vault.algorithm}`);
    console.log(`Key Derivation: ${vault.keyDerivation}`);
    console.log(`Timestamp: ${new Date(vault.timestamp).toISOString()}\n`);

    // Production vault saving to encrypted file
    console.log('💾 In production, save vault to secure storage:');
    console.log('```javascript');
    console.log('await fs.writeFile("secure-vault.json", JSON.stringify(vault));');
    console.log('```\n');

    // Show vault status
    const vaultStatus = trojan.getStatus().vault;
    console.log('Vault Status:');
    console.log(`  Locked: ${vaultStatus.isLocked}`);
    console.log(`  Key Count: ${vaultStatus.keyCount}`);
    console.log(`  Auto-lock Enabled: ${vaultStatus.autoLockEnabled}\n`);

    // Lock the vault
    console.log('🔒 Locking vault...');
    trojan.lock();
    console.log('✅ Vault locked\n');

    // Unlock the vault
    console.log('🔓 Unlocking vault...');
    await trojan.unlock(password);
    console.log('✅ Vault unlocked\n');

    // Use the vault for threat detection with API keys
    console.log('🔍 Using vault-protected API keys for enhanced detection...');
    const enhancedThreats = await trojan.scout('suspicious-domain.com');
    console.log(`Enhanced scan complete: ${enhancedThreats.length} indicators found\n`);

  } catch (error) {
    console.error('❌ Error in vault example:', error.message);
    
    // Handle specific error types
    if (error.name === 'SecurityError') {
      console.error('This is a security-related error. Check your configuration.');
    } else if (error.name === 'AuthenticationError') {
      console.error('Authentication failed. Check your password or API keys.');
    }
  }
}

async function performanceExample() {
  console.log('⚡ Performance Example\n');

  try {
    const trojan = new TrojanHorse({
      sources: ['urlhaus'],
      strategy: 'balanced'
    });

    // Batch processing example
    const targets = [
      'example.com',
      'test.com',
      'sample.org',
      'demo.net',
      'placeholder.io'
    ];

    console.log(`🚀 Processing ${targets.length} targets in batch...`);
    const startTime = Date.now();

    // Process all targets concurrently
    const results = await Promise.allSettled(
      targets.map(target => trojan.scout(target))
    );

    const endTime = Date.now();
    const processingTime = endTime - startTime;

    console.log(`✅ Batch processing completed in ${processingTime}ms`);
    console.log(`Average: ${(processingTime / targets.length).toFixed(1)}ms per target\n`);

    // Results summary
    const successful = results.filter(r => r.status === 'fulfilled').length;
    const failed = results.filter(r => r.status === 'rejected').length;
    const totalThreats = results
      .filter(r => r.status === 'fulfilled')
      .reduce((sum, r) => sum + r.value.length, 0);

    console.log('📊 Batch Results:');
    console.log(`  Successful: ${successful}/${targets.length}`);
    console.log(`  Failed: ${failed}/${targets.length}`);
    console.log(`  Total Threats: ${totalThreats}`);
    console.log(`  Throughput: ${(targets.length / processingTime * 1000).toFixed(2)} req/sec\n`);

  } catch (error) {
    console.error('❌ Error in performance example:', error.message);
  }
}

// Main execution
async function main() {
  console.log('🎯 TrojanHorse.js Comprehensive Examples\n');
  console.log('This example demonstrates real-world usage patterns.\n');
  console.log('='.repeat(60) + '\n');

  try {
    await basicThreatDetection();
    console.log('='.repeat(60) + '\n');
    
    await vaultManagementExample();
    console.log('='.repeat(60) + '\n');
    
    await performanceExample();
    console.log('='.repeat(60) + '\n');

    console.log('🎉 All examples completed successfully!');
    console.log('\nNext steps:');
    console.log('  1. Check the API documentation: ./API_DOCUMENTATION.md');
    console.log('  2. Explore enterprise features: ./examples/enterprise-setup.js');
    console.log('  3. Set up production deployment: ./PRODUCTION_DEPLOYMENT.md');

  } catch (error) {
    console.error('💥 Example execution failed:', error.message);
    process.exit(1);
  }
}

// Handle unhandled rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  process.exit(1);
});

// Run the examples
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
} 
#!/usr/bin/env node
// ============================================================================
// AiDA — Ed25519 Key Pair Generator
// ============================================================================
// Generates an Ed25519 signing key pair for the license server.
//
// Usage:
//   node generate-keys.js [output-dir]
//
// Output:
//   ed25519_private.pem    — PEM-encoded PKCS#8 private key (for .env)
//   ed25519_public.pem     — PEM-encoded public key (for client embedding)
//   ed25519_private_b64.txt — Base64 DER private key (paste into .env)
//   ed25519_public_b64.txt  — Base64 DER public key (for reference)
//
// The ED25519_PRIVATE_KEY_B64 value from ed25519_private_b64.txt goes into
// the server .env file.
// ============================================================================

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const outputDir = process.argv[2] || '/opt/aida/keys';

// Generate Ed25519 key pair
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');

// Export in multiple formats for different uses
const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
const publicPem = publicKey.export({ type: 'spki', format: 'pem' });
const privateDer = privateKey.export({ type: 'pkcs8', format: 'der' });
const publicDer = publicKey.export({ type: 'spki', format: 'der' });

const privateB64 = privateDer.toString('base64');
const publicB64 = publicDer.toString('base64');

// Ensure output directory exists
if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true, mode: 0o700 });
}

// Write files
const files = {
    'ed25519_private.pem': privatePem,
    'ed25519_public.pem': publicPem,
    'ed25519_private_b64.txt': privateB64,
    'ed25519_public_b64.txt': publicB64,
};

for (const [filename, content] of Object.entries(files)) {
    const filePath = path.join(outputDir, filename);
    fs.writeFileSync(filePath, content, { mode: 0o600 });
    console.log(`  Written: ${filePath}`);
}

console.log('\n── Ed25519 Key Pair Generated ──────────────────────────────');
console.log(`  Output directory: ${outputDir}`);
console.log(`\n  For server .env, paste this as ED25519_PRIVATE_KEY_B64:`);
console.log(`  ${privateB64}`);
console.log(`\n  Public key (PEM) for client verification:`);
console.log(publicPem);

// Verify the key pair works
const testPayload = Buffer.from('test');
const sig = crypto.sign(null, testPayload, privateKey);
const valid = crypto.verify(null, testPayload, publicKey, sig);
console.log(`  Key pair self-test: ${valid ? 'PASSED' : 'FAILED'}`);

if (!valid) {
    console.error('\n  ERROR: Key pair self-test failed! Do NOT use these keys.');
    process.exit(1);
}

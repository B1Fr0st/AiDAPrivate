#!/usr/bin/env node


const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const outputDir = process.argv[2] || '/opt/aida/keys';


const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');


const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
const publicPem = publicKey.export({ type: 'spki', format: 'pem' });
const privateDer = privateKey.export({ type: 'pkcs8', format: 'der' });
const publicDer = publicKey.export({ type: 'spki', format: 'der' });

const privateB64 = privateDer.toString('base64');
const publicB64 = publicDer.toString('base64');


if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true, mode: 0o700 });
}


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


const testPayload = Buffer.from('test');
const sig = crypto.sign(null, testPayload, privateKey);
const valid = crypto.verify(null, testPayload, publicKey, sig);
console.log(`  Key pair self-test: ${valid ? 'PASSED' : 'FAILED'}`);

if (!valid) {
    console.error('\n  ERROR: Key pair self-test failed! Do NOT use these keys.');
    process.exit(1);
}

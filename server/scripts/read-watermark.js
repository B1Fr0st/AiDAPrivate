#!/usr/bin/env node


const crypto = require('crypto');
const fs = require('fs');

const args = process.argv.slice(2);
if (args.length < 2) {
    console.error('Usage: ARC_MASTER_SECRET=<secret> node read-watermark.js <AiDA.exe> <license_key>');
    process.exit(1);
}

const filePath = args[0];
const licenseKey = args[1];
const masterSecret = process.env.ARC_MASTER_SECRET;

if (!masterSecret || masterSecret.length < 32) {
    console.error('Error: ARC_MASTER_SECRET environment variable must be at least 32 characters');
    process.exit(1);
}

if (!fs.existsSync(filePath)) {
    console.error(`Error: File not found: ${filePath}`);
    process.exit(1);
}

const data = fs.readFileSync(filePath);
if (data.length < 258) {
    console.error('Error: File too small to contain a watermark');
    process.exit(1);
}


const block = Buffer.from(data.subarray(data.length - 256));
const originalBinary = data.subarray(0, data.length - 256);


const trailerTimestamp = Number(block.readBigUInt64LE(8));
const streamKey = crypto.createHash('sha256')
    .update('watermark-stream|', 'utf8')
    .update(String(licenseKey), 'utf8')
    .update('|', 'utf8')
    .update(String(trailerTimestamp), 'utf8')
    .update('|', 'utf8')
    .update(masterSecret, 'utf8')
    .digest();
for (let i = 0; i < 256; i++) {
    if (i >= 8 && i < 16) continue;
    block[i] ^= streamKey[i % 32];
}


const magic = block.readUInt32BE(0);
const version = block.readUInt32BE(4);

if (magic !== 0xA1DA0001) {
    console.error(`Error: No AiDA watermark found (magic: 0x${magic.toString(16).padStart(8, '0')})`);
    console.error('This binary may not be watermarked, or the ARC_MASTER_SECRET is wrong.');
    process.exit(1);
}

const timestamp = Number(block.readBigUInt64LE(8));
const identityHmac = block.subarray(16, 48).toString('hex');
const binaryHash = block.subarray(48, 80).toString('hex');
const keyHash = block.subarray(80, 144).toString('hex');
const hwidHash = block.subarray(144, 176).toString('hex');
const ipHash = block.subarray(176, 192).toString('hex');
const integrityHmac = block.subarray(192, 224).toString('hex');


const expectedIntegrity = crypto.createHmac('sha256', masterSecret)
    .update(block.subarray(0, 192))
    .digest('hex');
const integrityValid = expectedIntegrity === integrityHmac;


const actualBinaryHash = crypto.createHash('sha256').update(originalBinary).digest('hex');
const binaryHashValid = actualBinaryHash === binaryHash;

const downloadDate = new Date(timestamp * 1000);

console.log('============================================================================');
console.log('  AiDA Binary Watermark Analysis');
console.log('============================================================================');
console.log(`  File:              ${filePath}`);
console.log(`  File size:         ${data.length} bytes (${originalBinary.length} + 256 watermark)`);
console.log(`  Watermark version: ${version}`);
console.log(`  Download time:     ${downloadDate.toISOString()} (${timestamp})`);
console.log(`  Identity HMAC:     ${identityHmac}`);
console.log(`  Binary SHA-256:    ${binaryHash}`);
console.log(`  License key hash:  ${keyHash.substring(0, 64)}...`);
console.log(`  HWID hash:         ${hwidHash}`);
console.log(`  IP hash (MD5):     ${ipHash}`);
console.log('----------------------------------------------------------------------------');
console.log(`  Integrity check:   ${integrityValid ? 'PASSED ✓' : 'FAILED ✗ (watermark may be tampered)'}`);
console.log(`  Binary hash check: ${binaryHashValid ? 'PASSED ✓' : 'FAILED ✗ (binary may be modified)'}`);
console.log('============================================================================');

if (!integrityValid) {
    console.log('\n  WARNING: The watermark integrity check FAILED.');
    console.log('  This could mean the binary was modified after distribution,');
    console.log('  or the ARC_MASTER_SECRET does not match the one used during distribution.');
}


console.log('\n  To identify the license holder, run this query on the server:');
console.log(`  SELECT key, hwid, note, plan FROM licenses`);
console.log('  Then compute SHA-512(key) and SHA-256(hwid) for each row');
console.log('  and compare against the hashes above.');

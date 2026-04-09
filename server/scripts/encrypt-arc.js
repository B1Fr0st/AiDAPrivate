#!/usr/bin/env node


const crypto = require('crypto');
const fs = require('fs');

const args = process.argv.slice(2);
if (args.length < 2) {
    console.error('Usage: ARC_MASTER_SECRET=<secret> node encrypt-arc.js <input.dll> <output.bin>');
    process.exit(1);
}

const [inputPath, outputPath] = args;
const masterSecret = process.env.ARC_MASTER_SECRET;

if (!masterSecret || masterSecret.length < 32) {
    console.error('Error: ARC_MASTER_SECRET environment variable must be at least 32 characters');
    process.exit(1);
}

if (!fs.existsSync(inputPath)) {
    console.error(`Error: Input file not found: ${inputPath}`);
    process.exit(1);
}

const plaintext = fs.readFileSync(inputPath);


if (plaintext.length < 2 || plaintext[0] !== 0x4D || plaintext[1] !== 0x5A) {
    console.error('Error: Input file does not have a valid MZ (PE) header');
    process.exit(1);
}


const atRestKey = crypto.createHash('sha256')
    .update(`arc-at-rest|${masterSecret}`)
    .digest();

const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv('aes-256-gcm', atRestKey, iv);
const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
const authTag = cipher.getAuthTag();


const output = Buffer.concat([iv, authTag, encrypted]);
fs.writeFileSync(outputPath, output);

console.log(`Encrypted ${plaintext.length} bytes → ${output.length} bytes`);
console.log(`  Input:  ${inputPath}`);
console.log(`  Output: ${outputPath}`);
console.log(`  SHA-256 of plaintext: ${crypto.createHash('sha256').update(plaintext).digest('hex')}`);

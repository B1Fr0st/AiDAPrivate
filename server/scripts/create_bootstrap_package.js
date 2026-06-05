'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const MAGIC = Buffer.from('AIDABOOTPKG1\n', 'ascii');

function arg(name) {
    const idx = process.argv.indexOf(name);
    if (idx < 0 || idx + 1 >= process.argv.length) return '';
    return process.argv[idx + 1];
}

function keyFromEnv(name) {
    const raw = String(process.env[name] || '').trim();
    if (!raw) throw new Error(`${name} is required`);
    const key = Buffer.from(raw, 'base64');
    if (key.length !== 32) throw new Error(`${name} must decode to 32 bytes`);
    return key;
}

function sha256Hex(buf) {
    return crypto.createHash('sha256').update(buf).digest('hex');
}

const inputPath = path.resolve(arg('--input'));
const outputPath = path.resolve(arg('--output'));
if (!inputPath || !outputPath || inputPath === process.cwd() || outputPath === process.cwd()) {
    throw new Error('usage: node server/scripts/create_bootstrap_package.js --input <exe> --output <pkg>');
}

const encKey = keyFromEnv('AIDA_BOOTSTRAP_PACKAGE_ENC_KEY_B64');
const macKey = keyFromEnv('AIDA_BOOTSTRAP_PACKAGE_MAC_KEY_B64');
const plain = fs.readFileSync(inputPath);
const iv = crypto.randomBytes(16);
const cipher = crypto.createCipheriv('aes-256-cbc', encKey, iv);
const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
const body = Buffer.concat([MAGIC, iv, ciphertext]);
const tag = crypto.createHmac('sha256', macKey).update(body).digest();
const pkg = Buffer.concat([body, tag]);

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, pkg, { mode: 0o600 });

const result = {
    output: outputPath,
    plaintext_sha256: sha256Hex(plain),
    plaintext_size: plain.length,
    package_sha256: sha256Hex(pkg),
    package_size: pkg.length,
};

console.log(JSON.stringify(result));

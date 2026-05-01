'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

let s_sodium = null;
let s_sodiumReady = false;

function tryLoadSodium() {
    if (s_sodium) return s_sodium;
    try {
        s_sodium = require('libsodium-wrappers');
        return s_sodium;
    } catch (_) {
        s_sodium = null;
        return null;
    }
}

async function ensureSodiumReady() {
    const sodium = tryLoadSodium();
    if (!sodium) return false;
    if (s_sodiumReady) return true;
    await sodium.ready;
    s_sodiumReady = true;
    return true;
}

const KEY_LEN = 32;
const SALT_LEN = 16;

function defaultHsmPath() {
    const explicit = process.env.LOCAL_HSM_PATH;
    if (explicit && explicit.length > 0) return explicit;
    const dir = path.join(__dirname, '..', 'keys');
    return path.join(dir, 'local_hsm.bin');
}

function defaultHsmPassphrase() {
    const explicit = process.env.LOCAL_HSM_PASSPHRASE;
    if (explicit && explicit.length > 0) return explicit;
    const arc = process.env.ARC_MASTER_SECRET || '';
    if (arc.length === 0) {
        throw new Error('local_hsm: neither LOCAL_HSM_PASSPHRASE nor ARC_MASTER_SECRET is set; cannot derive HSM passphrase');
    }
    return arc;
}

function deriveHsmKekScrypt(passphrase, salt) {
    const N = parseInt(process.env.LOCAL_HSM_SCRYPT_N || '16384', 10);
    const r = parseInt(process.env.LOCAL_HSM_SCRYPT_R || '8', 10);
    const p = parseInt(process.env.LOCAL_HSM_SCRYPT_P || '1', 10);
    const maxmem = 64 * 1024 * 1024;
    return crypto.scryptSync(Buffer.from(passphrase, 'utf8'), salt, KEY_LEN, { N, r, p, maxmem });
}

function restrictFilePermissions(filePath) {
    if (process.platform === 'win32') {
        try {
            fs.chmodSync(filePath, 0o600);
        } catch (_) { }
        try {
            const { execFileSync } = require('child_process');
            const user = process.env.USERNAME || os.userInfo().username || '';
            if (user) {
                execFileSync('icacls', [filePath, '/inheritance:r'], { stdio: 'ignore' });
                execFileSync('icacls', [filePath, '/grant:r', `${user}:F`], { stdio: 'ignore' });
            }
        } catch (_) { }
        return;
    }
    try {
        fs.chmodSync(filePath, 0o600);
    } catch (_) { }
}

function ensureDirectory(filePath) {
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
}

function readEnvelope(filePath) {
    const buf = fs.readFileSync(filePath);
    if (buf.length < 1) throw new Error('local_hsm: envelope file empty');
    const magic = buf.subarray(0, 4).toString('utf8');
    if (magic !== 'AHSM') throw new Error('local_hsm: bad magic header');
    const version = buf[4];
    if (version !== 1) throw new Error('local_hsm: unsupported envelope version ' + version);
    const algoId = buf[5];
    if (algoId !== 1 && algoId !== 2) {
        throw new Error('local_hsm: unsupported algo id ' + algoId);
    }
    const salt = buf.subarray(6, 6 + SALT_LEN);
    const rest = buf.subarray(6 + SALT_LEN);
    return { algoId, salt, rest };
}

async function unsealWithSodium(passphrase, salt, rest) {
    const sodium = tryLoadSodium();
    if (!sodium) throw new Error('local_hsm: sodium algo selected but libsodium-wrappers not installed');
    if (!s_sodiumReady) await sodium.ready;
    s_sodiumReady = true;
    const opslimit = parseInt(process.env.LOCAL_HSM_SODIUM_OPSLIMIT || String(sodium.crypto_pwhash_OPSLIMIT_MODERATE), 10);
    const memlimit = parseInt(process.env.LOCAL_HSM_SODIUM_MEMLIMIT || String(sodium.crypto_pwhash_MEMLIMIT_MODERATE), 10);
    const kek = sodium.crypto_pwhash(
        sodium.crypto_secretbox_KEYBYTES,
        passphrase,
        salt,
        opslimit,
        memlimit,
        sodium.crypto_pwhash_ALG_ARGON2ID13
    );
    const nonce = rest.subarray(0, sodium.crypto_secretbox_NONCEBYTES);
    const cipher = rest.subarray(sodium.crypto_secretbox_NONCEBYTES);
    const opened = sodium.crypto_secretbox_open_easy(cipher, nonce, kek);
    if (!opened || opened.length !== KEY_LEN) {
        throw new Error('local_hsm: sodium open failed or wrong key length');
    }
    return Buffer.from(opened);
}

function unsealWithScrypt(passphrase, salt, rest) {
    const kek = deriveHsmKekScrypt(passphrase, salt);
    const IV_LEN = 12;
    const TAG_LEN = 16;
    if (rest.length < IV_LEN + TAG_LEN + KEY_LEN) {
        throw new Error('local_hsm: scrypt envelope truncated');
    }
    const iv = rest.subarray(0, IV_LEN);
    const tag = rest.subarray(IV_LEN, IV_LEN + TAG_LEN);
    const ct = rest.subarray(IV_LEN + TAG_LEN);
    const decipher = crypto.createDecipheriv('aes-256-gcm', kek, iv);
    decipher.setAuthTag(tag);
    const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
    if (pt.length !== KEY_LEN) {
        throw new Error('local_hsm: unwrapped key length mismatch');
    }
    return pt;
}

async function sealWithSodium(passphrase, salt, key) {
    const sodium = tryLoadSodium();
    if (!sodium) return null;
    if (!s_sodiumReady) await sodium.ready;
    s_sodiumReady = true;
    const opslimit = parseInt(process.env.LOCAL_HSM_SODIUM_OPSLIMIT || String(sodium.crypto_pwhash_OPSLIMIT_MODERATE), 10);
    const memlimit = parseInt(process.env.LOCAL_HSM_SODIUM_MEMLIMIT || String(sodium.crypto_pwhash_MEMLIMIT_MODERATE), 10);
    const kek = sodium.crypto_pwhash(
        sodium.crypto_secretbox_KEYBYTES,
        passphrase,
        salt,
        opslimit,
        memlimit,
        sodium.crypto_pwhash_ALG_ARGON2ID13
    );
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
    const cipher = sodium.crypto_secretbox_easy(key, nonce, kek);
    return Buffer.concat([Buffer.from(nonce), Buffer.from(cipher)]);
}

function sealWithScrypt(passphrase, salt, key) {
    const kek = deriveHsmKekScrypt(passphrase, salt);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', kek, iv);
    const ct = Buffer.concat([cipher.update(key), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, tag, ct]);
}

function loadOrCreateColumnRootKey() {
    const filePath = defaultHsmPath();
    const passphrase = defaultHsmPassphrase();
    if (fs.existsSync(filePath)) {
        const env = readEnvelope(filePath);
        if (env.algoId === 1) {
            return unsealWithScrypt(passphrase, env.salt, env.rest);
        }
        if (env.algoId === 2) {
            const sodium = tryLoadSodium();
            if (!sodium) {
                throw new Error('local_hsm: envelope was sealed with sodium but libsodium-wrappers is not installed; install it or set LOCAL_HSM_FORCE_SCRYPT=1 and recreate the file');
            }
            const buf = Buffer.alloc(0);
            throw new Error('local_hsm: sodium-sealed envelope requires async unseal via initializeColumnRootKeyAsync');
        }
        throw new Error('local_hsm: unknown algoId ' + env.algoId);
    }
    return createColumnRootKeySync(filePath, passphrase);
}

async function initializeColumnRootKeyAsync() {
    const filePath = defaultHsmPath();
    const passphrase = defaultHsmPassphrase();
    if (fs.existsSync(filePath)) {
        const env = readEnvelope(filePath);
        if (env.algoId === 1) {
            return unsealWithScrypt(passphrase, env.salt, env.rest);
        }
        if (env.algoId === 2) {
            return await unsealWithSodium(passphrase, env.salt, env.rest);
        }
        throw new Error('local_hsm: unknown algoId ' + env.algoId);
    }
    return await createColumnRootKeyAsync(filePath, passphrase);
}

function createColumnRootKeySync(filePath, passphrase) {
    ensureDirectory(filePath);
    const key = crypto.randomBytes(KEY_LEN);
    const salt = crypto.randomBytes(SALT_LEN);
    const sealed = sealWithScrypt(passphrase, salt, key);
    const header = Buffer.alloc(6);
    header.write('AHSM', 0, 4, 'utf8');
    header[4] = 1;
    header[5] = 1;
    const envelope = Buffer.concat([header, salt, sealed]);
    fs.writeFileSync(filePath, envelope, { mode: 0o600 });
    restrictFilePermissions(filePath);
    return key;
}

async function createColumnRootKeyAsync(filePath, passphrase) {
    if (process.env.LOCAL_HSM_FORCE_SCRYPT === '1') {
        return createColumnRootKeySync(filePath, passphrase);
    }
    const sodium = tryLoadSodium();
    if (!sodium) {
        return createColumnRootKeySync(filePath, passphrase);
    }
    if (!s_sodiumReady) await sodium.ready;
    s_sodiumReady = true;
    ensureDirectory(filePath);
    const key = Buffer.from(sodium.randombytes_buf(KEY_LEN));
    const salt = Buffer.from(sodium.randombytes_buf(SALT_LEN));
    const sealed = await sealWithSodium(passphrase, salt, key);
    if (!sealed) {
        return createColumnRootKeySync(filePath, passphrase);
    }
    const header = Buffer.alloc(6);
    header.write('AHSM', 0, 4, 'utf8');
    header[4] = 1;
    header[5] = 2;
    const envelope = Buffer.concat([header, salt, sealed]);
    fs.writeFileSync(filePath, envelope, { mode: 0o600 });
    restrictFilePermissions(filePath);
    return key;
}

function exportEnvelopePathForDocs() {
    return defaultHsmPath();
}

module.exports = {
    loadOrCreateColumnRootKey,
    initializeColumnRootKeyAsync,
    exportEnvelopePathForDocs,
    ensureSodiumReady,
};

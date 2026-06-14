'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const kwWrap = require('./kw_wrap');
const signing = require('./signing');

const PACKED_MAGIC = 0x41504B44;
const PACKED_VERSION = 0x00030000;
const PACKED_HEADER_SIZE = 96;
const AUX_MAGIC = 0x4D585541;
const AUX_VERSION = 0x00030000;
const AUX_SIZE = 368;
const AUX_WATERMARK_OFFSET = 24;
const AUX_WATERMARK_SIZE = 16;
const AUX_WATERMARK_HASH_OFFSET = 40;
const AUX_WATERMARK_HASH_SIZE = 32;
const FOOTER_MAGIC = Buffer.from('AIDA_CAPSULE_V1\0', 'ascii');
const FOOTER_VERSION = 1;
const FOOTER_SIZE = 104;
const SECRET_WRAP_LABEL = 'standalone_capsule_secret/v1';

function sha256Hex(value) {
    return crypto.createHash('sha256').update(value).digest('hex');
}

function base64Url(buf) {
    return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function serverKeyMaterial(label) {
    const direct = String(process.env.SERVER_MASTER_KEY_B64 || '').trim();
    if (direct) {
        const buf = Buffer.from(direct, 'base64');
        if (buf.length !== 32) throw new Error('customer_capsule_server_master_key_invalid');
        return crypto.createHmac('sha256', buf).update(String(label || ''), 'utf8').digest();
    }
    const arc = String(process.env.ARC_MASTER_SECRET || '');
    if (!arc || arc.length < 32) throw new Error('customer_capsule_server_key_unavailable');
    return crypto.createHmac('sha256', Buffer.from(arc, 'utf8')).update(String(label || ''), 'utf8').digest();
}

function hmacHex(label, value) {
    return crypto.createHmac('sha256', serverKeyMaterial('aida/customer-capsule/hmac-key/v1'))
        .update(String(label || ''), 'utf8')
        .update('\0', 'utf8')
        .update(String(value || ''), 'utf8')
        .digest('hex');
}

function markerForCustomer(capsuleId, licenseKey, discordId) {
    return crypto.createHmac('sha256', serverKeyMaterial('aida/customer-capsule/watermark-key/v1'))
        .update(String(capsuleId || ''), 'utf8')
        .update('\0', 'utf8')
        .update(String(licenseKey || ''), 'utf8')
        .update('\0', 'utf8')
        .update(String(discordId || ''), 'utf8')
        .digest()
        .subarray(0, AUX_WATERMARK_SIZE);
}

function readUInt32LE(buf, off) {
    if (!Buffer.isBuffer(buf) || off < 0 || off + 4 > buf.length) return null;
    return buf.readUInt32LE(off);
}

function parsePeSections(buf) {
    if (!Buffer.isBuffer(buf) || buf.length < 0x100) return [];
    if (buf.readUInt16LE(0) !== 0x5A4D) return [];
    const peOff = readUInt32LE(buf, 0x3c);
    if (!Number.isInteger(peOff) || peOff <= 0 || peOff + 0x18 > buf.length) return [];
    if (buf.readUInt32LE(peOff) !== 0x00004550) return [];
    const sectionCount = buf.readUInt16LE(peOff + 6);
    const optionalSize = buf.readUInt16LE(peOff + 20);
    const sectionTable = peOff + 24 + optionalSize;
    if (sectionCount <= 0 || sectionCount > 96 || sectionTable <= 0 || sectionTable + sectionCount * 40 > buf.length) return [];
    const sections = [];
    for (let i = 0; i < sectionCount; ++i) {
        const off = sectionTable + i * 40;
        const rawSize = buf.readUInt32LE(off + 16);
        const rawPtr = buf.readUInt32LE(off + 20);
        if (rawPtr > 0 && rawSize > 0 && rawPtr < buf.length) {
            sections.push({
                raw_ptr: rawPtr,
                raw_size: Math.min(rawSize, buf.length - rawPtr),
            });
        }
    }
    return sections;
}

function patchAuxBlock(exe, marker) {
    const out = Buffer.from(exe);
    const sections = parsePeSections(out);
    for (const section of sections) {
        const base = section.raw_ptr;
        if (section.raw_size < PACKED_HEADER_SIZE || base + PACKED_HEADER_SIZE > out.length) continue;
        const magic = out.readUInt32LE(base);
        const version = out.readUInt32LE(base + 4);
        if (magic !== PACKED_MAGIC || version !== PACKED_VERSION) continue;
        const auxOffset = out.readUInt32LE(base + 60);
        const auxSize = out.readUInt32LE(base + 64);
        if (auxOffset <= 0 || auxSize !== AUX_SIZE) continue;
        const auxAbs = base + auxOffset;
        if (auxAbs < base || auxAbs + AUX_SIZE > out.length || auxOffset + AUX_SIZE > section.raw_size) continue;
        if (out.readUInt32LE(auxAbs) !== AUX_MAGIC || out.readUInt32LE(auxAbs + 4) !== AUX_VERSION) continue;
        marker.copy(out, auxAbs + AUX_WATERMARK_OFFSET, 0, AUX_WATERMARK_SIZE);
        const markerHash = crypto.createHash('sha256').update(marker).digest();
        markerHash.copy(out, auxAbs + AUX_WATERMARK_HASH_OFFSET, 0, AUX_WATERMARK_HASH_SIZE);
        return {
            buffer: out,
            aux_patched: true,
            packed_header_offset: base,
            aux_offset: auxAbs,
        };
    }
    return {
        buffer: out,
        aux_patched: false,
        packed_header_offset: null,
        aux_offset: null,
    };
}

function resolveBaseExePath() {
    const explicit = String(process.env.AIDA_STANDALONE_BASE_EXE || '').trim();
    const repoRoot = path.resolve(__dirname, '..', '..');
    const candidates = [];
    if (explicit) candidates.push(path.resolve(explicit));
    candidates.push(path.join(repoRoot, 'private', 'AiDAStandalone.base.exe'));
    candidates.push(path.join(repoRoot, 'private', 'AiDAStandalone.exe'));
    candidates.push(path.join(repoRoot, 'build-ninja', 'Release', 'AiDAStandalone.exe'));
    candidates.push(path.join(repoRoot, 'build', 'Release', 'AiDAStandalone.exe'));
    for (const candidate of candidates) {
        try {
            const st = fs.statSync(candidate);
            if (st.isFile() && st.size > 0) return candidate;
        } catch (_) {
        }
    }
    return '';
}

function loadBaseExe() {
    const exePath = resolveBaseExePath();
    if (!exePath) throw new Error('customer_standalone_base_exe_unavailable');
    const buffer = fs.readFileSync(exePath);
    if (!Buffer.isBuffer(buffer) || buffer.length < 0x100 || buffer.readUInt16LE(0) !== 0x5A4D) {
        throw new Error('customer_standalone_base_exe_invalid');
    }
    return {
        path: exePath,
        buffer,
        base_sha256: sha256Hex(buffer),
        base_size: buffer.length,
        base_version: String(process.env.AIDA_STANDALONE_BASE_VERSION || process.env.AIDA_BOOTSTRAP_ARTIFACT_VERSION || 'current').trim() || 'current',
    };
}

function appendFooter(exe, capsulePayload) {
    const capsuleJson = Buffer.from(JSON.stringify(capsulePayload), 'utf8');
    const baseSha = crypto.createHash('sha256').update(exe).digest();
    const capsuleSha = crypto.createHash('sha256').update(capsuleJson).digest();
    const footer = Buffer.alloc(FOOTER_SIZE);
    FOOTER_MAGIC.copy(footer, 0);
    footer.writeUInt32LE(FOOTER_VERSION, 16);
    footer.writeUInt32LE(FOOTER_SIZE, 20);
    footer.writeBigUInt64LE(BigInt(capsuleJson.length), 24);
    footer.writeBigUInt64LE(BigInt(exe.length), 32);
    baseSha.copy(footer, 40);
    capsuleSha.copy(footer, 72);
    return {
        output: Buffer.concat([exe, capsuleJson, footer]),
        capsule_json: capsuleJson,
        base_sha256: baseSha.toString('hex'),
        capsule_sha256: capsuleSha.toString('hex'),
    };
}

function createPersonalizedExe(opts) {
    const base = opts && opts.base ? opts.base : loadBaseExe();
    const now = Number(opts && opts.issued_at) || Math.floor(Date.now() / 1000);
    const expiresAt = Number(opts && opts.expires_at) || (now + 300);
    const capsuleId = (opts && opts.capsule_id) || crypto.randomUUID();
    const licenseKey = String(opts && opts.license_key || '');
    const discordId = String(opts && opts.discord_id || '');
    const hwid = String(opts && opts.hwid || '').trim();
    const secret = Buffer.isBuffer(opts && opts.secret) ? Buffer.from(opts.secret) : crypto.randomBytes(32);
    const marker = markerForCustomer(capsuleId, licenseKey, discordId);
    const patched = patchAuxBlock(base.buffer, marker);
    const patchedBaseSha256 = sha256Hex(patched.buffer);
    const licenseIdentityHash = hmacHex('license', licenseKey);
    const discordIdentityHash = hmacHex('discord', discordId);
    const hwidHash = hwid ? hmacHex('hwid', hwid) : '';
    const signatureKid = signing.activeKidForCanonical();
    const capsule = {
        version: 1,
        capsule_id: capsuleId,
        base_sha256: patchedBaseSha256,
        source_base_sha256: base.base_sha256,
        base_size: patched.buffer.length,
        base_version: base.base_version,
        issued_at: now,
        expires_at: expiresAt,
        license_identity_hash: licenseIdentityHash,
        discord_identity_hash: discordIdentityHash,
        hwid_hash: hwidHash,
        aux_patched: patched.aux_patched === true,
        proof_algorithm: 'aida/customer-standalone-capsule/v1+ed25519+hmac-sha256+kw-aes256-gcm',
        signature_kid: signatureKid,
        secret_b64: secret.toString('base64'),
        secret_b64u: base64Url(secret),
        marker_hex: marker.toString('hex'),
    };
    const signed = signing.signWithKid(capsule);
    const signedCapsule = Object.assign({}, capsule, {
        kid: signed.kid,
        signature_alg: 'Ed25519',
        signature_hex: signed.signature,
        canonical_sha256: sha256Hex(Buffer.from(signed.canonical, 'utf8')),
    });
    const appended = appendFooter(patched.buffer, signedCapsule);
    return {
        output: appended.output,
        envelope: signedCapsule,
        capsule: signedCapsule,
        capsule_sha256: appended.capsule_sha256,
        base,
        aux_patched: patched.aux_patched === true,
        marker_hex: marker.toString('hex'),
        secret_wrapped: kwWrap.wrap(secret, SECRET_WRAP_LABEL),
    };
}

function parseFooter(exe) {
    if (!Buffer.isBuffer(exe) || exe.length < FOOTER_SIZE) return null;
    const footerStart = exe.length - FOOTER_SIZE;
    const footer = exe.subarray(footerStart);
    if (!crypto.timingSafeEqual(footer.subarray(0, FOOTER_MAGIC.length), FOOTER_MAGIC)) return null;
    const version = footer.readUInt32LE(16);
    const footerSize = footer.readUInt32LE(20);
    const capsuleSize = Number(footer.readBigUInt64LE(24));
    const baseSize = Number(footer.readBigUInt64LE(32));
    if (version !== FOOTER_VERSION || footerSize !== FOOTER_SIZE) return null;
    if (!Number.isSafeInteger(capsuleSize) || !Number.isSafeInteger(baseSize)) return null;
    if (capsuleSize <= 0 || baseSize <= 0 || baseSize + capsuleSize + FOOTER_SIZE !== exe.length) return null;
    const baseSha = footer.subarray(40, 72).toString('hex');
    const capsuleSha = footer.subarray(72, 104).toString('hex');
    const actualBaseSha = sha256Hex(exe.subarray(0, baseSize));
    const capsuleBytes = exe.subarray(baseSize, baseSize + capsuleSize);
    const actualCapsuleSha = sha256Hex(capsuleBytes);
    if (baseSha !== actualBaseSha || capsuleSha !== actualCapsuleSha) return null;
    const parsed = JSON.parse(capsuleBytes.toString('utf8'));
    return {
        footer_magic: FOOTER_MAGIC.toString('ascii').replace(/\0+$/, ''),
        footer_version: version,
        footer_size: footerSize,
        base_size: baseSize,
        capsule_size: capsuleSize,
        base_sha256: baseSha,
        capsule_sha256: capsuleSha,
        capsule: parsed,
        signature_alg: parsed.signature_alg || '',
        signature_hex: parsed.signature_hex || '',
    };
}

module.exports = {
    PACKED_MAGIC,
    PACKED_VERSION,
    AUX_MAGIC,
    AUX_VERSION,
    AUX_SIZE,
    FOOTER_MAGIC,
    FOOTER_SIZE,
    SECRET_WRAP_LABEL,
    hmacHex,
    markerForCustomer,
    patchAuxBlock,
    resolveBaseExePath,
    loadBaseExe,
    appendFooter,
    createPersonalizedExe,
    parseFooter,
};

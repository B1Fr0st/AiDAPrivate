

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const pool = require('../db/pool');
const { encryptPage, splitIntoPages, deriveChainTag } = require('../crypto/arc-encrypt');
const arcLicenseBind = require('../crypto/arc-license-bind');
const columnCrypt = require('../crypto/column_crypt');
const licenseRateLimit = require('../middleware/license_rate_limit');
const canonicalResponse = require('../crypto/canonical_response');
const auditLog = require('../middleware/audit_log');
const pageKeys = require('../crypto/page_keys');
const { signPayload } = require('../crypto/signing');

const router = express.Router();

const DOWNLOAD_EAUTH_BUDGET_MS = parseInt(process.env.DOWNLOAD_EAUTH_BUDGET_MS || '250', 10) || 250;
const DOWNLOAD_EAUTH_JITTER_MS = parseInt(process.env.DOWNLOAD_EAUTH_JITTER_MS || '20', 10) || 20;
const DOWNLOAD_EAUTH_BODY = JSON.stringify({ ok: false, error_code: 'EAUTH' });
const DOWNLOAD_EAUTH_LENGTH = Buffer.byteLength(DOWNLOAD_EAUTH_BODY, 'utf8');

function dlJitter() {
    if (DOWNLOAD_EAUTH_JITTER_MS <= 0) return 0;
    return crypto.randomInt(0, DOWNLOAD_EAUTH_JITTER_MS + 1);
}

async function sendDownloadEauth(res, startedAt) {
    const elapsed = Date.now() - (startedAt || Date.now());
    const target = DOWNLOAD_EAUTH_BUDGET_MS + dlJitter();
    const remaining = target - elapsed;
    if (remaining > 0) {
        await new Promise(resolve => setTimeout(resolve, remaining));
    }
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Length', String(DOWNLOAD_EAUTH_LENGTH));
    res.setHeader('Cache-Control', 'no-store');
    return res.status(401).send(DOWNLOAD_EAUTH_BODY);
}

async function gateLicenseRate(req, res) {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const licenseKey = typeof body.license_key === 'string' ? body.license_key.trim() : '';
    if (!licenseKey) return true;
    const rl = await licenseRateLimit.check(licenseKey, {});
    if (!rl.ok) {
        auditLog.logV2({
            action: 'download.rate_limit',
            license_key: licenseKey,
            source_ip: (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.ip || '',
            user_agent: req.headers['user-agent'] || '',
            decision: 'deny',
            reason_code: 'rate_limited:' + (rl.scope || ''),
            extra: { retry_after: rl.retry_after || 0 },
        }).catch(() => {});
        await sendDownloadEauth(res, req._reqStart || Date.now());
        return false;
    }
    return true;
}

router.use(async (req, res, next) => {
    req._reqStart = Date.now();
    try {
        const cont = await gateLicenseRate(req, res);
        if (!cont) return;
        next();
    } catch (err) {
        return sendDownloadEauth(res, req._reqStart);
    }
});


function decryptSessionRowLocal(row) {
    if (!row) return row;
    const uuid = typeof row.session_uuid === 'string' ? row.session_uuid : '';
    if (!uuid) return row;
    if (typeof row.session_token === 'string' && columnCrypt.isCiphertext(row.session_token)) {
        try {
            row.session_token = columnCrypt.decrypt(uuid, 'sessions/session_token', row.session_token);
        } catch (err) {
            console.error('[download] session_token decrypt failed for', row.license_key, err && err.message);
            row.session_token = '';
        }
    }
    if (typeof row.last_proof_token === 'string' && row.last_proof_token.length > 0
        && columnCrypt.isCiphertext(row.last_proof_token)) {
        try {
            row.last_proof_token = columnCrypt.decrypt(uuid, 'sessions/last_proof_token', row.last_proof_token);
        } catch (err) {
            console.error('[download] last_proof_token decrypt failed for', row.license_key, err && err.message);
            row.last_proof_token = '';
        }
    }
    return row;
}


const ARC_BLOB_PATH = process.env.ARC_BLOB_PATH || '/opt/aida/arc/aida_core.bin';


let cachedArcBlob = null;


function loadArcBlob() {
    if (cachedArcBlob) return cachedArcBlob;

    if (!fs.existsSync(ARC_BLOB_PATH)) {
        throw new Error(`ARC blob not found at ${ARC_BLOB_PATH}`);
    }

    const raw = fs.readFileSync(ARC_BLOB_PATH);


    if (raw.length < 28) {
        throw new Error('ARC blob file is too small — corrupt or invalid');
    }

    const iv = raw.subarray(0, 12);
    const authTag = raw.subarray(12, 28);
    const ciphertext = raw.subarray(28);

    const masterSecret = process.env.ARC_MASTER_SECRET;
    if (!masterSecret || masterSecret.length < 32) {
        throw new Error('ARC_MASTER_SECRET must be at least 32 characters');
    }


    const atRestKey = crypto.createHash('sha256')
        .update(`arc-at-rest|${masterSecret}`)
        .digest();

    const decipher = crypto.createDecipheriv('aes-256-gcm', atRestKey, iv);
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final(),
    ]);


    if (decrypted.length < 2 || decrypted[0] !== 0x4D || decrypted[1] !== 0x5A) {
        throw new Error('Decrypted ARC blob does not have valid MZ header');
    }

    cachedArcBlob = decrypted;
    console.log(`[arc] Loaded ARC blob: ${decrypted.length} bytes`);
    return cachedArcBlob;
}


const TRANSFORMED_BLOB_TTL_MS = 30 * 60 * 1000;
const transformedArcBlobCache = new Map();

function getTransformedArcBlob(sessionRow, licenseRow) {
    if (!sessionRow || typeof sessionRow.session_token !== 'string' || sessionRow.session_token.length === 0) {
        throw new Error('arc_transform_missing_session_token');
    }
    const sessionToken = sessionRow.session_token;
    const now = Date.now();
    const cached = transformedArcBlobCache.get(sessionToken);
    if (cached && cached.blob && (now - cached.ts) < TRANSFORMED_BLOB_TTL_MS) {
        cached.ts = now;
        return cached.blob;
    }
    const baseBlob = loadArcBlob();
    const transformed = arcLicenseBind.applyLicenseTransform(baseBlob, licenseRow, sessionRow);
    transformedArcBlobCache.set(sessionToken, { blob: transformed, ts: now });
    return transformed;
}

function evictTransformedArcBlob(sessionToken) {
    if (!sessionToken || typeof sessionToken !== 'string') return;
    transformedArcBlobCache.delete(sessionToken);
}

function purgeExpiredTransformedBlobs() {
    const now = Date.now();
    for (const [token, entry] of transformedArcBlobCache) {
        if (!entry || !entry.blob || (now - entry.ts) >= TRANSFORMED_BLOB_TTL_MS) {
            transformedArcBlobCache.delete(token);
        }
    }
}

setInterval(purgeExpiredTransformedBlobs, 5 * 60 * 1000).unref();

function currentStreamingEpoch() {
    return pageKeys.currentEpoch(Math.floor(Date.now() / 1000));
}

function validateClientEpoch(clientEpoch, currentEpoch) {
    if (clientEpoch === undefined || clientEpoch === null || clientEpoch === '') return null;
    const n = Number(clientEpoch);
    if (!Number.isFinite(n) || !Number.isInteger(n) || n < 0) {
        return { stale: false, invalid: true };
    }
    if (n !== currentEpoch) {
        return { stale: true, invalid: false };
    }
    return null;
}


async function validateSession(licenseKey, sessionToken, hwid) {
    if (!licenseKey || !sessionToken || !hwid) {
        return { valid: false, reason: 'missing_fields' };
    }


    const banResult = await pool.query(
        'SELECT 1 FROM bans WHERE (ban_type = $1 AND value = $2) LIMIT 1',
        ['hwid', hwid]
    );
    if (banResult.rows.length > 0) {
        return { valid: false, reason: 'banned' };
    }


    const { rows: licRows } = await pool.query(
        'SELECT * FROM licenses WHERE key = $1',
        [licenseKey]
    );
    if (licRows.length === 0 || !licRows[0].active) {
        return { valid: false, reason: 'invalid_license' };
    }
    const license = licRows[0];
    if (license.expires && license.expires !== '' && license.expires < new Date().toISOString().slice(0, 10)) {
        return { valid: false, reason: 'expired' };
    }


    const { rows: sesRows } = await pool.query(
        'SELECT * FROM sessions WHERE license_key = $1',
        [licenseKey]
    );
    if (sesRows.length === 0) {
        return { valid: false, reason: 'session_mismatch' };
    }
    const session = decryptSessionRowLocal(sesRows[0]);
    if (session.session_token !== sessionToken) {
        return { valid: false, reason: 'session_mismatch' };
    }


    if (session.hwid && session.hwid !== hwid) {
        return { valid: false, reason: 'hwid_mismatch' };
    }


    const now = Math.floor(Date.now() / 1000);
    const graceFactor = parseFloat(process.env.SESSION_TTL_GRACE_FACTOR || '1.1') || 1.1;
    if (session.issued_at && session.ttl) {
        const expiresAt = session.issued_at + Math.floor(session.ttl * graceFactor);
        if (now > expiresAt) {
            evictTransformedArcBlob(session.session_token);
            return { valid: false, reason: 'session_expired' };
        }
    }

    if (session.kill_flag) {
        evictTransformedArcBlob(session.session_token);
    }

    return { valid: true, session, license };
}

router.post('/streaming/info', async (req, res) => {
    try {
        const { license_key, session_token, hwid, client_epoch } = req.body || {};
        const validation = await validateSession(license_key, session_token, hwid);
        if (!validation.valid) {
            return res.status(403).json({ status: 'error', reason: validation.reason });
        }

        const currentEpoch = currentStreamingEpoch();
        const epochCheck = validateClientEpoch(client_epoch, currentEpoch);
        if (epochCheck && epochCheck.invalid) {
            return res.status(400).json({ status: 'error', reason: 'invalid_client_epoch' });
        }
        if (epochCheck && epochCheck.stale) {
            return res.status(409).json({ status: 'error', reason: 'epoch_stale', current_epoch: currentEpoch });
        }

        const arcBlob = loadArcBlob();
        const totalPages = pageKeys.getPageCount(arcBlob.length);
        const epochNonce = pageKeys.epochNonce(currentEpoch, session_token, hwid);
        const responsePayload = {
            status: 'ok',
            total_pages: totalPages,
            page_size: pageKeys.PAGE_SIZE_BYTES,
            blob_size: arcBlob.length,
            current_epoch: currentEpoch,
            epoch_nonce: epochNonce.toString('hex'),
        };
        responsePayload.signature = signPayload(responsePayload);
        return res.json(responsePayload);
    } catch (err) {
        console.error('[arc-streaming/info] error:', err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

router.post('/page/:idx', async (req, res) => {
    try {
        const pageIndex = Number(req.params.idx);
        if (!Number.isInteger(pageIndex) || pageIndex < 0) {
            return res.status(400).json({ status: 'error', reason: 'invalid_page_index' });
        }

        const { license_key, session_token, hwid, client_epoch } = req.body || {};
        const validation = await validateSession(license_key, session_token, hwid);
        if (!validation.valid) {
            return res.status(403).json({ status: 'error', reason: validation.reason });
        }

        const currentEpoch = currentStreamingEpoch();
        const epochCheck = validateClientEpoch(client_epoch, currentEpoch);
        if (epochCheck && epochCheck.invalid) {
            return res.status(400).json({ status: 'error', reason: 'invalid_client_epoch' });
        }
        if (epochCheck && epochCheck.stale) {
            return res.status(409).json({ status: 'error', reason: 'epoch_stale', current_epoch: currentEpoch });
        }

        const arcBlob = loadArcBlob();
        const bounds = pageKeys.pageBoundsForBlob(arcBlob.length, pageIndex);
        if (!bounds) {
            return res.status(404).json({ status: 'error', reason: 'page_not_found' });
        }

        const totalPages = pageKeys.getPageCount(arcBlob.length);
        const plaintext = arcBlob.subarray(bounds.start, bounds.end);
        const enc = pageKeys.encryptPage(plaintext, license_key, session_token, hwid, pageIndex, currentEpoch);
        const responsePayload = {
            status: 'ok',
            page_index: pageIndex,
            total_pages: totalPages,
            page_size: pageKeys.PAGE_SIZE_BYTES,
            blob_size: arcBlob.length,
            current_epoch: currentEpoch,
            epoch_nonce: pageKeys.epochNonce(currentEpoch, session_token, hwid).toString('hex'),
            data: enc.ciphertext.toString('base64'),
            iv: enc.iv.toString('hex'),
            auth_tag: enc.authTag.toString('hex'),
            hmac: enc.hmac.toString('hex'),
        };
        responsePayload.signature = signPayload(responsePayload);
        return res.json(responsePayload);
    } catch (err) {
        console.error('[arc-page] error:', err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});




router.post('/arc/pages/bulk', async (req, res) => {
    const t0 = Date.now();
    try {
        const { license_key, session_token, hwid, proof_token } = req.body || {};
        const lkPrefix = (typeof license_key === 'string' ? license_key : '').slice(0, 10);
        const hwidPrefix = (typeof hwid === 'string' ? hwid : '').slice(0, 12);
        console.warn(`[arc-bulk] request_entered lk_prefix=${lkPrefix} hwid_prefix=${hwidPrefix} ` +
            `has_session_token=${session_token ? 1 : 0} has_proof_token=${proof_token ? 1 : 0}`);

        const validation = await validateSession(license_key, session_token, hwid);
        if (!validation.valid) {
            console.warn(`[arc-bulk] validate_session_failed reason=${validation.reason} lk_prefix=${lkPrefix}`);
            return res.status(403).json({ status: 'error', reason: validation.reason });
        }
        console.warn(`[arc-bulk] validate_session_ok lk_prefix=${lkPrefix} hwid_prefix=${hwidPrefix}`);

        const session = validation.session;
        const license = validation.license;

        if (session.kill_flag) {
            console.warn(`[arc-bulk] kill_flag_set lk_prefix=${lkPrefix}`);
            return res.status(403).json({ status: 'error', reason: 'killed' });
        }

        const lastProof = session.last_proof_token || '';
        const clientProof = proof_token || '';
        if (!clientProof || (lastProof && clientProof !== lastProof)) {
            console.warn(`[arc-bulk] stale_proof_token last_proof_len=${lastProof.length} client_proof_len=${clientProof.length} lk_prefix=${lkPrefix}`);
            return res.status(403).json({ status: 'error', reason: 'stale_proof_token' });
        }
        console.warn(`[arc-bulk] proof_token_ok lk_prefix=${lkPrefix} client_proof_len=${clientProof.length}`);

        let arcBlob;
        try {
            arcBlob = getTransformedArcBlob(session, license);
        } catch (err) {
            console.error(`[arc-bulk] arc_blob_load_failed err=${err && err.message ? err.message : err} lk_prefix=${lkPrefix}`);
            return res.status(503).json({ status: 'error', reason: 'service_unavailable' });
        }
        console.warn(`[arc-bulk] arc_blob_loaded size=${arcBlob.length} lk_prefix=${lkPrefix}`);

        const rawPages = splitIntoPages(arcBlob);
        const totalPages = rawPages.length;
        console.warn(`[arc-bulk] pages_split total=${totalPages} page_size=4096 blob_size=${arcBlob.length}`);

        let prevChainTag = '';
        const pages = [];
        const digest = crypto.createHash('sha256');

        const licenseeIdBulk = arcLicenseBind.deriveLicenseeId(license);
        console.warn(`[arc-bulk] licensee_id_derived id_prefix=${(licenseeIdBulk || '').slice(0, 16)}`);

        const codeBindingTuples = [];
        const issuedAtNow = Math.floor(Date.now() / 1000);
        let codeBindFailures = 0;
        const loopStart = Date.now();
        for (let pageIndex = 0; pageIndex < rawPages.length; pageIndex++) {
            const { encrypted, iv, authTag, hmac } = encryptPage(
                rawPages[pageIndex],
                pageIndex,
                session.session_token,
                hwid,
                session.issued_at,
                clientProof,
                prevChainTag
            );
            const nextChainTag = deriveChainTag(prevChainTag, authTag).toString('hex');
            let codeBindingSig = '';
            let codeBindingDigest = '';
            try {
                const bindingResult = arcLicenseBind.signCodePage(license, session, hwid, pageIndex, encrypted);
                codeBindingSig = bindingResult.signature.toString('hex');
                codeBindingDigest = bindingResult.digest.toString('hex');
                codeBindingTuples.push([license_key, pageIndex, codeBindingDigest, codeBindingSig, issuedAtNow]);
            } catch (bindErr) {
                codeBindFailures++;
                console.warn(`[arc-bulk] code_binding_signing_failed page=${pageIndex} err=${bindErr && bindErr.message ? bindErr.message : bindErr}`);
            }
            const pagePayload = {
                status: 'ok',
                page_index: pageIndex,
                total_pages: totalPages,
                blob_size: arcBlob.length,
                data: encrypted.toString('base64'),
                iv: iv.toString('hex'),
                auth_tag: authTag.toString('hex'),
                hmac: hmac.toString('hex'),
                page_trailer: buildPageWatermark(license_key, hwid, pageIndex, session.session_token).toString('hex'),
                code_binding_sig: codeBindingSig,
                code_binding_digest: codeBindingDigest,
                licensee_id: licenseeIdBulk,
            };
            digest.update(String(pagePayload.page_index));
            digest.update('|');
            digest.update(pagePayload.data);
            digest.update('|');
            digest.update(pagePayload.iv);
            digest.update('|');
            digest.update(pagePayload.auth_tag);
            digest.update('|');
            digest.update(pagePayload.hmac);
            digest.update('|');
            digest.update(pagePayload.page_trailer);
            digest.update('|');
            digest.update(pagePayload.code_binding_sig);
            digest.update('\n');
            pages.push(pagePayload);
            prevChainTag = nextChainTag;
        }
        const loopMs = Date.now() - loopStart;
        console.warn(`[arc-bulk] pages_loop_done total=${totalPages} elapsed_ms=${loopMs} code_bind_failures=${codeBindFailures}`);

        if (codeBindingTuples.length > 0) {
            try {
                const valuesSql = [];
                const params = [];
                let pi = 1;
                for (const tuple of codeBindingTuples) {
                    valuesSql.push(`($${pi++}, $${pi++}, $${pi++}, $${pi++}, $${pi++})`);
                    params.push(tuple[0], tuple[1], tuple[2], tuple[3], tuple[4]);
                }
                await pool.query(
                    `INSERT INTO code_page_signatures (license_key, page_index, page_digest, page_signature, issued_at)
                     VALUES ${valuesSql.join(', ')}
                     ON CONFLICT (license_key, page_index) DO UPDATE SET
                        page_digest = EXCLUDED.page_digest,
                        page_signature = EXCLUDED.page_signature,
                        issued_at = EXCLUDED.issued_at`,
                    params
                );
                console.warn(`[arc-bulk] code_page_signatures_upserted rows=${codeBindingTuples.length}`);
            } catch (storeErr) {
                console.warn(`[arc-bulk] code_page_signatures_upsert_failed err=${storeErr && storeErr.message ? storeErr.message : storeErr}`);
            }
        } else {
            console.warn(`[arc-bulk] code_page_signatures_skipped reason=no_tuples`);
        }

        await pool.query(
            'UPDATE sessions SET last_chain_tag = $1 WHERE license_key = $2',
            [prevChainTag, license_key]
        );
        console.warn(`[arc-bulk] chain_tag_persisted last_chain_tag_prefix=${prevChainTag.slice(0, 16)}`);

        const pagesDigestHex = digest.digest('hex');
        const signedPayload = {
            status: 'ok',
            total_pages: totalPages,
            page_size: 4096,
            blob_size: arcBlob.length,
            pages_digest: pagesDigestHex,
            licensee_id: licenseeIdBulk,
        };

        const envelope = canonicalResponse.buildEnvelope({
            ...signedPayload,
            pages,
        });
        const payloadLen = typeof envelope.payload === 'string' ? envelope.payload.length : 0;
        const sigLen = typeof envelope.sig === 'string' ? envelope.sig.length : 0;
        console.warn(`[arc-bulk] envelope_built kid=${envelope.kid} payload_b64_len=${payloadLen} sig_b64_len=${sigLen} pages=${pages.length} pages_digest_prefix=${pagesDigestHex.slice(0, 16)}`);

        const elapsedMs = Date.now() - t0;
        console.warn(`[arc-bulk] response_sending status=200 elapsed_ms=${elapsedMs} lk_prefix=${lkPrefix}`);
        return res.json(envelope);
    } catch (err) {
        const elapsedMs = Date.now() - t0;
        console.error(`[arc-bulk] handler_exception err=${err && err.message ? err.message : err} elapsed_ms=${elapsedMs}`);
        if (err && err.stack) console.error(`[arc-bulk] handler_exception_stack ${err.stack}`);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

function buildPageWatermark(licenseKey, hwid, pageIndex, sessionToken) {
    const masterSecret = process.env.ARC_MASTER_SECRET || '';
    const trailer = Buffer.alloc(64, 0);
    trailer.writeUInt32BE(0xA1DA0002, 0);
    trailer.writeUInt32BE(pageIndex >>> 0, 4);
    const identity = crypto.createHmac('sha256', masterSecret)
        .update(`${licenseKey}|${hwid}|${pageIndex}|${sessionToken}`)
        .digest();
    identity.copy(trailer, 8, 0, 24);
    const integrity = crypto.createHmac('sha256', masterSecret)
        .update(trailer.subarray(0, 32))
        .digest();
    integrity.copy(trailer, 32, 0, 32);
    return trailer;
}

function envelopeJson(res, status, payload) {
    return res.status(status).json(canonicalResponse.buildEnvelope(payload || {}));
}

module.exports = router;
module.exports.envelopeJson = envelopeJson;

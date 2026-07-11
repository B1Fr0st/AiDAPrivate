'use strict';

const crypto = require('crypto');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const pool = require('../db/pool');

const PERSONALIZER_PATH = process.env.AIDA_PERSONALIZER_PATH || '/var/aida/bin/protector_personalize.exe';
const PERSONALIZER_SHA256 = String(process.env.AIDA_PERSONALIZER_SHA256 || '').trim().toLowerCase();
const TEMPLATE_DIR = process.env.AIDA_TEMPLATE_DIR || '/var/aida/templates';
const OUTPUT_DIR = process.env.AIDA_OUTPUT_DIR || '/var/aida/output';
const TMP_DIR = process.env.AIDA_BUILD_TMP_DIR || '/var/aida/tmp';
const BUILD_TIMEOUT_SECONDS = parseInt(process.env.AIDA_BUILD_TIMEOUT_SECONDS || '60', 10);
const ADAPTIVE_EXTENSION_SECONDS = parseInt(process.env.AIDA_BUILD_ADAPTIVE_EXTENSION_SECONDS || '30', 10);
const OUTPUT_TTL_SECONDS = parseInt(process.env.AIDA_OUTPUT_TTL_SECONDS || '3600', 10);
const CLEANUP_INTERVAL_SECONDS = parseInt(process.env.AIDA_BUILD_CLEANUP_INTERVAL_SECONDS || '300', 10);
const TEMPLATE_GRACE_SECONDS = 30 * 24 * 60 * 60;
const POLL_INTERVAL_MS = 1000;
const MAX_BUILD_TIMEOUT_MS = (BUILD_TIMEOUT_SECONDS + ADAPTIVE_EXTENSION_SECONDS) * 1000;
const PACKED_MAGIC = 0x41504B44;

let s_running = false;
let s_currentJob = null;
let s_cleanupTimer = null;
let s_pollTimer = null;
let s_enqueueResolver = null;
let s_personalizerVerified = false;
let s_shuttingDown = false;

function nowSec() {
    return Math.floor(Date.now() / 1000);
}

function log(msg) {
    console.log(`[build_queue] ${msg}`);
}

function logError(msg) {
    console.error(`[build_queue] ${msg}`);
}

function outputFilename(buildId) {
    return `AiDAStandalone_${buildId}.exe`;
}

function outputPath(buildId) {
    return path.join(OUTPUT_DIR, outputFilename(buildId));
}

function templateFilename(version) {
    return `AiDAStandalone_template_v${version}.exe`;
}

function templatePath(version) {
    return path.join(TEMPLATE_DIR, templateFilename(version));
}

function parsePeSections(buf) {
    if (!Buffer.isBuffer(buf) || buf.length < 0x100) return [];
    if (buf.readUInt16LE(0) !== 0x5A4D) return [];
    const peOff = buf.readUInt32LE(0x3c);
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

function hasPackedMagic(filePath) {
    try {
        const fd = fs.openSync(filePath, 'r');
        try {
            const headerSize = Math.min(4096, fs.statSync(filePath).size);
            const buf = Buffer.alloc(headerSize);
            fs.readSync(fd, buf, 0, headerSize, 0);
            const sections = parsePeSections(buf);
            for (const section of sections) {
                if (section.raw_size >= 4 && section.raw_ptr + 4 <= buf.length) {
                    const magic = buf.readUInt32LE(section.raw_ptr);
                    if (magic === PACKED_MAGIC) return true;
                }
            }
        } finally {
            fs.closeSync(fd);
        }
    } catch (_) {
    }
    return false;
}

function sha256File(filePath) {
    const hash = crypto.createHash('sha256');
    const fd = fs.openSync(filePath, 'r');
    try {
        const buf = Buffer.alloc(1024 * 1024);
        let pos = 0;
        while (true) {
            const bytesRead = fs.readSync(fd, buf, 0, buf.length, pos);
            if (bytesRead === 0) break;
            hash.update(buf.subarray(0, bytesRead));
            pos += bytesRead;
        }
    } finally {
        fs.closeSync(fd);
    }
    return hash.digest('hex');
}

function verifyPersonalizerIntegrity() {
    if (!PERSONALIZER_SHA256) {
        log('personalizer SHA-256 not configured, skipping integrity check');
        s_personalizerVerified = true;
        return;
    }
    try {
        const st = fs.statSync(PERSONALIZER_PATH);
        if (!st.isFile()) {
            logError('personalizer_not_found: ' + PERSONALIZER_PATH);
            s_personalizerVerified = false;
            return;
        }
        const actualHash = sha256File(PERSONALIZER_PATH);
        if (actualHash !== PERSONALIZER_SHA256) {
            logError(`personalizer_hash_mismatch: expected=${PERSONALIZER_SHA256} actual=${actualHash}`);
            s_personalizerVerified = false;
            return;
        }
        log('personalizer integrity verified');
        s_personalizerVerified = true;
    } catch (err) {
        logError('personalizer_integrity_check_failed: ' + (err && err.message ? err.message : err));
        s_personalizerVerified = false;
    }
}

function cleanTmpDir() {
    try {
        if (!fs.existsSync(TMP_DIR)) {
            fs.mkdirSync(TMP_DIR, { recursive: true });
            return;
        }
        const entries = fs.readdirSync(TMP_DIR);
        for (const entry of entries) {
            const fullPath = path.join(TMP_DIR, entry);
            try {
                fs.unlinkSync(fullPath);
            } catch (_) {
            }
        }
        log('tmp directory cleaned');
    } catch (err) {
        logError('tmp_cleanup_failed: ' + (err && err.message ? err.message : err));
    }
}

function runPersonalizer(buildRow) {
    return new Promise((resolve) => {
        const tmplPath = templatePath(buildRow.template_version);
        const outPath = outputPath(buildRow.build_id);
        const watermarkHex = String(buildRow.watermark_id || '').replace(/-/g, '');
        const customerId = String(buildRow.license_key || '');
        const args = [
            '--template', tmplPath,
            '--watermark', watermarkHex,
            '--customer-id', customerId,
            '--template-version', String(buildRow.template_version),
            '--output', outPath,
        ];
        const env = {
            AIDA_MASTER_KEY_B64: String(process.env.AIDA_BUILD_MASTER_KEY_B64 || process.env.SERVER_MASTER_KEY_B64 || ''),
            PATH: process.env.PATH || '/usr/local/bin:/usr/bin:/bin',
            SystemRoot: process.env.SystemRoot || 'C:\\Windows',
        };

        let stdoutBuf = '';
        let stderrBuf = '';
        let lastProgress = 0;
        let killed = false;
        let timeoutFired = false;
        let extendedTimeout = false;
        let processExited = false;

        const child = spawn(PERSONALIZER_PATH, args, {
            env,
            stdio: ['ignore', 'pipe', 'pipe'],
            cwd: OUTPUT_DIR,
        });

        const initialTimeoutMs = BUILD_TIMEOUT_SECONDS * 1000;
        let timer = null;

        const killProcess = () => {
            timeoutFired = true;
            killed = true;
            try { child.kill('SIGTERM'); } catch (_) {}
            setTimeout(() => {
                if (!processExited) {
                    try { child.kill('SIGKILL'); } catch (_) {}
                }
            }, 5000);
        };

        timer = setTimeout(() => {
            if (processExited) return;
            if (!extendedTimeout && lastProgress > 50) {
                extendedTimeout = true;
                log(`build ${buildRow.build_id}: progress ${lastProgress}%, extending timeout by ${ADAPTIVE_EXTENSION_SECONDS}s`);
                clearTimeout(timer);
                timer = setTimeout(() => {
                    if (processExited) return;
                    killProcess();
                }, ADAPTIVE_EXTENSION_SECONDS * 1000);
                return;
            }
            killProcess();
        }, initialTimeoutMs);

        if (child.stdout) {
            child.stdout.on('data', (chunk) => {
                const text = chunk.toString('utf8');
                stdoutBuf += text;
                const lines = text.split('\n');
                for (const line of lines) {
                    const m = /progress:(\d+)/.exec(line.trim());
                    if (m) {
                        lastProgress = parseInt(m[1], 10);
                        updateProgress(buildRow.build_id, lastProgress).catch(() => {});
                    }
                }
            });
        }
        if (child.stderr) {
            child.stderr.on('data', (chunk) => {
                stderrBuf += chunk.toString('utf8');
            });
        }

        child.on('error', (err) => {
            processExited = true;
            clearTimeout(timer);
            resolve({
                ok: false,
                error: 'personalizer_spawn_failed',
                stdout: stdoutBuf,
                stderr: stderrBuf,
                progress: lastProgress,
            });
        });

        child.on('exit', (code, signal) => {
            processExited = true;
            clearTimeout(timer);
            if (killed && timeoutFired) {
                resolve({
                    ok: false,
                    error: 'personalizer_timeout',
                    stdout: stdoutBuf,
                    stderr: stderrBuf,
                    progress: lastProgress,
                });
                return;
            }
            if (killed) {
                resolve({
                    ok: false,
                    error: 'personalizer_killed',
                    stdout: stdoutBuf,
                    stderr: stderrBuf,
                    progress: lastProgress,
                });
                return;
            }
            if (code !== 0) {
                resolve({
                    ok: false,
                    error: 'personalizer_exit_' + (code !== null ? code : 'unknown'),
                    stdout: stdoutBuf,
                    stderr: stderrBuf,
                    progress: lastProgress,
                });
                return;
            }
            resolve({
                ok: true,
                stdout: stdoutBuf,
                stderr: stderrBuf,
                progress: 100,
            });
        });
    });
}

async function updateProgress(buildId, pct) {
    await pool.query(
        'UPDATE build_requests SET progress_pct = $1 WHERE build_id = $2',
        [Math.min(100, Math.max(0, pct)), buildId]
    );
}

async function verifyOutput(buildId) {
    const outPath = outputPath(buildId);
    if (!fs.existsSync(outPath)) {
        return { ok: false, error: 'output_missing' };
    }
    const st = fs.statSync(outPath);
    if (!st.isFile()) {
        return { ok: false, error: 'output_not_file' };
    }
    if (st.size <= 1024) {
        return { ok: false, error: 'output_too_small' };
    }
    const fd = fs.openSync(outPath, 'r');
    try {
        const header = Buffer.alloc(2);
        fs.readSync(fd, header, 0, 2, 0);
        if (header[0] !== 0x5A || header[1] !== 0x4D) {
            return { ok: false, error: 'output_invalid_mz' };
        }
    } finally {
        fs.closeSync(fd);
    }
    const sha256 = sha256File(outPath);
    return { ok: true, sha256, size: st.size };
}

async function processBuild(buildRow) {
    const buildId = buildRow.build_id;
    log(`processing build ${buildId} (template v${buildRow.template_version})`);

    if (!s_personalizerVerified) {
        verifyPersonalizerIntegrity();
        if (!s_personalizerVerified) {
            await markBuildFailed(buildId, 'personalizer_not_verified');
            return;
        }
    }

    const tmplPath = templatePath(buildRow.template_version);
    if (!fs.existsSync(tmplPath)) {
        logError(`build ${buildId}: template not found at ${tmplPath}`);
        await markBuildFailed(buildId, 'template_not_found');
        return;
    }

    const result = await runPersonalizer(buildRow);

    if (!result.ok) {
        logError(`build ${buildId}: ${result.error}`);
        await markBuildFailed(buildId, result.error);
        try {
            const outPath = outputPath(buildId);
            if (fs.existsSync(outPath)) fs.unlinkSync(outPath);
        } catch (_) {}
        return;
    }

    const verify = await verifyOutput(buildId);
    if (!verify.ok) {
        logError(`build ${buildId}: ${verify.error}`);
        await markBuildFailed(buildId, verify.error);
        try {
            const outPath = outputPath(buildId);
            if (fs.existsSync(outPath)) fs.unlinkSync(outPath);
        } catch (_) {}
        return;
    }

    const completedAt = nowSec();
    await pool.query(
        `UPDATE build_requests
            SET status = 'ready',
                output_filename = $1,
                output_sha256 = $2,
                output_size = $3,
                completed_at = $4,
                progress_pct = 100
          WHERE build_id = $5`,
        [outputFilename(buildId), verify.sha256, verify.size, completedAt, buildId]
    );
    log(`build ${buildId}: ready (sha256=${verify.sha256.slice(0, 16)}... size=${verify.size})`);
}

async function markBuildFailed(buildId, errorMessage) {
    const completedAt = nowSec();
    await pool.query(
        `UPDATE build_requests
            SET status = 'failed',
                error_message = $1,
                completed_at = $2
          WHERE build_id = $3`,
        [errorMessage, completedAt, buildId]
    );
}

async function claimNextBuild() {
    const { rows } = await pool.query(
        `SELECT build_id, license_key, discord_id, template_version, watermark_id
           FROM build_requests
          WHERE status = 'queued'
          ORDER BY requested_at ASC
          LIMIT 1`
    );
    if (rows.length === 0) return null;
    const row = rows[0];
    const claim = await pool.query(
        `UPDATE build_requests
            SET status = 'building', started_at = $1
          WHERE build_id = $2 AND status = 'queued'
          RETURNING *`,
        [nowSec(), row.build_id]
    );
    if (claim.rowCount !== 1) return null;
    return claim.rows[0];
}

async function pollLoop() {
    if (s_shuttingDown) return;
    if (s_currentJob) {
        scheduleNextPoll();
        return;
    }
    try {
        const build = await claimNextBuild();
        if (!build) {
            scheduleNextPoll();
            return;
        }
        s_currentJob = build;
        await processBuild(build);
        s_currentJob = null;
    } catch (err) {
        logError('poll_loop_error: ' + (err && err.message ? err.message : err));
        s_currentJob = null;
    }
    scheduleNextPoll();
}

function scheduleNextPoll() {
    if (s_shuttingDown) return;
    if (s_enqueueResolver) {
        Promise.resolve(s_enqueueResolver).then(() => {
            s_enqueueResolver = null;
            setImmediate(pollLoop);
        });
        return;
    }
    s_pollTimer = setTimeout(pollLoop, POLL_INTERVAL_MS);
}

async function cleanupExpiredOutputs() {
    try {
        const { rows } = await pool.query(
            `SELECT build_id, output_filename
               FROM build_requests
              WHERE status = 'ready'
                AND completed_at < (EXTRACT(EPOCH FROM now())::BIGINT - $1)`,
            [OUTPUT_TTL_SECONDS]
        );
        for (const row of rows) {
            const filePath = path.join(OUTPUT_DIR, row.output_filename);
            try {
                if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
            } catch (err) {
                logError(`cleanup: failed to delete ${row.output_filename}: ${err && err.message ? err.message : err}`);
            }
            await pool.query(
                `UPDATE build_requests SET status = 'expired' WHERE build_id = $1`,
                [row.build_id]
            );
            log(`cleanup: expired build ${row.build_id}`);
        }
        if (rows.length > 0) {
            log(`cleanup: expired ${rows.length} output files`);
        }
    } catch (err) {
        logError('cleanup_expired_outputs_failed: ' + (err && err.message ? err.message : err));
    }
}

async function cleanupOldTemplates() {
    try {
        const { rows } = await pool.query(
            `SELECT id, version, file_path, filename
               FROM build_templates
              WHERE active = false
                AND archived_at < (EXTRACT(EPOCH FROM now())::BIGINT - $1)`,
            [TEMPLATE_GRACE_SECONDS]
        );
        for (const row of rows) {
            try {
                if (row.file_path && fs.existsSync(row.file_path)) {
                    fs.unlinkSync(row.file_path);
                }
                const metadataPath = path.join(TEMPLATE_DIR, `template_metadata_v${row.version}.json`);
                if (fs.existsSync(metadataPath)) {
                    fs.unlinkSync(metadataPath);
                }
            } catch (err) {
                logError(`template_cleanup: failed to delete v${row.version}: ${err && err.message ? err.message : err}`);
            }
            await pool.query('DELETE FROM build_templates WHERE id = $1', [row.id]);
            log(`template_cleanup: deleted template v${row.version}`);
        }
    } catch (err) {
        logError('cleanup_old_templates_failed: ' + (err && err.message ? err.message : err));
    }
}

async function cleanupSweep() {
    await cleanupExpiredOutputs();
    await cleanupOldTemplates();
}

function enqueue(_buildId) {
    if (s_shuttingDown) return;
    if (!s_running) return;
    s_enqueueResolver = Promise.resolve();
}

function start() {
    if (s_running) return;
    s_running = true;
    s_shuttingDown = false;
    log('starting build queue worker');
    log(`personalizer: ${PERSONALIZER_PATH}`);
    log(`template_dir: ${TEMPLATE_DIR}`);
    log(`output_dir: ${OUTPUT_DIR}`);
    log(`timeout: ${BUILD_TIMEOUT_SECONDS}s (adaptive: +${ADAPTIVE_EXTENSION_SECONDS}s = ${BUILD_TIMEOUT_SECONDS + ADAPTIVE_EXTENSION_SECONDS}s)`);
    log(`output_ttl: ${OUTPUT_TTL_SECONDS}s (${OUTPUT_TTL_SECONDS / 3600}h)`);
    log(`cleanup_interval: ${CLEANUP_INTERVAL_SECONDS}s`);

    verifyPersonalizerIntegrity();
    cleanTmpDir();

    setImmediate(pollLoop);

    s_cleanupTimer = setInterval(cleanupSweep, CLEANUP_INTERVAL_SECONDS * 1000);

    process.on('SIGTERM', stop);
    process.on('SIGINT', stop);
}

function stop() {
    if (!s_running) return;
    s_shuttingDown = true;
    s_running = false;
    log('stopping build queue worker');
    if (s_pollTimer) {
        clearTimeout(s_pollTimer);
        s_pollTimer = null;
    }
    if (s_cleanupTimer) {
        clearInterval(s_cleanupTimer);
        s_cleanupTimer = null;
    }
}

module.exports = {
    enqueue,
    start,
    stop,
    _internal: {
        pollLoop,
        cleanupSweep,
        cleanupExpiredOutputs,
        cleanupOldTemplates,
        processBuild,
        claimNextBuild,
        verifyOutput,
        runPersonalizer,
        markBuildFailed,
        updateProgress,
        verifyPersonalizerIntegrity,
        cleanTmpDir,
        sha256File,
        hasPackedMagic,
        parsePeSections,
        outputFilename,
        outputPath,
        templateFilename,
        templatePath,
        nowSec,
        PACKED_MAGIC,
        BUILD_TIMEOUT_SECONDS,
        ADAPTIVE_EXTENSION_SECONDS,
        OUTPUT_TTL_SECONDS,
        TEMPLATE_GRACE_SECONDS,
    },
};

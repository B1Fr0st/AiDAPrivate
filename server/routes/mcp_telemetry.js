'use strict';

const express = require('express');
const crypto = require('crypto');
const pool = require('../db/pool');
const hmacAuth = require('../middleware/hmac_auth');
const { getDefaultManager } = require('../anomaly/behavioral');

const router = express.Router();

router.use(hmacAuth.authenticate);

const MAX_TOOL_CALLS_PER_REPORT = 256;

function clientIp(req) {
    return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
        || req.socket.remoteAddress
        || 'unknown';
}

function sanitizeToolName(name) {
    return String(name || '').trim().slice(0, 128);
}

function computeParamsHash(params) {
    if (!params || typeof params !== 'object') return '';
    try {
        const canonical = JSON.stringify(params, Object.keys(params).sort());
        return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex').slice(0, 64);
    } catch (_) {
        return '';
    }
}

router.post('/report', async (req, res) => {
    try {
        const session = req.aidaSession;
        if (!session || !session.license_key) {
            return res.status(403).json({ status: 'error', reason: 'auth_required' });
        }

        const { license_key, tool_calls } = req.body || {};

        if (!license_key || license_key !== session.license_key) {
            return res.status(403).json({ status: 'error', reason: 'license_key_mismatch' });
        }

        if (!Array.isArray(tool_calls) || tool_calls.length === 0) {
            return res.status(400).json({ status: 'error', reason: 'missing_tool_calls' });
        }

        const ip = clientIp(req);
        const hwid = session.hwid || '';
        const sessionToken = session.session_token || '';
        const manager = getDefaultManager();
        const toolCounts = {};
        let stored = 0;
        let failed = 0;

        const calls = tool_calls.slice(0, MAX_TOOL_CALLS_PER_REPORT);
        for (const call of calls) {
            const toolName = sanitizeToolName(call.tool_name || call.tool);
            if (!toolName) { failed++; continue; }

            const paramsHash = typeof call.params_hash === 'string'
                ? call.params_hash.slice(0, 64)
                : computeParamsHash(call.params);
            const source = typeof call.source === 'string' ? call.source.slice(0, 32) : 'mcp_telemetry';

            try {
                await manager.storeToolCall(license_key, toolName, hwid, sessionToken, paramsHash, ip, source);
                stored++;
            } catch (err) {
                if (err && err.code === '42P01') { failed++; continue; }
                console.error('[mcp_telemetry] storeToolCall error:', err.message);
                failed++;
            }

            toolCounts[toolName] = (toolCounts[toolName] || 0) + 1;
        }

        try {
            await manager.batchUpdateProfile(license_key, toolCounts, hwid, ip);
        } catch (err) {
            if (err && err.code !== '42P01') {
                console.error('[mcp_telemetry] batchUpdateProfile error:', err.message);
            }
        }

        let assessment = null;
        try {
            assessment = await manager.assess(license_key);
        } catch (err) {
            if (err && err.code !== '42P01') {
                console.error('[mcp_telemetry] assess error:', err.message);
            }
        }

        if (assessment && assessment.recommendation === 'revoke') {
            try {
                await pool.query(
                    'UPDATE sessions SET kill_flag = true WHERE license_key = $1',
                    [license_key]
                );
                await pool.query(
                    `INSERT INTO violations (hwid, ip, reason, timestamp, timestamp_iso, plugin_version, license_key)
                     VALUES ($1, $2, $3, $4, $5, 'behavioral', $6)`,
                    [hwid || 'unknown', ip,
                     `behavioral_divergence:${assessment.divergenceScore.toFixed(4)}`,
                     Math.floor(Date.now() / 1000), new Date().toISOString(),
                     license_key]
                );
            } catch (err) {
                console.error('[mcp_telemetry] revoke action error:', err.message);
            }
        }

        return res.json({
            status: 'ok',
            stored,
            failed,
            assessment: assessment ? {
                recommendation: assessment.recommendation,
                divergence_score: assessment.divergenceScore,
                cosine_similarity: assessment.cosineSimilarity,
                reason: assessment.reason,
                profile_samples: assessment.profileSamples,
                current_samples: assessment.currentSamples,
            } : null,
        });
    } catch (err) {
        console.error('[mcp_telemetry] POST /report error:', err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

router.get('/status', async (req, res) => {
    try {
        const session = req.aidaSession;
        if (!session || !session.license_key) {
            return res.status(403).json({ status: 'error', reason: 'auth_required' });
        }

        const manager = getDefaultManager();
        const assessment = await manager.assess(session.license_key);

        return res.json({
            status: 'ok',
            assessment: {
                recommendation: assessment.recommendation,
                divergence_score: assessment.divergenceScore,
                cosine_similarity: assessment.cosineSimilarity,
                reason: assessment.reason,
                profile_samples: assessment.profileSamples,
                current_samples: assessment.currentSamples,
            },
        });
    } catch (err) {
        console.error('[mcp_telemetry] GET /status error:', err);
        return res.status(500).json({ status: 'error', reason: 'internal_error' });
    }
});

module.exports = { router };

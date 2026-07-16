'use strict';

const pool = require('../db/pool');

const COSINE_DIVERGENT_THRESHOLD = parseFloat(process.env.BEHAVIORAL_COSINE_THRESHOLD || '0.30');
const DIVERGENCE_FLAG_THRESHOLD = parseFloat(process.env.BEHAVIORAL_FLAG_DIVERGENCE || '0.45');
const DIVERGENCE_REVOKE_THRESHOLD = parseFloat(process.env.BEHAVIORAL_REVOKE_DIVERGENCE || '0.70');
const MIN_PROFILE_SAMPLES = parseInt(process.env.BEHAVIORAL_MIN_PROFILE_SAMPLES || '100', 10);
const BEHAVIORAL_WINDOW_SIZE = parseInt(process.env.BEHAVIORAL_WINDOW_SIZE || '500', 10);
const BEHAVIORAL_DIVERGENCE_WINDOW_SEC = parseInt(process.env.BEHAVIORAL_DIVERGENCE_WINDOW_SEC || '3600', 10);
const MAX_TOOLS_PER_PROFILE = 256;

function cosineSimilarity(vecA, vecB) {
    const keys = new Set([...Object.keys(vecA), ...Object.keys(vecB)]);
    let dot = 0, normA = 0, normB = 0;
    for (const key of keys) {
        const a = Number(vecA[key] || 0);
        const b = Number(vecB[key] || 0);
        dot += a * b;
        normA += a * a;
        normB += b * b;
    }
    if (normA === 0 || normB === 0) return 0;
    return dot / (Math.sqrt(normA) * Math.sqrt(normB));
}

function buildCurrentSessionVector(rows) {
    const counts = {};
    let total = 0;
    for (const row of rows) {
        const tool = String(row.tool_name || '').trim();
        if (!tool) continue;
        counts[tool] = (counts[tool] || 0) + 1;
        total += 1;
    }
    const vec = {};
    if (total > 0) {
        for (const k of Object.keys(counts)) {
            vec[k] = counts[k] / total;
        }
    }
    return vec;
}

function normalizeStoredFrequency(rawFreq) {
    if (!rawFreq || typeof rawFreq !== 'object') return {};
    const vec = {};
    for (const k of Object.keys(rawFreq)) {
        const v = Number(rawFreq[k]);
        if (Number.isFinite(v)) vec[k] = v;
    }
    return vec;
}

class BehavioralProfileManager {
    constructor(options) {
        const opts = options || {};
        this.flagThreshold = Number.isFinite(opts.flagThreshold) ? opts.flagThreshold : DIVERGENCE_FLAG_THRESHOLD;
        this.revokeThreshold = Number.isFinite(opts.revokeThreshold) ? opts.revokeThreshold : DIVERGENCE_REVOKE_THRESHOLD;
        this.minSamples = Number.isFinite(opts.minSamples) ? opts.minSamples : MIN_PROFILE_SAMPLES;
        this.windowSize = Number.isFinite(opts.windowSize) ? opts.windowSize : BEHAVIORAL_WINDOW_SIZE;
        this.divergenceWindowSec = Number.isFinite(opts.divergenceWindowSec) ? opts.divergenceWindowSec : BEHAVIORAL_DIVERGENCE_WINDOW_SEC;
        this.maxTools = Number.isFinite(opts.maxTools) ? opts.maxTools : MAX_TOOLS_PER_PROFILE;
        this.cosineDivergent = Number.isFinite(opts.cosineDivergent) ? opts.cosineDivergent : COSINE_DIVERGENT_THRESHOLD;
        this.cache = new Map();
        this.cacheTtlMs = 60000;
    }

    async loadProfile(licenseKey) {
        const cached = this.cache.get(licenseKey);
        if (cached && (Date.now() - cached.loadedAt) < this.cacheTtlMs) {
            return cached;
        }

        const { rows } = await pool.query(
            'SELECT tool_frequency, total_calls, training_complete FROM behavioral_profiles WHERE license_key = $1',
            [licenseKey]
        );

        if (rows.length === 0) {
            const profile = {
                licenseKey,
                vector: {},
                sampleCount: 0,
                trainingComplete: false,
                loadedAt: Date.now(),
            };
            this.cache.set(licenseKey, profile);
            return profile;
        }

        const row = rows[0];
        const vector = normalizeStoredFrequency(row.tool_frequency);
        const sampleCount = parseInt(row.total_calls, 10) || 0;

        const profile = {
            licenseKey,
            vector,
            sampleCount,
            trainingComplete: !!row.training_complete,
            loadedAt: Date.now(),
        };
        this.cache.set(licenseKey, profile);
        return profile;
    }

    async loadCurrentSession(licenseKey, sessionWindowSec) {
        const windowSec = sessionWindowSec || this.divergenceWindowSec;
        const cutoff = Math.floor(Date.now() / 1000) - windowSec;
        const { rows } = await pool.query(
            `SELECT tool_name
               FROM mcp_tool_calls
              WHERE license_key = $1
                AND called_at > $2
              ORDER BY called_at DESC
              LIMIT $3`,
            [licenseKey, cutoff, this.windowSize]
        );

        return {
            vector: buildCurrentSessionVector(rows),
            sampleCount: rows.length,
        };
    }

    async assess(licenseKey, currentVector, currentSampleCount) {
        const profile = await this.loadProfile(licenseKey);
        const profileVec = profile.vector;
        const profileSamples = profile.sampleCount;

        let currentVec = currentVector;
        let currentSamples = currentSampleCount;
        if (!currentVec) {
            const session = await this.loadCurrentSession(licenseKey);
            currentVec = session.vector;
            currentSamples = session.sampleCount;
        }

        if (!profile.trainingComplete || profileSamples < this.minSamples) {
            return {
                licenseKey,
                cosineSimilarity: null,
                divergenceScore: 1.0,
                recommendation: 'allow',
                reason: 'insufficient_baseline',
                profileSamples,
                currentSamples,
                trainingComplete: profile.trainingComplete,
                threshold: this.cosineDivergent,
            };
        }

        if (currentSamples < 3) {
            return {
                licenseKey,
                cosineSimilarity: null,
                divergenceScore: 0.0,
                recommendation: 'allow',
                reason: 'insufficient_current_samples',
                profileSamples,
                currentSamples,
                trainingComplete: profile.trainingComplete,
                threshold: this.cosineDivergent,
            };
        }

        const similarity = cosineSimilarity(profileVec, currentVec);
        const divergence = 1.0 - similarity;

        let recommendation = 'allow';
        let reason = 'normal';

        if (similarity < this.cosineDivergent) {
            if (divergence >= this.revokeThreshold) {
                recommendation = 'revoke';
                reason = `behavioral_divergence_revoke:${divergence.toFixed(4)}`;
            } else if (divergence >= this.flagThreshold) {
                recommendation = 'flag';
                reason = `behavioral_divergence_flag:${divergence.toFixed(4)}`;
            } else {
                recommendation = 'flag';
                reason = `behavioral_divergence_cosine:${similarity.toFixed(4)}`;
            }
        }

        return {
            licenseKey,
            cosineSimilarity: similarity,
            divergenceScore: divergence,
            recommendation,
            reason,
            profileSamples,
            currentSamples,
            trainingComplete: profile.trainingComplete,
            threshold: this.cosineDivergent,
        };
    }

    async storeToolCall(licenseKey, toolName, hwid, sessionToken, paramsHash, clientIp, source) {
        const now = Math.floor(Date.now() / 1000);
        const hour = new Date().getUTCHours();
        await pool.query(
            `INSERT INTO mcp_tool_calls (license_key, hwid, session_token, tool_name, tool_params_hash, called_at, called_at_hour, client_ip, source)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
            [
                licenseKey,
                String(hwid || '').slice(0, 256),
                String(sessionToken || '').slice(0, 256),
                String(toolName || '').trim().slice(0, 128),
                String(paramsHash || '').slice(0, 64),
                now,
                hour,
                String(clientIp || '').slice(0, 64),
                String(source || 'mcp_telemetry').slice(0, 32),
            ]
        );
    }

    async batchUpdateProfile(licenseKey, toolCounts, hwid, clientIp) {
        const now = Math.floor(Date.now() / 1000);

        const { rows: profileRows } = await pool.query(
            'SELECT * FROM behavioral_profiles WHERE license_key = $1',
            [licenseKey]
        );

        let profile = profileRows.length > 0 ? profileRows[0] : null;

        if (!profile) {
            await pool.query(
                `INSERT INTO behavioral_profiles (license_key, first_call_at, last_updated_at)
                 VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
                [licenseKey, now, now]
            );
            const { rows: newRows } = await pool.query(
                'SELECT * FROM behavioral_profiles WHERE license_key = $1',
                [licenseKey]
            );
            profile = newRows.length > 0 ? newRows[0] : null;
        }
        if (!profile) return;

        const batchCount = Object.values(toolCounts).reduce((a, b) => a + (parseInt(b, 10) || 0), 0);
        const totalCalls = parseInt(profile.total_calls, 10) + batchCount;
        const trainingComplete = totalCalls >= 100;

        let hwidsSeen = Array.isArray(profile.hwids_seen) ? profile.hwids_seen : [];
        let ipsSeen = Array.isArray(profile.ips_seen) ? profile.ips_seen : [];
        if (hwid && !hwidsSeen.includes(hwid)) hwidsSeen = [...hwidsSeen, hwid].slice(-32);
        if (clientIp && !ipsSeen.includes(clientIp)) ipsSeen = [...ipsSeen, clientIp].slice(-32);

        const lastUpdated = parseInt(profile.last_updated_at, 10) || 0;
        const needsRecompute = !trainingComplete ||
            (lastUpdated > 0 && (now - lastUpdated) > 604800);

        let toolFrequency = profile.tool_frequency || {};
        let hourHistogram = profile.hour_histogram || new Array(24).fill(0);

        if (needsRecompute || !trainingComplete) {
            const { rows: recentCalls } = await pool.query(
                `SELECT tool_name, called_at_hour FROM mcp_tool_calls
                 WHERE license_key = $1 ORDER BY called_at DESC LIMIT $2`,
                [licenseKey, this.windowSize]
            );
            const freq = {};
            const histogram = new Array(24).fill(0);
            for (const call of recentCalls) {
                const tn = String(call.tool_name || '');
                if (tn) freq[tn] = (freq[tn] || 0) + 1;
                const h = Number(call.called_at_hour || 0);
                if (h >= 0 && h < 24) histogram[h] = (histogram[h] || 0) + 1;
            }
            const total = Object.values(freq).reduce((a, b) => a + b, 0);
            if (total > 0) {
                for (const k of Object.keys(freq)) freq[k] /= total;
            }
            toolFrequency = freq;
            hourHistogram = histogram;
        }

        await pool.query(
            `UPDATE behavioral_profiles SET
                tool_frequency = $1::jsonb,
                hour_histogram = $2::jsonb,
                total_calls = $3,
                training_complete = $4,
                last_updated_at = $5,
                hwids_seen = $6::TEXT[],
                ips_seen = $7::TEXT[]
              WHERE license_key = $8`,
            [
                JSON.stringify(toolFrequency),
                JSON.stringify(hourHistogram),
                totalCalls,
                trainingComplete,
                now,
                hwidsSeen,
                ipsSeen,
                licenseKey,
            ]
        );

        this.cache.delete(licenseKey);
    }

    invalidateCache(licenseKey) {
        if (licenseKey) {
            this.cache.delete(licenseKey);
        } else {
            this.cache.clear();
        }
    }
}

let s_instance = null;

function getDefaultManager() {
    if (s_instance) return s_instance;
    s_instance = new BehavioralProfileManager({});
    return s_instance;
}

function resetDefaultManagerForTests() {
    s_instance = null;
}

module.exports = {
    BehavioralProfileManager,
    getDefaultManager,
    resetDefaultManagerForTests,
    cosineSimilarity,
    buildCurrentSessionVector,
    normalizeStoredFrequency,
    COSINE_DIVERGENT_THRESHOLD,
    DIVERGENCE_FLAG_THRESHOLD,
    DIVERGENCE_REVOKE_THRESHOLD,
    MIN_PROFILE_SAMPLES,
};

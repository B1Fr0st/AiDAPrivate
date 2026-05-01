'use strict';

const crypto = require('crypto');
const { getDefaultModel, METRIC_NAMES } = require('./model');

const FLAG_THRESHOLD = parseFloat(process.env.ANOMALY_FLAG_THRESHOLD || '2.5');
const REVOKE_THRESHOLD = parseFloat(process.env.ANOMALY_REVOKE_THRESHOLD || '4.0');
const MIN_BASELINE_SAMPLES = parseInt(process.env.ANOMALY_MIN_SAMPLES || '32', 10);
const SLACK_WEBHOOK_URL = process.env.SLACK_WEBHOOK_URL || '';
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL || '';

function safeNumber(value) {
    const n = Number(value);
    return Number.isFinite(n) ? n : null;
}

function computeRdtscDeltaStats(rdtscSamples) {
    if (!Array.isArray(rdtscSamples) || rdtscSamples.length < 2) {
        return { mean: null, std: null, deltaCount: 0 };
    }
    const numeric = [];
    for (const v of rdtscSamples) {
        const n = typeof v === 'string' ? Number(v) : Number(v);
        if (Number.isFinite(n)) numeric.push(n);
    }
    if (numeric.length < 2) return { mean: null, std: null, deltaCount: 0 };
    const deltas = [];
    for (let i = 1; i < numeric.length; i++) {
        const d = numeric[i] - numeric[i - 1];
        if (Number.isFinite(d)) deltas.push(d);
    }
    if (deltas.length === 0) return { mean: null, std: null, deltaCount: 0 };
    const mean = deltas.reduce((a, b) => a + b, 0) / deltas.length;
    let sumSq = 0;
    for (const d of deltas) sumSq += (d - mean) * (d - mean);
    const variance = deltas.length > 1 ? sumSq / (deltas.length - 1) : 0;
    return { mean, std: Math.sqrt(variance), deltaCount: deltas.length };
}

function extractMetricsFromHeartbeat(body, session) {
    const metrics = {};

    let cadence = safeNumber(body.cadence_ms);
    if (cadence === null) cadence = safeNumber(body.heartbeat_cadence_ms);
    if (cadence === null && session && Array.isArray(session.heartbeat_times) && session.heartbeat_times.length >= 1) {
        const last = Number(session.heartbeat_times[session.heartbeat_times.length - 1]);
        const now = Math.floor(Date.now() / 1000);
        if (Number.isFinite(last) && now > last) {
            cadence = (now - last) * 1000;
        }
    }
    if (cadence !== null && cadence >= 0) metrics.cadenceMs = cadence;

    const rdtscArr = Array.isArray(body.rdtsc_deltas) ? body.rdtsc_deltas
        : Array.isArray(body.rdtsc_samples) ? body.rdtsc_samples
        : null;
    if (rdtscArr) {
        const numeric = [];
        for (const v of rdtscArr.slice(-8)) {
            const n = typeof v === 'string' ? Number(v) : Number(v);
            if (Number.isFinite(n)) numeric.push(n);
        }
        if (numeric.length >= 2) {
            const stats = computeRdtscDeltaStats(numeric);
            if (stats.mean !== null) metrics.rdtscDeltaMean = stats.mean;
            if (stats.std !== null) metrics.rdtscDeltaStd = stats.std;
        } else if (numeric.length === 1) {
            metrics.rdtscDeltaMean = numeric[0];
        }
    } else {
        const dm = safeNumber(body.rdtsc_delta_mean);
        const ds = safeNumber(body.rdtsc_delta_std);
        if (dm !== null) metrics.rdtscDeltaMean = dm;
        if (ds !== null) metrics.rdtscDeltaStd = ds;
    }

    const exc = safeNumber(body.exception_count);
    if (exc !== null && exc >= 0) metrics.exceptionCount = exc;

    const moduleSeq = Array.isArray(body.module_load_sequence) ? body.module_load_sequence : null;
    if (moduleSeq) {
        const norm = moduleSeq.map(m => typeof m === 'string' ? m.trim().toLowerCase() : '').filter(Boolean);
        metrics.moduleLoadCount = norm.length;
        metrics.moduleLoadUnique = new Set(norm).size;
    } else {
        const mc = safeNumber(body.module_load_count);
        const mu = safeNumber(body.module_load_unique);
        if (mc !== null && mc >= 0) metrics.moduleLoadCount = mc;
        if (mu !== null && mu >= 0) metrics.moduleLoadUnique = mu;
    }

    return metrics;
}

function postJson(url, payload, timeoutMs) {
    if (!url) return Promise.resolve({ ok: false, status: 0, reason: 'no_webhook_url' });
    return new Promise((resolve) => {
        const ctrl = new AbortController();
        const t = setTimeout(() => ctrl.abort(), Number.isFinite(timeoutMs) ? timeoutMs : 5000);
        fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
            signal: ctrl.signal,
        }).then((res) => {
            clearTimeout(t);
            resolve({ ok: res.ok, status: res.status });
        }).catch((err) => {
            clearTimeout(t);
            resolve({ ok: false, status: 0, reason: err && err.message ? err.message : 'fetch_failed' });
        });
    });
}

function buildAlertFields(licenseKey, hwid, scoreResult, metrics, action) {
    const fields = [
        { name: 'License', value: '`' + String(licenseKey || 'unknown') + '`' },
        { name: 'HWID', value: '`' + String(hwid || 'unknown') + '`' },
        { name: 'Action', value: action },
        { name: 'Score', value: scoreResult.score.toFixed(3) },
        { name: 'Samples', value: String(scoreResult.sampleCount) },
    ];
    const significant = [];
    for (const name of METRIC_NAMES) {
        const m = scoreResult.perMetric[name];
        if (!m || !Number.isFinite(m.z)) continue;
        if (m.z >= 1.5) {
            significant.push(`${name}=${m.value} z=${m.z.toFixed(2)} mean=${m.mean !== null ? m.mean.toFixed(2) : 'na'} std=${m.std !== null ? m.std.toFixed(2) : 'na'}`);
        }
    }
    if (significant.length > 0) {
        fields.push({ name: 'Anomalous metrics', value: significant.join('\n').slice(0, 1000) });
    }
    if (metrics) {
        const flat = [];
        for (const name of METRIC_NAMES) {
            if (Number.isFinite(metrics[name])) flat.push(`${name}=${metrics[name]}`);
        }
        if (flat.length > 0) {
            fields.push({ name: 'Live metrics', value: flat.join(' ').slice(0, 1000) });
        }
    }
    return fields;
}

async function sendDiscordAnomalyAlert(title, fields, color) {
    if (!DISCORD_WEBHOOK_URL) return { ok: false, reason: 'no_discord_webhook' };
    const embed = {
        title,
        color: color || 0xFF8800,
        fields: fields.map(f => ({
            name: f.name,
            value: String(f.value).slice(0, 1024),
            inline: f.inline !== false,
        })),
        timestamp: new Date().toISOString(),
        footer: { text: 'AiDA Anomaly Engine' },
    };
    return postJson(DISCORD_WEBHOOK_URL, { embeds: [embed] }, 5000);
}

async function sendSlackAnomalyAlert(title, fields, severity) {
    if (!SLACK_WEBHOOK_URL) return { ok: false, reason: 'no_slack_webhook' };
    const blocks = [
        { type: 'header', text: { type: 'plain_text', text: title.slice(0, 150) } },
    ];
    const fieldElems = fields.map(f => ({
        type: 'mrkdwn',
        text: `*${f.name}*\n${String(f.value).slice(0, 300)}`,
    }));
    while (fieldElems.length > 0) {
        const chunk = fieldElems.splice(0, 10);
        blocks.push({ type: 'section', fields: chunk });
    }
    const fallback = `${title} severity=${severity || 'warn'}`;
    return postJson(SLACK_WEBHOOK_URL, { text: fallback, blocks }, 5000);
}

class AnomalyScoringEngine {
    constructor(options) {
        const opts = options || {};
        this.model = opts.model || getDefaultModel();
        this.flagThreshold = Number.isFinite(opts.flagThreshold) ? opts.flagThreshold : FLAG_THRESHOLD;
        this.revokeThreshold = Number.isFinite(opts.revokeThreshold) ? opts.revokeThreshold : REVOKE_THRESHOLD;
        this.minBaselineSamples = Number.isFinite(opts.minBaselineSamples) ? opts.minBaselineSamples : MIN_BASELINE_SAMPLES;
        this.lastDecisionByLicense = new Map();
        this.recentDecisions = [];
        this.maxRecentDecisions = opts.maxRecentDecisions || 64;
        this.alerter = opts.alerter || null;
    }

    record(licenseKey, metrics, ts) {
        this.model.addSample(licenseKey, metrics, ts);
    }

    evaluate(licenseKey, metrics) {
        const scoreResult = this.model.score(licenseKey, metrics);
        let action = 'observe';
        let reason = 'normal';
        if (scoreResult.warmup || scoreResult.sampleCount < this.minBaselineSamples) {
            action = 'warmup';
            reason = 'insufficient_baseline';
        } else if (scoreResult.score >= this.revokeThreshold) {
            action = 'revoke';
            reason = `score_exceeds_revoke:${scoreResult.score.toFixed(3)}`;
        } else if (scoreResult.score >= this.flagThreshold) {
            action = 'flag';
            reason = `score_exceeds_flag:${scoreResult.score.toFixed(3)}`;
        }
        const decision = {
            licenseKey,
            score: scoreResult.score,
            action,
            reason,
            sampleCount: scoreResult.sampleCount,
            perMetric: scoreResult.perMetric,
            metrics,
            ts: Date.now(),
        };
        this.lastDecisionByLicense.set(licenseKey, decision);
        this.recentDecisions.push(decision);
        if (this.recentDecisions.length > this.maxRecentDecisions) {
            this.recentDecisions.splice(0, this.recentDecisions.length - this.maxRecentDecisions);
        }
        return decision;
    }

    async dispatchAlerts(decision, licenseKey, hwid) {
        if (!decision) return { discord: null, slack: null };
        if (decision.action !== 'flag' && decision.action !== 'revoke') return { discord: null, slack: null };
        const fields = buildAlertFields(licenseKey, hwid, decision, decision.metrics, decision.action);
        const isRevoke = decision.action === 'revoke';
        const title = isRevoke
            ? `AiDA anomaly auto-revoke (score=${decision.score.toFixed(2)})`
            : `AiDA anomaly flag (score=${decision.score.toFixed(2)})`;
        const color = isRevoke ? 0xFF0000 : 0xFFAA00;
        const severity = isRevoke ? 'critical' : 'warn';

        const tasks = [];
        if (this.alerter && typeof this.alerter.discord === 'function') {
            tasks.push(this.alerter.discord(title, fields, color));
        } else {
            tasks.push(sendDiscordAnomalyAlert(title, fields, color));
        }
        if (this.alerter && typeof this.alerter.slack === 'function') {
            tasks.push(this.alerter.slack(title, fields, severity));
        } else {
            tasks.push(sendSlackAnomalyAlert(title, fields, severity));
        }

        const [discord, slack] = await Promise.all(tasks);
        return { discord, slack };
    }

    snapshot(licenseKey) {
        const last = this.lastDecisionByLicense.get(licenseKey);
        return last ? { ...last } : null;
    }

    fingerprintBaseline(licenseKey) {
        return this.model.fingerprint(licenseKey);
    }

    flushPersistedSamples() {
        this.model.persistSync();
    }

    pruneAll() {
        this.model.pruneAll();
    }

    sampleCount(licenseKey) {
        return this.model.sampleCount(licenseKey);
    }
}

let s_engine = null;

function getDefaultEngine() {
    if (s_engine) return s_engine;
    s_engine = new AnomalyScoringEngine({});
    return s_engine;
}

function resetDefaultEngineForTests() {
    s_engine = null;
}

function syntheticHash(s) {
    return crypto.createHash('sha256').update(String(s || '')).digest('hex').slice(0, 16);
}

module.exports = {
    AnomalyScoringEngine,
    getDefaultEngine,
    resetDefaultEngineForTests,
    extractMetricsFromHeartbeat,
    computeRdtscDeltaStats,
    sendDiscordAnomalyAlert,
    sendSlackAnomalyAlert,
    syntheticHash,
    FLAG_THRESHOLD,
    REVOKE_THRESHOLD,
    METRIC_NAMES,
};

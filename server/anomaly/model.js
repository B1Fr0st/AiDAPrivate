'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DEFAULT_PERSIST_DIR = path.join(__dirname, '..', 'data');
const DEFAULT_PERSIST_FILE = path.join(DEFAULT_PERSIST_DIR, 'anomaly_baseline.json');
const DEFAULT_RETENTION_DAYS = 30;
const DEFAULT_MAX_SAMPLES = 4096;

const METRIC_NAMES = [
    'cadenceMs',
    'rdtscDeltaMean',
    'rdtscDeltaStd',
    'exceptionCount',
    'moduleLoadCount',
    'moduleLoadUnique',
];

class AnomalyModel {
    constructor(options) {
        const opts = options || {};
        this.persistPath = opts.persistPath || DEFAULT_PERSIST_FILE;
        this.retentionMs = (opts.retentionDays || DEFAULT_RETENTION_DAYS) * 86400 * 1000;
        this.maxSamples = opts.maxSamples || DEFAULT_MAX_SAMPLES;
        this.licenses = new Map();
        this.dirty = false;
        this.flushTimer = null;
        this.flushIntervalMs = opts.flushIntervalMs || 30000;
        this.persistEnabled = opts.persistEnabled !== false;
        this.loaded = false;
    }

    static metricNames() {
        return METRIC_NAMES.slice();
    }

    load() {
        if (this.loaded) return;
        this.loaded = true;
        if (!this.persistEnabled) return;
        try {
            if (fs.existsSync(this.persistPath)) {
                const raw = fs.readFileSync(this.persistPath, 'utf8');
                if (raw.length > 0) {
                    const parsed = JSON.parse(raw);
                    if (parsed && typeof parsed === 'object' && parsed.licenses) {
                        for (const [licenseKey, payload] of Object.entries(parsed.licenses)) {
                            if (!payload || typeof payload !== 'object') continue;
                            const samples = Array.isArray(payload.samples) ? payload.samples : [];
                            this.licenses.set(licenseKey, {
                                samples: samples.filter(s => Number.isFinite(s.ts) && s.metrics && typeof s.metrics === 'object'),
                                firstSeen: Number(payload.firstSeen) || Date.now(),
                            });
                        }
                    }
                }
            }
        } catch (err) {
            console.warn(`[anomaly] load failed (${err.code || 'EUNKNOWN'}): ${err.message}; starting fresh`);
            this.licenses.clear();
        }
    }

    schedulePersist() {
        if (!this.persistEnabled) return;
        if (this.flushTimer) return;
        this.flushTimer = setTimeout(() => {
            this.flushTimer = null;
            try { this.persistSync(); }
            catch (err) { console.error('[anomaly] persist error:', err.message); }
        }, this.flushIntervalMs);
        if (typeof this.flushTimer.unref === 'function') this.flushTimer.unref();
    }

    persistSync() {
        if (!this.persistEnabled) return;
        if (!this.dirty) return;
        const dir = path.dirname(this.persistPath);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        const out = { version: 1, savedAt: Date.now(), licenses: {} };
        for (const [licenseKey, record] of this.licenses.entries()) {
            out.licenses[licenseKey] = {
                firstSeen: record.firstSeen,
                samples: record.samples.slice(-this.maxSamples),
            };
        }
        const tmp = this.persistPath + '.tmp';
        fs.writeFileSync(tmp, JSON.stringify(out));
        fs.renameSync(tmp, this.persistPath);
        this.dirty = false;
    }

    pruneSamplesInPlace(record) {
        const cutoff = Date.now() - this.retentionMs;
        if (record.samples.length === 0) return;
        let writeIdx = 0;
        for (let i = 0; i < record.samples.length; i++) {
            if (record.samples[i].ts >= cutoff) {
                if (writeIdx !== i) record.samples[writeIdx] = record.samples[i];
                writeIdx++;
            }
        }
        record.samples.length = writeIdx;
        if (record.samples.length > this.maxSamples) {
            record.samples.splice(0, record.samples.length - this.maxSamples);
        }
    }

    addSample(licenseKey, metrics, ts) {
        this.load();
        if (!licenseKey || typeof licenseKey !== 'string') return;
        const cleanMetrics = {};
        for (const name of METRIC_NAMES) {
            const v = Number(metrics ? metrics[name] : null);
            if (Number.isFinite(v)) cleanMetrics[name] = v;
        }
        if (Object.keys(cleanMetrics).length === 0) return;
        const sampleTs = Number.isFinite(ts) ? ts : Date.now();
        let record = this.licenses.get(licenseKey);
        if (!record) {
            record = { samples: [], firstSeen: sampleTs };
            this.licenses.set(licenseKey, record);
        }
        record.samples.push({ ts: sampleTs, metrics: cleanMetrics });
        this.pruneSamplesInPlace(record);
        this.dirty = true;
        this.schedulePersist();
    }

    summary(licenseKey) {
        this.load();
        const record = this.licenses.get(licenseKey);
        if (!record || record.samples.length === 0) return null;
        const out = {
            sampleCount: record.samples.length,
            firstSeen: record.firstSeen,
            metrics: {},
        };
        for (const name of METRIC_NAMES) {
            const values = [];
            for (const s of record.samples) {
                const v = Number(s.metrics[name]);
                if (Number.isFinite(v)) values.push(v);
            }
            if (values.length === 0) {
                out.metrics[name] = { count: 0, mean: 0, std: 0 };
                continue;
            }
            const mean = values.reduce((a, b) => a + b, 0) / values.length;
            let sumSq = 0;
            for (const v of values) sumSq += (v - mean) * (v - mean);
            const variance = values.length > 1 ? sumSq / (values.length - 1) : 0;
            const std = Math.sqrt(variance);
            out.metrics[name] = { count: values.length, mean, std };
        }
        return out;
    }

    score(licenseKey, metrics) {
        this.load();
        const result = {
            score: 0,
            perMetric: {},
            sampleCount: 0,
            warmup: false,
            unknown: false,
        };
        const record = this.licenses.get(licenseKey);
        if (!record || record.samples.length < 8) {
            result.warmup = true;
            result.sampleCount = record ? record.samples.length : 0;
            for (const name of METRIC_NAMES) {
                const v = Number(metrics ? metrics[name] : NaN);
                result.perMetric[name] = { z: 0, value: Number.isFinite(v) ? v : null, mean: null, std: null };
            }
            return result;
        }

        result.sampleCount = record.samples.length;
        let maxZ = 0;
        for (const name of METRIC_NAMES) {
            const v = Number(metrics ? metrics[name] : NaN);
            const values = [];
            for (const s of record.samples) {
                const sv = Number(s.metrics[name]);
                if (Number.isFinite(sv)) values.push(sv);
            }
            if (!Number.isFinite(v) || values.length < 8) {
                result.perMetric[name] = { z: 0, value: Number.isFinite(v) ? v : null, mean: null, std: null };
                continue;
            }
            const mean = values.reduce((a, b) => a + b, 0) / values.length;
            let sumSq = 0;
            for (const sv of values) sumSq += (sv - mean) * (sv - mean);
            const variance = sumSq / (values.length - 1);
            const std = Math.sqrt(variance);
            const epsilon = Math.max(1e-6, mean * 1e-6);
            const denom = std > epsilon ? std : epsilon;
            const z = Math.abs(v - mean) / denom;
            result.perMetric[name] = { z, value: v, mean, std };
            if (z > maxZ) maxZ = z;
        }
        result.score = maxZ;
        return result;
    }

    pruneAll() {
        this.load();
        for (const record of this.licenses.values()) {
            this.pruneSamplesInPlace(record);
        }
        this.dirty = true;
        this.schedulePersist();
    }

    sampleCount(licenseKey) {
        this.load();
        const r = this.licenses.get(licenseKey);
        return r ? r.samples.length : 0;
    }

    reset() {
        this.licenses.clear();
        this.dirty = true;
        this.loaded = true;
    }

    fingerprint(licenseKey) {
        this.load();
        const r = this.licenses.get(licenseKey);
        if (!r) return null;
        const h = crypto.createHash('sha256');
        for (const s of r.samples) {
            h.update(String(s.ts));
            for (const name of METRIC_NAMES) {
                h.update(name);
                const v = s.metrics[name];
                h.update(Number.isFinite(v) ? String(v) : 'NaN');
            }
        }
        return h.digest('hex');
    }
}

let s_default = null;

function getDefaultModel() {
    if (s_default) return s_default;
    s_default = new AnomalyModel({
        persistPath: process.env.ANOMALY_BASELINE_PATH || DEFAULT_PERSIST_FILE,
        persistEnabled: process.env.ANOMALY_BASELINE_DISABLE !== '1',
        retentionDays: parseInt(process.env.ANOMALY_BASELINE_DAYS || String(DEFAULT_RETENTION_DAYS), 10) || DEFAULT_RETENTION_DAYS,
    });
    s_default.load();
    return s_default;
}

module.exports = {
    AnomalyModel,
    getDefaultModel,
    METRIC_NAMES,
    DEFAULT_RETENTION_DAYS,
    DEFAULT_PERSIST_FILE,
};

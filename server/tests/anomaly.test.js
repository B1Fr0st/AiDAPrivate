'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

process.env.SERVER_MASTER_KEY_B64 = process.env.SERVER_MASTER_KEY_B64
    || crypto.randomBytes(32).toString('base64');
process.env.ARC_MASTER_SECRET = process.env.ARC_MASTER_SECRET
    || 'aida-test-arc-master-secret-fixed-32x';
if (!process.env.ED25519_PRIVATE_KEY_B64) {
    const { privateKey } = crypto.generateKeyPairSync('ed25519');
    process.env.ED25519_PRIVATE_KEY_B64 = privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64');
}

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aida-anomaly-test-'));
process.env.ANOMALY_BASELINE_PATH = path.join(tmpDir, 'baseline.json');
process.env.ANOMALY_BASELINE_DISABLE = '0';

const anomalyScore = require('../anomaly/score');
const { AnomalyModel, METRIC_NAMES } = require('../anomaly/model');

test('AnomalyModel z-score over normal baseline returns near-zero', () => {
    const m = new AnomalyModel({ persistEnabled: false, retentionDays: 60 });
    let rngState = 0x12345678;
    const rng = () => {
        rngState = (rngState * 1664525 + 1013904223) >>> 0;
        return rngState / 0xFFFFFFFF;
    };
    for (let i = 0; i < 200; i++) {
        m.addSample('LIC-NORMAL-1', {
            cadenceMs: 5000 + (rng() * 80 - 40),
            rdtscDeltaMean: 1e9 + rng() * 1e6,
            rdtscDeltaStd: 1e5 + rng() * 800,
            exceptionCount: rng() < 0.2 ? 1 : 0,
            moduleLoadCount: 12 + Math.floor(rng() * 4),
            moduleLoadUnique: 11 + Math.floor(rng() * 4),
        }, Date.now() - (200 - i) * 60_000);
    }
    const summary = m.summary('LIC-NORMAL-1');
    const result = m.score('LIC-NORMAL-1', {
        cadenceMs: summary.metrics.cadenceMs.mean,
        rdtscDeltaMean: summary.metrics.rdtscDeltaMean.mean,
        rdtscDeltaStd: summary.metrics.rdtscDeltaStd.mean,
        exceptionCount: summary.metrics.exceptionCount.mean,
        moduleLoadCount: summary.metrics.moduleLoadCount.mean,
        moduleLoadUnique: summary.metrics.moduleLoadUnique.mean,
    });
    assert.ok(result.score < 1.0, `expected score<1.0 got ${result.score}`);
    assert.equal(result.warmup, false);
    assert.ok(result.sampleCount >= 200);
});

test('AnomalyModel scores anomalous sample > revoke threshold after 30-day clean baseline', () => {
    const m = new AnomalyModel({ persistEnabled: false, retentionDays: 60 });
    const now = Date.now();
    const baselineCount = 30 * 24;
    for (let i = 0; i < baselineCount; i++) {
        m.addSample('LIC-TRIP-1', {
            cadenceMs: 5000 + (Math.sin(i / 7) * 30),
            rdtscDeltaMean: 1e9 + Math.cos(i / 13) * 5e5,
            rdtscDeltaStd: 1e5 + Math.cos(i / 19) * 100,
            exceptionCount: 0,
            moduleLoadCount: 12 + (i % 3),
            moduleLoadUnique: 12 + (i % 3),
        }, now - (baselineCount - i) * 3600_000);
    }

    let lastDecision = null;
    const engine = new anomalyScore.AnomalyScoringEngine({
        model: m,
        minBaselineSamples: 32,
        revokeThreshold: 4.0,
        minRevokeBaselineSamples: 32,
        revokeSustainedConsecutive: 3,
        revokeSustainedThreshold: 4.0,
    });
    const anomalousMetrics = [
        { cadenceMs: 50, rdtscDeltaMean: 1e3, rdtscDeltaStd: 100, exceptionCount: 17, moduleLoadCount: 84, moduleLoadUnique: 84 },
        { cadenceMs: 25, rdtscDeltaMean: 5e2, rdtscDeltaStd: 50, exceptionCount: 22, moduleLoadCount: 100, moduleLoadUnique: 99 },
        { cadenceMs: 10, rdtscDeltaMean: 1e2, rdtscDeltaStd: 30, exceptionCount: 31, moduleLoadCount: 120, moduleLoadUnique: 119 },
        { cadenceMs: 5, rdtscDeltaMean: 50, rdtscDeltaStd: 10, exceptionCount: 44, moduleLoadCount: 130, moduleLoadUnique: 130 },
        { cadenceMs: 2, rdtscDeltaMean: 25, rdtscDeltaStd: 5, exceptionCount: 60, moduleLoadCount: 150, moduleLoadUnique: 150 },
    ];
    for (const metrics of anomalousMetrics) {
        const decision = engine.evaluate('LIC-TRIP-1', metrics);
        engine.record('LIC-TRIP-1', metrics, Date.now());
        if (decision.action === 'revoke') {
            lastDecision = decision;
            break;
        }
        lastDecision = decision;
    }
    assert.ok(lastDecision, 'should have produced a decision');
    assert.equal(lastDecision.action, 'revoke', `expected action=revoke, got ${lastDecision.action} score=${lastDecision.score}`);
    assert.ok(lastDecision.score >= 4.0,
        `expected score>=4.0, got ${lastDecision.score}`);
});

test('AnomalyModel flags slightly-anomalous metrics between flag and revoke thresholds', () => {
    const m = new AnomalyModel({ persistEnabled: false, retentionDays: 60 });
    const baselineCount = 200;
    for (let i = 0; i < baselineCount; i++) {
        m.addSample('LIC-FLAG', {
            cadenceMs: 5000,
            rdtscDeltaMean: 1e9,
            rdtscDeltaStd: 1e5,
            exceptionCount: 0,
            moduleLoadCount: 12,
            moduleLoadUnique: 12,
        }, Date.now() - (baselineCount - i) * 60_000);
    }
    for (let i = 0; i < baselineCount; i++) {
        const cadenceJitter = (i % 101) - 50;
        const rdtscJitter = ((i * 37) % 1009) * 1000;
        m.addSample('LIC-FLAG', {
            cadenceMs: 5000 + cadenceJitter,
            rdtscDeltaMean: 1e9 + rdtscJitter,
            rdtscDeltaStd: 1e5 + (i % 200),
            exceptionCount: 0,
            moduleLoadCount: 12 + (i % 20 === 0 ? 1 : 0),
            moduleLoadUnique: 12,
        }, Date.now() - (baselineCount - i) * 30_000);
    }
    const engine = new anomalyScore.AnomalyScoringEngine({ model: m, minBaselineSamples: 32 });
    const summary = m.summary('LIC-FLAG');
    const rdtscStd = Math.max(1, summary.metrics.rdtscDeltaMean.std);
    const flagDelta = (anomalyScore.FLAG_THRESHOLD + 0.4) * rdtscStd;
    const decision = engine.evaluate('LIC-FLAG', {
        cadenceMs: summary.metrics.cadenceMs.mean,
        rdtscDeltaMean: summary.metrics.rdtscDeltaMean.mean + flagDelta,
        rdtscDeltaStd: summary.metrics.rdtscDeltaStd.mean,
        exceptionCount: summary.metrics.exceptionCount.mean,
        moduleLoadCount: summary.metrics.moduleLoadCount.mean,
        moduleLoadUnique: summary.metrics.moduleLoadUnique.mean,
    });
    assert.ok(decision.score >= anomalyScore.FLAG_THRESHOLD,
        `expected score>=flag(${anomalyScore.FLAG_THRESHOLD}) got ${decision.score}`);
    assert.equal(decision.action === 'flag' || decision.action === 'revoke', true);
});

test('AnomalyScoringEngine warmup state suppresses flag/revoke until enough samples', () => {
    const m = new AnomalyModel({ persistEnabled: false });
    const engine = new anomalyScore.AnomalyScoringEngine({ model: m, minBaselineSamples: 32 });
    for (let i = 0; i < 5; i++) {
        m.addSample('LIC-WARM', {
            cadenceMs: 1000 + i,
            rdtscDeltaMean: 1e9,
            rdtscDeltaStd: 1e5,
            exceptionCount: 0,
            moduleLoadCount: 5,
            moduleLoadUnique: 5,
        }, Date.now() - (5 - i) * 1000);
    }
    const decision = engine.evaluate('LIC-WARM', { cadenceMs: 50000, exceptionCount: 999 });
    assert.equal(decision.action, 'warmup');
});

test('extractMetricsFromHeartbeat decodes rdtsc samples and module sequences', () => {
    const metrics = anomalyScore.extractMetricsFromHeartbeat({
        cadence_ms: 4500,
        rdtsc_deltas: ['1000000000', '1000050000', '1000100000', '1000160000'],
        exception_count: 2,
        module_load_sequence: ['ntdll.dll', 'kernel32.dll', 'KERNEL32.DLL', 'user32.dll'],
    }, null);
    assert.equal(metrics.cadenceMs, 4500);
    assert.ok(Number.isFinite(metrics.rdtscDeltaMean));
    assert.ok(Number.isFinite(metrics.rdtscDeltaStd));
    assert.equal(metrics.exceptionCount, 2);
    assert.equal(metrics.moduleLoadCount, 4);
    assert.equal(metrics.moduleLoadUnique, 3);
});

test('AnomalyModel persistSync round-trips license baselines via JSON', () => {
    const persistPath = path.join(tmpDir, 'roundtrip.json');
    const m1 = new AnomalyModel({ persistPath, persistEnabled: true });
    for (let i = 0; i < 20; i++) {
        m1.addSample('LIC-RT', { cadenceMs: 5000 + i, exceptionCount: 0 }, Date.now());
    }
    m1.persistSync();
    const m2 = new AnomalyModel({ persistPath, persistEnabled: true });
    m2.load();
    const summary = m2.summary('LIC-RT');
    assert.ok(summary, 'baseline should be reloaded');
    assert.ok(summary.sampleCount >= 20);
});

test('AnomalyScoringEngine simulated 30-day baseline + 5 anomalous heartbeats trip auto-revoke (integration log)', () => {
    const m = new AnomalyModel({ persistEnabled: false });
    const log = [];
    const baselineCount = 30 * 24;
    for (let i = 0; i < baselineCount; i++) {
        m.addSample('LIC-INT', {
            cadenceMs: 5000 + (Math.random() * 60 - 30),
            rdtscDeltaMean: 1e9,
            rdtscDeltaStd: 1e5,
            exceptionCount: 0,
            moduleLoadCount: 12,
            moduleLoadUnique: 12,
        }, Date.now() - (baselineCount - i) * 3600_000);
    }
    const engine = new anomalyScore.AnomalyScoringEngine({
        model: m,
        minBaselineSamples: 32,
        revokeThreshold: 4.0,
        minRevokeBaselineSamples: 32,
        revokeSustainedConsecutive: 3,
        revokeSustainedThreshold: 4.0,
    });
    let revokedAt = -1;
    for (let i = 0; i < 5; i++) {
        const metrics = {
            cadenceMs: 50 - i * 5,
            rdtscDeltaMean: 1e3,
            rdtscDeltaStd: 100,
            exceptionCount: 50 + i * 10,
            moduleLoadCount: 80 + i * 10,
            moduleLoadUnique: 80 + i * 10,
        };
        const decision = engine.evaluate('LIC-INT', metrics);
        engine.record('LIC-INT', metrics, Date.now());
        log.push(`heartbeat[${i}] action=${decision.action} score=${decision.score.toFixed(3)} reason=${decision.reason}`);
        if (decision.action === 'revoke' && revokedAt === -1) {
            revokedAt = i;
        }
    }
    console.log('[anomaly-trip-log]\n' + log.join('\n'));
    assert.notEqual(revokedAt, -1, 'expected at least one revoke decision in the 5 anomalous heartbeats');
});

test('false_positive_slow_cadence_should_not_revoke (regression for production revoke at z=4.116 cadenceMs=36000 mean=21220.41 std=3590.56 samples=676)', () => {
    const m = new AnomalyModel({ persistEnabled: false });
    const targetMean = 21220.41;
    const targetStd = 3590.56;
    const targetCount = 676;
    let rngState = 0xC0FFEE42;
    const rng = () => {
        rngState = (rngState * 1664525 + 1013904223) >>> 0;
        return rngState / 0xFFFFFFFF;
    };
    const gauss = () => {
        const u1 = Math.max(rng(), 1e-12);
        const u2 = rng();
        return Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
    };
    const raw = [];
    for (let i = 0; i < targetCount; i++) raw.push(gauss());
    const rawMean = raw.reduce((a, b) => a + b, 0) / raw.length;
    let rawSumSq = 0;
    for (const v of raw) rawSumSq += (v - rawMean) * (v - rawMean);
    const rawStd = Math.sqrt(rawSumSq / (raw.length - 1));
    const cadenceSeries = raw.map(v => targetMean + ((v - rawMean) / rawStd) * targetStd);
    const now = Date.now();
    for (let i = 0; i < targetCount; i++) {
        m.addSample('LIC-FALSE-POSITIVE', {
            cadenceMs: cadenceSeries[i],
            rdtscDeltaMean: 1e9 + (rng() * 1e6),
            rdtscDeltaStd: 1e5 + (rng() * 200),
            exceptionCount: 0,
            moduleLoadCount: 12,
            moduleLoadUnique: 12,
        }, now - (targetCount - i) * 60_000);
    }
    const summary = m.summary('LIC-FALSE-POSITIVE');
    assert.ok(summary, 'baseline summary must exist');
    assert.ok(Math.abs(summary.metrics.cadenceMs.mean - targetMean) < 1.0,
        `expected baseline mean ~${targetMean}, got ${summary.metrics.cadenceMs.mean}`);
    assert.ok(Math.abs(summary.metrics.cadenceMs.std - targetStd) < 1.0,
        `expected baseline std ~${targetStd}, got ${summary.metrics.cadenceMs.std}`);
    assert.equal(summary.sampleCount, targetCount);

    const engine = new anomalyScore.AnomalyScoringEngine({
        model: m,
        minBaselineSamples: 32,
    });
    const decision = engine.evaluate('LIC-FALSE-POSITIVE', {
        cadenceMs: 36000,
        rdtscDeltaMean: summary.metrics.rdtscDeltaMean.mean,
        rdtscDeltaStd: summary.metrics.rdtscDeltaStd.mean,
        exceptionCount: 0,
        moduleLoadCount: 12,
        moduleLoadUnique: 12,
    });
    assert.ok(decision.score >= 4.0,
        `raw z must still cross 4.0 for the test premise (got ${decision.score})`);
    assert.notEqual(decision.action, 'revoke',
        `slow-cadence outlier (laptop suspend/network blip) must NOT auto-revoke; got action=${decision.action} reason=${decision.reason}`);
    assert.equal(decision.action, 'observe',
        `expected action=observe for slow-cadence-only outlier within grace; got ${decision.action} reason=${decision.reason}`);
    assert.equal(decision.cadenceDirection, 'slow');
    assert.equal(decision.cadenceWithinSlowGrace, true);
    assert.equal(decision.suppression, 'slow_cadence_within_grace');
});

test('sustained_fast_cadence_bot_pattern_should_revoke_after_consecutive_samples (counterpart: bot spamming heartbeats trips even when single sample below z=6)', () => {
    const m = new AnomalyModel({ persistEnabled: false });
    const targetMean = 21220.41;
    const targetStd = 3590.56;
    const targetCount = 1024;
    let rngState = 0xBADF00D1;
    const rng = () => {
        rngState = (rngState * 1664525 + 1013904223) >>> 0;
        return rngState / 0xFFFFFFFF;
    };
    const gauss = () => {
        const u1 = Math.max(rng(), 1e-12);
        const u2 = rng();
        return Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
    };
    const raw = [];
    for (let i = 0; i < targetCount; i++) raw.push(gauss());
    const rawMean = raw.reduce((a, b) => a + b, 0) / raw.length;
    let rawSumSq = 0;
    for (const v of raw) rawSumSq += (v - rawMean) * (v - rawMean);
    const rawStd = Math.sqrt(rawSumSq / (raw.length - 1));
    const cadenceSeries = raw.map(v => targetMean + ((v - rawMean) / rawStd) * targetStd);
    const now = Date.now();
    for (let i = 0; i < targetCount; i++) {
        m.addSample('LIC-BOT', {
            cadenceMs: cadenceSeries[i],
            rdtscDeltaMean: 1e9,
            rdtscDeltaStd: 1e5,
            exceptionCount: 0,
            moduleLoadCount: 12,
            moduleLoadUnique: 12,
        }, now - (targetCount - i) * 60_000);
    }
    const engine = new anomalyScore.AnomalyScoringEngine({
        model: m,
        minBaselineSamples: 32,
    });
    let revokeAt = -1;
    let lastDecision = null;
    for (let i = 0; i < 12; i++) {
        const fastCadence = 1000;
        const decision = engine.evaluate('LIC-BOT', {
            cadenceMs: fastCadence,
            rdtscDeltaMean: 1e9,
            rdtscDeltaStd: 1e5,
            exceptionCount: 0,
            moduleLoadCount: 12,
            moduleLoadUnique: 12,
        });
        lastDecision = decision;
        if (decision.action === 'revoke' && revokeAt === -1) {
            revokeAt = i;
            break;
        }
    }
    assert.notEqual(revokeAt, -1,
        `sustained fast-cadence automation MUST eventually revoke; lastDecision=${JSON.stringify(lastDecision && { action: lastDecision.action, reason: lastDecision.reason, score: lastDecision.score, consecutive: lastDecision.consecutiveAnomalous })}`);
    assert.ok(revokeAt >= anomalyScore.REVOKE_SUSTAINED_CONSECUTIVE - 1,
        `should not revoke before ${anomalyScore.REVOKE_SUSTAINED_CONSECUTIVE} consecutive anomalous samples; revoked at ${revokeAt}`);
});

test('single_high_z_below_revoke_threshold_with_low_baseline_should_flag_not_revoke', () => {
    const m = new AnomalyModel({ persistEnabled: false });
    const baselineCount = 200;
    for (let i = 0; i < baselineCount; i++) {
        m.addSample('LIC-LOW-BASE', {
            cadenceMs: 5000,
            rdtscDeltaMean: 1e9,
            rdtscDeltaStd: 1e5,
            exceptionCount: 0,
            moduleLoadCount: 12,
            moduleLoadUnique: 12,
        }, Date.now() - (baselineCount - i) * 60_000);
    }
    const engine = new anomalyScore.AnomalyScoringEngine({
        model: m,
        minBaselineSamples: 32,
    });
    const decision = engine.evaluate('LIC-LOW-BASE', {
        cadenceMs: 50,
        rdtscDeltaMean: 1,
        rdtscDeltaStd: 1,
        exceptionCount: 99,
        moduleLoadCount: 99,
        moduleLoadUnique: 99,
    });
    assert.ok(decision.score >= anomalyScore.REVOKE_THRESHOLD,
        `single-sample score must cross immediate-revoke threshold for this test (got ${decision.score})`);
    assert.notEqual(decision.action, 'revoke',
        `immature baseline (samples=${decision.sampleCount} < ${anomalyScore.MIN_REVOKE_BASELINE_SAMPLES}) must NOT auto-revoke; got ${decision.action}`);
    assert.equal(decision.action, 'flag');
    assert.equal(decision.suppression, 'revoke_baseline_immature');
});

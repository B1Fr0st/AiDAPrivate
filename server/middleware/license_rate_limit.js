'use strict';

const pool = require('../db/pool');

const MINUTE_SECONDS = 60;
const HOUR_SECONDS = 3600;
const DAY_SECONDS = 86400;

function parseLimit(name, fallback) {
    const value = parseInt(process.env[name] || String(fallback), 10);
    return Number.isFinite(value) && value > 0 ? value : fallback;
}

const DEFAULT_PER_MINUTE = parseLimit('LICENSE_RL_PER_MINUTE', 30);
const DEFAULT_PER_HOUR = parseLimit('LICENSE_RL_PER_HOUR', 100);
const DEFAULT_PER_DAY = parseLimit('LICENSE_RL_PER_DAY', 500);
const DEFAULT_HEARTBEAT_PER_MINUTE = parseLimit('LICENSE_HEARTBEAT_RL_PER_MINUTE', 8);
const DEFAULT_HEARTBEAT_PER_HOUR = parseLimit('LICENSE_HEARTBEAT_RL_PER_HOUR', 420);
const DEFAULT_HEARTBEAT_PER_DAY = parseLimit('LICENSE_HEARTBEAT_RL_PER_DAY', 7500);

let s_last_purge_at = 0;

async function purgeExpired(now) {
    try {
        await pool.query(
            'DELETE FROM license_request_rate WHERE window_kind = $1 AND window_start < $2',
            ['minute', now - MINUTE_SECONDS * 3]
        );
        await pool.query(
            'DELETE FROM license_request_rate WHERE window_kind = $1 AND window_start < $2',
            ['hour', now - HOUR_SECONDS * 3]
        );
        await pool.query(
            'DELETE FROM license_request_rate WHERE window_kind = $1 AND window_start < $2',
            ['day', now - DAY_SECONDS * 3]
        );
    } catch (_) { }
}

function windowStartFor(kind, now) {
    const n = Math.floor(now);
    if (kind === 'minute') return Math.floor(n / MINUTE_SECONDS) * MINUTE_SECONDS;
    if (kind === 'hour') return Math.floor(n / HOUR_SECONDS) * HOUR_SECONDS;
    return Math.floor(n / DAY_SECONDS) * DAY_SECONDS;
}

async function bumpAndCheckWindow(licenseKey, kind, now, limit) {
    const windowStart = windowStartFor(kind, now);
    const { rows } = await pool.query(
        `INSERT INTO license_request_rate (license_key, window_kind, window_start, count)
         VALUES ($1, $2, $3, 1)
         ON CONFLICT (license_key, window_kind, window_start)
         DO UPDATE SET count = license_request_rate.count + 1
         RETURNING count`,
        [licenseKey, kind, windowStart]
    );
    const current = rows.length > 0 ? Number(rows[0].count) : 1;
    return { current, limit, exceeded: current > limit, window_start: windowStart };
}

function normalizeBucket(value) {
    if (typeof value !== 'string')
        return 'default';
    const bucket = value.trim().toLowerCase();
    if (!/^[a-z0-9_.:-]{1,32}$/.test(bucket))
        return 'default';
    return bucket;
}

function rateKeyFor(licenseKey, bucket) {
    const normalizedBucket = normalizeBucket(bucket);
    return normalizedBucket === 'default' ? licenseKey : `${licenseKey}|${normalizedBucket}`;
}

async function check(licenseKey, options) {
    if (!licenseKey || typeof licenseKey !== 'string') {
        return { ok: true, skipped: true };
    }
    const opts = options || {};
    const perMinute = Number.isFinite(opts.per_minute) ? opts.per_minute : DEFAULT_PER_MINUTE;
    const perHour = Number.isFinite(opts.per_hour) ? opts.per_hour : DEFAULT_PER_HOUR;
    const perDay = Number.isFinite(opts.per_day) ? opts.per_day : DEFAULT_PER_DAY;
    const bucket = normalizeBucket(opts.bucket);
    const rateKey = rateKeyFor(licenseKey, bucket);

    const now = Math.floor(Date.now() / 1000);
    if (now - s_last_purge_at > 300) {
        s_last_purge_at = now;
        purgeExpired(now).catch(() => {});
    }

    try {
        const minute = await bumpAndCheckWindow(rateKey, 'minute', now, perMinute);
        if (minute.exceeded) {
            return {
                ok: false,
                reason: 'rate_limited',
                scope: 'minute',
                bucket,
                retry_after: Math.max(1, (minute.window_start + MINUTE_SECONDS) - now),
            };
        }
        const hour = await bumpAndCheckWindow(rateKey, 'hour', now, perHour);
        if (hour.exceeded) {
            return {
                ok: false,
                reason: 'rate_limited',
                scope: 'hour',
                bucket,
                retry_after: Math.max(1, (hour.window_start + HOUR_SECONDS) - now),
            };
        }
        const day = await bumpAndCheckWindow(rateKey, 'day', now, perDay);
        if (day.exceeded) {
            return {
                ok: false,
                reason: 'rate_limited',
                scope: 'day',
                bucket,
                retry_after: Math.max(1, (day.window_start + DAY_SECONDS) - now),
            };
        }
        return { ok: true, bucket, minute: minute.current, hour: hour.current, day: day.current };
    } catch (err) {
        console.warn('[license_rate_limit] check failed:', err && err.message ? err.message : err);
        if (opts.fail_closed) {
            return { ok: false, reason: 'rate_limit_unavailable', soft_fail: true };
        }
        return { ok: true, soft_fail: true };
    }
}

module.exports = {
    check,
    purgeExpired,
    rateKeyFor,
    DEFAULT_PER_MINUTE,
    DEFAULT_PER_HOUR,
    DEFAULT_PER_DAY,
    DEFAULT_HEARTBEAT_PER_MINUTE,
    DEFAULT_HEARTBEAT_PER_HOUR,
    DEFAULT_HEARTBEAT_PER_DAY,
};

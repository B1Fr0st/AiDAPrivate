'use strict';

const crypto = require('crypto');

const HEARTBEAT_INTERVAL_KEY_PREFIX = 'aida:hb:int:';
const HEARTBEAT_WINDOW_KEY_PREFIX = 'aida:hb:win:';
const HEARTBEAT_INTERVAL_SECONDS = parseInt(process.env.HEARTBEAT_MIN_INTERVAL_SECONDS || '10', 10);
const HEARTBEAT_WINDOW_SECONDS = parseInt(process.env.HEARTBEAT_WINDOW_SECONDS || '60', 10);
const HEARTBEAT_WINDOW_MAX_EVENTS = parseInt(process.env.HEARTBEAT_WINDOW_MAX_EVENTS || '5', 10);

let s_redis = null;
let s_redisInitTried = false;
let s_redisOk = false;
let s_inmemoryStore = null;
let s_inmemoryWarned = false;

function loadRedis() {
    if (s_redisInitTried) return s_redis;
    s_redisInitTried = true;
    const url = (process.env.REDIS_URL || '').trim();
    if (!url) {
        return null;
    }
    let Redis;
    try {
        Redis = require('ioredis');
    } catch (_) {
        return null;
    }
    try {
        const client = new Redis(url, {
            lazyConnect: false,
            maxRetriesPerRequest: 2,
            enableReadyCheck: true,
            reconnectOnError: () => true,
        });
        client.on('error', (err) => {
            s_redisOk = false;
            console.warn('[rate_limit] redis error:', err && err.message ? err.message : err);
        });
        client.on('ready', () => {
            s_redisOk = true;
            console.log('[rate_limit] redis ready at', url.replace(/:[^:@/]+@/, ':***@'));
        });
        s_redis = client;
        return client;
    } catch (err) {
        console.warn('[rate_limit] redis init failed:', err && err.message ? err.message : err);
        return null;
    }
}

function setRedisClientForTesting(client) {
    s_redis = client;
    s_redisInitTried = true;
    s_redisOk = !!client;
}

function getRedisStatus() {
    return {
        configured: !!s_redis,
        ready: !!s_redisOk,
    };
}

function ensureInMemoryStore() {
    if (s_inmemoryStore) return s_inmemoryStore;
    if (!s_inmemoryWarned) {
        s_inmemoryWarned = true;
        console.warn('[rate_limit] REDIS_URL not configured; using in-memory fallback (single-instance only). Set REDIS_URL for production.');
    }
    s_inmemoryStore = {
        intervals: new Map(),
        windows: new Map(),
        nonces: new Map(),
    };
    setInterval(() => {
        const now = Date.now();
        for (const [k, v] of s_inmemoryStore.intervals) {
            if (v.expiresAtMs < now) s_inmemoryStore.intervals.delete(k);
        }
        for (const [k, v] of s_inmemoryStore.windows) {
            v.events = v.events.filter(e => (now - e) < HEARTBEAT_WINDOW_SECONDS * 1000);
            if (v.events.length === 0) s_inmemoryStore.windows.delete(k);
        }
        for (const [k, v] of s_inmemoryStore.nonces) {
            if (v.expiresAtMs < now) s_inmemoryStore.nonces.delete(k);
        }
    }, 5000).unref();
    return s_inmemoryStore;
}

function bucketKey(prefix, licenseKey, sessionToken) {
    const hmac = crypto.createHash('sha256').update(`${licenseKey}|${sessionToken}`).digest('hex').slice(0, 32);
    return prefix + hmac;
}

async function checkAndRegisterHeartbeat(licenseKey, sessionToken) {
    if (!licenseKey || !sessionToken) {
        return { ok: false, reason: 'missing_identifiers', retryAfter: 0 };
    }
    const intervalKey = bucketKey(HEARTBEAT_INTERVAL_KEY_PREFIX, licenseKey, sessionToken);
    const windowKey = bucketKey(HEARTBEAT_WINDOW_KEY_PREFIX, licenseKey, sessionToken);

    const redis = loadRedis();
    if (redis && s_redisOk) {
        try {
            const setResult = await redis.set(intervalKey, '1', 'EX', HEARTBEAT_INTERVAL_SECONDS, 'NX');
            if (setResult !== 'OK') {
                const ttl = await redis.ttl(intervalKey).catch(() => 0);
                return { ok: false, reason: 'heartbeat_too_fast', retryAfter: Math.max(1, ttl) };
            }
            const nowMs = Date.now();
            const cutoff = nowMs - (HEARTBEAT_WINDOW_SECONDS * 1000);
            const eventId = `${nowMs}-${crypto.randomBytes(4).toString('hex')}`;
            const pipe = redis.multi();
            pipe.zremrangebyscore(windowKey, 0, cutoff);
            pipe.zadd(windowKey, nowMs, eventId);
            pipe.zcard(windowKey);
            pipe.expire(windowKey, HEARTBEAT_WINDOW_SECONDS + 5);
            const results = await pipe.exec();
            const card = results && results[2] && Number(results[2][1]);
            if (Number.isFinite(card) && card > HEARTBEAT_WINDOW_MAX_EVENTS) {
                return { ok: false, reason: 'heartbeat_window_exceeded', retryAfter: HEARTBEAT_WINDOW_SECONDS };
            }
            return { ok: true };
        } catch (err) {
            console.warn('[rate_limit] redis heartbeat check error, falling back to in-memory:', err && err.message);
        }
    }

    const store = ensureInMemoryStore();
    const nowMs = Date.now();
    const existing = store.intervals.get(intervalKey);
    if (existing && existing.expiresAtMs > nowMs) {
        const retryAfter = Math.max(1, Math.ceil((existing.expiresAtMs - nowMs) / 1000));
        return { ok: false, reason: 'heartbeat_too_fast', retryAfter };
    }
    store.intervals.set(intervalKey, { expiresAtMs: nowMs + HEARTBEAT_INTERVAL_SECONDS * 1000 });
    let win = store.windows.get(windowKey);
    if (!win) {
        win = { events: [] };
        store.windows.set(windowKey, win);
    }
    const cutoff = nowMs - HEARTBEAT_WINDOW_SECONDS * 1000;
    win.events = win.events.filter(e => e > cutoff);
    win.events.push(nowMs);
    if (win.events.length > HEARTBEAT_WINDOW_MAX_EVENTS) {
        return { ok: false, reason: 'heartbeat_window_exceeded', retryAfter: HEARTBEAT_WINDOW_SECONDS };
    }
    return { ok: true };
}

async function registerNonce(licenseKey, sessionToken, nonce, ttlSeconds) {
    if (!licenseKey || !sessionToken || !nonce) return { ok: false, reason: 'missing_identifiers' };
    const ttl = Number.isFinite(ttlSeconds) && ttlSeconds > 0 ? Math.floor(ttlSeconds) : 60;
    const key = bucketKey('aida:nc:', licenseKey, sessionToken) + ':' + nonce;

    const redis = loadRedis();
    if (redis && s_redisOk) {
        try {
            const setResult = await redis.set(key, '1', 'EX', ttl, 'NX');
            if (setResult !== 'OK') {
                return { ok: false, reason: 'nonce_replay' };
            }
            return { ok: true };
        } catch (err) {
            console.warn('[rate_limit] redis nonce register error, falling back:', err && err.message);
        }
    }
    const store = ensureInMemoryStore();
    const nowMs = Date.now();
    const existing = store.nonces.get(key);
    if (existing && existing.expiresAtMs > nowMs) {
        return { ok: false, reason: 'nonce_replay' };
    }
    store.nonces.set(key, { expiresAtMs: nowMs + ttl * 1000 });
    return { ok: true };
}

async function nonceSeen(licenseKey, sessionToken, nonce) {
    if (!licenseKey || !sessionToken || !nonce) return false;
    const key = bucketKey('aida:nc:', licenseKey, sessionToken) + ':' + nonce;
    const redis = loadRedis();
    if (redis && s_redisOk) {
        try {
            const v = await redis.get(key);
            return v !== null;
        } catch (err) {
            console.warn('[rate_limit] redis nonce check error:', err && err.message);
        }
    }
    const store = ensureInMemoryStore();
    const nowMs = Date.now();
    const existing = store.nonces.get(key);
    if (!existing) return false;
    if (existing.expiresAtMs <= nowMs) {
        store.nonces.delete(key);
        return false;
    }
    return true;
}

async function shutdownForTests() {
    try {
        if (s_redis && typeof s_redis.quit === 'function') {
            await s_redis.quit();
        }
    } catch (_) { }
    s_redis = null;
    s_redisOk = false;
    s_redisInitTried = false;
    s_inmemoryStore = null;
    s_inmemoryWarned = false;
}

module.exports = {
    checkAndRegisterHeartbeat,
    registerNonce,
    nonceSeen,
    setRedisClientForTesting,
    getRedisStatus,
    shutdownForTests,
    HEARTBEAT_INTERVAL_SECONDS,
    HEARTBEAT_WINDOW_SECONDS,
    HEARTBEAT_WINDOW_MAX_EVENTS,
};

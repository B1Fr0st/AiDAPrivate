// ============================================================================
// AiDA License Bot — Discord bot for managing AiDA license keys
// ============================================================================
// Migrated from Firebase RTDB to PostgreSQL.
//
// Commands (owner-only slash commands):
//   /generate      duration plan [note]          — Create one license key
//   /bulk_generate count duration plan [note]    — Create multiple keys
//   /revoke        key                           — Delete a license key permanently
//   /info          key                           — Full details of a key
//   /list          [filter]                      — List keys with optional filter
//   /search        query                         — Search by note/plan/creator
//   /stats                                       — Aggregate statistics
//   /reset_hwid    key                           — Clear HWID binding
//   /extend        key [days] [hours]            — Extend expiry by days or hours
//   /setnote       key note                      — Update note/label
//   /transfer      key new_hwid                  — Transfer license to new HWID
//   /set_plan      key plan                      — Change subscription plan
//   /set_expiry    key date                      — Set exact expiry date
//   /ban           hwid [ip] [reason]            — Manually ban HWID/IP
//   /unban         target                        — Remove ban by HWID or IP
//   /baninfo       target                        — Show ban details
//   /bans                                        — List all active bans
//   /violations    [limit]                       — View violation audit log
//   /lookup_hwid   hwid                          — Find licenses by HWID
//   /purge_expired                               — Delete all expired licenses
//   /sessions                                    — List active sessions
//   /nuke          key                           — Delete license + session + bans
//   /dashboard                                   — Combined stats overview
//
// Only OWNER_ID can invoke any command.
// Uses direct PostgreSQL queries (replaces Firebase REST).
// ============================================================================

(function loadDotEnv() {
    const fs = require('fs');
    const path = require('path');
    const envPath = path.join(__dirname, '.env');
    if (!fs.existsSync(envPath)) return;
    let raw;
    try {
        raw = fs.readFileSync(envPath, 'utf8');
    } catch (err) {
        console.error('[bot] failed to read .env:', err && err.message ? err.message : err);
        return;
    }
    const lines = raw.split(/\r?\n/);
    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const eqIdx = trimmed.indexOf('=');
        if (eqIdx <= 0) continue;
        const key = trimmed.substring(0, eqIdx).trim();
        if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
        let value = trimmed.substring(eqIdx + 1).trim();
        if ((value.startsWith('"') && value.endsWith('"') && value.length >= 2) ||
            (value.startsWith("'") && value.endsWith("'") && value.length >= 2)) {
            value = value.slice(1, -1);
        }
        if (process.env[key] === undefined || process.env[key] === '') {
            process.env[key] = value;
        }
    }
})();

const {
    Client,
    GatewayIntentBits,
    SlashCommandBuilder,
    REST,
    Routes,
    EmbedBuilder,
    MessageFlags,
} = require('discord.js');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const { Pool } = require('pg');
const audit = require('./audit');
const dbReadonly = require('./db_readonly');

const BOT_TOKEN          = process.env.AIDA_BOT_TOKEN          || '';
const RAW_OWNER_IDS      = process.env.AIDA_OWNER_IDS          || process.env.AIDA_OWNER_ID || '';
const DATABASE_URL       = process.env.AIDA_DATABASE_URL       || '';
const ADMIN_API_BASE     = process.env.AIDA_ADMIN_API_BASE     || '';
const ADMIN_HMAC_KEY     = process.env.AIDA_ADMIN_HMAC_KEY     || '';
const ADMIN_API_KEY      = process.env.AIDA_ADMIN_API_KEY      || '';
const BOT_ED25519_PRIV_B64 = process.env.BOT_ED25519_PRIVATE_KEY_B64 || '';

let _botPrivKey = null;
function getBotPrivateKey() {
    if (_botPrivKey) return _botPrivKey;
    if (!BOT_ED25519_PRIV_B64) return null;
    try {
        const raw = Buffer.from(BOT_ED25519_PRIV_B64, 'base64');
        if (raw.length === 32) {
            const PKCS8_PREFIX = Buffer.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);
            _botPrivKey = crypto.createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, raw]), format: 'der', type: 'pkcs8' });
        } else {
            _botPrivKey = crypto.createPrivateKey({ key: raw, format: 'der', type: 'pkcs8' });
        }
        return _botPrivKey;
    } catch (err) {
        console.error('[bot] BOT_ED25519_PRIVATE_KEY_B64 parse failed:', err && err.message ? err.message : err);
        return null;
    }
}

function botCanonicalize(payload) {
    return JSON.stringify(Object.keys(payload).sort().reduce((acc, k) => {
        acc[k] = payload[k];
        return acc;
    }, {}));
}

function signBotPayload(payload) {
    const key = getBotPrivateKey();
    if (!key) return '';
    const canonical = botCanonicalize(payload);
    return crypto.sign(null, Buffer.from(canonical, 'utf8'), key).toString('base64');
}

async function callServerAction(action, fields) {
    if (!ADMIN_API_BASE) {
        return { ok: false, reason: 'admin_api_base_not_configured' };
    }
    const base = ADMIN_API_BASE.trim().replace(/\/+$/, '');
    const url = /\/api\/license$/i.test(base)
        ? base + '/' + encodeURIComponent(action)
        : /\/api$/i.test(base)
            ? base + '/license/' + encodeURIComponent(action)
            : base + '/api/license/' + encodeURIComponent(action);
    const payload = Object.assign({
        action,
        nonce: crypto.randomBytes(16).toString('hex'),
        ts: Math.floor(Date.now() / 1000),
    }, fields || {});
    if (ADMIN_API_KEY) {
        payload.admin_key = ADMIN_API_KEY;
    }
    const sig = signBotPayload(payload);
    const headers = { 'Content-Type': 'application/json' };
    if (sig) headers['x-bot-signature'] = sig;
    try {
        const resp = await fetch(url, {
            method: 'POST',
            headers,
            body: JSON.stringify(payload),
        });
        const text = await resp.text();
        let body = null;
        try { body = JSON.parse(text); } catch { body = { raw: text }; }
        return { ok: resp.ok, status: resp.status, body };
    } catch (err) {
        return { ok: false, reason: 'network_error', error: err && err.message ? err.message : String(err) };
    }
}

function serverActionFailure(result) {
    const body = result && (result.body || result.response);
    const parts = [];
    if (body && typeof body === 'object') {
        for (const key of ['reason', 'error_code', 'error', 'status']) {
            if (body[key]) {
                parts.push(String(body[key]));
                break;
            }
        }
        if (!parts.length && typeof body.raw === 'string' && body.raw.trim()) {
            parts.push(body.raw.trim().replace(/\s+/g, ' ').slice(0, 160));
        }
    }
    if (!parts.length && result && result.reason) parts.push(String(result.reason));
    if (!parts.length && result && result.error) parts.push(String(result.error));
    if (result && result.status) parts.push('HTTP ' + result.status);
    return parts.length ? parts.join(' / ') : 'unknown';
}

function embedPayloadLength(embed) {
    const data = typeof embed.toJSON === 'function' ? embed.toJSON() : (embed || {});
    let total = 0;
    const add = value => {
        if (value !== undefined && value !== null) total += String(value).length;
    };
    add(data.title);
    add(data.description);
    if (data.author) add(data.author.name);
    if (data.footer) add(data.footer.text);
    if (Array.isArray(data.fields)) {
        for (const field of data.fields) {
            add(field.name);
            add(field.value);
        }
    }
    return total;
}

function chunkLines(lines, maxLength = 3800) {
    const chunks = [];
    let current = '';
    for (const rawLine of lines) {
        const line = String(rawLine || '');
        if (line.length > maxLength) {
            if (current) {
                chunks.push(current);
                current = '';
            }
            chunks.push(line.slice(0, maxLength - 3) + '...');
            continue;
        }
        const next = current ? `${current}\n${line}` : line;
        if (next.length > maxLength) {
            if (current) chunks.push(current);
            current = line;
        } else {
            current = next;
        }
    }
    if (current) chunks.push(current);
    return chunks;
}

async function sendEmbedPages(interaction, embeds) {
    const pages = Array.isArray(embeds) ? embeds.filter(Boolean) : [];
    if (!pages.length) return interaction.editReply('No results.');

    const messages = [];
    let current = [];
    let currentLength = 0;
    for (const embed of pages) {
        const length = embedPayloadLength(embed);
        if (current.length > 0 && (current.length >= 10 || currentLength + length > 5800)) {
            messages.push(current);
            current = [];
            currentLength = 0;
        }
        current.push(embed);
        currentLength += length;
    }
    if (current.length > 0) messages.push(current);

    await interaction.editReply({ embeds: messages[0] });
    for (const batch of messages.slice(1)) {
        await interaction.followUp({ embeds: batch, flags: MessageFlags.Ephemeral });
    }
}

if (!BOT_TOKEN) {
    console.error('[bot] FATAL: AIDA_BOT_TOKEN must be set in env (no in-source default).');
    process.exit(1);
}
if (!DATABASE_URL) {
    console.error('[bot] FATAL: AIDA_DATABASE_URL must be set in env.');
    process.exit(1);
}

const OWNER_IDS = new Set(
    RAW_OWNER_IDS.split(',').map(s => s.trim()).filter(s => /^[0-9]{15,25}$/.test(s))
);
if (OWNER_IDS.size === 0) {
    console.error('[bot] FATAL: AIDA_OWNER_IDS must list at least one Discord user id.');
    process.exit(1);
}

// ─── PostgreSQL connection pool ───────────────────────────────────────────────

const _dbUrl                = DATABASE_URL || '';
const _isLocalDb            = /(@|\/\/)(localhost|127\.0\.0\.1)\b/i.test(_dbUrl);
const _sslModeMatch         = _dbUrl.match(/[?&]sslmode=([a-zA-Z-]+)/);
const _sslModeFromUrl       = _sslModeMatch ? _sslModeMatch[1].toLowerCase() : '';
const _sslExplicitlyDisabled = _sslModeFromUrl === 'disable';
const _sslVerify            = String(process.env.AIDA_BOT_PG_SSL_VERIFY || '0') === '1';
const _poolSsl =
    _sslExplicitlyDisabled ? false :
    _isLocalDb             ? false :
                             { rejectUnauthorized: _sslVerify };

const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: _poolSsl,
    max: 5,
    idleTimeoutMillis: 30000,
});

pool.on('error', (err) => {
    console.error('PostgreSQL pool error:', err.message);
});

// ─── PostgreSQL helpers ───────────────────────────────────────────────────────

async function pgQuery(text, params) {
    return pool.query(text, params);
}

// ─── Constants & Helpers ─────────────────────────────────────────────────────

const PLANS = ['pro', 'basic', 'enterprise', 'lifetime', 'trial'];

const DURATION_CHOICES = [
    { name: '1 day',     value: 1   },
    { name: '7 days',    value: 7   },
    { name: '30 days',   value: 30  },
    { name: '90 days',   value: 90  },
    { name: '180 days',  value: 180 },
    { name: '365 days',  value: 365 },
    { name: 'Perpetual', value: 0   },
];

function generateKey() {
    const raw = uuidv4().replace(/-/g, '').toUpperCase().slice(0, 16);
    return `AIDA-${raw.slice(0,4)}-${raw.slice(4,8)}-${raw.slice(8,12)}-${raw.slice(12,16)}`;
}

function todayStr() {
    return new Date().toISOString().slice(0, 10);
}

function addDays(base, days) {
    const d = base ? new Date(base) : new Date();
    d.setDate(d.getDate() + days);
    return d.toISOString().slice(0, 10);
}

function isDateOnly(value) {
    return /^\d{4}-\d{2}-\d{2}$/.test(value);
}

function parseExpiry(value) {
    if (!value) return null;
    if (isDateOnly(value)) return new Date(`${value}T23:59:59.999Z`);
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? null : d;
}

function isExpired(value) {
    const d = parseExpiry(value);
    return d ? d.getTime() < Date.now() : false;
}

function formatExpiry(dateStr) {
    if (!dateStr) return '♾️ Perpetual';
    const d = parseExpiry(dateStr);
    if (!d) return dateStr;
    const expired = d.getTime() < Date.now();
    const label = isDateOnly(dateStr)
        ? dateStr
        : `${d.toISOString().slice(0, 10)} ${d.toISOString().slice(11, 16)} UTC`;
    return expired ? `~~${label}~~ *(expired)*` : label;
}

function addDuration(base, days, hours) {
    const baseDate = parseExpiry(base) || new Date();
    const d = new Date(baseDate.getTime());
    if (days) d.setUTCDate(d.getUTCDate() + days);
    if (hours) d.setUTCHours(d.getUTCHours() + hours);
    const includeTime = hours || (base && !isDateOnly(base));
    return includeTime ? d.toISOString() : d.toISOString().slice(0, 10);
}

function licenseStatus(data) {
    if (isExpired(data.expires))
        return { label: '⚠️ Expired',  color: 0xFF8800 };
    return     { label: '✅ Active',   color: 0x00FF88 };
}

function isOwner(interaction) {
    return OWNER_IDS.has(interaction.user.id);
}

const DISCORD_ADMIN_ROLE_ID = (process.env.DISCORD_ADMIN_ROLE_ID || '').trim();

function isAdminInteraction(interaction) {
    if (isOwner(interaction)) return true;
    if (!DISCORD_ADMIN_ROLE_ID) return false;
    try {
        const member = interaction.member;
        if (!member) return false;
        const roles = member.roles && member.roles.cache;
        if (roles && typeof roles.has === 'function') {
            return roles.has(DISCORD_ADMIN_ROLE_ID);
        }
        if (Array.isArray(member.roles)) {
            return member.roles.includes(DISCORD_ADMIN_ROLE_ID);
        }
    } catch (_) { }
    return false;
}

const BOT_RATE_LIMITS = {
    issuePerHour: parseInt(process.env.AIDA_BOT_ISSUE_PER_HOUR || '3', 10) || 3,
    issuePerDay: parseInt(process.env.AIDA_BOT_ISSUE_PER_DAY || '10', 10) || 10,
    burstWindowSeconds: parseInt(process.env.AIDA_BOT_BURST_WINDOW_S || '60', 10) || 60,
    burstMax: parseInt(process.env.AIDA_BOT_BURST_MAX || '5', 10) || 5,
    burstLockoutSeconds: parseInt(process.env.AIDA_BOT_BURST_LOCKOUT_S || '600', 10) || 600,
};

const ISSUE_COMMAND_SET = new Set(['generate', 'bulk_generate']);

const inMemoryActivity = new Map();

function pruneActivity(userId, now) {
    const arr = inMemoryActivity.get(userId);
    if (!arr) return [];
    const cutoff = now - BOT_RATE_LIMITS.burstWindowSeconds * 1000 - 5000;
    const fresh = arr.filter(entry => entry.ts >= cutoff);
    if (fresh.length === 0) {
        inMemoryActivity.delete(userId);
    } else {
        inMemoryActivity.set(userId, fresh);
    }
    return fresh;
}

function recordActivity(userId, action) {
    const now = Date.now();
    const fresh = pruneActivity(userId, now);
    fresh.push({ ts: now, action });
    inMemoryActivity.set(userId, fresh);
    return fresh;
}

async function isLockedOut(userId, now) {
    try {
        const nowSec = Math.floor((now || Date.now()) / 1000);
        const { rows } = await pgQuery(
            'SELECT locked_until, reason FROM bot_user_lockout WHERE discord_user_id = $1',
            [userId]
        );
        if (rows.length > 0 && Number(rows[0].locked_until) > nowSec) {
            return { locked: true, until: Number(rows[0].locked_until), reason: rows[0].reason || '' };
        }
        if (rows.length > 0 && Number(rows[0].locked_until) <= nowSec) {
            await pgQuery('DELETE FROM bot_user_lockout WHERE discord_user_id = $1', [userId]).catch(() => {});
        }
    } catch (_) { }
    return { locked: false };
}

async function setLockout(userId, durationSec, reason) {
    const until = Math.floor(Date.now() / 1000) + Math.floor(durationSec || 0);
    try {
        await pgQuery(
            `INSERT INTO bot_user_lockout (discord_user_id, locked_until, reason)
             VALUES ($1, $2, $3)
             ON CONFLICT (discord_user_id)
             DO UPDATE SET locked_until = EXCLUDED.locked_until, reason = EXCLUDED.reason, created_at = NOW()`,
            [userId, until, String(reason || '').slice(0, 256)]
        );
    } catch (err) {
        console.warn('[bot] setLockout failed:', err && err.message ? err.message : err);
    }
}

async function bumpWindow(userId, kind, now, limit) {
    let windowStart;
    if (kind === 'hour') windowStart = Math.floor(now / 3600) * 3600;
    else if (kind === 'day') windowStart = Math.floor(now / 86400) * 86400;
    else windowStart = Math.floor(now / 60) * 60;
    try {
        const { rows } = await pgQuery(
            `INSERT INTO bot_command_rate (discord_user_id, window_kind, window_start, count)
             VALUES ($1, $2, $3, 1)
             ON CONFLICT (discord_user_id, window_kind, window_start)
             DO UPDATE SET count = bot_command_rate.count + 1
             RETURNING count`,
            [userId, kind, windowStart]
        );
        const current = rows.length > 0 ? Number(rows[0].count) : 1;
        return { current, exceeded: current > limit, window_start: windowStart };
    } catch (err) {
        return { current: 0, exceeded: false, window_start: windowStart };
    }
}

async function checkAbuseGate(interaction) {
    const userId = interaction.user.id;
    const commandName = interaction.commandName;
    const nowMs = Date.now();
    const nowSec = Math.floor(nowMs / 1000);

    const lock = await isLockedOut(userId, nowMs);
    if (lock.locked) {
        return { ok: false, reason: 'locked_out', message: `⛔ You are temporarily locked out (until <t:${lock.until}:R>).` };
    }

    const activity = recordActivity(userId, commandName);
    const windowCutoff = nowMs - BOT_RATE_LIMITS.burstWindowSeconds * 1000;
    const recent = activity.filter(e => e.ts >= windowCutoff).length;
    if (recent > BOT_RATE_LIMITS.burstMax) {
        await setLockout(userId, BOT_RATE_LIMITS.burstLockoutSeconds, 'burst_exceeded');
        try { await callServerAuditLog('bot.lockout', '', userId, 'burst_exceeded', { recent, window_s: BOT_RATE_LIMITS.burstWindowSeconds }); } catch (_) { }
        return { ok: false, reason: 'burst_exceeded', message: `⛔ Burst limit hit (${recent}/${BOT_RATE_LIMITS.burstMax} in ${BOT_RATE_LIMITS.burstWindowSeconds}s). Locked out for ${Math.floor(BOT_RATE_LIMITS.burstLockoutSeconds/60)}m.` };
    }

    if (ISSUE_COMMAND_SET.has(commandName)) {
        const hour = await bumpWindow(userId, 'hour', nowSec, BOT_RATE_LIMITS.issuePerHour);
        if (hour.exceeded) {
            try { await callServerAuditLog('bot.issue_rate_limited', '', userId, 'hour', { count: hour.current, limit: BOT_RATE_LIMITS.issuePerHour }); } catch (_) { }
            return { ok: false, reason: 'issue_hour', message: `⛔ Hourly license-issue limit reached (${hour.current}/${BOT_RATE_LIMITS.issuePerHour}).` };
        }
        const day = await bumpWindow(userId, 'day', nowSec, BOT_RATE_LIMITS.issuePerDay);
        if (day.exceeded) {
            try { await callServerAuditLog('bot.issue_rate_limited', '', userId, 'day', { count: day.current, limit: BOT_RATE_LIMITS.issuePerDay }); } catch (_) { }
            return { ok: false, reason: 'issue_day', message: `⛔ Daily license-issue limit reached (${day.current}/${BOT_RATE_LIMITS.issuePerDay}).` };
        }
    }

    if (commandName === 'generate') {
        try {
            const { rows } = await pgQuery(
                'SELECT key FROM licenses WHERE discord_id = $1 LIMIT 1',
                [userId]
            );
            if (rows.length > 0 && !isOwner(interaction)) {
                return { ok: false, reason: 'one_per_user', message: `⛔ You already claimed a license (\`${rows[0].key}\`). One key per Discord user.` };
            }
        } catch (_) { }
    }

    return { ok: true };
}

async function callServerAuditLog(action, target, userId, reason, extra) {
    try {
        await pgQuery(
            `INSERT INTO audit_log_v2 (action, license_key_hmac, hwid_hash, source_ip, user_agent_hash, decision, reason_code, extra)
             VALUES ($1, $2, NULL, NULL, NULL, $3, $4, $5::jsonb)`,
            [
                String(action || 'bot.event'),
                String(userId || ''),
                'deny',
                String(reason || ''),
                JSON.stringify(Object.assign({ target: target || '' }, extra || {})),
            ]
        );
    } catch (err) {
        console.warn('[bot] audit_log_v2 insert failed:', err && err.message ? err.message : err);
    }
}

function signAdminCommand(commandObj) {
    if (!ADMIN_HMAC_KEY) return '';
    const canonical = JSON.stringify(Object.keys(commandObj).sort().reduce((acc, k) => {
        acc[k] = commandObj[k]; return acc;
    }, {}));
    return crypto.createHmac('sha256', ADMIN_HMAC_KEY).update(canonical).digest('hex');
}

async function postSignedAdminCommand(action, payload) {
    if (!ADMIN_API_BASE) {
        return { ok: false, reason: 'admin_api_base_not_configured' };
    }
    if (!ADMIN_API_KEY) {
        return { ok: false, reason: 'admin_api_key_not_configured' };
    }
    const nonce = crypto.randomBytes(16).toString('hex');
    const ts = Math.floor(Date.now() / 1000);
    const body = {
        action,
        nonce,
        timestamp: ts,
        admin_key: ADMIN_API_KEY,
        ...payload,
    };
    const signature = signAdminCommand({ action, nonce, timestamp: ts, ...payload });
    if (signature) body.signature = signature;
    try {
        const url = ADMIN_API_BASE.replace(/\/+$/, '') + '/api/license';
        const resp = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        const text = await resp.text();
        let json = null;
        try { json = JSON.parse(text); } catch { json = { raw: text }; }
        return { ok: resp.ok, status: resp.status, response: json };
    } catch (err) {
        return { ok: false, reason: 'network_error', error: err.message };
    }
}

function ownerDenied(interaction) {
    return interaction.reply({
        content: '❌ Only the bot owner can use this command.',
        flags: MessageFlags.Ephemeral,
    });
}

async function logAudit(interaction, action, target, details) {
    try {
        await audit.appendAuditEntry(pool, {
            actorId: interaction.user.id,
            actorTag: interaction.user.tag,
            action,
            target: target || '',
            details: details || {},
        });
    } catch (err) {
        console.error('[bot] audit append failed:', err.message);
    }
}

// ─── Discord Client ───────────────────────────────────────────────────────────

const client = new Client({ intents: [GatewayIntentBits.Guilds] });

// ─── Slash Command Definitions ────────────────────────────────────────────────

const commands = [

    // /generate
    new SlashCommandBuilder()
        .setName('generate')
        .setDescription('🔑 Generate a new AiDA license key')
        .addIntegerOption(opt =>
            opt.setName('duration')
               .setDescription('License duration')
               .setRequired(true)
               .addChoices(...DURATION_CHOICES))
        .addStringOption(opt =>
            opt.setName('plan')
               .setDescription('Subscription plan (type to search)')
               .setRequired(true)
               .setAutocomplete(true))
        .addStringOption(opt =>
            opt.setName('note')
               .setDescription('Customer name or tag (optional)')
               .setRequired(false)),

    // /bulk_generate
    new SlashCommandBuilder()
        .setName('bulk_generate')
        .setDescription('🔑 Generate multiple license keys at once')
        .addIntegerOption(opt =>
            opt.setName('count')
               .setDescription('Number of keys to generate (1–25)')
               .setRequired(true)
               .setMinValue(1)
               .setMaxValue(25))
        .addIntegerOption(opt =>
            opt.setName('duration')
               .setDescription('License duration')
               .setRequired(true)
               .addChoices(...DURATION_CHOICES))
        .addStringOption(opt =>
            opt.setName('plan')
               .setDescription('Subscription plan')
               .setRequired(true)
               .setAutocomplete(true))
        .addStringOption(opt =>
            opt.setName('note')
               .setDescription('Batch note (optional)')
               .setRequired(false)),

    // /revoke
    new SlashCommandBuilder()
        .setName('revoke')
        .setDescription('🗑️ Revoke and permanently delete a license key')
        .addStringOption(opt =>
            opt.setName('key')
               .setDescription('License key to revoke')
               .setRequired(true)),

    // /info
    new SlashCommandBuilder()
        .setName('info')
        .setDescription('📋 Show full details for a license key')
        .addStringOption(opt =>
            opt.setName('key')
               .setDescription('License key to inspect')
               .setRequired(true)),

    // /list
    new SlashCommandBuilder()
        .setName('list')
        .setDescription('📦 List license keys')
        .addStringOption(opt =>
            opt.setName('filter')
               .setDescription('Filter results (default: all)')
               .setRequired(false)
               .addChoices(
                   { name: 'All',     value: 'all'     },
                   { name: 'Active',  value: 'active'  },
                   { name: 'Expired', value: 'expired' },
                   { name: 'Unbound', value: 'unbound' },
               )),

    // /search
    new SlashCommandBuilder()
        .setName('search')
        .setDescription('🔍 Search licenses by key, note, plan, or creator')
        .addStringOption(opt =>
            opt.setName('query')
               .setDescription('Search term')
               .setRequired(true)),

    // /stats
    new SlashCommandBuilder()
        .setName('stats')
        .setDescription('📊 License statistics overview'),

    // /reset_hwid
    new SlashCommandBuilder()
        .setName('reset_hwid')
        .setDescription('🔄 Clear HWID so the key can be activated on a new machine')
        .addStringOption(opt =>
            opt.setName('key')
               .setDescription('License key to reset')
               .setRequired(true)),

    // /extend
    new SlashCommandBuilder()
        .setName('extend')
        .setDescription('📅 Extend a license expiry by days or hours')
        .addStringOption(opt =>
            opt.setName('key')
               .setDescription('License key to extend')
               .setRequired(true))
        .addIntegerOption(opt =>
            opt.setName('days')
               .setDescription('Number of days to add (optional)')
               .setRequired(false)
               .setMinValue(1))
        .addIntegerOption(opt =>
            opt.setName('hours')
               .setDescription('Number of hours to add (optional)')
               .setRequired(false)
               .setMinValue(1)),

    // /setnote
    new SlashCommandBuilder()
        .setName('setnote')
        .setDescription('📝 Update the note/label on a license key')
        .addStringOption(opt =>
            opt.setName('key')
               .setDescription('License key to update')
               .setRequired(true))
        .addStringOption(opt =>
            opt.setName('note')
               .setDescription('New note text')
               .setRequired(true)),

    // /ban
    new SlashCommandBuilder()
        .setName('ban')
        .setDescription('🔨 Manually ban a HWID and/or IP address')
        .addStringOption(opt =>
            opt.setName('hwid')
               .setDescription('HWID to ban')
               .setRequired(true))
        .addStringOption(opt =>
            opt.setName('ip')
               .setDescription('IP address to also ban (optional)')
               .setRequired(false))
        .addStringOption(opt =>
            opt.setName('reason')
               .setDescription('Ban reason')
               .setRequired(false)),

    // /unban
    new SlashCommandBuilder()
        .setName('unban')
        .setDescription('🔓 Remove a ban by HWID or IP address')
        .addStringOption(opt =>
            opt.setName('target')
               .setDescription('HWID or IP address to unban')
               .setRequired(true)),

    // /baninfo
    new SlashCommandBuilder()
        .setName('baninfo')
        .setDescription('🔍 Show details about a ban')
        .addStringOption(opt =>
            opt.setName('target')
               .setDescription('HWID or IP to look up')
               .setRequired(true)),

    // /bans
    new SlashCommandBuilder()
        .setName('bans')
        .setDescription('📛 List all active HWID and IP bans'),

    // /violations
    new SlashCommandBuilder()
        .setName('violations')
        .setDescription('🚨 View recent violation audit log')
        .addIntegerOption(opt =>
            opt.setName('limit')
               .setDescription('Number of entries to show (default: 10)')
               .setRequired(false)
               .setMinValue(1)
               .setMaxValue(50)),

    // /lookup_hwid
    new SlashCommandBuilder()
        .setName('lookup_hwid')
        .setDescription('🔎 Find all licenses bound to a HWID')
        .addStringOption(opt =>
            opt.setName('hwid')
               .setDescription('HWID to search for')
               .setRequired(true)),

    // /transfer
    new SlashCommandBuilder()
        .setName('transfer')
        .setDescription('🔄 Transfer a license to a new HWID')
        .addStringOption(opt =>
            opt.setName('key')
               .setDescription('License key to transfer')
               .setRequired(true))
        .addStringOption(opt =>
            opt.setName('new_hwid')
               .setDescription('New HWID to bind the license to')
               .setRequired(true)),

    // /set_plan
    new SlashCommandBuilder()
        .setName('set_plan')
        .setDescription('📦 Change the plan on a license key')
        .addStringOption(opt =>
            opt.setName('key')
               .setDescription('License key to update')
               .setRequired(true))
        .addStringOption(opt =>
            opt.setName('plan')
               .setDescription('New plan')
               .setRequired(true)
               .setAutocomplete(true)),

    // /set_expiry
    new SlashCommandBuilder()
        .setName('set_expiry')
        .setDescription('📅 Set exact expiry date on a license key')
        .addStringOption(opt =>
            opt.setName('key')
               .setDescription('License key to update')
               .setRequired(true))
        .addStringOption(opt =>
            opt.setName('date')
               .setDescription('Expiry date (YYYY-MM-DD) or "never" for perpetual')
               .setRequired(true)),

    // /purge_expired
    new SlashCommandBuilder()
        .setName('purge_expired')
        .setDescription('🧹 Delete all expired licenses from the database'),

    // /sessions
    new SlashCommandBuilder()
        .setName('sessions')
        .setDescription('📡 List all active license sessions'),

    // /nuke
    new SlashCommandBuilder()
        .setName('nuke')
        .setDescription('💣 Delete a license and all associated data (session, bans)')
        .addStringOption(opt =>
            opt.setName('key')
               .setDescription('License key to nuke')
               .setRequired(true)),

    // /dashboard
    new SlashCommandBuilder()
        .setName('dashboard')
        .setDescription('📊 Combined dashboard: stats, recent activity, bans'),

    // /extend_all (Phase 6 admin)
    new SlashCommandBuilder()
        .setName('extend_all')
        .setDescription('📅 Extend EVERY active license by N days (use with care)')
        .addIntegerOption(opt =>
            opt.setName('days')
               .setDescription('Number of days to add to every active license')
               .setRequired(true)
               .setMinValue(1)
               .setMaxValue(365)),

    // /kill (Phase 6 admin)
    new SlashCommandBuilder()
        .setName('kill')
        .setDescription('☠️ Mark a license\'s session kill_flag = true (server refuses further heartbeats)')
        .addStringOption(opt =>
            opt.setName('key')
               .setDescription('License key whose session should be killed')
               .setRequired(true))
        .addStringOption(opt =>
            opt.setName('reason')
               .setDescription('Reason (logged)')
               .setRequired(false)),

    // /anomaly_report (Phase 6 admin)
    new SlashCommandBuilder()
        .setName('anomaly_report')
        .setDescription('🚨 List sessions sorted by anomaly_score (top offenders)')
        .addIntegerOption(opt =>
            opt.setName('limit')
               .setDescription('Max rows (default 15)')
               .setRequired(false)
               .setMinValue(1)
               .setMaxValue(100)),

    // /global_kill_all (Phase 6 admin)
    new SlashCommandBuilder()
        .setName('global_kill_all')
        .setDescription('🔥 EMERGENCY: kill every session globally (requires confirm=YES)')
        .addStringOption(opt =>
            opt.setName('confirm')
               .setDescription('Type YES to confirm')
               .setRequired(true)),

    // /rotate_kw (Phase 6 admin)
    new SlashCommandBuilder()
        .setName('rotate_kw')
        .setDescription('🔑 Force Kw (per-license master key) rotation for one license')
        .addStringOption(opt =>
            opt.setName('key')
               .setDescription('License key whose Kw should rotate on next activation')
               .setRequired(true)),

    new SlashCommandBuilder()
        .setName('aida-kill')
        .setDescription('💣 Add a license key to the kill-switch table (immediate auth deny)')
        .addStringOption(opt =>
            opt.setName('key')
               .setDescription('License key to kill')
               .setRequired(true))
        .addStringOption(opt =>
            opt.setName('reason')
               .setDescription('Reason')
               .setRequired(false)),

    new SlashCommandBuilder()
        .setName('aida-kill-hwid')
        .setDescription('💣 Add a HWID hash to the kill-switch table')
        .addStringOption(opt =>
            opt.setName('hwid_hash')
               .setDescription('SHA-256 hex of HWID (64 hex chars)')
               .setRequired(true))
        .addStringOption(opt =>
            opt.setName('reason')
               .setDescription('Reason')
               .setRequired(false)),

    new SlashCommandBuilder()
        .setName('aida-killswitch-global')
        .setDescription('💣 Toggle the global kill switch on/off')
        .addStringOption(opt =>
            opt.setName('mode')
               .setDescription('on or off')
               .setRequired(true)
               .addChoices(
                   { name: 'on', value: 'on' },
                   { name: 'off', value: 'off' },
               ))
        .addStringOption(opt =>
            opt.setName('reason')
               .setDescription('Reason')
               .setRequired(false)),
];

// ─── Register Commands on Ready ───────────────────────────────────────────────

client.once('clientReady', async () => {
    console.log(`✅ Bot logged in as ${client.user.tag}`);

    const rest = new REST().setToken(BOT_TOKEN);
    try {
        console.log('Registering slash commands...');
        await rest.put(
            Routes.applicationCommands(client.user.id),
            { body: commands.map(c => c.toJSON()) },
        );
        console.log('✅ Slash commands registered globally.');
    } catch (err) {
        console.error('❌ Failed to register commands:', err);
    }
});

// ─── Interaction Handler ──────────────────────────────────────────────────────

client.on('interactionCreate', async (interaction) => {

    // ── Autocomplete (plan field) ─────────────────────────────────────────────
    if (interaction.isAutocomplete()) {
        const focused = interaction.options.getFocused().toLowerCase();
        const matches = PLANS
            .filter(p => p.includes(focused))
            .map(p => ({ name: p.charAt(0).toUpperCase() + p.slice(1), value: p }));
        return interaction.respond(matches.slice(0, 6));
    }

    if (!interaction.isChatInputCommand()) return;

    const { commandName } = interaction;
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });

    const KILL_COMMANDS = new Set(['aida-kill', 'aida-kill-hwid', 'aida-killswitch-global']);
    if (KILL_COMMANDS.has(commandName)) {
        if (!isAdminInteraction(interaction)) {
            return interaction.editReply('❌ Only the bot owner or an admin role can use this command.');
        }
    } else if (!isOwner(interaction)) {
        return interaction.editReply('❌ Only the bot owner can use this command.');
    }

    const abuseGate = await checkAbuseGate(interaction);
    if (!abuseGate.ok) {
        return interaction.editReply(abuseGate.message || '❌ Rate-limited.');
    }

    try {

        // ── /generate ─────────────────────────────────────────────────────────
        if (commandName === 'generate') {
            const duration = interaction.options.getInteger('duration');
            const plan     = interaction.options.getString('plan').toLowerCase();
            const note     = interaction.options.getString('note') ?? '';
            const expires  = duration > 0 ? addDays(todayStr(), duration) : '';

            const serverPlan = plan === 'pro' ? 'pro' : 'pro';
            const result = await callServerAction('create', {
                plan: serverPlan,
                tier: plan,
                note,
                created_by: interaction.user.tag,
                expires,
                discord_id: interaction.user.id,
            });
            if (!result.ok) {
                return interaction.editReply(`❌ Server refused: \`${serverActionFailure(result)}\``);
            }
            const key = result.body && result.body.key;
            if (!key) {
                return interaction.editReply(`❌ Server returned no key (status ${result.status}).`);
            }
            await logAudit(interaction, 'license.generate', key, { plan, expires, note });

            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setAuthor({ name: 'AiDA License System' })
                    .setTitle('🔑 License Key Generated')
                    .setColor(0x00FF88)
                    .setDescription(`\`\`\`\n${key}\n\`\`\``)
                    .addFields(
                        { name: '📦 Plan',    value: plan,                  inline: true },
                        { name: '📅 Expires', value: formatExpiry(expires), inline: true },
                        { name: '📝 Note',    value: note || '*(none)*',     inline: true },
                    )
                    .setFooter({ text: `Created by ${interaction.user.tag}` })
                    .setTimestamp(),
            ]});
        }

        // ── /bulk_generate ────────────────────────────────────────────────────
        else if (commandName === 'bulk_generate') {
            const count    = interaction.options.getInteger('count');
            const duration = interaction.options.getInteger('duration');
            const plan     = interaction.options.getString('plan').toLowerCase();
            const note     = interaction.options.getString('note') ?? '';
            const expires  = duration > 0 ? addDays(todayStr(), duration) : '';

            const serverPlan = plan === 'pro' ? 'pro' : 'pro';
            const result = await callServerAction('bulk_create', {
                plan: serverPlan,
                tier: plan,
                count,
                note,
                created_by: interaction.user.tag,
                expires,
                discord_id: interaction.user.id,
            });
            if (!result.ok || !result.body || !Array.isArray(result.body.keys)) {
                return interaction.editReply(`❌ Server refused bulk_create: \`${serverActionFailure(result)}\``);
            }
            const keys = result.body.keys;
            await logAudit(interaction, 'license.bulk_generate', `count=${keys.length}`, { plan, expires, note, keys });

            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setAuthor({ name: 'AiDA License System' })
                    .setTitle(`🔑 ${keys.length} Keys Generated`)
                    .setColor(0x00FF88)
                    .setDescription(`\`\`\`\n${keys.join('\n')}\n\`\`\``)
                    .addFields(
                        { name: '📦 Plan',    value: plan,                  inline: true },
                        { name: '📅 Expires', value: formatExpiry(expires), inline: true },
                        { name: '📝 Note',    value: note || '*(none)*',     inline: true },
                    )
                    .setFooter({ text: `Generated by ${interaction.user.tag}` })
                    .setTimestamp(),
            ]});
        }

        // ── /revoke ───────────────────────────────────────────────────────────
        else if (commandName === 'revoke') {
            const key = interaction.options.getString('key').toUpperCase().trim();

            const { rows } = await pgQuery('SELECT * FROM licenses WHERE key = $1', [key]);
            if (!rows.length) return interaction.editReply(`❌ Key \`${key}\` not found.`);
            const data = rows[0];

            const result = await callServerAction('revoke', { key, reason: 'discord_bot_revoke' });
            if (!result.ok) {
                return interaction.editReply(`❌ Server refused revoke: \`${serverActionFailure(result)}\``);
            }
            await logAudit(interaction, 'license.revoke', key, { plan: data.plan, hwid: data.hwid, note: data.note });

            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setTitle('🗑️ License Revoked')
                    .setColor(0xFF4444)
                    .setDescription(`\`${key}\`\nLicense has been deactivated server-side.`)
                    .addFields(
                        { name: '📝 Note', value: data.note || '—', inline: true },
                        { name: '📦 Plan', value: data.plan || '—', inline: true },
                        { name: '🖥️ HWID', value: data.hwid || '*(unbound)*', inline: true },
                    )
                    .setTimestamp(),
            ]});
        }

        // ── /info ─────────────────────────────────────────────────────────────
        else if (commandName === 'info') {
            const key = interaction.options.getString('key').toUpperCase().trim();

            const { rows } = await pgQuery('SELECT * FROM licenses WHERE key = $1', [key]);
            if (!rows.length) return interaction.editReply(`❌ Key \`${key}\` not found.`);
            const data = rows[0];
            const { label, color } = licenseStatus(data);

            // Get created_at as a displayable string
            const createdStr = data.created_at
                ? new Date(data.created_at * 1000).toISOString().slice(0, 10)
                : '—';

            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setAuthor({ name: 'AiDA License System' })
                    .setTitle('📋 License Details')
                    .setColor(color)
                    .setDescription(`\`\`\`\n${key}\n\`\`\``)
                    .addFields(
                        { name: '⚡ Status',  value: label,                             inline: true  },
                        { name: '📦 Plan',    value: data.plan || '—',                  inline: true  },
                        { name: '📅 Expires', value: formatExpiry(data.expires),        inline: true  },
                        { name: '🖥️ HWID',  value: data.hwid
                            ? `\`\`\`${data.hwid}\`\`\``
                            : '*(not bound yet)*',                                      inline: false },
                        { name: '📅 Created', value: createdStr,                       inline: true  },
                        { name: '👤 Creator', value: data.created_by || '—',           inline: true  },
                        { name: '📝 Note',    value: data.note || '—',                 inline: true  },
                    )
                    .setTimestamp(),
            ]});
        }

        // ── /list ─────────────────────────────────────────────────────────────
        else if (commandName === 'list') {
            const filter = interaction.options.getString('filter') ?? 'all';

            let query = 'SELECT * FROM licenses ORDER BY created_at DESC';
            const { rows: allLicenses } = await pgQuery(query);

            if (!allLicenses.length)
                return interaction.editReply('📭 No licenses found.');

            let entries = allLicenses;

            if (filter === 'active')  entries = entries.filter(d =>  d.active && !isExpired(d.expires));
            if (filter === 'expired') entries = entries.filter(d =>  isExpired(d.expires));
            if (filter === 'unbound') entries = entries.filter(d => !d.hwid);

            if (!entries.length)
                return interaction.editReply(`📭 No licenses match filter: **${filter}**.`);

            const lines = entries.map(d => {
                const { label } = licenseStatus(d);
                const lock = d.hwid ? '🔒' : '🔓';
                const note = d.note ? ` *(${d.note})*` : '';
                return `${label} ${lock} \`${d.key}\` — \`${d.plan || '?'}\`${note}`;
            });

            const chunks = chunkLines(lines);

            const embeds = chunks.map((chunk, i) =>
                new EmbedBuilder()
                    .setTitle(i === 0
                        ? `📦 Licenses — ${filter} (${entries.length})`
                        : '📦 Continued...')
                    .setColor(0x5865F2)
                    .setDescription(chunk)
                    .setFooter({ text: '✅ active  ⚠️ expired  🔒 hwid-bound  🔓 unbound' })
                    .setTimestamp(),
            );

            await sendEmbedPages(interaction, embeds);
        }

        // ── /search ───────────────────────────────────────────────────────────
        else if (commandName === 'search') {
            const query = interaction.options.getString('query').toLowerCase();

            const { rows: matches } = await pgQuery(
                `SELECT * FROM licenses
                 WHERE LOWER(key) LIKE $1
                    OR LOWER(note) LIKE $1
                    OR LOWER(plan) LIKE $1
                    OR LOWER(created_by) LIKE $1
                 ORDER BY created_at DESC`,
                [`%${query}%`]
            );

            if (!matches.length)
                return interaction.editReply(`🔍 No keys match \`${query}\`.`);

            const lines = matches.map(d => {
                const { label } = licenseStatus(d);
                const note = d.note ? ` *(${d.note})*` : '';
                return `${label} \`${d.key}\` — \`${d.plan || '?'}\`${note}`;
            });

            const displayedLines = lines.slice(0, 30);
            const chunks = chunkLines(displayedLines);
            const embeds = chunks.map((chunk, i) =>
                new EmbedBuilder()
                    .setTitle(i === 0
                        ? `Search: "${query}" - ${matches.length} result(s)`
                        : 'Search continued')
                    .setColor(0xA855F7)
                    .setDescription(chunk)
                    .setFooter({ text: `Showing first ${displayedLines.length} result(s)` })
                    .setTimestamp(),
            );
            await sendEmbedPages(interaction, embeds);
        }

        // ── /stats ────────────────────────────────────────────────────────────
        else if (commandName === 'stats') {
            const { rows: allLicenses } = await pgQuery('SELECT * FROM licenses');
            const all     = allLicenses;
            const total   = all.length;
            const active  = all.filter(d =>  d.active && !isExpired(d.expires)).length;
            const expired = all.filter(d =>  isExpired(d.expires)).length;
            const bound   = all.filter(d =>  d.hwid).length;
            const unbound = total - bound;

            const perPlan = {};
            for (const d of all)
                perPlan[d.plan || 'unknown'] = (perPlan[d.plan || 'unknown'] || 0) + 1;
            const planLines = Object.entries(perPlan)
                .sort((a, b) => b[1] - a[1])
                .map(([p, c]) => `\`${p}\`: ${c}`)
                .join('\n') || '—';

            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setAuthor({ name: 'AiDA License System' })
                    .setTitle('📊 License Statistics')
                    .setColor(0x5865F2)
                    .addFields(
                        { name: '📦 Total',    value: String(total),   inline: true },
                        { name: '✅ Active',   value: String(active),  inline: true },
                        { name: '⚠️ Expired', value: String(expired), inline: true },
                        { name: '🔒 Bound',    value: String(bound),   inline: true },
                        { name: '🔓 Unbound',  value: String(unbound), inline: true },
                        { name: '📈 By Plan',  value: planLines,       inline: false },
                    )
                    .setTimestamp(),
            ]});
        }

        // ── /reset_hwid ───────────────────────────────────────────────────────
        else if (commandName === 'reset_hwid') {
            const key = interaction.options.getString('key').toUpperCase().trim();

            const { rows } = await pgQuery('SELECT * FROM licenses WHERE key = $1', [key]);
            if (!rows.length) return interaction.editReply(`❌ Key \`${key}\` not found.`);
            const data = rows[0];

            const result = await callServerAction('reset_hwid', { key });
            if (!result.ok) {
                return interaction.editReply(`❌ Server refused reset_hwid: \`${serverActionFailure(result)}\``);
            }
            await logAudit(interaction, 'license.reset_hwid', key, { previous_hwid: data.hwid });

            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setTitle('🔄 HWID Reset')
                    .setColor(0xFFAA00)
                    .setDescription(`\`${key}\`\nHWID cleared — key can now be activated on a new machine.`)
                    .addFields({ name: '📝 Note', value: data.note || '—', inline: true })
                    .setTimestamp(),
            ]});
        }

        // ── /extend ───────────────────────────────────────────────────────────
        else if (commandName === 'extend') {
            const key   = interaction.options.getString('key').toUpperCase().trim();
            const days  = interaction.options.getInteger('days');
            const hours = interaction.options.getInteger('hours');

            const { rows } = await pgQuery('SELECT * FROM licenses WHERE key = $1', [key]);
            if (!rows.length) return interaction.editReply(`❌ Key \`${key}\` not found.`);
            const data = rows[0];

            if (!days && !hours)
                return interaction.editReply('Error: provide days or hours to extend.');
            if (days && hours)
                return interaction.editReply('Error: provide either days or hours, not both.');

            const base = data.expires || (hours ? new Date().toISOString() : todayStr());
            const newExpiry = addDuration(base, days || 0, hours || 0);
            const addedText = hours ? String(hours) + ' hour(s)' : String(days) + ' day(s)';
            await pgQuery('UPDATE licenses SET expires = $1, active = true WHERE key = $2', [newExpiry, key]);
            await logAudit(interaction, 'license.extend', key, { previous_expires: data.expires, new_expires: newExpiry, days, hours });

            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setTitle('📅 License Extended')
                    .setColor(0x00AAFF)
                    .setDescription(`\`${key}\``)
                    .addFields(
                        { name: '📅 Old Expiry', value: formatExpiry(data.expires), inline: true },
                        { name: '📅 New Expiry', value: formatExpiry(newExpiry),    inline: true },
                        { name: '➕ Added',       value: addedText,                 inline: true },
                    )
                    .setTimestamp(),
            ]});
        }

        // ── /setnote ──────────────────────────────────────────────────────────
        else if (commandName === 'setnote') {
            const key  = interaction.options.getString('key').toUpperCase().trim();
            const note = interaction.options.getString('note');

            const { rows } = await pgQuery('SELECT * FROM licenses WHERE key = $1', [key]);
            if (!rows.length) return interaction.editReply(`❌ Key \`${key}\` not found.`);
            const data = rows[0];

            await pgQuery('UPDATE licenses SET note = $1 WHERE key = $2', [note, key]);
            await logAudit(interaction, 'license.setnote', key, { previous_note: data.note, new_note: note });

            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setTitle('📝 Note Updated')
                    .setColor(0x5865F2)
                    .setDescription(`\`${key}\``)
                    .addFields(
                        { name: 'Old Note', value: data.note || '*(empty)*', inline: true },
                        { name: 'New Note', value: note,                     inline: true },
                    )
                    .setTimestamp(),
            ]});
        }

        // ── /ban ──────────────────────────────────────────────────────────────
        else if (commandName === 'ban') {
            const hwid   = interaction.options.getString('hwid').trim();
            const ip     = interaction.options.getString('ip')?.trim() ?? '';
            const reason = interaction.options.getString('reason')?.trim() || 'manual_ban';
            const now    = Math.floor(Date.now() / 1000);
            const nowIso = new Date().toISOString();

            // Insert HWID ban
            await pgQuery(
                `INSERT INTO bans (ban_type, value, reason, banned_at, banned_at_iso, ip, banned_by)
                 VALUES ('hwid', $1, $2, $3, $4, $5, $6)
                 ON CONFLICT (ban_type, value) DO UPDATE SET
                     reason = EXCLUDED.reason, banned_at = EXCLUDED.banned_at,
                     banned_at_iso = EXCLUDED.banned_at_iso, ip = EXCLUDED.ip,
                     banned_by = EXCLUDED.banned_by`,
                [hwid, reason, now, nowIso, ip || 'unknown', interaction.user.tag]
            );

            // Also ban IP if provided
            if (ip) {
                const normalizedIp = ip.replace(/[.:]/g, '_');
                await pgQuery(
                    `INSERT INTO bans (ban_type, value, reason, banned_at, banned_at_iso, hwid, original_ip, banned_by)
                     VALUES ('ip', $1, $2, $3, $4, $5, $6, $7)
                     ON CONFLICT (ban_type, value) DO UPDATE SET
                         reason = EXCLUDED.reason, banned_at = EXCLUDED.banned_at,
                         banned_at_iso = EXCLUDED.banned_at_iso, hwid = EXCLUDED.hwid,
                         original_ip = EXCLUDED.original_ip, banned_by = EXCLUDED.banned_by`,
                    [normalizedIp, reason, now, nowIso, hwid, ip, interaction.user.tag]
                );
            }

            // Delete all licenses bound to this HWID
            const { rows: boundLicenses } = await pgQuery(
                'SELECT key FROM licenses WHERE hwid = $1', [hwid]
            );
            const deleted = [];
            for (const row of boundLicenses) {
                await pgQuery('DELETE FROM sessions WHERE license_key = $1', [row.key]);
                await pgQuery('DELETE FROM licenses WHERE key = $1', [row.key]);
                deleted.push(row.key);
            }

            await logAudit(interaction, 'ban.hwid_ip', hwid, { ip, reason, deleted_keys: deleted });

            const fields = [
                { name: '🖥️ HWID',   value: `\`${hwid}\``,  inline: true },
                { name: '🌐 IP',      value: ip || '*(none)*', inline: true },
                { name: '📝 Reason',   value: reason,           inline: true },
            ];
            if (deleted.length)
                fields.push({ name: '🗑️ Deleted Keys', value: deleted.map(k => `\`${k}\``).join('\n'), inline: false });

            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setTitle('🔨 HWID/IP Banned')
                    .setColor(0xFF0000)
                    .addFields(fields)
                    .setFooter({ text: `Banned by ${interaction.user.tag}` })
                    .setTimestamp(),
            ]});
        }

        // ── /unban ────────────────────────────────────────────────────────────
        else if (commandName === 'unban') {
            const target = interaction.options.getString('target').trim();
            const removed = [];

            // Try as HWID
            if (!/[.:]/.test(target)) {
                const res = await pgQuery(
                    "DELETE FROM bans WHERE ban_type = 'hwid' AND value = $1 RETURNING *", [target]
                );
                if (res.rowCount > 0) removed.push(`HWID \`${target}\``);
            }

            // Try as IP (normalized)
            const normalizedTarget = target.replace(/[.:]/g, '_');
            const res = await pgQuery(
                "DELETE FROM bans WHERE ban_type = 'ip' AND value = $1 RETURNING *", [normalizedTarget]
            );
            if (res.rowCount > 0) removed.push(`IP \`${target}\``);

            if (!removed.length)
                return interaction.editReply(`❌ No bans found for \`${target}\`.`);

            await logAudit(interaction, 'ban.unban', target, { removed });

            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setTitle('🔓 Ban Removed')
                    .setColor(0x00FF88)
                    .setDescription(removed.join('\n'))
                    .setFooter({ text: `Unbanned by ${interaction.user.tag}` })
                    .setTimestamp(),
            ]});
        }

        // ── /baninfo ──────────────────────────────────────────────────────────
        else if (commandName === 'baninfo') {
            const target = interaction.options.getString('target').trim();

            // Check HWID bans
            let hwidBan = null;
            if (!/[.:]/.test(target)) {
                const res = await pgQuery(
                    "SELECT * FROM bans WHERE ban_type = 'hwid' AND value = $1", [target]
                );
                if (res.rows.length) hwidBan = res.rows[0];
            }

            // Check IP bans
            const normalizedTarget = target.replace(/[.:]/g, '_');
            const ipRes = await pgQuery(
                "SELECT * FROM bans WHERE ban_type = 'ip' AND value = $1", [normalizedTarget]
            );
            const ipBan = ipRes.rows.length ? ipRes.rows[0] : null;

            if (!hwidBan && !ipBan)
                return interaction.editReply(`❌ No ban found for \`${target}\`.`);

            const ban = hwidBan || ipBan;
            const type = hwidBan ? 'HWID' : 'IP';

            const fields = [
                { name: '🏷️ Type',     value: type,                           inline: true },
                { name: '🎯 Target',   value: `\`${target}\``,                inline: true },
                { name: '📝 Reason',   value: ban.reason || '—',               inline: true },
                { name: '📅 Banned',   value: ban.banned_at_iso || '—',       inline: true },
                { name: '👤 Banned by',value: ban.banned_by || '*(system)*',  inline: true },
                { name: '📦 Version',  value: ban.plugin_version || '—',      inline: true },
            ];
            if (ban.hwid) fields.push({ name: '🖥️ HWID', value: `\`${ban.hwid}\``, inline: true });
            if (ban.ip || ban.original_ip) fields.push({ name: '🌐 IP', value: `\`${ban.original_ip || ban.ip}\``, inline: true });

            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setTitle('🔍 Ban Details')
                    .setColor(0xFF4444)
                    .addFields(fields)
                    .setTimestamp(),
            ]});
        }

        // ── /bans ─────────────────────────────────────────────────────────────
        else if (commandName === 'bans') {
            const { rows: hwidBans } = await pgQuery(
                "SELECT * FROM bans WHERE ban_type = 'hwid' ORDER BY banned_at DESC"
            );
            const { rows: ipBans } = await pgQuery(
                "SELECT * FROM bans WHERE ban_type = 'ip' ORDER BY banned_at DESC"
            );

            if (!hwidBans.length && !ipBans.length)
                return interaction.editReply('📭 No active bans.');

            const lines = [];
            for (const d of hwidBans) {
                const reason = d.reason ? ` — *${d.reason}*` : '';
                lines.push(`🖥️ HWID \`${d.value}\`${reason}`);
            }
            for (const d of ipBans) {
                const ip = d.original_ip || d.value;
                const reason = d.reason ? ` — *${d.reason}*` : '';
                lines.push(`🌐 IP \`${ip}\`${reason}`);
            }

            const chunks = chunkLines(lines);

            const embeds = chunks.map((chunk, i) =>
                new EmbedBuilder()
                    .setTitle(i === 0
                        ? `📛 Active Bans (${hwidBans.length} HWID, ${ipBans.length} IP)`
                        : '📛 Continued...')
                    .setColor(0xFF4444)
                    .setDescription(chunk)
                    .setTimestamp(),
            );
            await sendEmbedPages(interaction, embeds);
        }

        // ── /violations ───────────────────────────────────────────────────────
        else if (commandName === 'violations') {
            const limit = interaction.options.getInteger('limit') ?? 10;

            const { rows: totalRes } = await pgQuery('SELECT count(*) FROM violations');
            const totalCount = parseInt(totalRes[0].count, 10);

            const { rows: entries } = await pgQuery(
                'SELECT * FROM violations ORDER BY timestamp DESC LIMIT $1', [limit]
            );

            if (!entries.length)
                return interaction.editReply('📭 No violations recorded.');

            const lines = entries.map(d => {
                const time = d.timestamp_iso ? d.timestamp_iso.slice(0, 19).replace('T', ' ') : '—';
                return `\`${time}\` 🚨 **${d.reason || '?'}** — HWID \`${(d.hwid || '?').slice(0, 12)}…\` IP \`${d.ip || '?'}\``;
            });

            const chunks = chunkLines(lines);
            const embeds = chunks.map((chunk, i) =>
                new EmbedBuilder()
                    .setTitle(i === 0
                        ? `Violation Log (${entries.length}/${totalCount})`
                        : 'Violation Log continued')
                    .setColor(0xFF8800)
                    .setDescription(chunk)
                    .setFooter({ text: `Showing ${entries.length} most recent` })
                    .setTimestamp(),
            );
            await sendEmbedPages(interaction, embeds);
        }

        // ── /lookup_hwid ──────────────────────────────────────────────────────
        else if (commandName === 'lookup_hwid') {
            const hwid = interaction.options.getString('hwid').trim();

            const { rows: matches } = await pgQuery(
                'SELECT * FROM licenses WHERE hwid = $1 ORDER BY created_at DESC', [hwid]
            );

            if (!matches.length)
                return interaction.editReply(`🔎 No licenses found for HWID \`${hwid}\`.`);

            const lines = matches.map(d => {
                const { label } = licenseStatus(d);
                const note = d.note ? ` *(${d.note})*` : '';
                return `${label} \`${d.key}\` — \`${d.plan || '?'}\`${note}`;
            });

            // Check ban status
            const { rows: banRows } = await pgQuery(
                "SELECT * FROM bans WHERE ban_type = 'hwid' AND value = $1", [hwid]
            );
            const ban = banRows.length ? banRows[0] : null;
            const banLine = ban
                ? `\n\n⛔ **This HWID is BANNED** — ${ban.reason || 'no reason'} (${ban.banned_at_iso || '?'})`
                : '';

            const prefix = `\`\`\`\n${hwid}\n\`\`\``;
            const chunks = chunkLines(lines);
            if (banLine && chunks.length > 0) {
                const last = chunks[chunks.length - 1];
                if ((last + banLine).length <= 3800) chunks[chunks.length - 1] = last + banLine;
                else chunks.push(banLine.trim());
            }
            const embeds = chunks.map((chunk, i) =>
                new EmbedBuilder()
                    .setTitle(i === 0 ? 'Licenses for HWID' : 'Licenses for HWID continued')
                    .setColor(ban ? 0xFF4444 : 0x5865F2)
                    .setDescription((i === 0 ? `${prefix}\n` : '') + chunk)
                    .setFooter({ text: `${matches.length} license(s) found` })
                    .setTimestamp(),
            );
            await sendEmbedPages(interaction, embeds);
        }

        // ── /transfer ─────────────────────────────────────────────────────────
        else if (commandName === 'transfer') {
            const key     = interaction.options.getString('key').toUpperCase().trim();
            const newHwid = interaction.options.getString('new_hwid').trim();

            const { rows } = await pgQuery('SELECT * FROM licenses WHERE key = $1', [key]);
            if (!rows.length) return interaction.editReply(`❌ Key \`${key}\` not found.`);
            const data = rows[0];

            const oldHwid = data.hwid || '*(unbound)*';
            const result = await callServerAction('transfer', { key, new_hwid: newHwid });
            if (!result.ok) {
                return interaction.editReply(`❌ Server refused transfer: \`${serverActionFailure(result)}\``);
            }
            await logAudit(interaction, 'license.transfer', key, { previous_hwid: data.hwid, new_hwid: newHwid });

            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setTitle('🔄 License Transferred')
                    .setColor(0x00AAFF)
                    .setDescription(`\`${key}\``)
                    .addFields(
                        { name: '🖥️ Old HWID', value: `\`${oldHwid}\``,  inline: true },
                        { name: '🖥️ New HWID', value: `\`${newHwid}\``,  inline: true },
                        { name: '📦 Plan',      value: data.plan || '—',  inline: true },
                    )
                    .setFooter({ text: `Transferred by ${interaction.user.tag}` })
                    .setTimestamp(),
            ]});
        }

        // ── /set_plan ─────────────────────────────────────────────────────────
        else if (commandName === 'set_plan') {
            const key  = interaction.options.getString('key').toUpperCase().trim();
            const plan = interaction.options.getString('plan').toLowerCase();

            const { rows } = await pgQuery('SELECT * FROM licenses WHERE key = $1', [key]);
            if (!rows.length) return interaction.editReply(`❌ Key \`${key}\` not found.`);
            const data = rows[0];

            const oldPlan = data.plan || '—';
            await pgQuery('UPDATE licenses SET plan = $1 WHERE key = $2', [plan, key]);
            await logAudit(interaction, 'license.set_plan', key, { previous_plan: oldPlan, new_plan: plan });

            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setTitle('📦 Plan Updated')
                    .setColor(0xA855F7)
                    .setDescription(`\`${key}\``)
                    .addFields(
                        { name: 'Old Plan', value: oldPlan, inline: true },
                        { name: 'New Plan', value: plan,    inline: true },
                    )
                    .setTimestamp(),
            ]});
        }

        // ── /set_expiry ───────────────────────────────────────────────────────
        else if (commandName === 'set_expiry') {
            const key  = interaction.options.getString('key').toUpperCase().trim();
            const date = interaction.options.getString('date').trim().toLowerCase();

            const { rows } = await pgQuery('SELECT * FROM licenses WHERE key = $1', [key]);
            if (!rows.length) return interaction.editReply(`❌ Key \`${key}\` not found.`);
            const data = rows[0];

            const newExpiry = date === 'never' ? '' : date;
            if (newExpiry && !/^\d{4}-\d{2}-\d{2}$/.test(newExpiry))
                return interaction.editReply('❌ Invalid date format. Use `YYYY-MM-DD` or `never`.');

            await pgQuery('UPDATE licenses SET expires = $1 WHERE key = $2', [newExpiry, key]);
            await logAudit(interaction, 'license.set_expiry', key, { previous_expires: data.expires, new_expires: newExpiry });

            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setTitle('📅 Expiry Updated')
                    .setColor(0x00AAFF)
                    .setDescription(`\`${key}\``)
                    .addFields(
                        { name: 'Old Expiry', value: formatExpiry(data.expires), inline: true },
                        { name: 'New Expiry', value: formatExpiry(newExpiry),     inline: true },
                    )
                    .setTimestamp(),
            ]});
        }

        // ── /purge_expired ────────────────────────────────────────────────────
        else if (commandName === 'purge_expired') {
            const today = todayStr();

            // Find all expired licenses (expires is non-empty and < today)
            const { rows: expired } = await pgQuery(
                "SELECT key, expires, note FROM licenses WHERE expires != '' AND expires < $1",
                [today]
            );

            if (!expired.length)
                return interaction.editReply('✅ No expired licenses to purge.');

            // Delete them all (sessions cascade via FK)
            const keys = expired.map(r => r.key);
            await pgQuery('DELETE FROM sessions WHERE license_key = ANY($1)', [keys]);
            await pgQuery('DELETE FROM licenses WHERE key = ANY($1)', [keys]);
            await logAudit(interaction, 'license.purge_expired', `count=${keys.length}`, { keys });

            const lines = expired.slice(0, 20).map(d => {
                const note = d.note ? ` *(${d.note})*` : '';
                return `\`${d.key}\` — expired \`${d.expires}\`${note}`;
            });
            const moreText = expired.length > 20 ? `\n…and ${expired.length - 20} more` : '';

            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setTitle(`🧹 Purged ${expired.length} Expired License(s)`)
                    .setColor(0xFF8800)
                    .setDescription(lines.join('\n') + moreText)
                    .setFooter({ text: `Purged by ${interaction.user.tag}` })
                    .setTimestamp(),
            ]});
        }

        // ── /sessions ─────────────────────────────────────────────────────────
        else if (commandName === 'sessions') {
            const { rows: sessions } = await pgQuery(
                'SELECT * FROM sessions ORDER BY last_heartbeat DESC'
            );

            if (!sessions.length)
                return interaction.editReply('📭 No active sessions.');

            const now = Math.floor(Date.now() / 1000);
            const lines = sessions.map(s => {
                const lastHb = s.last_heartbeat
                    ? `${Math.floor((now - s.last_heartbeat) / 60)}m ago`
                    : '—';
                const hwid = s.hwid ? `\`${s.hwid.slice(0, 12)}…\`` : '—';
                return `🔑 \`${s.license_key}\` — ${hwid} — last heartbeat: ${lastHb}`;
            });

            const chunks = chunkLines(lines);

            const embeds = chunks.map((chunk, i) =>
                new EmbedBuilder()
                    .setTitle(i === 0
                        ? `📡 Active Sessions (${sessions.length})`
                        : '📡 Continued...')
                    .setColor(0x00AAFF)
                    .setDescription(chunk)
                    .setTimestamp(),
            );
            await sendEmbedPages(interaction, embeds);
        }

        // ── /nuke ─────────────────────────────────────────────────────────────
        else if (commandName === 'nuke') {
            const key = interaction.options.getString('key').toUpperCase().trim();

            const { rows } = await pgQuery('SELECT * FROM licenses WHERE key = $1', [key]);
            if (!rows.length) return interaction.editReply(`❌ Key \`${key}\` not found.`);
            const data = rows[0];

            const nuked = ['license'];

            // Delete the license (session cascades via FK ON DELETE CASCADE)
            const { rowCount: sessDeleted } = await pgQuery(
                'DELETE FROM sessions WHERE license_key = $1', [key]
            );
            if (sessDeleted > 0) nuked.push('session');

            await pgQuery('DELETE FROM licenses WHERE key = $1', [key]);

            // If HWID-bound, remove HWID ban
            if (data.hwid) {
                const { rowCount: banDeleted } = await pgQuery(
                    "DELETE FROM bans WHERE ban_type = 'hwid' AND value = $1", [data.hwid]
                );
                if (banDeleted > 0) nuked.push(`HWID ban (${data.hwid.slice(0, 12)}…)`);
            }
            await logAudit(interaction, 'license.nuke', key, { plan: data.plan, hwid: data.hwid, nuked });

            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setTitle('💣 License Nuked')
                    .setColor(0xFF0000)
                    .setDescription(`\`${key}\`\n\nDeleted: ${nuked.join(', ')}`)
                    .addFields(
                        { name: '📦 Plan', value: data.plan || '—',              inline: true },
                        { name: '📝 Note', value: data.note || '—',              inline: true },
                        { name: '🖥️ HWID', value: data.hwid || '*(unbound)*',  inline: true },
                    )
                    .setFooter({ text: `Nuked by ${interaction.user.tag}` })
                    .setTimestamp(),
            ]});
        }

        // ── /dashboard ────────────────────────────────────────────────────────
        else if (commandName === 'dashboard') {
            // Run all queries in parallel for speed
            const [licensesRes, sessionsRes, hwidBansRes, ipBansRes, violationsRes] = await Promise.all([
                pgQuery('SELECT * FROM licenses'),
                pgQuery('SELECT * FROM sessions'),
                pgQuery("SELECT count(*) FROM bans WHERE ban_type = 'hwid'"),
                pgQuery("SELECT count(*) FROM bans WHERE ban_type = 'ip'"),
                pgQuery('SELECT * FROM violations ORDER BY timestamp DESC LIMIT 5'),
            ]);

            const all  = licensesRes.rows;
            const now  = Math.floor(Date.now() / 1000);

            const total   = all.length;
            const active  = all.filter(d =>  d.active && !isExpired(d.expires)).length;
            const expired = all.filter(d =>  d.active && isExpired(d.expires)).length;
            const bound   = all.filter(d =>  d.hwid).length;

            // Recent activity — keys created in the last 7 days
            const weekAgo   = Math.floor(Date.now() / 1000) - 7 * 86400;
            const recentKeys = all.filter(d => d.created_at && d.created_at >= weekAgo).length;

            // Active sessions (heartbeat within last 10 min)
            const activeSessions = sessionsRes.rows
                .filter(s => s.last_heartbeat && (now - s.last_heartbeat) < 600).length;

            // Recent violations
            const recentViolations = violationsRes.rows;
            const violationLines = recentViolations.length
                ? recentViolations.map(d => {
                    const time = d.timestamp_iso ? d.timestamp_iso.slice(0, 16).replace('T', ' ') : '—';
                    return `\`${time}\` **${d.reason || '?'}** — \`${(d.hwid || '?').slice(0, 12)}…\``;
                }).join('\n')
                : '*(none)*';

            // Per plan breakdown
            const perPlan = {};
            for (const d of all)
                perPlan[d.plan || 'unknown'] = (perPlan[d.plan || 'unknown'] || 0) + 1;
            const planLines = Object.entries(perPlan)
                .sort((a, b) => b[1] - a[1])
                .map(([p, c]) => `\`${p}\`: ${c}`)
                .join('  ·  ') || '—';

            const hwidBanCount = parseInt(hwidBansRes.rows[0].count, 10);
            const ipBanCount   = parseInt(ipBansRes.rows[0].count, 10);

            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setAuthor({ name: 'AiDA License System' })
                    .setTitle('📊 Dashboard')
                    .setColor(0x5865F2)
                    .addFields(
                        { name: '📦 Total Keys',       value: String(total),           inline: true },
                        { name: '✅ Active',           value: String(active),           inline: true },
                        { name: '⚠️ Expired',         value: String(expired),          inline: true },
                        { name: '🔒 HWID Bound',       value: String(bound),           inline: true },
                        { name: '📡 Online Now',        value: String(activeSessions),  inline: true },
                        { name: '🆕 New (7d)',          value: String(recentKeys),      inline: true },
                        { name: '📈 Plans',             value: planLines,               inline: false },
                        { name: '📛 Bans',              value: `${hwidBanCount} HWID · ${ipBanCount} IP`, inline: false },
                        { name: '🚨 Recent Violations', value: violationLines,         inline: false },
                    )
                    .setFooter({ text: `${sessionsRes.rows.length} total sessions` })
                    .setTimestamp(),
            ]});
        }

        // ── /extend_all ───────────────────────────────────────────────────────
        else if (commandName === 'extend_all') {
            const days = interaction.options.getInteger('days');
            const today = todayStr();
            const { rows: active } = await pgQuery(
                "SELECT key, expires FROM licenses WHERE active = true AND (expires = '' OR expires >= $1)",
                [today]
            );
            if (!active.length)
                return interaction.editReply('📭 No active licenses to extend.');

            let updated = 0;
            for (const r of active) {
                const base = r.expires || todayStr();
                const newExpiry = addDuration(base, days, 0);
                await pgQuery('UPDATE licenses SET expires = $1 WHERE key = $2', [newExpiry, r.key]);
                updated++;
            }
            await logAudit(interaction, 'license.extend_all', `count=${updated}`, { days });

            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setTitle(`📅 Extended ${updated} License(s) by ${days}d`)
                    .setColor(0x00AAFF)
                    .setFooter({ text: `By ${interaction.user.tag}` })
                    .setTimestamp(),
            ]});
        }

        // ── /kill ─────────────────────────────────────────────────────────────
        else if (commandName === 'kill') {
            const key = interaction.options.getString('key').toUpperCase().trim();
            const reason = interaction.options.getString('reason') || 'admin_kill';

            const { rowCount } = await pgQuery(
                'UPDATE sessions SET kill_flag = true WHERE license_key = $1',
                [key]
            );
            if (rowCount === 0)
                return interaction.editReply(`❌ No active session for \`${key}\`.`);

            await pgQuery(
                "INSERT INTO violations (hwid, reason, timestamp, timestamp_iso) VALUES ($1, $2, $3, $4)",
                [key, `admin_kill:${reason}`, Math.floor(Date.now()/1000), new Date().toISOString()]
            );
            await logAudit(interaction, 'session.kill', key, { reason });

            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setTitle('☠️ Session Killed')
                    .setColor(0xFF0000)
                    .setDescription(`\`${key}\`\nReason: \`${reason}\``)
                    .setFooter({ text: `By ${interaction.user.tag}` })
                    .setTimestamp(),
            ]});
        }

        // ── /anomaly_report ───────────────────────────────────────────────────
        else if (commandName === 'anomaly_report') {
            const limit = interaction.options.getInteger('limit') || 15;
            const { rows } = await pgQuery(
                `SELECT license_key, anomaly_score, kill_flag, last_heartbeat, hwid, ip
                 FROM sessions
                 WHERE anomaly_score > 0
                 ORDER BY anomaly_score DESC
                 LIMIT $1`,
                [limit]
            );
            if (!rows.length)
                return interaction.editReply('✅ No sessions with anomaly_score > 0.');

            const now = Math.floor(Date.now() / 1000);
            const lines = rows.map(r => {
                const age = r.last_heartbeat ? `${Math.floor((now - r.last_heartbeat)/60)}m` : '—';
                const killed = r.kill_flag ? ' ☠️' : '';
                return `\`${r.license_key}\` · **${r.anomaly_score}** · ${age}${killed}`;
            });

            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setTitle(`🚨 Anomaly Report (top ${rows.length})`)
                    .setColor(0xFFA500)
                    .setDescription(lines.join('\n'))
                    .setTimestamp(),
            ]});
        }

        // ── /global_kill_all ──────────────────────────────────────────────────
        else if (commandName === 'global_kill_all') {
            const confirm = interaction.options.getString('confirm');
            if (confirm !== 'YES')
                return interaction.editReply('❌ Aborted — confirm must be exactly `YES`.');

            const { rowCount } = await pgQuery(
                'UPDATE sessions SET kill_flag = true WHERE kill_flag = false'
            );
            await logAudit(interaction, 'session.global_kill_all', `affected=${rowCount}`, { confirm });

            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setTitle(`🔥 GLOBAL KILL — ${rowCount} Session(s)`)
                    .setColor(0xFF0000)
                    .setDescription('Every active session now has kill_flag = true.')
                    .setFooter({ text: `By ${interaction.user.tag}` })
                    .setTimestamp(),
            ]});
        }

        // ── /rotate_kw ────────────────────────────────────────────────────────
        else if (commandName === 'rotate_kw') {
            const key = interaction.options.getString('key').toUpperCase().trim();
            const { rows } = await pgQuery('SELECT key FROM licenses WHERE key = $1', [key]);
            if (!rows.length)
                return interaction.editReply(`❌ Key \`${key}\` not found.`);

            // Bump key_rotation_ts — next activation re-wraps Kw under new epoch.
            const now = Math.floor(Date.now() / 1000);
            await pgQuery(
                'UPDATE licenses SET key_rotation_ts = $1 WHERE key = $2',
                [now, key]
            );
            // Also invalidate current session so client must re-validate.
            await pgQuery(
                'UPDATE sessions SET kill_flag = true WHERE license_key = $1',
                [key]
            );
            await logAudit(interaction, 'license.rotate_kw', key, { rotation_ts: now });

            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setTitle('🔑 Kw Rotation Armed')
                    .setColor(0x9B59B6)
                    .setDescription(`\`${key}\`\nkey_rotation_ts = ${now}\nsession killed — next activation will re-wrap.`)
                    .setFooter({ text: `By ${interaction.user.tag}` })
                    .setTimestamp(),
            ]});
        }

        else if (commandName === 'aida-kill') {
            const key = interaction.options.getString('key').toUpperCase().trim();
            const reason = interaction.options.getString('reason') || 'discord_admin_kill';
            const result = await callServerAction('kill', {
                target_license: key,
                reason,
                discord_id: interaction.user.id,
            });
            if (!result.ok) {
                return interaction.editReply(`❌ Server refused kill: \`${serverActionFailure(result)}\``);
            }
            await logAudit(interaction, 'kill_switch.license_key', key, { reason });
            await callServerAuditLog('bot.kill_switch.license_key', key, interaction.user.id, reason, {});
            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setTitle('💣 Kill Switch — License Key')
                    .setColor(0xFF0000)
                    .setDescription(`\`${key}\``)
                    .addFields(
                        { name: 'Switches Added', value: String((result.body && result.body.switches_added) || 0), inline: true },
                        { name: 'Sessions Killed', value: String((result.body && result.body.killed) || 0), inline: true },
                        { name: 'Reason', value: reason, inline: false },
                    )
                    .setFooter({ text: `By ${interaction.user.tag}` })
                    .setTimestamp(),
            ]});
        }

        else if (commandName === 'aida-kill-hwid') {
            const hwidHash = interaction.options.getString('hwid_hash').trim();
            const reason = interaction.options.getString('reason') || 'discord_admin_kill_hwid';
            if (!/^[0-9a-fA-F]{32,128}$/.test(hwidHash)) {
                return interaction.editReply('❌ hwid_hash must be 32-128 hex characters.');
            }
            const result = await callServerAction('kill', {
                target_hwid: hwidHash,
                reason,
                discord_id: interaction.user.id,
            });
            if (!result.ok) {
                return interaction.editReply(`❌ Server refused kill: \`${serverActionFailure(result)}\``);
            }
            await logAudit(interaction, 'kill_switch.hwid_hash', hwidHash, { reason });
            await callServerAuditLog('bot.kill_switch.hwid_hash', hwidHash, interaction.user.id, reason, {});
            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setTitle('💣 Kill Switch — HWID Hash')
                    .setColor(0xFF0000)
                    .setDescription(`\`${hwidHash}\``)
                    .addFields(
                        { name: 'Switches Added', value: String((result.body && result.body.switches_added) || 0), inline: true },
                        { name: 'Sessions Killed', value: String((result.body && result.body.killed) || 0), inline: true },
                        { name: 'Reason', value: reason, inline: false },
                    )
                    .setFooter({ text: `By ${interaction.user.tag}` })
                    .setTimestamp(),
            ]});
        }

        else if (commandName === 'aida-killswitch-global') {
            const mode = interaction.options.getString('mode');
            const reason = interaction.options.getString('reason') || 'discord_admin_global';
            const result = await callServerAction('kill', {
                target_global: mode === 'on',
                reason,
                discord_id: interaction.user.id,
            });
            if (!result.ok) {
                return interaction.editReply(`❌ Server refused: \`${serverActionFailure(result)}\``);
            }
            await logAudit(interaction, 'kill_switch.global', mode, { reason });
            await callServerAuditLog('bot.kill_switch.global', mode, interaction.user.id, reason, {});
            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setTitle(`💣 Global Kill Switch — ${mode.toUpperCase()}`)
                    .setColor(mode === 'on' ? 0xFF0000 : 0x00FF88)
                    .setDescription(mode === 'on' ? 'ALL traffic will be denied at the edge.' : 'Global kill cleared.')
                    .addFields({ name: 'Reason', value: reason, inline: false })
                    .setFooter({ text: `By ${interaction.user.tag}` })
                    .setTimestamp(),
            ]});
        }

    } catch (err) {
        console.error(`[${commandName}] Error:`, err);
        const msg = `❌ Error: ${err.message}`;
        try {
            await interaction.editReply(msg);
        } catch {
            await interaction.followUp({ content: msg, flags: MessageFlags.Ephemeral });
        }
    }
});

// ─── Graceful shutdown ────────────────────────────────────────────────────────

process.on('SIGINT', async () => {
    console.log('\nShutting down...');
    try { await pool.end(); } catch (_) { }
    try { await dbReadonly.close(); } catch (_) { }
    client.destroy();
    process.exit(0);
});

process.on('SIGTERM', async () => {
    console.log('\nShutting down...');
    try { await pool.end(); } catch (_) { }
    try { await dbReadonly.close(); } catch (_) { }
    client.destroy();
    process.exit(0);
});

// ─── Start ────────────────────────────────────────────────────────────────────

client.login(BOT_TOKEN).catch(err => {
    console.error('❌ Failed to login:', err.message);
    process.exit(1);
});

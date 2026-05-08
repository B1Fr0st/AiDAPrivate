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

const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: false,
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
    if (!isOwner(interaction)) return ownerDenied(interaction);

    const { commandName } = interaction;
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });

    try {

        // ── /generate ─────────────────────────────────────────────────────────
        if (commandName === 'generate') {
            const duration = interaction.options.getInteger('duration');
            const plan     = interaction.options.getString('plan').toLowerCase();
            const note     = interaction.options.getString('note') ?? '';
            const key      = generateKey();
            const expires  = duration > 0 ? addDays(todayStr(), duration) : '';

            await pgQuery(
                `INSERT INTO licenses (key, active, hwid, expires, plan, note, created_at, created_by)
                 VALUES ($1, true, '', $2, $3, $4, $5, $6)`,
                [key, expires, plan, note, Math.floor(Date.now() / 1000), interaction.user.tag]
            );
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
            const now      = Math.floor(Date.now() / 1000);

            const keys = [];
            for (let i = 0; i < count; i++) {
                const key = generateKey();
                await pgQuery(
                    `INSERT INTO licenses (key, active, hwid, expires, plan, note, created_at, created_by)
                     VALUES ($1, true, '', $2, $3, $4, $5, $6)`,
                    [key, expires, plan, note, now, interaction.user.tag]
                );
                keys.push(key);
            }
            await logAudit(interaction, 'license.bulk_generate', `count=${count}`, { plan, expires, note, keys });

            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setAuthor({ name: 'AiDA License System' })
                    .setTitle(`🔑 ${count} Keys Generated`)
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

            // Delete session first (FK cascade would handle it, but be explicit)
            await pgQuery('DELETE FROM sessions WHERE license_key = $1', [key]);
            await pgQuery('DELETE FROM licenses WHERE key = $1', [key]);
            await logAudit(interaction, 'license.revoke', key, { plan: data.plan, hwid: data.hwid, note: data.note });

            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setTitle('🗑️ License Revoked & Deleted')
                    .setColor(0xFF4444)
                    .setDescription(`\`${key}\`\nLicense has been permanently removed from the database.`)
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

            const chunks = [];
            let cur = '';
            for (const line of lines) {
                const next = cur ? `${cur}\n${line}` : line;
                if (next.length > 3800) { chunks.push(cur); cur = line; }
                else cur = next;
            }
            if (cur) chunks.push(cur);

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

            await interaction.editReply({ embeds: embeds.slice(0, 10) });
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

            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setTitle(`🔍 Search: "${query}" — ${matches.length} result(s)`)
                    .setColor(0xA855F7)
                    .setDescription(lines.slice(0, 30).join('\n'))
                    .setFooter({ text: 'Showing first 30 results' })
                    .setTimestamp(),
            ]});
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

            await pgQuery("UPDATE licenses SET hwid = '' WHERE key = $1", [key]);
            // Also delete session — new HWID means new session
            await pgQuery('DELETE FROM sessions WHERE license_key = $1', [key]);
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

            const chunks = [];
            let cur = '';
            for (const line of lines) {
                const next = cur ? `${cur}\n${line}` : line;
                if (next.length > 3800) { chunks.push(cur); cur = line; }
                else cur = next;
            }
            if (cur) chunks.push(cur);

            const embeds = chunks.map((chunk, i) =>
                new EmbedBuilder()
                    .setTitle(i === 0
                        ? `📛 Active Bans (${hwidBans.length} HWID, ${ipBans.length} IP)`
                        : '📛 Continued...')
                    .setColor(0xFF4444)
                    .setDescription(chunk)
                    .setTimestamp(),
            );
            await interaction.editReply({ embeds: embeds.slice(0, 10) });
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

            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setTitle(`🚨 Violation Log (${entries.length}/${totalCount})`)
                    .setColor(0xFF8800)
                    .setDescription(lines.join('\n'))
                    .setFooter({ text: `Showing ${entries.length} most recent` })
                    .setTimestamp(),
            ]});
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

            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setTitle(`🔎 Licenses for HWID`)
                    .setColor(ban ? 0xFF4444 : 0x5865F2)
                    .setDescription(`\`\`\`\n${hwid}\n\`\`\`\n${lines.join('\n')}${banLine}`)
                    .setFooter({ text: `${matches.length} license(s) found` })
                    .setTimestamp(),
            ]});
        }

        // ── /transfer ─────────────────────────────────────────────────────────
        else if (commandName === 'transfer') {
            const key     = interaction.options.getString('key').toUpperCase().trim();
            const newHwid = interaction.options.getString('new_hwid').trim();

            const { rows } = await pgQuery('SELECT * FROM licenses WHERE key = $1', [key]);
            if (!rows.length) return interaction.editReply(`❌ Key \`${key}\` not found.`);
            const data = rows[0];

            const oldHwid = data.hwid || '*(unbound)*';
            await pgQuery('UPDATE licenses SET hwid = $1 WHERE key = $2', [newHwid, key]);
            await pgQuery('DELETE FROM sessions WHERE license_key = $1', [key]);
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

            const chunks = [];
            let cur = '';
            for (const line of lines) {
                const next = cur ? `${cur}\n${line}` : line;
                if (next.length > 3800) { chunks.push(cur); cur = line; }
                else cur = next;
            }
            if (cur) chunks.push(cur);

            const embeds = chunks.map((chunk, i) =>
                new EmbedBuilder()
                    .setTitle(i === 0
                        ? `📡 Active Sessions (${sessions.length})`
                        : '📡 Continued...')
                    .setColor(0x00AAFF)
                    .setDescription(chunk)
                    .setTimestamp(),
            );
            await interaction.editReply({ embeds: embeds.slice(0, 10) });
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

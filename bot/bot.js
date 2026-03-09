// ============================================================================
// AiDA License Bot — Discord bot for managing AiDA license keys
// ============================================================================
//
// Commands (owner-only slash commands):
//   /generate      duration plan [note]          — Create one license key
//   /bulk_generate count duration plan [note]    — Create multiple keys
//   /revoke        key                           — Deactivate a key
//   /reactivate    key                           — Re-enable a revoked key
//   /info          key                           — Full details of a key
//   /list          [filter]                      — List keys with optional filter
//   /search        query                         — Search by note/plan/creator
//   /stats                                       — Aggregate statistics
//   /reset_hwid    key                           — Clear HWID binding
//   /extend        key days                      — Extend expiry by N days
//   /setnote       key note                      — Update note/label
//   /ban           hwid [ip] [reason]            — Manually ban HWID/IP
//   /unban         target                        — Remove ban by HWID or IP
//   /baninfo       target                        — Show ban details
//   /bans                                        — List all active bans
//   /violations    [limit]                       — View violation audit log
//   /lookup_hwid   hwid                          — Find licenses by HWID
//   /watermark     id buyer discord_user key     — Register buyer watermark
//   /watermarks                                  — List registered watermarks
//
// Only OWNER_ID can invoke any command.
// Firebase writes use the database secret to bypass security rules.
// ============================================================================

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

// ─── Configuration ────────────────────────────────────────────────────────────

const BOT_TOKEN       = process.env.AIDA_BOT_TOKEN       || 'MTQ2NzU4MjM4NzQ0ODk3MTI4NQ.Gug6jm.ycGFOlwxRMlK2kY5n069yZ41CmaxR0g023jGqE';
const OWNER_ID        = process.env.AIDA_OWNER_ID        || '924624884968079370';
const FIREBASE_DB_URL = process.env.AIDA_FIREBASE_DB_URL || 'https://aida-license-prod-default-rtdb.europe-west1.firebasedatabase.app';
// Firebase Database Secret — grants admin bypass of all security rules.
const FIREBASE_SECRET = process.env.AIDA_FIREBASE_SECRET || 'bWLmMKBhD3TE7iYMnKizIjOrt4jXd9R1m0CVCj6P';

// ─── Firebase REST helpers ────────────────────────────────────────────────────

/** Append ?auth=<secret> so every REST call has admin access. */
function fbUrl(path) {
    return `${FIREBASE_DB_URL}/${path}.json?auth=${FIREBASE_SECRET}`;
}

async function fbGet(path) {
    const res = await fetch(fbUrl(path));
    if (!res.ok) {
        const body = await res.text().catch(() => '');
        throw new Error(`Firebase GET ${path} failed: ${res.status} — ${body}`);
    }
    return res.json();
}

async function fbPut(path, data) {
    const res = await fetch(fbUrl(path), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
    });
    if (!res.ok) {
        const body = await res.text().catch(() => '');
        throw new Error(`Firebase PUT ${path} failed: ${res.status} — ${body}`);
    }
    return res.json();
}

async function fbPatch(path, data) {
    const res = await fetch(fbUrl(path), {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
    });
    if (!res.ok) {
        const body = await res.text().catch(() => '');
        throw new Error(`Firebase PATCH ${path} failed: ${res.status} — ${body}`);
    }
    return res.json();
}

async function fbDelete(path) {
    const res = await fetch(fbUrl(path), { method: 'DELETE' });
    if (!res.ok) {
        const body = await res.text().catch(() => '');
        throw new Error(`Firebase DELETE ${path} failed: ${res.status} — ${body}`);
    }
    return res.json();
}

// ─── Constants & Helpers ─────────────────────────────────────────────────────

/** Plans offered — used for autocomplete. */
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

function formatExpiry(dateStr) {
    if (!dateStr) return '♾️ Perpetual';
    return dateStr < todayStr() ? `~~${dateStr}~~ *(expired)*` : dateStr;
}

/** Returns { label, color } based on live state of the license record. */
function licenseStatus(data) {
    if (!data.active)
        return { label: '🚫 Revoked',  color: 0xFF4444 };
    if (data.expires && data.expires < todayStr())
        return { label: '⚠️ Expired',  color: 0xFF8800 };
    return     { label: '✅ Active',   color: 0x00FF88 };
}

function isOwner(interaction) {
    return interaction.user.id === OWNER_ID;
}

function ownerDenied(interaction) {
    return interaction.reply({
        content: '❌ Only the bot owner can use this command.',
        flags: MessageFlags.Ephemeral,
    });
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
        .setDescription('🚫 Revoke/deactivate a license key')
        .addStringOption(opt =>
            opt.setName('key')
               .setDescription('License key to revoke')
               .setRequired(true)),

    // /reactivate
    new SlashCommandBuilder()
        .setName('reactivate')
        .setDescription('✅ Re-activate a previously revoked key')
        .addStringOption(opt =>
            opt.setName('key')
               .setDescription('License key to reactivate')
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
                   { name: 'Revoked', value: 'revoked' },
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
        .setDescription('📅 Extend a license expiry by N days')
        .addStringOption(opt =>
            opt.setName('key')
               .setDescription('License key to extend')
               .setRequired(true))
        .addIntegerOption(opt =>
            opt.setName('days')
               .setDescription('Number of days to add')
               .setRequired(true)
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

    // /watermark
    new SlashCommandBuilder()
        .setName('watermark')
        .setDescription('🏷️ Register a per-buyer watermark for build stamping')
        .addStringOption(opt =>
            opt.setName('id')
               .setDescription('Watermark ID (will be stamped into the DLL)')
               .setRequired(true))
        .addStringOption(opt =>
            opt.setName('buyer')
               .setDescription('Buyer name/tag')
               .setRequired(true))
        .addUserOption(opt =>
            opt.setName('discord_user')
               .setDescription('Buyer Discord user (optional)')
               .setRequired(false))
        .addStringOption(opt =>
            opt.setName('key')
               .setDescription('Associated license key (optional)')
               .setRequired(false)),

    // /watermarks
    new SlashCommandBuilder()
        .setName('watermarks')
        .setDescription('🏷️ List all registered buyer watermarks'),
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

            await fbPut(`licenses/${key}`, {
                active: true, hwid: '', expires, plan, note,
                created_at: todayStr(),
                created_by: interaction.user.tag,
            });

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

            const keys = [];
            for (let i = 0; i < count; i++) {
                const key = generateKey();
                await fbPut(`licenses/${key}`, {
                    active: true, hwid: '', expires, plan, note,
                    created_at: todayStr(),
                    created_by: interaction.user.tag,
                });
                keys.push(key);
            }

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
            const key  = interaction.options.getString('key').toUpperCase().trim();
            const data = await fbGet(`licenses/${key}`);
            if (!data) return interaction.editReply(`❌ Key \`${key}\` not found.`);

            await fbPatch(`licenses/${key}`, { active: false });

            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setTitle('🚫 License Revoked')
                    .setColor(0xFF4444)
                    .setDescription(`\`${key}\``)
                    .addFields(
                        { name: '📝 Note', value: data.note || '—', inline: true },
                        { name: '📦 Plan', value: data.plan || '—', inline: true },
                    )
                    .setTimestamp(),
            ]});
        }

        // ── /reactivate ───────────────────────────────────────────────────────
        else if (commandName === 'reactivate') {
            const key  = interaction.options.getString('key').toUpperCase().trim();
            const data = await fbGet(`licenses/${key}`);
            if (!data) return interaction.editReply(`❌ Key \`${key}\` not found.`);

            await fbPatch(`licenses/${key}`, { active: true });

            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setTitle('✅ License Reactivated')
                    .setColor(0x00FF88)
                    .setDescription(`\`${key}\``)
                    .addFields({ name: '📝 Note', value: data.note || '—', inline: true })
                    .setTimestamp(),
            ]});
        }

        // ── /info ─────────────────────────────────────────────────────────────
        else if (commandName === 'info') {
            const key  = interaction.options.getString('key').toUpperCase().trim();
            const data = await fbGet(`licenses/${key}`);
            if (!data) return interaction.editReply(`❌ Key \`${key}\` not found.`);

            const { label, color } = licenseStatus(data);

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
                        { name: '📅 Created', value: data.created_at || '—',           inline: true  },
                        { name: '👤 Creator', value: data.created_by || '—',           inline: true  },
                        { name: '📝 Note',    value: data.note || '—',                 inline: true  },
                    )
                    .setTimestamp(),
            ]});
        }

        // ── /list ─────────────────────────────────────────────────────────────
        else if (commandName === 'list') {
            const filter   = interaction.options.getString('filter') ?? 'all';
            const licenses = await fbGet('licenses');

            if (!licenses || !Object.keys(licenses).length)
                return interaction.editReply('📭 No licenses found.');

            const today = todayStr();
            let entries = Object.entries(licenses);

            if (filter === 'active')  entries = entries.filter(([, d]) =>  d.active && !(d.expires && d.expires < today));
            if (filter === 'revoked') entries = entries.filter(([, d]) => !d.active);
            if (filter === 'expired') entries = entries.filter(([, d]) =>  d.active && d.expires && d.expires < today);
            if (filter === 'unbound') entries = entries.filter(([, d]) => !d.hwid);

            if (!entries.length)
                return interaction.editReply(`📭 No licenses match filter: **${filter}**.`);

            const lines = entries.map(([key, d]) => {
                const { label } = licenseStatus(d);
                const lock = d.hwid ? '🔒' : '🔓';
                const note = d.note ? ` *(${d.note})*` : '';
                return `${label} ${lock} \`${key}\` — \`${d.plan || '?'}\`${note}`;
            });

            // Paginate into ≤3800-char chunks to stay under Discord's 4096 embed limit
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
                    .setFooter({ text: '✅ active  🚫 revoked  ⚠️ expired  🔒 hwid-bound  🔓 unbound' })
                    .setTimestamp(),
            );

            await interaction.editReply({ embeds: embeds.slice(0, 10) });
        }

        // ── /search ───────────────────────────────────────────────────────────
        else if (commandName === 'search') {
            const query    = interaction.options.getString('query').toLowerCase();
            const licenses = await fbGet('licenses');
            if (!licenses) return interaction.editReply('📭 No licenses found.');

            const matches = Object.entries(licenses).filter(([key, d]) =>
                key.toLowerCase().includes(query) ||
                (d.note       && d.note.toLowerCase().includes(query))       ||
                (d.plan       && d.plan.toLowerCase().includes(query))       ||
                (d.created_by && d.created_by.toLowerCase().includes(query))
            );

            if (!matches.length)
                return interaction.editReply(`🔍 No keys match \`${query}\`.`);

            const lines = matches.map(([key, d]) => {
                const { label } = licenseStatus(d);
                const note = d.note ? ` *(${d.note})*` : '';
                return `${label} \`${key}\` — \`${d.plan || '?'}\`${note}`;
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
            const licenses = await fbGet('licenses');
            const all      = Object.values(licenses || {});
            const today    = todayStr();

            const total   = all.length;
            const active  = all.filter(d =>  d.active && !(d.expires && d.expires < today)).length;
            const revoked = all.filter(d => !d.active).length;
            const expired = all.filter(d =>  d.active && d.expires && d.expires < today).length;
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
                        { name: '🚫 Revoked',  value: String(revoked), inline: true },
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
            const key  = interaction.options.getString('key').toUpperCase().trim();
            const data = await fbGet(`licenses/${key}`);
            if (!data) return interaction.editReply(`❌ Key \`${key}\` not found.`);

            await fbPatch(`licenses/${key}`, { hwid: '' });

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
            const key  = interaction.options.getString('key').toUpperCase().trim();
            const days = interaction.options.getInteger('days');
            const data = await fbGet(`licenses/${key}`);
            if (!data) return interaction.editReply(`❌ Key \`${key}\` not found.`);

            const newExpiry = addDays(data.expires || todayStr(), days);
            await fbPatch(`licenses/${key}`, { expires: newExpiry, active: true });

            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setTitle('📅 License Extended')
                    .setColor(0x00AAFF)
                    .setDescription(`\`${key}\``)
                    .addFields(
                        { name: '📅 Old Expiry', value: formatExpiry(data.expires), inline: true },
                        { name: '📅 New Expiry', value: newExpiry,                  inline: true },
                        { name: '➕ Days Added', value: `${days} day(s)`,          inline: true },
                    )
                    .setTimestamp(),
            ]});
        }

        // ── /setnote ──────────────────────────────────────────────────────────
        else if (commandName === 'setnote') {
            const key  = interaction.options.getString('key').toUpperCase().trim();
            const note = interaction.options.getString('note');
            const data = await fbGet(`licenses/${key}`);
            if (!data) return interaction.editReply(`❌ Key \`${key}\` not found.`);

            await fbPatch(`licenses/${key}`, { note });

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

            const banRecord = {
                reason,
                banned_at: now,
                banned_at_iso: new Date().toISOString(),
                banned_by: interaction.user.tag,
            };

            await fbPut(`bans/hwid/${hwid}`, { ...banRecord, ip: ip || 'unknown' });

            if (ip) {
                const normalizedIp = ip.replace(/[.:]/g, '_');
                await fbPut(`bans/ip/${normalizedIp}`, { ...banRecord, hwid, original_ip: ip });
            }

            // Revoke all licenses bound to this HWID
            const licenses = await fbGet('licenses');
            const revoked = [];
            if (licenses) {
                for (const [key, d] of Object.entries(licenses)) {
                    if (d.hwid === hwid) {
                        await fbPatch(`licenses/${key}`, {
                            active: false,
                            revoked_reason: `ban: ${reason}`,
                            revoked_at: now,
                        });
                        revoked.push(key);
                    }
                }
            }

            const fields = [
                { name: '🖥️ HWID',   value: `\`${hwid}\``,  inline: true },
                { name: '🌐 IP',      value: ip || '*(none)*', inline: true },
                { name: '📝 Reason',   value: reason,           inline: true },
            ];
            if (revoked.length)
                fields.push({ name: '🚫 Revoked Keys', value: revoked.map(k => `\`${k}\``).join('\n'), inline: false });

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
            let removed = [];

            // Try as HWID
            const hwidBan = await fbGet(`bans/hwid/${target}`);
            if (hwidBan) {
                await fbDelete(`bans/hwid/${target}`);
                removed.push(`HWID \`${target}\``);
            }

            // Try as IP (both raw and normalized)
            const normalizedTarget = target.replace(/[.:]/g, '_');
            const ipBan = await fbGet(`bans/ip/${normalizedTarget}`);
            if (ipBan) {
                await fbDelete(`bans/ip/${normalizedTarget}`);
                removed.push(`IP \`${target}\``);
            }

            if (!removed.length)
                return interaction.editReply(`❌ No bans found for \`${target}\`.`);

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
            const hwidBan = await fbGet(`bans/hwid/${target}`);
            // Check IP bans
            const normalizedTarget = target.replace(/[.:]/g, '_');
            const ipBan = await fbGet(`bans/ip/${normalizedTarget}`);

            if (!hwidBan && !ipBan)
                return interaction.editReply(`❌ No ban found for \`${target}\`.`);

            const ban = hwidBan || ipBan;
            const type = hwidBan ? 'HWID' : 'IP';

            const fields = [
                { name: '🏷️ Type',     value: type,                                        inline: true },
                { name: '🎯 Target',   value: `\`${target}\``,                             inline: true },
                { name: '📝 Reason',   value: ban.reason || '—',                            inline: true },
                { name: '📅 Banned',   value: ban.banned_at_iso || '—',                    inline: true },
                { name: '👤 Banned by',value: ban.banned_by || '*(system)*',               inline: true },
                { name: '📦 Version',  value: ban.plugin_version || '—',                   inline: true },
            ];
            if (ban.hwid) fields.push({ name: '🖥️ HWID', value: `\`${ban.hwid}\``, inline: true });
            if (ban.ip || ban.original_ip) fields.push({ name: '🌐 IP', value: `\`${ban.original_ip || ban.ip}\``, inline: true });
            if (ban.watermark) fields.push({ name: '🔏 Watermark', value: `\`${ban.watermark}\``, inline: true });

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
            const hwidBans = await fbGet('bans/hwid') || {};
            const ipBans   = await fbGet('bans/ip') || {};

            const hwidEntries = Object.entries(hwidBans);
            const ipEntries   = Object.entries(ipBans);

            if (!hwidEntries.length && !ipEntries.length)
                return interaction.editReply('📭 No active bans.');

            const lines = [];
            for (const [hwid, d] of hwidEntries) {
                const reason = d.reason ? ` — *${d.reason}*` : '';
                lines.push(`🖥️ HWID \`${hwid}\`${reason}`);
            }
            for (const [, d] of ipEntries) {
                const ip = d.original_ip || '?';
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
                        ? `📛 Active Bans (${hwidEntries.length} HWID, ${ipEntries.length} IP)`
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
            const violations = await fbGet('violations') || {};
            const entries = Object.entries(violations)
                .sort((a, b) => (b[1].timestamp || 0) - (a[1].timestamp || 0))
                .slice(0, limit);

            if (!entries.length)
                return interaction.editReply('📭 No violations recorded.');

            const lines = entries.map(([id, d]) => {
                const time = d.timestamp_iso ? d.timestamp_iso.slice(0, 19).replace('T', ' ') : '—';
                const wm = d.watermark && d.watermark !== 'unknown' ? ` 🔏\`${d.watermark}\`` : '';
                return `\`${time}\` 🚨 **${d.reason || '?'}** — HWID \`${(d.hwid || '?').slice(0, 12)}…\` IP \`${d.ip || '?'}\`${wm}`;
            });

            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setTitle(`🚨 Violation Log (${entries.length}/${Object.keys(violations).length})`)
                    .setColor(0xFF8800)
                    .setDescription(lines.join('\n'))
                    .setFooter({ text: `Showing ${entries.length} most recent` })
                    .setTimestamp(),
            ]});
        }

        // ── /lookup_hwid ──────────────────────────────────────────────────────
        else if (commandName === 'lookup_hwid') {
            const hwid    = interaction.options.getString('hwid').trim();
            const licenses = await fbGet('licenses') || {};
            const matches = Object.entries(licenses).filter(([, d]) => d.hwid === hwid);

            if (!matches.length)
                return interaction.editReply(`🔎 No licenses found for HWID \`${hwid}\`.`);

            const lines = matches.map(([key, d]) => {
                const { label } = licenseStatus(d);
                const note = d.note ? ` *(${d.note})*` : '';
                return `${label} \`${key}\` — \`${d.plan || '?'}\`${note}`;
            });

            // Check ban status
            const ban = await fbGet(`bans/hwid/${hwid}`);
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

        // ── /watermark ────────────────────────────────────────────────────────
        else if (commandName === 'watermark') {
            const id          = interaction.options.getString('id').trim();
            const buyer       = interaction.options.getString('buyer').trim();
            const discordUser = interaction.options.getUser('discord_user');
            const licenseKey  = interaction.options.getString('key')?.toUpperCase().trim() ?? '';

            // Validate watermark ID format (alphanumeric, max 32 chars)
            if (!/^[A-Za-z0-9]{1,32}$/.test(id))
                return interaction.editReply('❌ Watermark ID must be 1–32 alphanumeric characters.');

            const record = {
                name: buyer,
                discord_user: discordUser ? discordUser.tag : '',
                discord_id: discordUser ? discordUser.id : '',
                license_key: licenseKey,
                created_at: new Date().toISOString(),
                created_by: interaction.user.tag,
            };

            await fbPut(`watermarks/${id}`, record);

            const fields = [
                { name: '🏷️ Watermark ID', value: `\`${id}\``,                               inline: true },
                { name: '👤 Buyer',         value: buyer,                                       inline: true },
                { name: '💬 Discord',       value: discordUser ? `<@${discordUser.id}>` : '—', inline: true },
                { name: '🔑 License Key',   value: licenseKey ? `\`${licenseKey}\`` : '—',     inline: true },
            ];

            await interaction.editReply({ embeds: [
                new EmbedBuilder()
                    .setTitle('🏷️ Watermark Registered')
                    .setColor(0x00FF88)
                    .addFields(fields)
                    .setFooter({ text: `Stamp DLL with: python pe_protect.py AiDA.dll --watermark ${id}` })
                    .setTimestamp(),
            ]});
        }

        // ── /watermarks ───────────────────────────────────────────────────────
        else if (commandName === 'watermarks') {
            const watermarks = await fbGet('watermarks') || {};
            const entries = Object.entries(watermarks);

            if (!entries.length)
                return interaction.editReply('📭 No watermarks registered.');

            const lines = entries.map(([id, d]) => {
                const discord = d.discord_id ? `<@${d.discord_id}>` : '';
                const key = d.license_key ? ` 🔑\`${d.license_key}\`` : '';
                return `🏷️ \`${id}\` — **${d.name || '?'}** ${discord}${key}`;
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
                        ? `🏷️ Registered Watermarks (${entries.length})`
                        : '🏷️ Continued...')
                    .setColor(0x5865F2)
                    .setDescription(chunk)
                    .setTimestamp(),
            );
            await interaction.editReply({ embeds: embeds.slice(0, 10) });
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

// ─── Start ────────────────────────────────────────────────────────────────────

client.login(BOT_TOKEN).catch(err => {
    console.error('❌ Failed to login:', err.message);
    process.exit(1);
});

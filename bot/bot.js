// ============================================================================
// AiDA License Bot — Discord bot for managing license keys
// ============================================================================
//
// Commands (slash commands, owner-only):
//   /generate [duration_days] [plan] [note]  — Create a new license key
//   /revoke <key>                            — Deactivate a license key
//   /info <key>                              — Show license details
//   /list                                    — List all licenses
//   /reset_hwid <key>                        — Clear HWID so key can be used on a new machine
//   /extend <key> <days>                     — Extend expiry by N days
//
// Only the owner (OWNER_ID) can use these commands.
//
// Uses Firebase Realtime Database REST API (no service account needed).
// ============================================================================

const { Client, GatewayIntentBits, SlashCommandBuilder, REST, Routes, EmbedBuilder } = require('discord.js');
const { v4: uuidv4 } = require('uuid');

// ─── Configuration ──────────────────────────────────────────────────────────

const BOT_TOKEN = process.env.AIDA_BOT_TOKEN || 'MTQ2NzU4MjM4NzQ0ODk3MTI4NQ.Gug6jm.ycGFOlwxRMlK2kY5n069yZ41CmaxR0g023jGqE';
const OWNER_ID  = process.env.AIDA_OWNER_ID  || '924624884968079370';

const FIREBASE_DB_URL = 'https://aida-license-prod-default-rtdb.europe-west1.firebasedatabase.app';

// ─── Firebase REST helpers ──────────────────────────────────────────────────

async function fbGet(path) {
    const res = await fetch(`${FIREBASE_DB_URL}/${path}.json`);
    if (!res.ok) throw new Error(`Firebase GET ${path} failed: ${res.status}`);
    return res.json();
}

async function fbPut(path, data) {
    const res = await fetch(`${FIREBASE_DB_URL}/${path}.json`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
    });
    if (!res.ok) throw new Error(`Firebase PUT ${path} failed: ${res.status}`);
    return res.json();
}

async function fbPatch(path, data) {
    const res = await fetch(`${FIREBASE_DB_URL}/${path}.json`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
    });
    if (!res.ok) throw new Error(`Firebase PATCH ${path} failed: ${res.status}`);
    return res.json();
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function generateKey() {
    // Format: AIDA-XXXX-XXXX-XXXX-XXXX (20 hex chars)
    const raw = uuidv4().replace(/-/g, '').toUpperCase().slice(0, 16);
    return `AIDA-${raw.slice(0,4)}-${raw.slice(4,8)}-${raw.slice(8,12)}-${raw.slice(12,16)}`;
}

function formatDate(dateStr) {
    if (!dateStr) return 'Perpetual';
    return dateStr;
}

function addDays(dateStr, days) {
    const d = dateStr ? new Date(dateStr) : new Date();
    d.setDate(d.getDate() + days);
    return d.toISOString().slice(0, 10); // YYYY-MM-DD
}

function todayStr() {
    return new Date().toISOString().slice(0, 10);
}

function isOwner(interaction) {
    return interaction.user.id === OWNER_ID;
}

function ownerDenied(interaction) {
    return interaction.reply({
        content: '❌ Only the bot owner can use this command.',
        ephemeral: true
    });
}

// ─── Discord Client ─────────────────────────────────────────────────────────

const client = new Client({
    intents: [GatewayIntentBits.Guilds],
});

// ─── Slash Command Definitions ──────────────────────────────────────────────

const commands = [
    new SlashCommandBuilder()
        .setName('generate')
        .setDescription('Generate a new AiDA license key')
        .addIntegerOption(opt =>
            opt.setName('duration_days')
               .setDescription('License duration in days (0 = perpetual)')
               .setRequired(false))
        .addStringOption(opt =>
            opt.setName('plan')
               .setDescription('Plan name (e.g. pro, basic)')
               .setRequired(false))
        .addStringOption(opt =>
            opt.setName('note')
               .setDescription('Optional note (e.g. customer name)')
               .setRequired(false)),

    new SlashCommandBuilder()
        .setName('revoke')
        .setDescription('Revoke/deactivate a license key')
        .addStringOption(opt =>
            opt.setName('key')
               .setDescription('The license key to revoke')
               .setRequired(true)),

    new SlashCommandBuilder()
        .setName('info')
        .setDescription('Show details of a license key')
        .addStringOption(opt =>
            opt.setName('key')
               .setDescription('The license key to look up')
               .setRequired(true)),

    new SlashCommandBuilder()
        .setName('list')
        .setDescription('List all license keys'),

    new SlashCommandBuilder()
        .setName('reset_hwid')
        .setDescription('Reset HWID binding so the key can be used on a new machine')
        .addStringOption(opt =>
            opt.setName('key')
               .setDescription('The license key to reset')
               .setRequired(true)),

    new SlashCommandBuilder()
        .setName('extend')
        .setDescription('Extend a license expiry by N days')
        .addStringOption(opt =>
            opt.setName('key')
               .setDescription('The license key to extend')
               .setRequired(true))
        .addIntegerOption(opt =>
            opt.setName('days')
               .setDescription('Number of days to add')
               .setRequired(true)),
];

// ─── Register Commands on Ready ─────────────────────────────────────────────

client.once('ready', async () => {
    console.log(`✅ Bot logged in as ${client.user.tag}`);

    const rest = new REST().setToken(BOT_TOKEN);
    try {
        console.log('Registering slash commands...');
        await rest.put(
            Routes.applicationCommands(client.user.id),
            { body: commands.map(c => c.toJSON()) }
        );
        console.log('✅ Slash commands registered globally.');
    } catch (err) {
        console.error('Failed to register commands:', err);
    }
});

// ─── Command Handler ────────────────────────────────────────────────────────

client.on('interactionCreate', async (interaction) => {
    if (!interaction.isChatInputCommand()) return;

    const { commandName } = interaction;

    // ── /generate ───────────────────────────────────────────────────────
    if (commandName === 'generate') {
        if (!isOwner(interaction)) return ownerDenied(interaction);

        await interaction.deferReply({ ephemeral: true });

        const durationDays = interaction.options.getInteger('duration_days') ?? 0;
        const plan = interaction.options.getString('plan') ?? 'pro';
        const note = interaction.options.getString('note') ?? '';

        const key = generateKey();
        const expires = durationDays > 0 ? addDays(todayStr(), durationDays) : '';

        const licenseData = {
            active: true,
            hwid: '',
            expires: expires,
            plan: plan,
            note: note,
            created_at: todayStr(),
            created_by: interaction.user.tag,
        };

        try {
            await fbPut(`licenses/${key}`, licenseData);

            const embed = new EmbedBuilder()
                .setTitle('🔑 License Key Generated')
                .setColor(0x00FF88)
                .addFields(
                    { name: 'Key',     value: `\`${key}\``, inline: false },
                    { name: 'Plan',    value: plan,         inline: true },
                    { name: 'Expires', value: expires || '♾️ Perpetual', inline: true },
                    { name: 'Note',    value: note || '—',  inline: true },
                )
                .setFooter({ text: 'AiDA License System' })
                .setTimestamp();

            await interaction.editReply({ embeds: [embed] });
        } catch (err) {
            console.error('Firebase write error:', err);
            await interaction.editReply(`❌ Failed to create license: ${err.message}`);
        }
    }

    // ── /revoke ─────────────────────────────────────────────────────────
    else if (commandName === 'revoke') {
        if (!isOwner(interaction)) return ownerDenied(interaction);

        await interaction.deferReply({ ephemeral: true });
        const key = interaction.options.getString('key');

        try {
            const data = await fbGet(`licenses/${key}`);
            if (data === null) {
                return interaction.editReply(`❌ Key \`${key}\` not found.`);
            }

            await fbPatch(`licenses/${key}`, { active: false });

            const embed = new EmbedBuilder()
                .setTitle('🚫 License Revoked')
                .setColor(0xFF4444)
                .addFields({ name: 'Key', value: `\`${key}\`` })
                .setTimestamp();

            await interaction.editReply({ embeds: [embed] });
        } catch (err) {
            console.error(err);
            await interaction.editReply(`❌ Firebase error: ${err.message}`);
        }
    }

    // ── /info ───────────────────────────────────────────────────────────
    else if (commandName === 'info') {
        if (!isOwner(interaction)) return ownerDenied(interaction);

        await interaction.deferReply({ ephemeral: true });
        const key = interaction.options.getString('key');

        try {
            const data = await fbGet(`licenses/${key}`);
            if (data === null) {
                return interaction.editReply(`❌ Key \`${key}\` not found.`);
            }

            const isExpired = data.expires && data.expires < todayStr();

            const embed = new EmbedBuilder()
                .setTitle('📋 License Info')
                .setColor(data.active && !isExpired ? 0x00FF88 : 0xFF4444)
                .addFields(
                    { name: 'Key',        value: `\`${key}\``,                       inline: false },
                    { name: 'Status',     value: data.active ? (isExpired ? '⚠️ Expired' : '✅ Active') : '🚫 Revoked', inline: true },
                    { name: 'Plan',       value: data.plan || '—',                   inline: true },
                    { name: 'Expires',    value: formatDate(data.expires),            inline: true },
                    { name: 'HWID',       value: data.hwid || '*(not bound yet)*',   inline: false },
                    { name: 'Created',    value: data.created_at || '—',             inline: true },
                    { name: 'Note',       value: data.note || '—',                   inline: true },
                )
                .setTimestamp();

            await interaction.editReply({ embeds: [embed] });
        } catch (err) {
            console.error(err);
            await interaction.editReply(`❌ Firebase error: ${err.message}`);
        }
    }

    // ── /list ───────────────────────────────────────────────────────────
    else if (commandName === 'list') {
        if (!isOwner(interaction)) return ownerDenied(interaction);

        await interaction.deferReply({ ephemeral: true });

        try {
            const licenses = await fbGet('licenses');

            if (!licenses || Object.keys(licenses).length === 0) {
                return interaction.editReply('📭 No licenses found.');
            }

            const entries = Object.entries(licenses);
            const lines = entries.map(([key, data]) => {
                const status = data.active ? '✅' : '🚫';
                const expired = data.expires && data.expires < todayStr() ? '⚠️EXP' : '';
                const hwid = data.hwid ? '🔒' : '🔓';
                return `${status}${expired} \`${key}\` ${hwid} ${data.plan || ''} ${data.note || ''}`.trim();
            });

            // Discord has a 4096 char embed limit — paginate if needed
            const chunks = [];
            let current = '';
            for (const line of lines) {
                if ((current + '\n' + line).length > 4000) {
                    chunks.push(current);
                    current = line;
                } else {
                    current += (current ? '\n' : '') + line;
                }
            }
            if (current) chunks.push(current);

            const embeds = chunks.map((chunk, i) =>
                new EmbedBuilder()
                    .setTitle(i === 0 ? `📦 All Licenses (${entries.length} total)` : '📦 Continued...')
                    .setColor(0x5865F2)
                    .setDescription(chunk)
                    .setFooter({ text: '✅=active  🚫=revoked  ⚠️EXP=expired  🔒=HWID bound  🔓=unbound' })
                    .setTimestamp()
            );

            await interaction.editReply({ embeds: embeds.slice(0, 10) });
        } catch (err) {
            console.error(err);
            await interaction.editReply(`❌ Firebase error: ${err.message}`);
        }
    }

    // ── /reset_hwid ─────────────────────────────────────────────────────
    else if (commandName === 'reset_hwid') {
        if (!isOwner(interaction)) return ownerDenied(interaction);

        await interaction.deferReply({ ephemeral: true });
        const key = interaction.options.getString('key');

        try {
            const data = await fbGet(`licenses/${key}`);
            if (data === null) {
                return interaction.editReply(`❌ Key \`${key}\` not found.`);
            }

            await fbPatch(`licenses/${key}`, { hwid: '' });

            const embed = new EmbedBuilder()
                .setTitle('🔄 HWID Reset')
                .setColor(0xFFAA00)
                .setDescription(`HWID cleared for \`${key}\`.\nThe key can now be activated on a new machine.`)
                .setTimestamp();

            await interaction.editReply({ embeds: [embed] });
        } catch (err) {
            console.error(err);
            await interaction.editReply(`❌ Firebase error: ${err.message}`);
        }
    }

    // ── /extend ─────────────────────────────────────────────────────────
    else if (commandName === 'extend') {
        if (!isOwner(interaction)) return ownerDenied(interaction);

        await interaction.deferReply({ ephemeral: true });
        const key = interaction.options.getString('key');
        const days = interaction.options.getInteger('days');

        try {
            const data = await fbGet(`licenses/${key}`);
            if (data === null) {
                return interaction.editReply(`❌ Key \`${key}\` not found.`);
            }
            const baseDate = data.expires || todayStr();
            const newExpiry = addDays(baseDate, days);

            await fbPatch(`licenses/${key}`, { expires: newExpiry, active: true });

            const embed = new EmbedBuilder()
                .setTitle('📅 License Extended')
                .setColor(0x00AAFF)
                .addFields(
                    { name: 'Key',         value: `\`${key}\``,   inline: false },
                    { name: 'Old Expiry',  value: formatDate(data.expires), inline: true },
                    { name: 'New Expiry',  value: newExpiry,       inline: true },
                    { name: 'Days Added',  value: `+${days}`,     inline: true },
                )
                .setTimestamp();

            await interaction.editReply({ embeds: [embed] });
        } catch (err) {
            console.error(err);
            await interaction.editReply(`❌ Firebase error: ${err.message}`);
        }
    }
});

// ─── Start ──────────────────────────────────────────────────────────────────

client.login(BOT_TOKEN).catch(err => {
    console.error('❌ Failed to login:', err.message);
    process.exit(1);
});

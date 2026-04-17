

const path = require('path');
const fs = require('fs');


function loadEnv() {
    const envPath = path.join(__dirname, '.env');
    const env = {};
    if (fs.existsSync(envPath)) {
        const lines = fs.readFileSync(envPath, 'utf8').split('\n');
        for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith('#')) continue;
            const eqIdx = trimmed.indexOf('=');
            if (eqIdx > 0) {
                env[trimmed.substring(0, eqIdx)] = trimmed.substring(eqIdx + 1);
            }
        }
    }
    return env;
}

const dotenv = loadEnv();

module.exports = {
    apps: [{
        name: 'aida-api',
        script: './server.js',
        cwd: '/opt/aida/api',
        instances: 1,
        exec_mode: 'fork',
        autorestart: true,
        max_restarts: 10,
        restart_delay: 5000,
        watch: false,
        max_memory_restart: '256M',
        env: {
            NODE_ENV: 'production',
            PORT: 3001,
            ...dotenv,
        },
        error_file: '/var/log/aida/error.log',
        out_file: '/var/log/aida/out.log',
        log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    }],
};

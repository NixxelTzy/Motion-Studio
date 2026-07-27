const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const securityEngine = require('./security'); // Engine kompleks

const app = express();

// Load Config from setting folder
const settingPath = path.join(__dirname, '../setting/securitySetting.json');
let config = {};
try {
    config = JSON.parse(fs.readFileSync(settingPath, 'utf-8'));
} catch (e) {
    console.error("Gagal membaca setting/securitySetting.json", e);
}

// Global Memory Logs (Karena Vercel serverless, log ini hanya bertahan saat instance hidup, tapi cukup untuk demo realtime panel)
global.securityLogs = [];
global.stats = { totalRequests: 0, blockedAttacks: 0 };

// Middleware Dasar
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

// Pasang Engine Keamanan Ultra-Kompleks
app.use(securityEngine);

// Endpoint 1: Untuk web.html mengambil URL
app.get('/api/get-target-url', (req, res) => {
    res.json({ url: config.system_config?.target_url || '' });
});

// Endpoint 2: Untuk admin panel mengambil data log realtime
app.get('/api/admin-logs', (req, res) => {
    // Ambil 50 log terakhir
    const recentLogs = global.securityLogs.slice(-50).reverse();
    res.json({
        stats: global.stats,
        logs: recentLogs
    });
});

module.exports = app;

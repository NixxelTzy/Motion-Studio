const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const xss = require('xss-clean');
const hpp = require('hpp');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');
const securityEngine = require('./security'); // Engine kompleks

const app = express();

// --- PENAMBAHAN MODULE KEAMANAN EKSTRA ---
// 1. Helmet: Melindungi aplikasi dari beberapa kerentanan web yang terkenal dengan mengatur HTTP header dengan tepat.
app.use(helmet({ contentSecurityPolicy: false })); // Dimatikan khusus utk CSP iframe agar web.html berjalan
// 2. Rate Limiting: Mencegah serangan brute-force dan DDoS ringan
const limiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 menit
    max: 60, // batasi setiap IP hingga 60 request
    message: "Terlalu banyak permintaan dari IP ini, coba lagi nanti."
});
app.use(limiter);
// 3. Parser JSON dan URL Encoded dengan batasan ukuran
app.use(express.json({ limit: '10kb' })); 
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
// 4. XSS Clean: Sanitasi input data pengguna (body, query, params)
app.use(xss());
// 5. HPP: Melindungi dari serangan HTTP Parameter Pollution
app.use(hpp());
app.use(cors());

// Load Config from setting folder
const settingPath = path.join(__dirname, '../setting/securitySetting.json');
let config = {};
try {
    config = JSON.parse(fs.readFileSync(settingPath, 'utf-8'));
} catch (e) {
    console.error("Gagal membaca setting/securitySetting.json", e);
} // TANDA KURUNG KURAWAL INI SEBELUMNYA HILANG!

// Global Memory Logs
global.securityLogs = global.securityLogs || [];
global.stats = global.stats || { totalRequests: 0, blockedAttacks: 0 };

// Pasang Engine Keamanan Ultra-Kompleks
app.use(securityEngine);

// --- PERBAIKAN CANNOT GET / ---
// Mendefinisikan route untuk menyajikan halaman HTML
app.get('/', (req, res) => res.sendFile(path.join(__dirname, '../index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, '../admin.html')));
app.get('/web', (req, res) => res.sendFile(path.join(__dirname, '../web.html')));

// Endpoint 1: Untuk web.html mengambil URL
app.get('/api/get-target-url', (req, res) => {
    res.json({ url: config.system_config?.target_url || '' });
});

// Endpoint 2: Untuk admin panel mengambil data log realtime
app.get('/api/admin-logs', (req, res) => {
    const recentLogs = global.securityLogs.slice(-50).reverse();
    res.json({
        stats: global.stats,
        logs: recentLogs
    });
});

// Agar bisa berjalan lokal via `node api/index.js` maupun serverless di Vercel
if (require.main === module) {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        console.log(`[SYSTEM] Server berjalan aman di port ${PORT}`);
    });
} else {
    module.exports = app;
}

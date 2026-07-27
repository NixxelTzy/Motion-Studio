// ==============================================================================
// ULTRA-COMPLEX WEB APPLICATION FIREWALL (WAF) ENGINE
// ==============================================================================
const WAF_SIGNATURES = [
    // --- SQL INJECTION CORE SIGNATURES ---
    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|EXEC|UNION|GRANT|REVOKE)\b)/i,
    /('--|\/\*|\*\/|;|' OR '1'='1|' OR 1=1|1=1|0x[0-9a-fA-F]+)/i,
    /(%27%20OR%20%271%27%3D%271|%27%20OR%201%3D1)/i,
    
    // --- XSS & HTML INJECTION SIGNATURES ---
    /(<script\b[^>]*>.*?<\/script>|<\s*script\b[^>]*>)/i,
    /(javascript:|onerror=|onload=|eval\(|document\.cookie|document\.location)/i,
    
    // --- REMOTE CODE EXECUTION (RCE) & LFI ---
    /(\|\||&&|;\s*(ls|cat|pwd|whoami|id|uname|curl|wget|bash|sh|nc|python|perl|php))/i,
    /(\/etc\/passwd|\/bin\/sh|cmd\.exe|boot\.ini)/i,
    /(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c)/i,

    // --- MALICIOUS PAYLOAD MOCK DB ---
    /malicious_payload_variant_[0-9a-zA-Z_]+/i
]; // SEBELUMNYA FILE TERPOTONG DI SINI (TIDAK ADA KURUNG TUTUP ARRAY)

// MENAMBAHKAN EXPORT MIDDLEWARE YANG HILANG
module.exports = function securityEngine(req, res, next) {
    // Inisialisasi variable global jika belum ada
    if (!global.stats) global.stats = { totalRequests: 0, blockedAttacks: 0 };
    if (!global.securityLogs) global.securityLogs = [];

    // Skip tracking for static files to avoid log flooding
    if (!req.originalUrl.includes('.html') && !req.originalUrl.includes('.css')) {
        global.stats.totalRequests++;
    }

    // Inspect Payload
    const reqData = decodeURIComponent(req.originalUrl + " " + JSON.stringify(req.body || {}));
    let isBlocked = false;
    let threatReason = '';

    // Check against signatures
    for (const sig of WAF_SIGNATURES) {
        if (sig.test(reqData)) {
            isBlocked = true;
            threatReason = 'WAF Signature Match';
            break;
        }
    }

    // Catat ke memori global
    if (!req.originalUrl.includes('/api/admin-logs')) { // Hindari looping log admin
        const logEntry = {
            time: new Date().toISOString(),
            ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1',
            method: req.method,
            path: req.originalUrl,
            action: isBlocked ? 'BLOCKED' : 'ALLOWED',
            reason: isBlocked ? threatReason : ''
        };

        global.securityLogs.push(logEntry);
        
        // Batasi ukuran log agar tidak memory leak
        if (global.securityLogs.length > 200) {
            global.securityLogs.shift();
        }
    }

    // Eksekusi Blokir jika terdeteksi ancaman
    if (isBlocked) {
        global.stats.blockedAttacks++;
        return res.status(403).send(`
            <html>
                <head><title>403 - Akses Ditolak WAF</title></head>
                <body style="background:#111; color:#f00; font-family:monospace; text-align:center; margin-top:10%;">
                    <h1>🚨 AKSES DIBLOKIR 🚨</h1>
                    <p>Web Application Firewall mendeteksi aktivitas yang mencurigakan (Threat Payload).</p>
                    <p>IP Anda telah dicatat oleh sistem keamanan.</p>
                </body>
            </html>
        `);
    }

    next();
};

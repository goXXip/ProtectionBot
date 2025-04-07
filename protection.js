const IRC = require('irc-framework');
const crypto = require('crypto');
const fs = require('fs');
const https = require('https');

// Yapilandirma
const config = {
    server: 'irc.basgelsin.net',
    port: 6667,
    ssl: false,
    nick: 'SpamGuard',
    username: 'spamguard',
    realname: 'Spam Protection Service v3.5',
    password: 'canceled',
    operName: 'RootNick',
    operPassword: 'rootuserpassword',
    operol: 'spamguard',
    operolpass: 'spamguardoperpass',
    adminFile: 'admins.json',
    channelsFile: 'channels.json',
    spamIpFile: 'spamips.json',
    bannedIpFile: 'bannedips.json',
    spamDbs: [
        'https://www.spamhaus.org/drop/drop.txt',
        'https://www.spamhaus.org/drop/edrop.txt',
        'https://check.torproject.org/torbulkexitlist',
        'https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt',
        'https://www.team-cymru.org/Services/Bogons/fullbogons-ipv6.txt',
        'https://reputation.alienvault.com/reputation.data',
        'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
        'https://www.blocklist.de/downloads/export-ips_all.txt',
        'https://lists.blocklist.de/lists/all.txt',
        'https://www.maxmind.com/en/high-risk-ip-sample-list'
    ],
    banReason: 'Spam IP detected',
    noticeMessage: 'IP adresiniz spam veritabanlarinda taraniyor',
    pingInterval: 120000,
    autoJoinChannels: ['#mainchannel'],
    klineDuration: '0',
    reconnectDelay: 15000,
    userAgent: 'SpamGuardBot/3.5',
    commandPrefix: '!',
    autoCheckUsers: true,
    checkInterval: 30000,
    banBatchSize: 25,
    banBatchDelay: 3000,
    autoBanOnStart: false,
    autoUpdateInterval: 15 * 60 * 1000,
    maxIpCacheAge: 5 * 60 * 1000,
    logLevel: 'debug' // trace, debug, info, warn, error
};

// Veri yapilari
let admins = {};
let spamIps = new Set();
let bannedIps = new Set();
const botChannels = new Set();
const pendingIpChecks = new Map();
const ipCache = new Map();
const client = new IRC.Client();
let pingTimer;
let updateTimer;

// Loglama Sistemi
const logLevels = {
    trace: 0,
    debug: 1,
    info: 2,
    warn: 3,
    error: 4
};

function log(level, message, data = null) {
    if (logLevels[level] < logLevels[config.logLevel]) return;
    
    const timestamp = new Date().toISOString();
    const logEntry = `[${timestamp}] [${level.toUpperCase()}] ${message}`;
    console.log(logEntry);
    
    if (data) {
        console.log('Detaylar:', JSON.stringify(data, null, 2));
    }
}

// Yardimci Fonksiyonlar
function sha256(text) {
    return crypto.createHash('sha256').update(text).digest('hex');
}

function saveAdmins() {
    try {
        fs.writeFileSync(config.adminFile, JSON.stringify(admins, null, 2));
        log('debug', 'Adminler dosyaya kaydedildi', { count: Object.keys(admins).length });
    } catch (e) {
        log('error', 'Adminler kaydedilirken hata olustu', { error: e.message });
    }
}

function saveChannels() {
    try {
        fs.writeFileSync(config.channelsFile, JSON.stringify(config.autoJoinChannels, null, 2));
        log('debug', 'Kanallar dosyaya kaydedildi', { channels: config.autoJoinChannels });
    } catch (e) {
        log('error', 'Kanallar kaydedilirken hata olustu', { error: e.message });
    }
}

function saveSpamIps() {
    const ipsArray = Array.from(spamIps);
    try {
        fs.writeFileSync(config.spamIpFile, JSON.stringify({
            lastUpdated: new Date().toISOString(),
            count: ipsArray.length,
            ips: ipsArray
        }, null, 2));
        log('debug', 'Spam IPler dosyaya kaydedildi', { count: ipsArray.length });
    } catch (e) {
        log('error', 'Spam IPler kaydedilirken hata olustu', { error: e.message });
    }
}

function saveBannedIps() {
    const ipsArray = Array.from(bannedIps);
    try {
        fs.writeFileSync(config.bannedIpFile, JSON.stringify({
            lastUpdated: new Date().toISOString(),
            count: ipsArray.length,
            ips: ipsArray
        }, null, 2));
        log('debug', 'Yasakli IPler dosyaya kaydedildi', { count: ipsArray.length });
    } catch (e) {
        log('error', 'Yasakli IPler kaydedilirken hata olustu', { error: e.message });
    }
}

function loadSpamIps() {
    try {
        const data = JSON.parse(fs.readFileSync(config.spamIpFile));
        spamIps = new Set(data.ips);
        log('info', 'Spam IPler dosyadan yuklendi', { count: spamIps.size });
        return true;
    } catch (e) {
        log('warn', 'Spam IP dosyasi yuklenemedi, yeni olusturulacak', { error: e.message });
        return false;
    }
}

function loadBannedIps() {
    try {
        const data = JSON.parse(fs.readFileSync(config.bannedIpFile));
        bannedIps = new Set(data.ips);
        log('info', 'Yasakli IPler dosyadan yuklendi', { count: bannedIps.size });
        return true;
    } catch (e) {
        log('warn', 'Yasakli IP dosyasi yuklenemedi, yeni olusturulacak', { error: e.message });
        return false;
    }
}

function loadChannels() {
    try {
        const channels = JSON.parse(fs.readFileSync(config.channelsFile));
        config.autoJoinChannels = channels;
        log('info', 'Kanallar dosyadan yuklendi', { channels });
    } catch (e) {
        log('warn', 'Kanallar dosyasi yuklenemedi, yeni olusturulacak', { error: e.message });
        saveChannels();
    }
}

function loadAdmins() {
    try {
        admins = JSON.parse(fs.readFileSync(config.adminFile));
        log('info', 'Adminler dosyadan yuklendi', { count: Object.keys(admins).length });
    } catch (e) {
        log('warn', 'Adminler dosyasi yuklenemedi, yeni olusturulacak', { error: e.message });
        saveAdmins();
    }
}

function generatePassword(length = 12) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

async function getUserIp(nick) {
    const lowerNick = nick.toLowerCase();
    
    if (ipCache.has(lowerNick)) {
        const { ip, timestamp } = ipCache.get(lowerNick);
        if (Date.now() - timestamp < config.maxIpCacheAge) {
            log('debug', 'IP onbellekten alindi', { nick, ip });
            return ip;
        }
        ipCache.delete(lowerNick);
    }

    log('debug', 'IP almak icin sunucuya sorgu gonderiliyor', { nick });

    return new Promise((resolve) => {
        const timeout = setTimeout(() => {
            pendingIpChecks.delete(lowerNick);
            log('warn', 'IP almak icin zaman asimi', { nick });
            resolve(null);
        }, 5000);

        pendingIpChecks.set(lowerNick, { resolve, timeout });
        client.raw(`USERIP ${nick}`);
    });
}

function cacheIp(nick, ip) {
    if (!ip) return;
    const lowerNick = nick.toLowerCase();
    ipCache.set(lowerNick, { ip, timestamp: Date.now() });
    log('trace', 'IP onbellege alindi', { nick, ip });
}

async function checkSpamIP(nick, ip) {
    if (!ip || ip === '0' || ip === 'localhost') {
        log('debug', 'Gecersiz IP, kontrol atlandi', { nick, ip });
        return;
    }

    log('info', 'IP kontrolu baslatildi', { nick, ip });

    if (spamIps.size === 0) {
        const loaded = loadSpamIps();
        if (!loaded) {
            log('info', 'Spam IP listesi bos, veritabanlari yukleniyor');
            await loadSpamDBs();
        }
    }
    
    if (spamIps.has(ip)) {
        if (!bannedIps.has(ip)) {
            log('warn', 'Spam IP tespit edildi, banlaniyor', { nick, ip });
            client.raw(`GLINE *@${ip} ${config.klineDuration} :${config.banReason}`);
            bannedIps.add(ip);
            saveBannedIps();
            client.notice(nick, `${config.noticeMessage}: ${ip} spam listesinde bulundu ve engellendi.`);
        } else {
            log('debug', 'IP zaten banli', { nick, ip });
        }
    } else {
        log('debug', 'IP temiz', { nick, ip });
        client.notice(nick, `${config.noticeMessage}: ${ip} - temiz.`);
    }
}

async function loadSpamDBs() {
    log('info', 'Spam veritabanlari yukleniyor...', {
        dbCount: config.spamDbs.length,
        currentIpCount: spamIps.size
    });
    
    try {
        for (const db of config.spamDbs) {
            try {
                log('debug', 'Spam veritabani yukleniyor', { url: db });
                const ips = await fetchSpamList(db);
                ips.forEach(ip => {
                    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
                        spamIps.add(ip);
                    }
                });
                log('debug', 'Spam veritabani yuklendi', {
                    url: db,
                    newIps: ips.length,
                    totalIps: spamIps.size
                });
            } catch (error) {
                log('error', 'Spam veritabani yuklenemedi', {
                    url: db,
                    error: error.message
                });
            }
        }
        
        saveSpamIps();
        log('info', 'Spam veritabanlari yukleme tamamlandi', {
            totalIps: spamIps.size
        });
        return spamIps.size;
    } catch (error) {
        log('error', 'Spam veritabani yukleme hatasi', {
            error: error.message
        });
        return 0;
    }
}

function fetchSpamList(url) {
    return new Promise((resolve, reject) => {
        const req = https.get(url, {
            headers: { 'User-Agent': config.userAgent },
            timeout: 10000
        }, (res) => {
            if (res.statusCode !== 200) {
                return reject(new Error(`HTTP ${res.statusCode}`));
            }
            
            let data = '';
            res.on('data', (chunk) => data += chunk);
            res.on('end', () => {
                const ips = data.split('\n')
                    .filter(line => line && !line.startsWith(';'))
                    .map(line => line.split(';')[0].trim())
                    .filter(ip => ip);
                resolve(ips);
            });
        });
        
        req.on('error', reject);
        req.on('timeout', () => {
            req.destroy();
            reject(new Error('Timeout'));
        });
    });
}

function banIpBatch(ips, callback) {
    let totalBanned = 0;
    let currentIndex = 0;
    const batchSize = config.banBatchSize;
    const batchDelay = config.banBatchDelay;

    log('info', 'IP banlama toplu islemi baslatildi', {
        totalIps: ips.length,
        batchSize,
        batchDelay
    });

    function processBatch() {
        const batchEnd = Math.min(currentIndex + batchSize, ips.length);
        
        for (let i = currentIndex; i < batchEnd; i++) {
            const ip = ips[i];
            if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
                client.raw(`GLINE *@${ip} ${config.klineDuration} :${config.banReason}`);
                bannedIps.add(ip);
                totalBanned++;
                log('debug', 'IP banlandi', { ip });
            }
        }

        currentIndex = batchEnd;
        
        if (currentIndex < ips.length) {
            setTimeout(processBatch, batchDelay);
        } else if (callback) {
            saveBannedIps();
            log('info', 'Toplu IP banlama tamamlandi', { totalBanned });
            callback(totalBanned);
        }
    }

    processBatch();
}

function banAllSpamIPs(callback) {
    if (spamIps.size === 0) {
        log('warn', 'Banlanacak spam IP bulunamadi');
        if (callback) callback(0);
        return 0;
    }

    const ipsArray = Array.from(spamIps);
    const newIpsToBan = ipsArray.filter(ip => !bannedIps.has(ip));

    if (newIpsToBan.length === 0) {
        log('info', 'Tum spam IPler zaten banli');
        if (callback) callback(0);
        return 0;
    }

    log('info', 'Tum spam IPler banlaniyor', {
        totalIps: newIpsToBan.length,
        batchSize: config.banBatchSize
    });

    let totalBanned = 0;
    let currentIndex = 0;

    function processBatch() {
        const batchEnd = Math.min(currentIndex + config.banBatchSize, newIpsToBan.length);
        
        for (let i = currentIndex; i < batchEnd; i++) {
            const ip = newIpsToBan[i];
            if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
                client.raw(`GLINE *@${ip} ${config.klineDuration} :${config.banReason}`);
                bannedIps.add(ip);
                totalBanned++;
                log('debug', 'IP banlandi', { ip });
            }
        }

        currentIndex = batchEnd;
        
        if (currentIndex < newIpsToBan.length) {
            setTimeout(processBatch, config.banBatchDelay);
        } else {
            saveBannedIps();
            log('info', 'Tum spam IPler banlama tamamlandi', { totalBanned });
            if (callback) callback(totalBanned);
        }
    }

    processBatch();
    return newIpsToBan.length;
}

function startAutoUpdates() {
    if (updateTimer) clearInterval(updateTimer);
    
    checkForUpdates().then(() => {
        updateTimer = setInterval(checkForUpdates, config.autoUpdateInterval);
        log('info', 'Otomatik guncelleme zamanlayicisi baslatildi', {
            interval: config.autoUpdateInterval
        });
    });
}

async function checkForUpdates() {
    log('info', 'Spam listeleri kontrol ediliyor...');
    const oldIps = new Set(spamIps);
    
    try {
        await loadSpamDBs();
        const addedIps = Array.from(spamIps).filter(ip => !oldIps.has(ip));
        
        if (addedIps.length > 0) {
            log('info', 'Yeni spam IPler bulundu', { count: addedIps.length });
            const ipsToBan = addedIps.filter(ip => !bannedIps.has(ip));
            if (ipsToBan.length > 0) {
                banIpBatch(ipsToBan, (bannedCount) => {
                    log('info', 'Yeni IPler banlandi', { count: bannedCount });
                });
            } else {
                log('info', 'Yeni IPler zaten banli');
            }
        } else {
            log('info', 'Yeni spam IP bulunamadi');
        }
    } catch (error) {
        log('error', 'Guncelleme sirasinda hata', { error: error.message });
    }
}

function verifyAdminHost(nick, callback) {
    if (nick === config.operName) {
        log('debug', 'Root admin host dogrulamasi atlandi');
        callback(true);
        return;
    }

    if (!admins[nick]) {
        log('warn', 'Admin bulunamadi', { nick });
        callback(false);
        return;
    }

    client.whois(nick, (whois) => {
        const currentHost = whois.hostname || 'unknown';
        const storedHost = admins[nick].host || 'unknown';
        const isValid = storedHost === 'unknown' || currentHost === storedHost;
        
        log('debug', 'Admin host dogrulama sonucu', {
            nick,
            currentHost,
            storedHost,
            isValid
        });
        
        callback(isValid);
    });
}

function handleIdentify(sender, password) {
    log('info', 'Kimlik dogrulama girisimi', { sender });
    
    if (!password) {
        client.notice(sender, 'Kullanim: !identify <sifre>');
        log('debug', 'Eksik sifre', { sender });
        return;
    }
    
    if (sender === config.operName && sha256(password) === sha256(config.operPassword)) {
        client.notice(sender, 'Root yetkiniz aktif edildi.');
        log('info', 'Root admin girisi basarili', { sender });
        return;
    }
    
    if (admins[sender]) {
        client.whois(sender, (whois) => {
            const currentHost = whois.hostname || 'unknown';
            const storedHost = admins[sender].host || 'unknown';
            
            if (storedHost !== 'unknown' && currentHost !== storedHost) {
                client.notice(sender, 'HATA: Farkli bir host uzerinden giris yapmaya calisiyorsunuz!');
                log('warn', 'Farkli hosttan admin girisi reddedildi', {
                    sender,
                    currentHost,
                    storedHost
                });
                return;
            }
            
            if (sha256(password) === admins[sender].passwordHash) {
                admins[sender].isActive = true;
                admins[sender].lastLogin = new Date().toISOString();
                admins[sender].host = currentHost;
                saveAdmins();
                client.notice(sender, 'Admin yetkileriniz aktif edildi.');
                client.raw(`MODE ${sender} +o`);
                log('info', 'Admin girisi basarili', { sender, host: currentHost });
            } else {
                client.notice(sender, 'Hatali sifre!');
                log('warn', 'Hatali admin sifresi', { sender });
            }
        });
    } else {
        client.notice(sender, 'Admin yetkiniz bulunmuyor.');
        log('warn', 'Admin olmayan girisim', { sender });
    }
}

function handleAdmin(sender, target, action, targetNick) {
    log('info', 'Admin yonetim komutu', {
        sender,
        action,
        targetNick
    });
    
    if (!action || !targetNick) {
        client.notice(target === config.nick ? sender : target, 'Kullanim: !admin <add/remove> <nick>');
        log('debug', 'Eksik parametre', { sender, action, targetNick });
        return;
    }
    
    const noticeTarget = target === config.nick ? sender : target;
    
    if (action.toLowerCase() === 'add') {
        client.whois(targetNick, (whois) => {
            const host = whois.hostname || 'unknown';
            const password = generatePassword();
            admins[targetNick] = {
                passwordHash: sha256(password),
                isActive: false,
                addedBy: sender,
                addedAt: new Date().toISOString(),
                host: host
            };
            
            saveAdmins();
            client.notice(sender, `${targetNick} admin olarak eklendi.`);
            client.notice(sender, `${targetNick} icin olusturulan sifre: ${password}`);
            client.notice(targetNick, `Merhaba, ${sender} tarafindan SpamGuard admini olarak eklendiniz.`);
            client.notice(targetNick, `Gecici sifreniz: ${password}`);
            client.notice(targetNick, `Yetkilerinizi aktif etmek icin: /msg ${config.nick} !identify ${password}`);
            log('info', 'Yeni admin eklendi', {
                adder: sender,
                newAdmin: targetNick,
                host
            });
        });
    } else if (action.toLowerCase() === 'remove') {
        if (targetNick === config.operName) {
            client.notice(noticeTarget, 'Root kullanici silinemez!');
            log('warn', 'Root admin silme girisimi', { sender, targetNick });
            return;
        }
        if (!admins[targetNick]) {
            client.notice(noticeTarget, `${targetNick} admin listesinde bulunamadi.`);
            log('warn', 'Bulunamayan admin silme girisimi', { sender, targetNick });
            return;
        }
        
        delete admins[targetNick];
        saveAdmins();
        client.notice(noticeTarget, `${targetNick} admin listesinden cikarildi.`);
        log('info', 'Admin silindi', { sender, removedAdmin: targetNick });
    } else {
        client.notice(noticeTarget, 'Gecersiz islem. Kullanim: !admin <add/remove> <nick>');
        log('warn', 'Gecersiz admin komutu', { sender, action });
    }
}

function handleListAdmins(sender, target) {
    log('debug', 'Admin listesi istegi', { sender });
    const noticeTarget = target === config.nick ? sender : target;
    const adminList = Object.keys(admins).filter(nick => admins[nick].isActive);
    
    if (adminList.length === 0) {
        client.notice(noticeTarget, 'Aktif admin bulunmuyor.');
        log('debug', 'Aktif admin bulunamadi', { sender });
        return;
    }
    
    client.notice(noticeTarget, `Aktif adminler (${adminList.length}):`);
    adminList.forEach((nick, index) => {
        const admin = admins[nick];
        const info = [
            `${index + 1}. ${nick}`,
            `Ekleyen: ${admin.addedBy}`,
            `Ekleme tarihi: ${admin.addedAt}`,
            `Host: ${admin.host || 'Bilinmiyor'}`
        ].join(' - ');
        client.notice(noticeTarget, info);
    });
    log('debug', 'Admin listesi gonderildi', {
        sender,
        count: adminList.length
    });
}

function handleSetPassword(sender, target, newPassword) {
    log('info', 'sifre degistirme girisimi', { sender });
    
    if (!newPassword) {
        client.notice(target === config.nick ? sender : target, 'Kullanim: !setpassword <yeni_sifre>');
        log('debug', 'Eksik sifre', { sender });
        return;
    }
    
    const noticeTarget = target === config.nick ? sender : target;
    
    if (sender === config.operName) {
        client.notice(noticeTarget, 'Root kullanici sifresi bu komutla degistirilemez.');
        log('warn', 'Root sifre degistirme girisimi', { sender });
        return;
    }
    
    if (admins[sender]) {
        admins[sender].passwordHash = sha256(newPassword);
        admins[sender].passwordChangedAt = new Date().toISOString();
        saveAdmins();
        client.notice(noticeTarget, 'sifreniz basariyla degistirildi.');
        log('info', 'sifre degistirildi', { sender });
    } else {
        client.notice(noticeTarget, 'Admin yetkiniz bulunmuyor.');
        log('warn', 'Admin olmayan sifre degistirme girisimi', { sender });
    }
}

function handleAddIP(sender, target, ip) {
    log('info', 'IP ekleme girisimi', { sender, ip });
    
    if (!ip) {
        client.notice(target === config.nick ? sender : target, 'Kullanim: !addip <ip>');
        log('debug', 'Eksik IP', { sender });
        return;
    }
    
    const noticeTarget = target === config.nick ? sender : target;
    
    if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
        client.notice(noticeTarget, 'Gecersiz IP formati.');
        log('warn', 'Gecersiz IP formati', { sender, ip });
        return;
    }
    
    if (spamIps.has(ip)) {
        client.notice(noticeTarget, `${ip} zaten spam listesinde.`);
        log('debug', 'Zaten var olan IP ekleme girisimi', { sender, ip });
        return;
    }
    
    spamIps.add(ip);
    saveSpamIps();
    if (!bannedIps.has(ip)) {
        client.raw(`GLINE *@${ip} ${config.klineDuration} :${config.banReason}`);
        bannedIps.add(ip);
        saveBannedIps();
        log('info', 'Yeni IP eklendi ve banlandi', { sender, ip });
    } else {
        log('info', 'Yeni IP eklendi (zaten banli)', { sender, ip });
    }
    client.notice(noticeTarget, `${ip} spam listesine eklendi ve sunucuda yasaklandi.`);
}

function handleRemoveIP(sender, target, ip) {
    log('info', 'IP silme girisimi', { sender, ip });
    
    if (!ip) {
        client.notice(target === config.nick ? sender : target, 'Kullanim: !removeip <ip>');
        log('debug', 'Eksik IP', { sender });
        return;
    }
    
    const noticeTarget = target === config.nick ? sender : target;
    
    if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
        client.notice(noticeTarget, 'Gecersiz IP formati.');
        log('warn', 'Gecersiz IP formati', { sender, ip });
        return;
    }
    
    if (!spamIps.has(ip)) {
        client.notice(noticeTarget, `${ip} spam listesinde bulunamadi.`);
        log('warn', 'Bulunamayan IP silme girisimi', { sender, ip });
        return;
    }
    
    spamIps.delete(ip);
    saveSpamIps();
    client.raw(`GLINE -*@${ip}`);
    bannedIps.delete(ip);
    saveBannedIps();
    client.notice(noticeTarget, `${ip} spam listesinden silindi ve sunucudaki GLINE kaldirildi.`);
    log('info', 'IP silindi ve ban kaldirildi', { sender, ip });
}

function handleIPStats(sender, target) {
    log('debug', 'IP istatistik istegi', { sender });
    const noticeTarget = target === config.nick ? sender : target;
    client.notice(noticeTarget, `Spam IP istatistikleri: ${spamIps.size} adet IP bulunuyor.`);
    client.notice(noticeTarget, `Banli IP sayisi: ${bannedIps.size}`);
    log('debug', 'IP istatistikleri gonderildi', {
        sender,
        spamIpCount: spamIps.size,
        bannedIpCount: bannedIps.size
    });
}

function handleJoin(sender, target, channel) {
    log('info', 'Kanala katilma istegi', { sender, channel });
    
    if (!channel) return;
    channel = channel.startsWith('#') ? channel : `#${channel}`;
    
    if (!config.autoJoinChannels.includes(channel)) {
        config.autoJoinChannels.push(channel);
        saveChannels();
        client.notice(target === config.nick ? sender : target, `${channel} kanalina eklendi ve kaydedildi.`);
        log('info', 'Yeni kanal eklendi', { sender, channel });
    }

    client.join(channel);
    botChannels.add(channel);
    log('debug', 'Kanala katilim saglandi', { channel });
}

function handlePart(sender, target, channel) {
    log('info', 'Kanaldan ayrilma istegi', { sender, channel });
    
    if (!channel) {
        client.notice(target === config.nick ? sender : target, 'Kullanim: !part #kanal');
        log('debug', 'Eksik kanal parametresi', { sender });
        return;
    }
    
    channel = channel.startsWith('#') ? channel : `#${channel}`;
    const noticeTarget = target === config.nick ? sender : target;
    
    if (!config.autoJoinChannels.includes(channel)) {
        client.notice(noticeTarget, `${channel} botun kanal listesinde bulunmuyor.`);
        log('warn', 'Listede olmayan kanaldan ayrilma girisimi', { sender, channel });
        return;
    }
    
    config.autoJoinChannels = config.autoJoinChannels.filter(c => c !== channel);
    saveChannels();
    client.part(channel);
    botChannels.delete(channel);
    client.notice(noticeTarget, `${channel} kanalindan ayrildi ve listeden silindi.`);
    log('info', 'Kanaldan ayrilindi ve listeden silindi', { sender, channel });
}

function sendHelp(target, sender, isAdmin) {
    log('debug', 'Yardim istegi', { sender, isAdmin });
    const noticeTarget = sender;
    
    const basicCommands = [
        'Kullanilabilir komutlar:',
        `${config.commandPrefix}help - Bu mesaji goster`,
        `${config.commandPrefix}identify <sifre> - Admin giris yap (sadece ozel mesaj)`,
        `${config.commandPrefix}version - Bot versiyonunu goster`
    ];
    
    const adminCommands = [
        '',
        'Admin komutlari:',
        `${config.commandPrefix}admin add <nick> - Admin ekle (otomatik sifre olusturur)`,
        `${config.commandPrefix}admin remove <nick> - Admin sil`,
        `${config.commandPrefix}listadmins - Aktif adminleri listele`,
        `${config.commandPrefix}setpassword <yeni_sifre> - sifrenizi degistirin`,
        `${config.commandPrefix}join #kanal - Kanala katil ve kaydet`,
        `${config.commandPrefix}part #kanal - Kanaldan ayril ve listeden sil`,
        `${config.commandPrefix}reload - Spam listesini yenile`,
        `${config.commandPrefix}checkip <ip> - IP kontrol et`,
        `${config.commandPrefix}checkuser <nick> - Kullaniciyi kontrol et`,
        `${config.commandPrefix}addip <ip> - Spam IP ekle ve GLINE uygula`,
        `${config.commandPrefix}removeip <ip> - Spam IP sil ve GLINE kaldir`,
        `${config.commandPrefix}ipstats - Spam IP istatistiklerini goster`,
        `${config.commandPrefix}banall - Tum spam IPleri GLINE ile engelle (${config.banBatchSize}'li gruplar halinde)`,
        `${config.commandPrefix}forceupdate - Spam listelerini manuel olarak guncelle`
    ];
    
    const helpMsg = [...basicCommands];
    if (isAdmin) {
        helpMsg.push(...adminCommands);
    }
    
    helpMsg.forEach(line => client.notice(noticeTarget, line));
    log('debug', 'Yardim mesaji gonderildi', { sender, isAdmin });
}

function handleCommand(sender, target, command) {
    const [cmd, ...args] = command.trim().split(/\s+/);
    const isPrivate = target === config.nick;
    const isAdmin = sender === config.operName || (admins[sender] && admins[sender].isActive);
    
    log('debug', 'Komut isleniyor', {
        sender,
        target,
        command: cmd,
        args,
        isPrivate,
        isAdmin
    });

    switch (cmd.toLowerCase()) {
        case 'help':
            sendHelp(target, sender, isAdmin);
            break;
            
        case 'identify':
            if (isPrivate) {
                handleIdentify(sender, args[0]);
            } else {
                client.notice(sender, 'Bu komut sadece ozel mesaj ile kullanilabilir.');
                log('warn', 'ozel olmayan identify komutu', { sender });
            }
            break;
            
        case 'version':
            client.notice(target === config.nick ? sender : target, config.realname);
            log('debug', 'Versiyon bilgisi gonderildi', { sender });
            break;
            
        case 'admin':
            if (isAdmin) {
                handleAdmin(sender, target, args[0], args[1]);
            } else {
                client.notice(target === config.nick ? sender : target, 'Bu komut sadece adminler icindir.');
                log('warn', 'Admin olmayan admin komutu girisimi', { sender });
            }
            break;
            
        case 'listadmins':
            if (isAdmin) {
                handleListAdmins(sender, target);
            } else {
                client.notice(target === config.nick ? sender : target, 'Bu komut sadece adminler icindir.');
                log('warn', 'Admin olmayan listadmins komutu girisimi', { sender });
            }
            break;
            
        case 'setpassword':
            if (isAdmin && isPrivate) {
                handleSetPassword(sender, target, args.join(' '));
            } else if (!isPrivate) {
                client.notice(sender, 'Bu komut sadece ozel mesaj ile kullanilabilir.');
                log('warn', 'ozel olmayan setpassword komutu', { sender });
            } else {
                client.notice(sender, 'Bu komut sadece adminler icindir.');
                log('warn', 'Admin olmayan setpassword komutu girisimi', { sender });
            }
            break;
            
        case 'addip':
            if (isAdmin) {
                handleAddIP(sender, target, args[0]);
            } else {
                client.notice(target === config.nick ? sender : target, 'Bu komut sadece adminler icindir.');
                log('warn', 'Admin olmayan addip komutu girisimi', { sender });
            }
            break;
            
        case 'removeip':
            if (isAdmin) {
                handleRemoveIP(sender, target, args[0]);
            } else {
                client.notice(target === config.nick ? sender : target, 'Bu komut sadece adminler icindir.');
                log('warn', 'Admin olmayan removeip komutu girisimi', { sender });
            }
            break;
            
        case 'ipstats':
            if (isAdmin) {
                handleIPStats(sender, target);
            } else {
                client.notice(target === config.nick ? sender : target, 'Bu komut sadece adminler icindir.');
                log('warn', 'Admin olmayan ipstats komutu girisimi', { sender });
            }
            break;
            
        case 'join':
            if (isAdmin) {
                handleJoin(sender, target, args[0]);
            } else {
                client.notice(target === config.nick ? sender : target, 'Bu komut sadece adminler icindir.');
                log('warn', 'Admin olmayan join komutu girisimi', { sender });
            }
            break;
            
        case 'part':
            if (isAdmin) {
                handlePart(sender, target, args[0]);
            } else {
                client.notice(target === config.nick ? sender : target, 'Bu komut sadece adminler icindir.');
                log('warn', 'Admin olmayan part komutu girisimi', { sender });
            }
            break;
            
        case 'reload':
            if (isAdmin) {
                loadSpamDBs().then(() => {
                    client.notice(target === config.nick ? sender : target, 'Spam listeleri yenilendi.');
                    log('info', 'Spam listeleri yenilendi', { sender });
                });
           } else {
                client.notice(target === config.nick ? sender : target, 'Bu komut sadece adminler icindir.');
                log('warn', 'Admin olmayan reload komutu girisimi', { sender });
            }
            break;
            
        case 'checkip':
            if (isAdmin) {
                checkSpamIP(sender, args[0]);
            } else {
                client.notice(target === config.nick ? sender : target, 'Bu komut sadece adminler icindir.');
                log('warn', 'Admin olmayan checkip komutu girisimi', { sender });
            }
            break;
            
        case 'checkuser':
            if (isAdmin) {
                getUserIp(args[0]).then(ip => {
                    if (ip) {
                        checkSpamIP(sender, ip);
                    } else {
                        client.notice(target === config.nick ? sender : target, 'Kullanici IP adresi alinamadi.');
                        log('warn', 'Kullanici IP alinamadi', { sender, targetNick: args[0] });
                    }
                });
            } else {
                client.notice(target === config.nick ? sender : target, 'Bu komut sadece adminler icindir.');
                log('warn', 'Admin olmayan checkuser komutu girisimi', { sender });
            }
            break;
            
        case 'banall':
            if (isAdmin) {
                banAllSpamIPs((count) => {
                    client.notice(target === config.nick ? sender : target, `${count} IP adresi banlandi.`);
                    log('info', 'Tum spam IPler banlandi', { sender, count });
                });
            } else {
                client.notice(target === config.nick ? sender : target, 'Bu komut sadece adminler icindir.');
                log('warn', 'Admin olmayan banall komutu girisimi', { sender });
            }
            break;
            
        case 'forceupdate':
            if (isAdmin) {
                checkForUpdates();
                client.notice(target === config.nick ? sender : target, 'Spam listeleri guncelleniyor...');
                log('info', 'Manuel guncelleme baslatildi', { sender });
            } else {
                client.notice(target === config.nick ? sender : target, 'Bu komut sadece adminler icindir.');
                log('warn', 'Admin olmayan forceupdate komutu girisimi', { sender });
            }
            break;
            
        default:
            client.notice(target === config.nick ? sender : target, 'Bilinmeyen komut. !help ile kullanilabilir komutlari gorebilirsiniz.');
            log('debug', 'Bilinmeyen komut', { sender, command });
    }
}

// IRC Olay Dinleyicileri
client.on('registered', () => {
    log('info', 'Sunucuya basariyla baglanildi', {
        server: config.server,
        nick: config.nick,
        channels: config.autoJoinChannels
    });
    
    client.raw(`OPER ${config.operol} ${config.operolpass}`);
    log('debug', 'OPER komutu gonderildi', {
        operName: config.operol
    });

    config.autoJoinChannels.forEach(channel => {
        client.join(channel);
        botChannels.add(channel);
        log('debug', 'Kanala katilim saglandi', { channel });
    });

    pingTimer = setInterval(() => {
        log('trace', 'Sunucuya PING gonderiliyor');
        client.raw('PING ' + config.server);
    }, config.pingInterval);

    startAutoUpdates();
});

client.on('raw', (event) => {
    if (event.line.match(/^:\S+ 307 \S+ \S+ :\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]@\S+$/)) {
        const match = event.line.match(/^:\S+ 307 \S+ (\S+) :\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]@\S+$/);
        const nick = match[1];
        const ip = match[2];
        
        cacheIp(nick, ip);
        
        if (pendingIpChecks.has(nick.toLowerCase())) {
            const { resolve, timeout } = pendingIpChecks.get(nick.toLowerCase());
            clearTimeout(timeout);
            pendingIpChecks.delete(nick.toLowerCase());
            resolve(ip);
            log('debug', 'IP yaniti alindi ve islendi', { nick, ip });
        }
    }
});

client.on('join', async (event) => {
    const { nick, channel } = event;
    
    if (nick === config.nick) {
        botChannels.add(channel);
        client.raw(`SAMODE ${channel} +q ${config.nick}`);
        log('debug', 'Bot kanala katildi ve yetki aldi', { channel });
    } 
    else if (botChannels.has(channel) && config.autoCheckUsers) {
        client.notice(nick, config.noticeMessage);
        log('debug', 'Kullaniciya IP kontrol mesaji gonderildi', { nick, channel });
        
        try {
            const ip = await getUserIp(nick);
            if (ip) {
                log('debug', 'Kullanici IPsi alindi, kontrol ediliyor', { nick, ip });
                checkSpamIP(nick, ip);
            } else {
                log('warn', 'Kullanici IPsi alinamadi', { nick });
            }
        } catch (err) {
            log('error', 'Kullanici IP kontrol hatasi', {
                nick,
                error: err.message
            });
        }
    }
});

client.on('part', (event) => {
    const { nick, channel } = event;
    
    if (nick === config.nick) {
        botChannels.delete(channel);
        log('debug', 'Bot kanaldan ayrildi', { channel });
    }
});

client.on('message', (event) => {
    const { nick, target, message } = event;
    
    if (message.startsWith('\x01VERSION\x01')) {
        client.notice(nick, `\x01VERSION ${config.realname}\x01`);
        log('debug', 'VERSION CTCP yaniti gonderildi', { nick });
    } 
    else if (message.startsWith(config.commandPrefix)) {
        handleCommand(nick, target, message.slice(config.commandPrefix.length));
    }
});

client.on('close', () => {
    log('warn', 'Baglanti kesildi, yeniden baglaniliyor', {
        reconnectDelay: config.reconnectDelay
    });
    clearInterval(pingTimer);
    if (updateTimer) clearInterval(updateTimer);
    botChannels.clear();
    setTimeout(initialize, config.reconnectDelay);
});

client.on('error', (error) => {
    log('error', 'IRC baglanti hatasi', {
        error: error.message,
        stack: error.stack
    });
});

// Baslatma
function initialize() {
    log('info', 'Bot baslatiliyor...');
    loadAdmins();
    loadChannels();
    loadSpamIps();
    loadBannedIps();
    
    client.connect({
        host: config.server,
        port: config.port,
        nick: config.nick,
        username: config.username,
        realname: config.realname,
        password: config.password,
        ssl: config.ssl,
        auto_reconnect: true,
        rejectUnauthorized: false
    });
}

initialize();

process.on('SIGINT', () => {
    log('info', 'Bot kapatiliyor...');
    if (updateTimer) clearInterval(updateTimer);
    saveBannedIps();
    client.disconnect('Bot kapatiliyor');
    clearInterval(pingTimer);
    process.exit();
});

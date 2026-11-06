// DRM LAB — kalit/license server + statistika (admin dashboard uchun)
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const wvmock = require('./wvmock');

const PORT = parseInt(process.env.PORT || '8000', 10);
// ===== PUBLIC/ONLINE rejim (ngrok/cloudflared tunnel ortida) =====
// PUBLIC_PROXY=1  -> video segmentlari app orqali MinIO'dan oqadi (bitta tunnel yetarli)
// PUBLIC=1        -> cookie Secure (brauzer https orqali ulanadi)
const PUBLIC_PROXY = process.env.PUBLIC_PROXY === '1';
const NO_MINIO = process.env.NO_MINIO === '1';   // MinIO yo'q (RAM-cheklangan host) -> segmentlar local fs'dan
const PUBLIC_HTTPS = process.env.PUBLIC === '1' || process.env.PUBLIC_HTTPS === '1';
const COOKIE_SECURE = PUBLIC_HTTPS ? '; Secure' : '';
const CONTENT = path.join(__dirname, '..', 'content');
const WEB = path.join(__dirname, '..', 'web');
const KEY_FILE = path.join(CONTENT, 'enc.key');

const stats = {
  started: Date.now(),
  tokensIssued: 0,
  activeTokens: [],
  counters: { key_ok: 0, key_denied: 0, clearkey_ok: 0, clearkey_denied: 0,
              sign_ok: 0, wv_ok: 0, wv_denied: 0, wvmock_ok: 0, wvmock_denied: 0 },
  events: []
};
function logEvent(type, detail, ip) {
  stats.events.unshift({ t: new Date().toISOString(), type, detail, ip });
  if (stats.events.length > 50) stats.events.pop();
}

const SECRET = 'drm-lab-demo-secret-CHANGE-ME';
const CREDS = { aaa: 'aaa' };            // login: aaa / parol: aaa
const SESSION_TTL = 12 * 60 * 60;        // 12 soat
const DRM_TOKEN_TTL = 12 * 60 * 60;      // drmauthtoken 12 soat
// Bitta aktiv sessiya: har user uchun faqat oxirgi login'ning jti si saqlanadi.
// Yangi qurilmadan kirsa -> jti o'zgaradi -> eski cookie kuchsiz (eski qurilma chiqadi).
const activeSessions = {};               // { user: jti }
function signToken(payloadObj, ttlSec) {
  const payload = { ...payloadObj, exp: Math.floor(Date.now() / 1000) + ttlSec };
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return body + '.' + sig;
}
function verifyToken(tok) {
  if (!tok) return null;
  const [body, sig] = tok.split('.');
  if (!body || !sig) return null;
  const expect = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  if (sig !== expect) return null;
  const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
  if (payload.exp < Math.floor(Date.now() / 1000)) return null;
  return payload;
}

const MIME = { '.m3u8': 'application/vnd.apple.mpegurl', '.ts': 'video/mp2t',
  '.html': 'text/html', '.js': 'application/javascript', '.mp4': 'video/mp4',
  '.mpd': 'application/dash+xml', '.json': 'application/json' };

// ===== MinIO (S3) obyekt-saqlash — video baytlari app'dan EMAS, to'g'ridan
//       obyekt-saqlashdan, qisqa muddatli presigned (SigV4) URL orqali keladi =====
const MINIO = {
  endpoint: process.env.MINIO_ENDPOINT || 'http://localhost:9000',
  host: process.env.MINIO_HOST || 'localhost:9000',
  region: 'us-east-1', bucket: 'videos',
  accessKey: 'minioadmin', secretKey: 'minioadmin',
};
const SEG_URL_TTL = 120;   // presigned segment URL = 120 soniya (token ortida beriladi)
function enc3986(s) {       // S3 uchun RFC3986 URI-encode
  return encodeURIComponent(s).replace(/[!*'()]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}
function hmac(key, data) { return crypto.createHmac('sha256', key).update(data).digest(); }
function presignGet(objectKey, expiresSec) {
  const amzdate = new Date().toISOString().replace(/[:\-]/g, '').replace(/\.\d{3}/, '');
  const datestamp = amzdate.slice(0, 8);
  const canonicalUri = '/' + MINIO.bucket + '/' + objectKey.split('/').map(enc3986).join('/');
  const scope = datestamp + '/' + MINIO.region + '/s3/aws4_request';
  const q = {
    'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
    'X-Amz-Credential': MINIO.accessKey + '/' + scope,
    'X-Amz-Date': amzdate,
    'X-Amz-Expires': String(expiresSec),
    'X-Amz-SignedHeaders': 'host',
  };
  const canonicalQuery = Object.keys(q).sort()
    .map(k => enc3986(k) + '=' + enc3986(q[k])).join('&');
  const canonicalRequest = ['GET', canonicalUri, canonicalQuery,
    'host:' + MINIO.host + '\n', 'host', 'UNSIGNED-PAYLOAD'].join('\n');
  const hashedCR = crypto.createHash('sha256').update(canonicalRequest).digest('hex');
  const stringToSign = ['AWS4-HMAC-SHA256', amzdate, scope, hashedCR].join('\n');
  const kDate = hmac('AWS4' + MINIO.secretKey, datestamp);
  const kSigning = hmac(hmac(hmac(kDate, MINIO.region), 's3'), 'aws4_request');
  const signature = crypto.createHmac('sha256', kSigning).update(stringToSign).digest('hex');
  return MINIO.endpoint + canonicalUri + '?' + canonicalQuery + '&X-Amz-Signature=' + signature;
}

const server = http.createServer((req, res) => {
  const u = new URL(req.url, `http://${req.headers.host}`);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization');
  const ip = req.socket.remoteAddress;

  const b64url = (hex) => Buffer.from(hex, 'hex').toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const getAuth = () => (req.headers['authorization'] || '').replace('Bearer ', '')
                 || u.searchParams.get('token');
  // cookie parse + sessiya tekshiruvi
  const cookies = Object.fromEntries((req.headers.cookie || '').split(';').map(c => {
    const i = c.indexOf('='); return [c.slice(0, i).trim(), decodeURIComponent(c.slice(i + 1))]; }).filter(x => x[0]));
  const session = (() => {
    const p = verifyToken(cookies['drmsess']);
    if (!p) return null;
    // jti oxirgi login bilan mos kelmasa -> bu qurilma chiqarilgan
    if (activeSessions[p.user] !== p.jti) return null;
    return p;
  })();

  // LOGIN sahifasi (GET) / tekshiruv (POST)
  if (u.pathname === '/login' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    return res.end(fs.readFileSync(path.join(WEB, 'login.html')));
  }
  if (u.pathname === '/login' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    return req.on('end', () => {
      const p = new URLSearchParams(body);
      const user = p.get('login'), pass = p.get('password');
      if (CREDS[user] && CREDS[user] === pass) {
        const jti = crypto.randomBytes(8).toString('hex');
        activeSessions[user] = jti;              // oxirgi login -> eski qurilma chiqadi
        const sess = signToken({ user, jti }, SESSION_TTL);
        logEvent('LOGIN', 'kirish OK user=' + user + ' (eski qurilma chiqarildi)', ip);
        res.writeHead(302, { 'Set-Cookie': `drmsess=${sess}; HttpOnly; Path=/; Max-Age=${SESSION_TTL}${COOKIE_SECURE}`, 'Location': '/' });
        return res.end();
      }
      logEvent('LOGIN', 'kirish RAD (login/parol notogri)', ip);
      res.writeHead(401, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end('<meta charset=utf-8><body style="font-family:sans-serif;background:#0f1115;color:#f06a6a;padding:40px">Login yoki parol notogri. <a style="color:#5aa9f0" href="/login">Qayta urinish</a></body>');
    });
  }
  if (u.pathname === '/logout') {
    res.writeHead(302, { 'Set-Cookie': 'drmsess=; Path=/; Max-Age=0', 'Location': '/login' });
    return res.end();
  }

  // AUTH -> drmauthtoken, FAQAT sessiya bo'lsa (platforma sessiyasi -> drm token)
  if (u.pathname === '/auth') {
    if (!session) { res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'NOT_LOGGED_IN' })); }
    const ttl = DRM_TOKEN_TTL;
    const token = signToken({ user: session.user, vid: 'sample' }, ttl);
    stats.tokensIssued++;
    stats.activeTokens = stats.activeTokens.filter(t => t.exp > Math.floor(Date.now()/1000));
    stats.activeTokens.push({ user: session.user, exp: Math.floor(Date.now()/1000) + ttl });
    logEvent('AUTH', 'drmauthtoken berildi user=' + session.user + ' (TTL 12h)', ip);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ token, ttl }));
  }

  if (u.pathname === '/stats') {
    stats.activeTokens = stats.activeTokens.filter(t => t.exp > Math.floor(Date.now()/1000));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ ...stats, uptime: Math.floor((Date.now()-stats.started)/1000) }));
  }

  if (u.pathname === '/key') {
    const payload = verifyToken(getAuth());
    if (!payload) { stats.counters.key_denied++; logEvent('KEY', 'RAD (token yoq)', ip);
      res.writeHead(403); return res.end('Forbidden: valid token required'); }
    stats.counters.key_ok++; logEvent('KEY', 'kalit berildi user=' + payload.user, ip);
    res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
    return res.end(fs.readFileSync(KEY_FILE));
  }

  if (u.pathname === '/clearkey' && req.method === 'POST') {
    const payload = verifyToken(getAuth());
    if (!payload) { stats.counters.clearkey_denied++; logEvent('CLEARKEY', 'RAD', ip);
      res.writeHead(403); return res.end('Forbidden'); }
    let body = '';
    req.on('data', c => body += c);
    return req.on('end', () => {
      const [kidHex, keyHex] = fs.readFileSync(path.join(CONTENT, 'cenc', 'keys.txt'), 'utf8').trim().split('\n');
      stats.counters.clearkey_ok++; logEvent('CLEARKEY', 'license berildi user=' + payload.user, ip);
      const resp = { keys: [{ kty: 'oct', kid: b64url(kidHex), k: b64url(keyHex) }], type: 'temporary' };
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(resp));
    });
  }

  if (u.pathname === '/sign') {
    const payload = verifyToken(getAuth());
    if (!payload) { res.writeHead(403); return res.end('Forbidden'); }
    const target = u.searchParams.get('path') || '';
    if (!target.startsWith('/wv/')) { res.writeHead(400); return res.end('bad path'); }
    const exp = Math.floor(Date.now() / 1000) + 60;
    const sig = crypto.createHmac('sha256', SECRET).update(target + exp).digest('hex').slice(0, 24);
    stats.counters.sign_ok++; logEvent('SIGN', 'signed URL: ' + target, ip);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ url: `${target}?exp=${exp}&sig=${sig}` }));
  }

  // 2d) MOCKWIDEVINE LICENSE — real Widevine alternativi (kalit tarmoqda ochiq EMAS)
  if (u.pathname === '/wvmock/license' && req.method === 'POST') {
    const payload = verifyToken(getAuth());
    if (!payload) { stats.counters.wvmock_denied++; logEvent('WVMOCK', 'RAD (token yoq)', ip);
      res.writeHead(403); return res.end(JSON.stringify({ status: 'NO_TOKEN' })); }
    let body = '';
    req.on('data', c => body += c);
    return req.on('end', () => {
      let reqObj; try { reqObj = JSON.parse(body); } catch { reqObj = {}; }
      // wvmock player AES-128 HLS (/hls/) oqimini o'ynaydi -> K = HLS enc.key bo'lishi shart
      // (CENC keys.txt EMAS, aks holda noto'g'ri kalit -> fragParsingError).
      const keyHex = fs.readFileSync(KEY_FILE).toString('hex');
      const result = wvmock.handleLicense(reqObj, keyHex);
      if (!result.ok) {
        stats.counters.wvmock_denied++;
        logEvent('WVMOCK', 'RAD: ' + result.status + ' dev=' + (reqObj.deviceId||'?'), ip);
        res.writeHead(403, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ status: result.status }));
      }
      stats.counters.wvmock_ok++;
      logEvent('WVMOCK', 'license berildi dev=' + reqObj.deviceId + ' (K shifrlangan)', ip);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'OK', ...result.response }));
    });
  }

  // Portal: login bo'lmasa /login ga yo'naltirish
  if (u.pathname === '/' || u.pathname === '/index.html') {
    if (!session) { res.writeHead(302, { 'Location': '/login' }); return res.end(); }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    return res.end(fs.readFileSync(path.join(WEB, 'portal.html')));
  }

  // ===== HLS content -> MinIO (presigned, token-gated) =====
  // Manifest token ortida; .ts qatorlari qisqa muddatli presigned MinIO URL'ga
  // almashtiriladi -> video baytlari app'dan emas, to'g'ridan obyekt-saqlashdan keladi.
  if (u.pathname.startsWith('/hls/') && u.pathname.endsWith('.m3u8')) {
    const payload = verifyToken(getAuth());
    if (!payload) { logEvent('HLS', 'manifest RAD (token yoq): ' + u.pathname, ip);
      res.writeHead(403); return res.end('Forbidden: valid token required'); }
    const name = path.basename(u.pathname);
    let m3u8;
    try { m3u8 = fs.readFileSync(path.join(CONTENT, 'hls', name), 'utf8'); }
    catch { res.writeHead(404); return res.end('not found'); }
    const out = m3u8.split('\n').map(line => {
      const t = line.trim();
      // #EXT-X-KEY URI'ni origin-relative qilamiz -> tunnel/public origin'da ham ishlaydi
      if (t.startsWith('#EXT-X-KEY')) return line.replace(/URI="[^"]*"/, 'URI="/key"');
      if (!t || t.startsWith('#')) return line;      // boshqa teglar o'zgarmaydi
      if (PUBLIC_PROXY || NO_MINIO) return line;     // public: .ts app-relative qoladi (app o'zi beradi)
      return presignGet('hls/' + t, SEG_URL_TTL);     // .ts -> presigned MinIO URL
    }).join('\n');
    logEvent('HLS', 'manifest presigned berildi user=' + payload.user + ' (' + SEG_URL_TTL + 's)', ip);
    res.writeHead(200, { 'Content-Type': MIME['.m3u8'] });
    return res.end(out);
  }
  // Agar .ts to'g'ridan app'ga kelsa (native player) -> presigned MinIO URL'ga 302
  if (u.pathname.startsWith('/hls/') && u.pathname.endsWith('.ts')) {
    if (NO_MINIO) {
      // MinIO yo'q: shifrlangan segmentni to'g'ridan local fs'dan beramiz (kalit baribir /key token ortida)
      const name = path.basename(u.pathname);
      try {
        const buf = fs.readFileSync(path.join(CONTENT, 'hls', name));
        logEvent('HLS', '.ts local (NO_MINIO): ' + u.pathname, ip);
        res.writeHead(200, { 'Content-Type': MIME['.ts'], 'Cache-Control': 'no-store' });
        return res.end(buf);
      } catch { res.writeHead(404); return res.end('not found'); }
    }
    const url = presignGet('hls' + u.pathname.slice('/hls'.length), SEG_URL_TTL);
    if (PUBLIC_PROXY) {
      // Public rejim: baytlarni MinIO'dan server-side olib, app orqali oqizamiz (bitta tunnel).
      // Segment AES-128 bilan shifrlangan -> kalitsiz foydasiz (kalit /key token ortida qoladi).
      logEvent('HLS', '.ts proxy MinIO->app: ' + u.pathname, ip);
      const lib = url.startsWith('https') ? require('https') : http;
      const preq = lib.get(url, pr => {
        if (pr.statusCode !== 200) { res.writeHead(pr.statusCode || 502); return pr.pipe(res); }
        res.writeHead(200, { 'Content-Type': MIME['.ts'], 'Cache-Control': 'no-store' });
        pr.pipe(res);
      });
      preq.on('error', e => { logEvent('HLS', '.ts proxy XATO: ' + e.message, ip); if (!res.headersSent) res.writeHead(502); res.end('proxy error'); });
      return;
    }
    logEvent('HLS', '.ts -> presigned 302: ' + u.pathname, ip);
    res.writeHead(302, { 'Location': url }); return res.end();
  }

  let base, rel;
  if (u.pathname.startsWith('/hls/') || u.pathname.startsWith('/cenc/')) { base = CONTENT; rel = u.pathname; }
  else if (u.pathname.startsWith('/wv/')) {
    const exp = parseInt(u.searchParams.get('exp') || '0', 10);
    const sig = u.searchParams.get('sig') || '';
    const expect = crypto.createHmac('sha256', SECRET).update(u.pathname + exp).digest('hex').slice(0, 24);
    if (sig !== expect) { stats.counters.wv_denied++; logEvent('WV', 'RAD imzo: ' + u.pathname, ip); res.writeHead(403); return res.end('bad signature'); }
    if (exp < Math.floor(Date.now() / 1000)) { stats.counters.wv_denied++; logEvent('WV', 'RAD muddat: ' + u.pathname, ip); res.writeHead(403); return res.end('expired'); }
    stats.counters.wv_ok++; logEvent('WV', 'OK: ' + u.pathname, ip);
    base = CONTENT; rel = u.pathname.split('?')[0];
  }
  else { base = WEB; rel = u.pathname; }
  const file = path.join(base, rel.split('?')[0]);
  if (!file.startsWith(base)) { res.writeHead(403); return res.end('no'); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); return res.end('not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(data);
  });
});

server.listen(PORT, () => console.log(`DRM LAB keyserver: http://localhost:${PORT}`));

// MockWidevine CDM client — qurilmadagi CDM modulini emulyatsiya qiladi.
// Vazifasi: license olish -> K ni ochish (sessiya kaliti bilan) -> kontentni deshifrlash.
// Real Widevine CDM kabi: K tarmoqdan ochiq kelmaydi, bu yerda ochiladi (xotirada).
const crypto = require('crypto');
const http = require('http');

function post(pathname, token, bodyObj) {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify(bodyObj));
    const req = http.request({ host: 'localhost', port: 8000, path: pathname, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': data.length,
                 'Authorization': 'Bearer ' + token } },
      res => { let b = ''; res.on('data', c => b += c); res.on('end', () => resolve({ code: res.statusCode, json: JSON.parse(b) })); });
    req.on('error', reject); req.write(data); req.end();
  });
}
function getToken() {
  return new Promise((resolve, reject) => {
    http.get('http://localhost:8000/auth', res => { let b=''; res.on('data',c=>b+=c); res.on('end',()=>resolve(JSON.parse(b).token)); }).on('error', reject);
  });
}

async function acquireKey(deviceId, requireLevel) {
  const token = await getToken();
  // CDM ephemeral ECDH kaliti
  const cdm = crypto.createECDH('prime256v1'); cdm.generateKeys();
  const nonce = crypto.randomBytes(16);
  const challenge = { deviceId, requireLevel,
    clientPubHex: cdm.getPublicKey('hex'), nonceHex: nonce.toString('hex') };
  const { code, json } = await post('/wvmock/license', token, challenge);
  if (json.status !== 'OK') return { ok: false, code, status: json.status };
  // Sessiya kalitini tiklash va K ni ochish
  const shared = cdm.computeSecret(Buffer.from(json.serverPubHex, 'hex'));
  const sessionKey = crypto.hkdfSync('sha256', shared, nonce, Buffer.from('mockwv-session'), 32);
  const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(sessionKey), Buffer.from(json.ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(json.tagHex, 'hex'));
  const K = Buffer.concat([decipher.update(Buffer.from(json.wrappedKeyHex, 'hex')), decipher.final()]);
  return { ok: true, status: 'OK', policy: json.policy, keyHex: K.toString('hex') };
}

(async () => {
  const tests = [
    ['CHROME-L1-001', 'L1'],     // ishonchli L1 -> OK
    ['ANDROID-L3-ROOT', 'L1'],   // root telefon L3, L1 talab -> RAD (Just'ning holati)
    ['ANDROID-L3-ROOT', 'L3'],   // L3 talab -> OK (past sifat yo'li)
    ['LEAKED-CDM-X', 'L1'],      // revoke qilingan -> RAD
    ['UNKNOWN-DEV', 'L1'],       // ro'yxatda yo'q -> RAD
  ];
  for (const [dev, lvl] of tests) {
    const r = await acquireKey(dev, lvl);
    if (r.ok) console.log(`${dev.padEnd(16)} require=${lvl}  -> OK, K=${r.keyHex.slice(0,16)}... level=${r.policy.securityLevel}`);
    else      console.log(`${dev.padEnd(16)} require=${lvl}  -> RAD: ${r.status}`);
  }
})();

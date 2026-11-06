// MockWidevine — real Widevine license serverining ALTERNATIVI (o'rgatish/lab uchun).
// Real Widevine xususiyatlarini takrorlaydi:
//  1) Kontent kaliti (K) tarmoqda HECH QACHON ochiq ko'rinmaydi (ClearKey'dan farq).
//     K sessiya kaliti bilan shifrlanadi (ECDH P-256 + HKDF + AES-256-GCM).
//  2) Device cert pinning: faqat ro'yxatdagi qurilma qabul qilinadi.
//  3) Security-level enforcement: L3 (dasturiy/root) rad etiladi, L1 talab qilinadi.
//     -> Aynan Just'ning root-telefon .wvd urinishidagi rad etish mantig'i.
const crypto = require('crypto');

// "Provisioned" qurilmalar reestri (real Widevine'da device cert).
const DEVICES = {
  'CHROME-L1-001':   { level: 'L1', revoked: false },  // ishonchli apparat CDM
  'EDGE-L1-002':     { level: 'L1', revoked: false },
  'ANDROID-L3-ROOT': { level: 'L3', revoked: false },  // root telefon — past daraja
  'LEAKED-CDM-X':    { level: 'L1', revoked: true  },   // tarqalgan/revoke qilingan CDM
};

// Server uzoq muddatli ECDH kaliti (real'da Widevine service key)
const serverECDH = crypto.createECDH('prime256v1');
serverECDH.generateKeys();

function hkdf(sharedSecret, salt, info, len = 32) {
  return crypto.hkdfSync('sha256', sharedSecret, salt, info, len);
}

// License challenge'ni qayta ishlash.
// req: { deviceId, clientPubHex, nonceHex, requireLevel }
// contentKeyHex: shu video uchun kontent kaliti (hex)
// return: { ok, status, response? }
function handleLicense(reqObj, contentKeyHex) {
  const dev = DEVICES[reqObj.deviceId];
  // 1) Device cert pinning
  if (!dev) return { ok: false, status: 'DEVICE_NOT_PROVISIONED' };
  // 2) Revocation (tarqalgan CDM qora ro'yxati)
  if (dev.revoked) return { ok: false, status: 'DEVICE_REVOKED' };
  // 3) Security level enforcement — L1 talab, L3 rad
  const need = reqObj.requireLevel || 'L1';
  const rank = { L3: 1, L2: 2, L1: 3 };
  if (rank[dev.level] < rank[need]) {
    return { ok: false, status: `SECURITY_LEVEL_TOO_LOW (device=${dev.level}, require=${need})` };
  }
  // 4) ECDH sessiya kaliti — K ni shifrlash uchun
  const clientPub = Buffer.from(reqObj.clientPubHex, 'hex');
  const shared = serverECDH.computeSecret(clientPub);
  const nonce = Buffer.from(reqObj.nonceHex, 'hex');
  const sessionKey = hkdf(shared, nonce, Buffer.from('mockwv-session'));
  // 5) K ni sessiya kaliti bilan shifrlab yuboramiz (ochiq matnda EMAS)
  const K = Buffer.from(contentKeyHex, 'hex');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', sessionKey, iv);
  const wrappedKey = Buffer.concat([cipher.update(K), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { ok: true, status: 'OK', response: {
    serverPubHex: serverECDH.getPublicKey('hex'),
    ivHex: iv.toString('hex'),
    wrappedKeyHex: wrappedKey.toString('hex'),
    tagHex: tag.toString('hex'),
    policy: { securityLevel: dev.level, hdcp: 'HDCP_V2_REQUIRED', persist: false }
  }};
}

module.exports = { handleLicense, DEVICES };

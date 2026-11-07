// LetMeUse JWT 驗證（HS256）。
//
// 刻意不引入 jose：HS256 就是對 `header.payload` 做 HMAC-SHA256，用 node:crypto
// 二十行就能寫完，少一個相依少一份供應鏈風險，部署也快。
//
// 🔒 一定要驗簽章，不能只 decode：只解碼的話任何人自編一段 base64 payload
// 就能冒充任何使用者上傳統計、灌爆排行榜。

const crypto = require("node:crypto");

function b64urlDecode(str) {
  return Buffer.from(str.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

/**
 * 驗證 LetMeUse token，通過回傳 payload，否則回傳 null。
 * @param {string} token
 * @param {{secret: string, appId?: string, now?: number}} opts
 */
function verifyLetMeUseToken(token, opts) {
  const secret = opts?.secret;
  if (!token || typeof token !== "string" || !secret) return null;

  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [headerB64, payloadB64, sigB64] = parts;

  let header;
  try {
    header = JSON.parse(b64urlDecode(headerB64).toString("utf8"));
  } catch (e) {
    return null;
  }
  // 只接受 HS256：擋掉 alg:none 與非對稱演算法混淆攻擊
  if (header?.alg !== "HS256") return null;

  const expected = crypto
    .createHmac("sha256", secret)
    .update(`${headerB64}.${payloadB64}`)
    .digest();
  const actual = b64urlDecode(sigB64);
  // 長度不同時 timingSafeEqual 會丟錯，先擋掉
  if (expected.length !== actual.length) return null;
  if (!crypto.timingSafeEqual(expected, actual)) return null;

  let payload;
  try {
    payload = JSON.parse(b64urlDecode(payloadB64).toString("utf8"));
  } catch (e) {
    return null;
  }

  const now = opts.now ?? Math.floor(Date.now() / 1000);
  if (typeof payload.exp === "number" && payload.exp <= now) return null;
  if (!payload.sub) return null;
  // 別的 app 的 token 不準借用
  if (opts.appId && payload.app && payload.app !== opts.appId) return null;

  return payload;
}

function extractBearerToken(authHeader) {
  if (!authHeader || typeof authHeader !== "string") return null;
  if (!authHeader.startsWith("Bearer ")) return null;
  const token = authHeader.slice(7).trim();
  return token || null;
}

module.exports = { verifyLetMeUseToken, extractBearerToken };

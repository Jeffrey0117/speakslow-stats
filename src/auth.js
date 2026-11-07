// LetMeUse JWT 驗證（ES256，公鑰走 JWKS）。
//
// 🔒 為什麼只收 ES256、不收 HS256（2026-11-07 改）：
// HS256 用 app secret 當簽章金鑰，等於「驗證方必須握著簽發金鑰」——secret
// 一外洩，任何人都能自簽一顆 `sub` 隨便填的 token 冒充任何使用者。pokkit
// 2026-10-25 就是這樣被當成免費圖床（見 infra-map）。所以這裡只收 ES256：
//   - 驗證只需要公鑰 → 這台機器不必、也不該存 LETMEUSE_APP_SECRET
//   - 就算 secret 已經洩了，偽造的 token 一樣進不來
//
// ⚠️ 簽發端的現況要分清楚（letmeuse/src/lib/auth/jwt.ts）：
//   - `verifyAccessToken` 已經只收 ES256，HS256 路徑真的刪了
//   - 但 `signAccessToken` 是「`LETMEUSE_SIGN_ALG=ES256` 且金鑰載得起來才簽
//     ES256，否則退回 HS256」。目前線上那兩個 env 都有設（實測 JWKS 正在發
//     ES256 公鑰），但萬一哪次 letmeuse 重新部署把 env 弄掉，它會無聲退回
//     HS256 → 這裡就會「全部 401 且零線索」。所以 JWKS 的狀態一定要能從
//     /api/health 看到（見 src/jwks.js 的 stats()）。
//
// 刻意不引入 jose：node:crypto 直接驗得動 ES256，維持零依賴。

const crypto = require("node:crypto");

function b64urlDecode(str) {
  return Buffer.from(str.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

// ES256 的簽章是 P-256 的 r||s，各 32 bytes。長度不對就不用往下算了
// （也順手擋掉 DER 編碼的簽章——那不是 JWT 規格）。
const ES256_SIG_BYTES = 64;

// 🔒 嚴格的 base64url 字集。`Buffer.from(x, "base64")` 會**默默忽略**非字母表
// 字元與非標準的尾端位元，所以同一顆 token 存在很多種等價字串（實測：簽章段
// 最後一字有 15 種寫法、中間插 `!` 或換行也照樣通過）。這本身不是驗簽漏洞
// （被簽的是 header/payload 的原始字串，而 payload 是驗完才解析的），但只要
// 以後有任何東西以 token 字串當 key——重放快取、idempotency key、撤銷黑名單、
// 限流桶、log 比對——就會被輕易繞過。先在這裡釘死，比日後踩到便宜。
// 64 bytes 的 base64url 不帶 padding 剛好 86 字元。
const B64URL_SEGMENT = /^[A-Za-z0-9_-]+$/;
const B64URL_ES256_SIG = /^[A-Za-z0-9_-]{86}$/;

/**
 * 驗證 LetMeUse token，通過回傳 payload，否則回傳 null。
 *
 * @param {string} token
 * @param {{
 *   getKey: (kid: string) => import("node:crypto").KeyObject | null,
 *   appId: string,
 *   now?: number,
 * }} opts getKey 通常來自 src/jwks.js 的快取；appId 必填，理由見下。
 */
function verifyLetMeUseToken(token, opts) {
  const getKey = opts?.getKey;
  const appId = opts?.appId;
  if (!token || typeof token !== "string") return null;
  if (typeof getKey !== "function") return null; // 設定不全 → fail-closed
  // 🔒 appId 必填：LetMeUse 所有 app 的 token 都用同一把 ES256 金鑰簽，
  // 不比對 app 就等於「任何 LetMeUse app 的使用者都能上傳到這裡」。
  if (typeof appId !== "string" || !appId) return null;

  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [headerB64, payloadB64, sigB64] = parts;
  if (!B64URL_SEGMENT.test(headerB64)) return null;
  if (!B64URL_SEGMENT.test(payloadB64)) return null;
  if (!B64URL_ES256_SIG.test(sigB64)) return null;

  let header;
  try {
    header = JSON.parse(b64urlDecode(headerB64).toString("utf8"));
  } catch (e) {
    return null;
  }
  // 只接受 ES256：擋掉 alg:none、HS256（secret 外洩自簽）與演算法混淆攻擊
  if (header?.alg !== "ES256") return null;
  if (typeof header.kid !== "string" || !header.kid) return null;

  const publicKey = getKey(header.kid);
  if (!publicKey) return null; // 不認識的 kid → 不放行

  const signature = b64urlDecode(sigB64);
  if (signature.length !== ES256_SIG_BYTES) return null;

  let ok = false;
  try {
    ok = crypto.verify(
      "sha256",
      Buffer.from(`${headerB64}.${payloadB64}`),
      { key: publicKey, dsaEncoding: "ieee-p1363" },
      signature,
    );
  } catch (e) {
    return null;
  }
  if (!ok) return null;

  let payload;
  try {
    payload = JSON.parse(b64urlDecode(payloadB64).toString("utf8"));
  } catch (e) {
    return null;
  }
  if (!payload || typeof payload !== "object") return null;

  const now = opts.now ?? Math.floor(Date.now() / 1000);
  // exp 必須存在且是數字：沒有 exp 的 token 等於「永不過期」，那不是合法的
  // access token（LetMeUse 一律簽 4h）。字串型 exp 也不接受，免得被 typeof
  // 檢查跳過變成無限期有效。
  if (typeof payload.exp !== "number" || payload.exp <= now) return null;
  if (typeof payload.nbf === "number" && payload.nbf > now) return null;
  // sub 會直接當 DB 的 userId，必須是非空字串
  if (typeof payload.sub !== "string" || !payload.sub) return null;
  // 別的 app 的 token 不準借用（缺 app claim 也一樣擋掉）
  if (payload.app !== appId) return null;

  return payload;
}

function extractBearerToken(authHeader) {
  if (!authHeader || typeof authHeader !== "string") return null;
  if (!authHeader.startsWith("Bearer ")) return null;
  const token = authHeader.slice(7).trim();
  return token || null;
}

module.exports = { verifyLetMeUseToken, extractBearerToken };

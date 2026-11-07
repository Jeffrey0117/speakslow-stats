// 測試共用：造 ES256 / HS256 token 與對應的 JWKS 條目。
const crypto = require("node:crypto");

function b64url(buf) {
  return Buffer.from(buf).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** 產生一組 ES256 測試金鑰，附上它在 JWKS 裡的樣子。 */
function makeKeyPair(kid = "test-kid") {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = { ...publicKey.export({ format: "jwk" }), kid, alg: "ES256", use: "sig" };
  return { publicKey, privateKey, kid, jwk };
}

/** 產生一組「曲線不對」的金鑰，用來確認 JWKS 過濾是真的在擋，而不是碰巧。 */
function makeP384KeyPair(kid = "p384-kid") {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-384" });
  const jwk = { ...publicKey.export({ format: "jwk" }), kid, alg: "ES384", use: "sig" };
  return { publicKey, privateKey, kid, jwk };
}

/**
 * 簽一顆 ES256 token。
 *
 * 簽章預設用 ieee-p1363（raw r||s）而非 DER —— JWT 規格與 LetMeUse（jose）
 * 都是這個格式，用 DER 會驗不過（`dsaEncoding: "der"` 就是拿來測這件事的）。
 *
 * header 的覆寫放在展開的最後，所以負面測試可以蓋掉 alg / kid
 * （給 `kid: undefined` 會被 JSON.stringify 丟掉，等於「沒帶 kid」）。
 */
function signEs256(payload, { privateKey, kid }, header = {}, { dsaEncoding = "ieee-p1363" } = {}) {
  const h = b64url(JSON.stringify({ alg: "ES256", typ: "JWT", kid, ...header }));
  const p = b64url(JSON.stringify(payload));
  const sig = crypto.sign("sha256", Buffer.from(`${h}.${p}`), { key: privateKey, dsaEncoding });
  return `${h}.${p}.${b64url(sig)}`;
}

/** 簽一顆 HS256 token：模擬「app secret 外洩後自簽冒充任意使用者」的攻擊。 */
function signHs256(payload, secret) {
  const h = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const p = b64url(JSON.stringify(payload));
  const sig = crypto.createHmac("sha256", secret).update(`${h}.${p}`).digest();
  return `${h}.${p}.${b64url(sig)}`;
}

/** 把一組（或多組）金鑰包成同步的 getKey，省掉測試裡的網路。 */
function getKeyFrom(...pairs) {
  const map = new Map(pairs.map((k) => [k.kid, k.publicKey]));
  return (kid) => map.get(kid) || null;
}

/**
 * 給 createServer 用的假 jwks。
 * ⚠️ 測試一定要注入這個：不注入的話 createServer 會自己建一個快取，
 * 於是 `npm test` 會真的去打 production 的 LetMeUse。
 */
function fakeJwks(...pairs) {
  return { getKey: getKeyFrom(...pairs) };
}

const future = () => Math.floor(Date.now() / 1000) + 3600;
const past = () => Math.floor(Date.now() / 1000) - 10;

module.exports = {
  b64url, makeKeyPair, makeP384KeyPair, signEs256, signHs256,
  getKeyFrom, fakeJwks, future, past,
};

const assert = require("node:assert/strict");
const test = require("node:test");
const { verifyLetMeUseToken, extractBearerToken } = require("../src/auth");
const {
  b64url, makeKeyPair, signEs256, signHs256, getKeyFrom, future, past,
} = require("./helpers");

// LetMeUse 從 2026-10-30 起只簽 ES256（見 letmeuse/src/lib/auth/jwt.ts）。
// 驗證方拿 JWKS 公鑰驗，自己不持有任何簽章金鑰。
const KEYS = makeKeyPair("kid-main");
const getKey = getKeyFrom(KEYS);

const APP = "app_mine";
const opts = { getKey, appId: APP };

// 舊版（HS256）用的 app secret。留在測試裡只為了證明「它再也打不開門」。
const LEAKED_SECRET = "leaked-app-secret";

/** 一顆正常的、該通過的 token。 */
const good = (extra = {}, keys = KEYS, header = undefined, signOpts = undefined) =>
  signEs256({ sub: "u1", app: APP, exp: future(), ...extra }, keys, header, signOpts);

test("正確簽章的 ES256 token 通過", () => {
  const payload = verifyLetMeUseToken(good({ name: "小明" }), opts);
  assert.equal(payload.sub, "u1");
  assert.equal(payload.name, "小明");
});

test("🔒 偽造簽章必須擋掉——這是排行榜防灌水的根本", () => {
  const attacker = makeKeyPair("kid-main"); // 冒用同一個 kid，但私鑰是自己的
  assert.equal(verifyLetMeUseToken(good({ sub: "attacker" }, attacker), opts), null);
});

test("🔒 HS256 一律擋掉，就算是用真的 app secret 簽的（pokkit 2026-10-25 事件回歸）", () => {
  // 攻擊劇本：app secret 外洩 → 自簽 HS256 冒充任意 sub。
  // 驗證端只認 ES256，所以 secret 洩漏也偽造不出有效 token。
  const forged = signHs256({ sub: "victim", app: APP, exp: future() }, LEAKED_SECRET);
  assert.equal(verifyLetMeUseToken(forged, opts), null);
});

test("🔒 alg:none 攻擊擋掉", () => {
  const h = b64url(JSON.stringify({ alg: "none", typ: "JWT", kid: KEYS.kid }));
  const p = b64url(JSON.stringify({ sub: "attacker", app: APP, exp: future() }));
  assert.equal(verifyLetMeUseToken(`${h}.${p}.`, opts), null);
});

test("🔒 未知 kid 擋掉（拿不到公鑰就 fail-closed，不放行）", () => {
  assert.equal(verifyLetMeUseToken(good({}, makeKeyPair("kid-unknown")), opts), null);
});

test("🔒 header 沒帶 kid 擋掉", () => {
  assert.equal(verifyLetMeUseToken(good({}, KEYS, { kid: undefined }), opts), null);
});

test("🔒 DER 格式簽章擋掉（只接受 JWT 規格的 raw r||s）", () => {
  const der = good({}, KEYS, undefined, { dsaEncoding: "der" });
  assert.equal(verifyLetMeUseToken(der, opts), null);
});

test("過期的 token 擋掉", () => {
  assert.equal(verifyLetMeUseToken(good({ exp: past() }), opts), null);
});

test("🔒 沒有 exp 的 token 擋掉——不能把「沒寫有效期」當成永久有效", () => {
  const h = b64url(JSON.stringify({ alg: "ES256", typ: "JWT", kid: KEYS.kid }));
  assert.equal(verifyLetMeUseToken(signEs256({ sub: "u1", app: APP }, KEYS), opts), null);
  void h;
});

test("🔒 字串型 exp 擋掉（否則 typeof 檢查會被跳過 = 無限期有效）", () => {
  assert.equal(verifyLetMeUseToken(good({ exp: String(future()) }), opts), null);
});

test("🔒 nbf 還沒到的 token 擋掉", () => {
  assert.equal(verifyLetMeUseToken(good({ nbf: future() }), opts), null);
});

test("exp 剛好等於 now 算過期", () => {
  const now = Math.floor(Date.now() / 1000);
  assert.equal(verifyLetMeUseToken(good({ exp: now }), { ...opts, now }), null);
  assert.ok(verifyLetMeUseToken(good({ exp: now + 1 }), { ...opts, now }));
});

test("🔒 別的 app 的 token 不準借用", () => {
  assert.equal(verifyLetMeUseToken(good({ app: "app_other" }), opts), null);
});

test("🔒 完全沒有 app claim 的 token 也擋掉（LetMeUse 全 app 共用同一把簽章金鑰）", () => {
  // 這是關鍵：JWKS 只有一把 ES256 金鑰、簽發所有 app 的 token。只靠簽章有效
  // 不足以證明這顆 token 是給「這個 app」的 —— 不比對 app 就等於「任何
  // LetMeUse app 的使用者都能寫進這裡的排行榜」。
  const h = b64url(JSON.stringify({ alg: "ES256", typ: "JWT", kid: KEYS.kid }));
  assert.equal(verifyLetMeUseToken(signEs256({ sub: "u1", exp: future() }, KEYS), opts), null);
  void h;
});

test("🔒 自己沒設 appId 就一律拒絕（設定漂移 = 開門給全生態，必須 fail-closed）", () => {
  const t = good();
  assert.equal(verifyLetMeUseToken(t, { getKey }), null);
  assert.equal(verifyLetMeUseToken(t, { getKey, appId: "" }), null);
  assert.equal(verifyLetMeUseToken(t, { getKey, appId: null }), null);
});

test("🔒 sub 一定要是非空字串（會直接當 DB 的 userId）", () => {
  for (const sub of [12345, { a: 1 }, ["x"], true, "", null]) {
    assert.equal(verifyLetMeUseToken(good({ sub }), opts), null, `sub=${JSON.stringify(sub)}`);
  }
});

test("沒有 getKey 就一律拒絕（設定不全不准放行）", () => {
  const t = good();
  assert.equal(verifyLetMeUseToken(t, { appId: APP }), null);
  assert.equal(verifyLetMeUseToken(t, { getKey: null, appId: APP }), null);
});

test("🔒 token 字串必須是嚴格的 base64url", () => {
  const t = good();
  const [h, p, s] = t.split(".");
  // Buffer.from(.., "base64") 會默默忽略這些字元，不先擋掉的話同一顆 token
  // 有無數種等價寫法 → 任何以 token 字串當 key 的機制都會被繞過
  assert.ok(verifyLetMeUseToken(t, opts), "原本的 token 應該通過");
  assert.equal(verifyLetMeUseToken(`${h}.${p}.${s.slice(0, 40)}!${s.slice(41)}`, opts), null);
  assert.equal(verifyLetMeUseToken(`${h}.${p}.${s}=`, opts), null);
  assert.equal(verifyLetMeUseToken(`${h}.${p}.${s}A`, opts), null, "長度不對");
  assert.equal(verifyLetMeUseToken(`${h}+.${p}.${s}`, opts), null);
  assert.equal(verifyLetMeUseToken(`${h}.${p}\n.${s}`, opts), null);
});

test("格式異常一律回 null，不丟例外", () => {
  for (const bad of [null, undefined, "", "abc", "a.b", "a.b.c.d", 123, {}]) {
    assert.equal(verifyLetMeUseToken(bad, opts), null);
  }
});

test("extractBearerToken 只接受 Bearer", () => {
  assert.equal(extractBearerToken("Bearer abc"), "abc");
  assert.equal(extractBearerToken("bearer abc"), null);
  assert.equal(extractBearerToken("abc"), null);
  assert.equal(extractBearerToken(null), null);
  assert.equal(extractBearerToken("Bearer   "), null);
});

const assert = require("node:assert/strict");
const test = require("node:test");
const crypto = require("node:crypto");
const { verifyLetMeUseToken, extractBearerToken } = require("../src/auth");

const SECRET = "test-secret-do-not-use";

function b64url(buf) {
  return Buffer.from(buf).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function makeToken(payload, { secret = SECRET, alg = "HS256" } = {}) {
  const h = b64url(JSON.stringify({ alg, typ: "JWT" }));
  const p = b64url(JSON.stringify(payload));
  const sig = crypto.createHmac("sha256", secret).update(`${h}.${p}`).digest();
  return `${h}.${p}.${b64url(sig)}`;
}

const future = () => Math.floor(Date.now() / 1000) + 3600;

test("正確簽章的 token 通過", () => {
  const token = makeToken({ sub: "u1", name: "小明", exp: future() });
  const payload = verifyLetMeUseToken(token, { secret: SECRET });
  assert.equal(payload.sub, "u1");
  assert.equal(payload.name, "小明");
});

test("🔒 偽造簽章必須擋掉——這是排行榜防灌水的根本", () => {
  const forged = makeToken({ sub: "attacker", exp: future() }, { secret: "wrong-secret" });
  assert.equal(verifyLetMeUseToken(forged, { secret: SECRET }), null);
});

test("🔒 自編 payload 不簽章也擋掉", () => {
  const h = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const p = b64url(JSON.stringify({ sub: "attacker", exp: future() }));
  assert.equal(verifyLetMeUseToken(`${h}.${p}.`, { secret: SECRET }), null);
  assert.equal(verifyLetMeUseToken(`${h}.${p}.AAAA`, { secret: SECRET }), null);
});

test("🔒 alg:none 攻擊擋掉", () => {
  const h = b64url(JSON.stringify({ alg: "none", typ: "JWT" }));
  const p = b64url(JSON.stringify({ sub: "attacker", exp: future() }));
  assert.equal(verifyLetMeUseToken(`${h}.${p}.`, { secret: SECRET }), null);
});

test("過期的 token 擋掉", () => {
  const token = makeToken({ sub: "u1", exp: Math.floor(Date.now() / 1000) - 10 });
  assert.equal(verifyLetMeUseToken(token, { secret: SECRET }), null);
});

test("別的 app 的 token 不準借用", () => {
  const token = makeToken({ sub: "u1", app: "app_other", exp: future() });
  assert.equal(verifyLetMeUseToken(token, { secret: SECRET, appId: "app_mine" }), null);
  assert.ok(verifyLetMeUseToken(token, { secret: SECRET, appId: "app_other" }));
});

test("沒有 sub 的 token 擋掉（無法歸戶）", () => {
  const token = makeToken({ name: "no-sub", exp: future() });
  assert.equal(verifyLetMeUseToken(token, { secret: SECRET }), null);
});

test("格式異常一律回 null，不丟例外", () => {
  for (const bad of [null, undefined, "", "abc", "a.b", "a.b.c.d", 123, {}]) {
    assert.equal(verifyLetMeUseToken(bad, { secret: SECRET }), null);
  }
});

test("extractBearerToken 只接受 Bearer", () => {
  assert.equal(extractBearerToken("Bearer abc"), "abc");
  assert.equal(extractBearerToken("bearer abc"), null);
  assert.equal(extractBearerToken("abc"), null);
  assert.equal(extractBearerToken(null), null);
  assert.equal(extractBearerToken("Bearer   "), null);
});

const assert = require("node:assert/strict");
const test = require("node:test");
const crypto = require("node:crypto");
const os = require("node:os");
const path = require("node:path");
const fs = require("node:fs");
const { isLoopbackRedirect } = require("../src/desktopLogin");
const { createServer } = require("../src/server");
const { makeKeyPair, fakeJwks } = require("./helpers");

// ⚠️ 一定要注入假 JWKS：不注入的話 createServer 會自己建一個快取，
// 於是 `npm test` 會真的對 production 的 LetMeUse 發請求。
const JWKS = fakeJwks(makeKeyPair("login-kid"));
const BASE = "https://letmeuse.example.test";

test("🔒 只接受本機回跳——擋開放重導（否則別人能偷走登入 token）", () => {
  assert.ok(isLoopbackRedirect("http://127.0.0.1:52341/callback"));
  assert.ok(isLoopbackRedirect("http://localhost:3000/callback"));

  // 以下全部必須擋掉
  for (const bad of [
    "https://evil.com/callback",
    "http://evil.com/callback",
    "http://127.0.0.1.evil.com/callback",      // 看起來像本機的網域
    "http://evil.com#127.0.0.1/callback",
    "http://127.0.0.1:52341/steal",            // 路徑不對
    "https://127.0.0.1:52341/callback",        // 本機回跳不會有憑證
    "javascript:alert(1)",
    "//evil.com/callback",
    "",
    "not a url",
    // 🔒 自帶 query / hash 也要擋：handOff 會自己接 `?token=`，而這是把
    // `</script>` 偷渡進頁面的另一條路
    "http://127.0.0.1:5000/callback?x=1",
    "http://127.0.0.1:5000/callback#frag",
    'http://127.0.0.1:5000/callback?x=</script><script>alert(1)</script>',
  ]) {
    assert.equal(isLoopbackRedirect(bad), false, `應擋掉：${bad}`);
  }
});

async function withServer(fn) {
  const dbFile = path.join(os.tmpdir(), `ss-login-${crypto.randomUUID()}.db`);
  const server = createServer({ dbFile, jwks: JWKS, appId: "app_test", baseUrl: BASE });
  await new Promise((r) => server.listen(0, r));
  try {
    await fn(`http://127.0.0.1:${server.address().port}`);
  } finally {
    await new Promise((r) => server.close(r));
    for (const sfx of ["", "-wal", "-shm"]) {
      try { fs.unlinkSync(dbFile + sfx); } catch (e) { /* ignore */ }
    }
  }
}

test("合法請求回登入頁，且帶入 app id", async () => {
  await withServer(async (base) => {
    const r = await fetch(`${base}/desktop-login?redirect_uri=${encodeURIComponent("http://127.0.0.1:5000/callback")}&state=abc123`);
    assert.equal(r.status, 200);
    const html = await r.text();
    assert.ok(html.includes("app_test"));
    assert.ok(html.includes("abc123"));
    assert.ok(html.includes("letmeuse.js"));
  });
});

test("🔒 外部回跳網址被拒，且不會把網址放進頁面", async () => {
  await withServer(async (base) => {
    const r = await fetch(`${base}/desktop-login?redirect_uri=${encodeURIComponent("https://evil.com/callback")}&state=abc`);
    assert.equal(r.status, 400);
    const html = await r.text();
    assert.ok(!html.includes("evil.com"), "拒絕頁不該回顯攻擊者的網址");
  });
});

test("🔒 state 裡的 </scr' + 'ipt> 不能跳出 script 標籤（會被用來偷 LetMeUse token）", async () => {
  await withServer(async (base) => {
    const redirect = encodeURIComponent("http://127.0.0.1:5000/callback");
    // 這一頁的 localStorage 有 access token 與 30 天 refresh token。
    // JSON.stringify 不轉義 `</script>`，所以字串裡放它就能關掉 script 元素、
    // 接著執行任意程式碼 → 直接把真 token 送走，完全繞過 ES256 驗證。
    const payloads = [
      "</script><script>alert(1)</script>",
      "</ScRiPt ><script>x</script>",
      "a b",
      "<img src=x onerror=alert(1)>",
      "abc\"+alert(1)+\"",
    ];
    for (const evil of payloads) {
      const r = await fetch(`${base}/desktop-login?redirect_uri=${redirect}&state=${encodeURIComponent(evil)}`);
      assert.equal(r.status, 400, `應該被 state 字集擋掉：${evil}`);
      const html = await r.text();
      assert.ok(!html.includes("</script><script>"), "拒絕頁不該回顯 payload");
      assert.ok(!html.includes("onerror="), "拒絕頁不該回顯 payload");
    }
  });
});

test("🔒 就算 state 字集沒擋住，嵌入時也一定被轉義（第二道防線）", () => {
  // 直接測嵌入函式本身：萬一哪天 state 的規則放寬，轉義還在。
  const { handleDesktopLogin } = require("../src/desktopLogin");
  let captured = "";
  const fakeRes = { writeHead() {}, end(b) { captured = String(b); } };
  const url = new URL("http://x/desktop-login?redirect_uri=http%3A%2F%2F127.0.0.1%3A5000%2Fcallback&state=ok123");
  handleDesktopLogin(url, fakeRes, { appId: "app_test", baseUrl: BASE });
  assert.ok(captured.includes("ok123"), "正常值要進得去");
  // 頁面裡除了結尾那個，不該有任何 </script> 是來自參數的
  const scriptCloses = captured.match(/<\/script>/gi) || [];
  assert.equal(scriptCloses.length, 2, "只該有 SDK 與 inline script 各一個結尾");
});

test("state 合法字元（含 . - _）要通過", async () => {
  await withServer(async (base) => {
    const redirect = encodeURIComponent("http://127.0.0.1:5000/callback");
    for (const ok of ["test", "abc123", "a.b-c_d", "x".repeat(128)]) {
      const r = await fetch(`${base}/desktop-login?redirect_uri=${redirect}&state=${ok}`);
      assert.equal(r.status, 200, `應該通過：${ok}`);
    }
    // 超長的擋掉
    const tooLong = await fetch(`${base}/desktop-login?redirect_uri=${redirect}&state=${"x".repeat(129)}`);
    assert.equal(tooLong.status, 400);
  });
});

test("缺少 state 會拒絕", async () => {
  await withServer(async (base) => {
    const r = await fetch(`${base}/desktop-login?redirect_uri=${encodeURIComponent("http://127.0.0.1:5000/callback")}`);
    assert.equal(r.status, 400);
  });
});

test("尚未設定 app id 時回 503 而不是壞掉的頁面", async () => {
  const dbFile = path.join(os.tmpdir(), `ss-login-${crypto.randomUUID()}.db`);
  const server = createServer({ dbFile, jwks: JWKS, appId: "", baseUrl: BASE });
  await new Promise((r) => server.listen(0, r));
  try {
    const base = `http://127.0.0.1:${server.address().port}`;
    const r = await fetch(`${base}/desktop-login?redirect_uri=${encodeURIComponent("http://127.0.0.1:5000/callback")}&state=a`);
    assert.equal(r.status, 503);
  } finally {
    await new Promise((r) => server.close(r));
    for (const sfx of ["", "-wal", "-shm"]) {
      try { fs.unlinkSync(dbFile + sfx); } catch (e) { /* ignore */ }
    }
  }
});

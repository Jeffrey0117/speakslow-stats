const assert = require("node:assert/strict");
const test = require("node:test");
const crypto = require("node:crypto");
const os = require("node:os");
const path = require("node:path");
const fs = require("node:fs");
const { isLoopbackRedirect } = require("../src/desktopLogin");
const { createServer } = require("../src/server");

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
  ]) {
    assert.equal(isLoopbackRedirect(bad), false, `應擋掉：${bad}`);
  }
});

async function withServer(fn) {
  const dbFile = path.join(os.tmpdir(), `ss-login-${crypto.randomUUID()}.db`);
  const server = createServer({ dbFile, secret: "s", appId: "app_test" });
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

test("缺少 state 會拒絕", async () => {
  await withServer(async (base) => {
    const r = await fetch(`${base}/desktop-login?redirect_uri=${encodeURIComponent("http://127.0.0.1:5000/callback")}`);
    assert.equal(r.status, 400);
  });
});

test("尚未設定 app id 時回 503 而不是壞掉的頁面", async () => {
  const dbFile = path.join(os.tmpdir(), `ss-login-${crypto.randomUUID()}.db`);
  const server = createServer({ dbFile, secret: "s", appId: "" });
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

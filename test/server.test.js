const assert = require("node:assert/strict");
const test = require("node:test");
const crypto = require("node:crypto");
const os = require("node:os");
const path = require("node:path");
const fs = require("node:fs");
const { createServer } = require("../src/server");

const SECRET = "e2e-secret";

function b64url(b) {
  return Buffer.from(b).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function token(payload, secret = SECRET) {
  const h = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const p = b64url(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 3600, ...payload }));
  const sig = crypto.createHmac("sha256", secret).update(`${h}.${p}`).digest();
  return `${h}.${p}.${b64url(sig)}`;
}

async function withServer(fn) {
  const dbFile = path.join(os.tmpdir(), `ss-stats-${crypto.randomUUID()}.db`);
  const server = createServer({ dbFile, secret: SECRET });
  await new Promise((r) => server.listen(0, r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    await fn(base);
  } finally {
    await new Promise((r) => server.close(r));
    for (const suffix of ["", "-wal", "-shm"]) {
      try { fs.unlinkSync(dbFile + suffix); } catch (e) { /* ignore */ }
    }
  }
}

const post = (base, body, auth) =>
  fetch(`${base}/api/stats`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(auth ? { Authorization: `Bearer ${auth}` } : {}) },
    body: JSON.stringify(body),
  });

test("健康檢查", async () => {
  await withServer(async (base) => {
    const r = await fetch(`${base}/api/health`);
    assert.equal(r.status, 200);
    assert.deepEqual(await r.json(), { ok: true });
  });
});

test("上傳統計 → 進排行榜 → 總量正確", async () => {
  await withServer(async (base) => {
    await post(base, { totalChars: 5000, totalSessions: 100, totalSeconds: 1200, activeDays: 20 },
      token({ sub: "u1", name: "小明" }));
    await post(base, { totalChars: 9000, totalSessions: 200, totalSeconds: 2400, activeDays: 10 },
      token({ sub: "u2", name: "大華" }));

    const lb = await (await fetch(`${base}/api/leaderboard?by=totalChars`)).json();
    assert.equal(lb.entries[0].name, "大華", "字數榜第一應是 9000 字的人");
    assert.equal(lb.entries[1].name, "小明");

    const byDays = await (await fetch(`${base}/api/leaderboard?by=activeDays`)).json();
    assert.equal(byDays.entries[0].name, "小明", "天數榜第一應是用了 20 天的人");

    const s = await (await fetch(`${base}/api/summary`)).json();
    assert.equal(s.users, 2);
    assert.equal(s.totalChars, 14000);
  });
});

test("🔒 沒帶 token 不能上傳", async () => {
  await withServer(async (base) => {
    const r = await post(base, { totalChars: 999999 });
    assert.equal(r.status, 401);
    const s = await (await fetch(`${base}/api/summary`)).json();
    assert.equal(s.users, 0, "未授權的資料不該進庫");
  });
});

test("🔒 偽造 token 不能灌排行榜", async () => {
  await withServer(async (base) => {
    const r = await post(base, { totalChars: 999999999 }, token({ sub: "attacker" }, "wrong-secret"));
    assert.equal(r.status, 401);
    const s = await (await fetch(`${base}/api/summary`)).json();
    assert.equal(s.users, 0);
  });
});

test("重複上傳同一份不會把數字翻倍", async () => {
  await withServer(async (base) => {
    const t = token({ sub: "u1", name: "小明" });
    const body = { totalChars: 1000, totalSessions: 10, totalSeconds: 100, activeDays: 5 };
    await post(base, body, t);
    await post(base, body, t);
    await post(base, body, t);
    const s = await (await fetch(`${base}/api/summary`)).json();
    assert.equal(s.users, 1);
    assert.equal(s.totalChars, 1000);
  });
});

test("不想上榜的人不出現在排行榜，但仍計入總量", async () => {
  await withServer(async (base) => {
    await post(base, { totalChars: 8000, leaderboardOptIn: false }, token({ sub: "shy", name: "低調" }));
    const lb = await (await fetch(`${base}/api/leaderboard`)).json();
    assert.equal(lb.entries.length, 0);
    const s = await (await fetch(`${base}/api/summary`)).json();
    assert.equal(s.totalChars, 8000);
  });
});

test("壞掉的 JSON 回 400 而不是 500", async () => {
  await withServer(async (base) => {
    const r = await fetch(`${base}/api/stats`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token({ sub: "u1" })}` },
      body: "{ not json",
    });
    assert.equal(r.status, 400);
  });
});

test("未知路徑回 404", async () => {
  await withServer(async (base) => {
    assert.equal((await fetch(`${base}/api/nope`)).status, 404);
  });
});

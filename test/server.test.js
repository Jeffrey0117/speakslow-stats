const assert = require("node:assert/strict");
const test = require("node:test");
const crypto = require("node:crypto");
const os = require("node:os");
const path = require("node:path");
const fs = require("node:fs");
const { createServer } = require("../src/server");
const { makeKeyPair, signEs256, signHs256, fakeJwks } = require("./helpers");

// 舊版用來簽 HS256 的 app secret。留著只為了證明它再也打不開門。
const LEAKED_SECRET = "e2e-secret";

// LetMeUse 的簽章金鑰（正牌）。測試用假 JWKS 直接餵公鑰，不碰網路。
const KEYS = makeKeyPair("e2e-kid");
const JWKS = fakeJwks(KEYS);
const APP = "app_e2e";

function token(payload, keys = KEYS) {
  return signEs256(
    { app: APP, exp: Math.floor(Date.now() / 1000) + 3600, ...payload },
    keys,
  );
}

async function withServer(fn) {
  const dbFile = path.join(os.tmpdir(), `ss-stats-${crypto.randomUUID()}.db`);
  const server = createServer({ dbFile, jwks: JWKS, appId: APP });
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
    // 攻擊者自己生一把金鑰、冒用同一個 kid
    const attacker = makeKeyPair("e2e-kid");
    const r = await post(base, { totalChars: 999999999 }, token({ sub: "attacker" }, attacker));
    assert.equal(r.status, 401);
    const s = await (await fetch(`${base}/api/summary`)).json();
    assert.equal(s.users, 0);
  });
});

test("🔒 別的 app 的 token 寫不進來（JWKS 是全 LetMeUse 共用一把金鑰）", async () => {
  await withServer(async (base) => {
    // 簽章完全有效、只是 app 不是我們 —— 必須擋掉，不然 pokkit/quickky 等
    // 任何 app 的使用者都能來灌這裡的排行榜
    const other = await post(base, { totalChars: 555 }, token({ sub: "u-other", app: "app_other" }));
    assert.equal(other.status, 401);
    // 連 app claim 都沒有的也一樣擋
    const noApp = await post(base, { totalChars: 555 }, token({ sub: "u-noapp", app: undefined }));
    assert.equal(noApp.status, 401);
    const s = await (await fetch(`${base}/api/summary`)).json();
    assert.equal(s.users, 0);
  });
});

test("🔒 email 不會被當成顯示名稱公開在排行榜上", async () => {
  await withServer(async (base) => {
    // 沒設暱稱的使用者（OAuth 註冊很常見）。/api/leaderboard 免登入 + CORS *，
    // 掉下去就是把 email 公開給全網路爬。
    await post(base, { totalChars: 100 }, token({ sub: "u-mail", email: "jeff.private@gmail.com" }));
    const lb = await (await fetch(`${base}/api/leaderboard`)).json();
    assert.equal(lb.entries.length, 1);
    assert.equal(lb.entries[0].name, "匿名使用者");
    assert.ok(!JSON.stringify(lb).includes("jeff.private"), "回應裡不該出現 email");
  });
});

test("🔒 顯示名稱裡的 HTML 會被清掉（公開 feed 不知道誰在渲染）", async () => {
  await withServer(async (base) => {
    await post(base, { totalChars: 100 }, token({ sub: "u-xss", name: "<svg onload=alert(1)>" }));
    const lb = await (await fetch(`${base}/api/leaderboard`)).json();
    const name = lb.entries[0].name;
    for (const ch of ["<", ">", "&", '"', "'"]) {
      assert.ok(!name.includes(ch), `名稱不該含 ${ch}：${name}`);
    }
  });
});

test("🔒 用外洩的 app secret 自簽 HS256 也進不來（pokkit 2026-10-25 事件回歸）", async () => {
  await withServer(async (base) => {
    const forged = signHs256(
      { sub: "victim", exp: Math.floor(Date.now() / 1000) + 3600 },
      LEAKED_SECRET,
    );
    const r = await post(base, { totalChars: 999999999 }, forged);
    assert.equal(r.status, 401);
    const s = await (await fetch(`${base}/api/summary`)).json();
    assert.equal(s.users, 0, "HS256 偽造的資料絕不該進庫");
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

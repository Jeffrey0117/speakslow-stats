const assert = require("node:assert/strict");
const test = require("node:test");
const { createJwksCache } = require("../src/jwks");
const { makeKeyPair, makeP384KeyPair } = require("./helpers");

/** 假的 fetch：依序回給定的回應，並記錄被呼叫幾次。 */
function stubFetch(bodies) {
  const queue = Array.isArray(bodies) ? [...bodies] : [bodies];
  const calls = { n: 0 };
  const fetchImpl = async () => {
    calls.n += 1;
    const body = queue.length > 1 ? queue.shift() : queue[0];
    if (body instanceof Error) throw body;
    if (body === "http-error") return { ok: false, status: 500, json: async () => ({}) };
    if (body === "bad-json") {
      return { ok: true, status: 200, json: async () => { throw new Error("invalid json"); } };
    }
    if (body === "stall") return new Promise(() => {}); // 接了連線但永遠不回
    return { ok: true, status: 200, json: async () => body };
  };
  return { fetchImpl, calls };
}

const quiet = { onError: () => {} };

test("抓到 JWKS 之後 getKey(kid) 回得到公鑰", async () => {
  const k = makeKeyPair("kid-a");
  const { fetchImpl } = stubFetch({ keys: [k.jwk] });
  const cache = createJwksCache({ url: "https://idp.test/jwks", fetchImpl, ...quiet });

  assert.equal(cache.getKey("kid-a"), null, "還沒抓之前應該是空的");
  await cache.refresh();

  const pub = cache.getKey("kid-a");
  assert.ok(pub, "抓完應該拿得到公鑰");
  assert.equal(pub.asymmetricKeyType, "ec");
});

test("非 ES256 / 非 P-256 / 非簽章用途的條目一律濾掉", async () => {
  const good = makeKeyPair("good");
  const p384 = makeP384KeyPair("wrong-curve"); // 真的 P-384 金鑰，不是假資料
  const encOnly = { ...makeKeyPair("enc-only").jwk, use: "enc" };
  const { fetchImpl } = stubFetch({
    keys: [
      good.jwk,
      p384.jwk,
      encOnly,
      { kty: "oct", k: "AAAA", kid: "symmetric", alg: "HS256" },
      { kty: "RSA", n: "a", e: "AQAB", kid: "rsa", alg: "RS256" },
      { ...makeKeyPair("no-kid").jwk, kid: undefined },
    ],
  });
  const cache = createJwksCache({ url: "https://idp.test/jwks", fetchImpl, ...quiet });
  await cache.refresh();

  assert.ok(cache.getKey("good"));
  for (const kid of ["wrong-curve", "enc-only", "symmetric", "rsa", "no-kid"]) {
    assert.equal(cache.getKey(kid), null, `${kid} 不該被收進快取`);
  }
});

test("🔒 格式正確的空 JWKS 會清空快取——緊急撤銷金鑰必須真的生效", async () => {
  // 劇本：LetMeUse 私鑰外洩 → 把金鑰從 JWKS 下架。如果這裡「空的不覆蓋」，
  // 就會繼續拿舊公鑰放行被盜金鑰簽的 token，直到有人想起來重啟 process。
  const k = makeKeyPair("leaked-kid");
  const { fetchImpl } = stubFetch([{ keys: [k.jwk] }, { keys: [] }]);
  const cache = createJwksCache({ url: "https://idp.test/jwks", fetchImpl, ...quiet });

  await cache.refresh();
  assert.ok(cache.getKey("leaked-kid"));

  await cache.refresh(); // 權威的空回應
  assert.equal(cache.getKey("leaked-kid"), null, "被撤銷的金鑰必須立刻失效");
  assert.match(cache.stats().lastError || "", /沒有任何可用/);
});

test("空 JWKS 會透過 onError 吼出來（fail-closed 不能無聲）", async () => {
  const { fetchImpl } = stubFetch({ keys: [] });
  const errors = [];
  const cache = createJwksCache({
    url: "https://idp.test/jwks", fetchImpl, onError: (e) => errors.push(e.message),
  });
  await cache.refresh();
  assert.equal(errors.length, 1);
  assert.match(errors[0], /沒有任何可用/);
});

test("傳輸層失敗（丟錯 / HTTP 500 / 壞 JSON）保留舊快取且不拋出", async () => {
  const k = makeKeyPair("kid-a");
  const { fetchImpl } = stubFetch([
    { keys: [k.jwk] }, new Error("ECONNREFUSED"), "http-error", "bad-json",
  ]);
  const cache = createJwksCache({ url: "https://idp.test/jwks", fetchImpl, ...quiet });

  await cache.refresh();
  for (let i = 0; i < 3; i += 1) {
    await cache.refresh();
    assert.ok(cache.getKey("kid-a"), "傳輸失敗時舊公鑰要留著（不然一次網路抖動全員登出）");
  }
  assert.ok(cache.stats().lastError, "但錯誤要記下來");
});

test("第一次就失敗時 getKey 回 null，不丟例外", async () => {
  const { fetchImpl } = stubFetch(new Error("boom"));
  const cache = createJwksCache({ url: "https://idp.test/jwks", fetchImpl, ...quiet });
  await cache.refresh();
  assert.equal(cache.getKey("anything"), null);
});

test("併發 refresh 只打一次網路", async () => {
  const k = makeKeyPair("kid-a");
  const { fetchImpl, calls } = stubFetch({ keys: [k.jwk] });
  const cache = createJwksCache({ url: "https://idp.test/jwks", fetchImpl, ...quiet });

  await Promise.all([cache.refresh(), cache.refresh(), cache.refresh()]);
  assert.equal(calls.n, 1);
});

test("kid 沒中會觸發背景重抓（金鑰輪換時自動跟上）", async () => {
  const oldKey = makeKeyPair("kid-old");
  const newKey = makeKeyPair("kid-new");
  const { fetchImpl, calls } = stubFetch([{ keys: [oldKey.jwk] }, { keys: [newKey.jwk] }]);
  const cache = createJwksCache({
    url: "https://idp.test/jwks", fetchImpl, missCooldownMs: 0, ...quiet,
  });

  await cache.refresh();
  assert.equal(calls.n, 1);

  assert.equal(cache.getKey("kid-new"), null, "這一次還是先回 null（fail-closed）");
  await cache.whenIdle();
  assert.equal(calls.n, 2, "沒中應該在背景重抓");
  assert.ok(cache.getKey("kid-new"), "重抓後就跟上輪換");
});

test("🔒 未知 kid 的冷卻真的有在節流（不然等於幫人 DoS LetMeUse）", async () => {
  const k = makeKeyPair("kid-a");
  const { fetchImpl, calls } = stubFetch({ keys: [k.jwk] });
  const cache = createJwksCache({
    url: "https://idp.test/jwks", fetchImpl, missCooldownMs: 10_000, ...quiet,
  });
  await cache.refresh();
  assert.equal(calls.n, 1);

  // 一萬個不同的未知 kid 打進來，冷卻期內只准多抓一次
  for (let i = 0; i < 10_000; i += 1) cache.getKey(`unknown-${i}`);
  await cache.whenIdle();
  assert.equal(calls.n, 2, `冷卻期內應該只多抓一次，實際 ${calls.n}`);
});

test("🔒 卡死的 fetch 不能把快取永久鎖住（node fetch 沒有預設逾時）", async () => {
  // 這是最毒的失效模式：對方接了連線但永遠不回 → promise 永不 settle →
  // inFlight 永遠占住 → 定時刷新變成 no-op、未知 kid 也不再重抓 →
  // 每個上傳都 401 直到重啟 process，而且零診斷。
  const k = makeKeyPair("kid-a");
  const { fetchImpl, calls } = stubFetch(["stall", { keys: [k.jwk] }]);
  const cache = createJwksCache({
    url: "https://idp.test/jwks", fetchImpl, timeoutMs: 30, missCooldownMs: 0, ...quiet,
  });

  await cache.refresh(); // 第一次卡住 → 應該在 30ms 後逾時放掉
  assert.equal(calls.n, 1);
  assert.equal(cache.getKey("kid-a"), null);
  assert.match(cache.stats().lastError || "", /timed out/);

  await cache.refresh(); // inFlight 已經放掉，所以這次真的會再打
  assert.equal(calls.n, 2, "逾時後必須還能重試");
  assert.ok(cache.getKey("kid-a"), "重試成功後要恢復");
});

test("🔒 太久沒成功更新就當作沒金鑰（不拿不知多舊的公鑰繼續放行）", async () => {
  const k = makeKeyPair("kid-a");
  const { fetchImpl } = stubFetch([{ keys: [k.jwk] }, new Error("down")]);
  const cache = createJwksCache({
    url: "https://idp.test/jwks", fetchImpl, maxStaleMs: 1, missCooldownMs: 10_000, ...quiet,
  });
  await cache.refresh();
  assert.ok(cache.getKey("kid-a"));

  await new Promise((r) => setTimeout(r, 5)); // 超過 maxStaleMs
  assert.equal(cache.getKey("kid-a"), null, "過期的快取不該再放行");
});

test("start() 會先抓一次並排定時刷新；stop() 之後不再抓", async () => {
  const k = makeKeyPair("kid-a");
  const { fetchImpl, calls } = stubFetch({ keys: [k.jwk] });
  const cache = createJwksCache({
    url: "https://idp.test/jwks", fetchImpl, refreshMs: 20, missCooldownMs: 10_000, ...quiet,
  });

  cache.start();
  await cache.whenIdle();
  assert.equal(calls.n, 1, "start 要立刻抓一次");

  await new Promise((r) => setTimeout(r, 70));
  const afterInterval = calls.n;
  assert.ok(afterInterval > 1, `定時刷新應該有再抓，實際 ${afterInterval}`);

  cache.stop();
  await new Promise((r) => setTimeout(r, 70));
  assert.equal(calls.n, afterInterval, "stop() 之後不該再抓");
});

test("refreshMs: 0 不排定時器（測試用的開關）", async () => {
  const k = makeKeyPair("kid-a");
  const { fetchImpl, calls } = stubFetch({ keys: [k.jwk] });
  const cache = createJwksCache({
    url: "https://idp.test/jwks", fetchImpl, refreshMs: 0, missCooldownMs: 10_000, ...quiet,
  });
  cache.start();
  await cache.whenIdle();
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(calls.n, 1);
  cache.stop();
});

test("getKey 在 inFlight 期間不會再開第二次抓取", async () => {
  const k = makeKeyPair("kid-a");
  const { fetchImpl, calls } = stubFetch({ keys: [k.jwk] });
  const cache = createJwksCache({
    url: "https://idp.test/jwks", fetchImpl, missCooldownMs: 0, ...quiet,
  });
  const p = cache.refresh();
  cache.getKey("whatever");
  cache.getKey("whatever2");
  await p;
  assert.equal(calls.n, 1);
});

test("stats() 回得出診斷資訊", async () => {
  const k = makeKeyPair("kid-a");
  const { fetchImpl } = stubFetch({ keys: [k.jwk] });
  const cache = createJwksCache({ url: "https://idp.test/jwks", fetchImpl, ...quiet });
  assert.deepEqual(
    { keys: cache.stats().keys, lastSuccessAt: cache.stats().lastSuccessAt },
    { keys: 0, lastSuccessAt: null },
  );
  await cache.refresh();
  const s = cache.stats();
  assert.equal(s.keys, 1);
  assert.equal(s.url, "https://idp.test/jwks");
  assert.ok(s.lastSuccessAt > 0);
  assert.equal(s.lastError, null);
});

test("getKey 對非字串 kid 回 null", async () => {
  const k = makeKeyPair("kid-a");
  const { fetchImpl } = stubFetch({ keys: [k.jwk] });
  const cache = createJwksCache({ url: "https://idp.test/jwks", fetchImpl, ...quiet });
  await cache.refresh();
  for (const bad of [null, undefined, "", 123, {}]) {
    assert.equal(cache.getKey(bad), null);
  }
});

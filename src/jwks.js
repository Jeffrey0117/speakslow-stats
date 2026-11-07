// LetMeUse JWKS 公鑰快取（ES256）。
//
// 為什麼不用 jose：`crypto.createPublicKey({ format: "jwk" })` 直接吃 JWK，
// `crypto.verify` 也直接驗 ES256，整件事用 node:crypto 就做完了——維持這個
// repo 的零依賴設計（少一份供應鏈風險，部署也快）。
//
// 為什麼要快取：驗證本身是同步的，抓 JWKS 是非同步的。所以背景抓好放進
// Map，驗證時同步讀——不讓每個 POST /api/stats 都去打一次 LetMeUse。
//
// 🔒 fail-closed：抓不到金鑰時 getKey 回 null，驗證就一律失敗。寧可拒絕真
// 使用者也不放行偽造的 token。但 fail-closed 必須「看得見」——所以有
// onError 與 stats()，讓 index.js 印 log、/api/health 曝露狀態。不然 JWKS
// 一掛就是「全部 401 但零診斷」，跟 infra-map 記的 Redis 事件同一個形狀。

const crypto = require("node:crypto");

const DEFAULT_REFRESH_MS = 60 * 60 * 1000; // 正常情況每小時刷新（JWKS 回的也是 max-age=3600）
const DEFAULT_MISS_COOLDOWN_MS = 60 * 1000; // kid 沒中（可能剛輪換）→ 最快 60 秒重抓
const DEFAULT_TIMEOUT_MS = 5000;
// 連續抓不到這麼久之後，寧可全部拒絕也不要拿「不知道多舊」的公鑰繼續放行。
// 給得寬鬆（一天）：短暫的 LetMeUse 停機不該讓所有人上傳失敗。
const DEFAULT_MAX_STALE_MS = 24 * 60 * 60 * 1000;
const WHEN_IDLE_MAX_HOPS = 10;

/**
 * 解析 JWKS 網址。
 *
 * 刻意不寫死任何主機：這個 repo 是公開的，自架服務的位址不該進公開原始碼。
 * 順序：明確傳入 → LETMEUSE_JWKS_URL → LETMEUSE_BASE_URL + /api/jwks → 空。
 * 空的話就抓不到金鑰 → 所有 token 驗證失敗（fail-closed），狀態會出現在
 * /api/health 的 jwks.lastError。
 */
function resolveJwksUrl(explicit) {
  if (explicit) return explicit;
  if (process.env.LETMEUSE_JWKS_URL) return process.env.LETMEUSE_JWKS_URL;
  const base = (process.env.LETMEUSE_BASE_URL || "").replace(/\/+$/, "");
  return base ? `${base}/api/jwks` : "";
}

/** JWK → KeyObject，只收得起 ES256 的那種；其餘回 null。 */
function toPublicKey(jwk) {
  if (!jwk || typeof jwk !== "object") return null;
  if (typeof jwk.kid !== "string" || !jwk.kid) return null;
  if (jwk.kty !== "EC" || jwk.crv !== "P-256") return null;
  if (jwk.alg && jwk.alg !== "ES256") return null;
  if (jwk.use && jwk.use !== "sig") return null; // 加密用的金鑰不拿來驗簽
  try {
    return crypto.createPublicKey({ key: jwk, format: "jwk" });
  } catch (e) {
    return null; // 壞 JWK 跳過，不要害整批抓不進來
  }
}

/**
 * 加上逾時。⚠️ 這不是多餘的保險：node 的 fetch 沒有預設逾時，對方「接了連線
 * 但永遠不回」時 promise 永不 settle → inFlight 永遠卡住 → 快取再也不會更新、
 * 每個上傳都 401 直到重啟。AbortSignal 負責真的中止網路，這層 race 則保證
 * 就算注入的 fetchImpl 不理 signal，inFlight 也一定會放掉。
 */
function withTimeout(promise, ms) {
  if (!(ms > 0)) return promise;
  return new Promise((resolve, reject) => {
    // 刻意不 unref：unref 的計時器在「沒有其他事情撐著 event loop」時不會觸發，
    // 卡死的 fetch 就永遠等不到逾時（測試裡直接現形）。這個計時器一旦 fetch
    // 回來就被 clear，只有真的逾時才會存在，最多延後 process 結束 timeoutMs。
    const timer = setTimeout(
      () => reject(new Error(`JWKS fetch timed out after ${ms}ms`)),
      ms,
    );
    promise.then(
      (value) => { clearTimeout(timer); resolve(value); },
      (err) => { clearTimeout(timer); reject(err); },
    );
  });
}

/**
 * @param {{
 *   url?: string,
 *   fetchImpl?: Function,
 *   refreshMs?: number,      // 0 = 不做定時刷新（測試用）
 *   missCooldownMs?: number, // kid 沒中時最快多久重抓一次
 *   timeoutMs?: number,      // 0 = 不加逾時（只在測試裡刻意關掉）
 *   onError?: (err: Error) => void,
 * }} options
 */
function createJwksCache(options = {}) {
  const url = resolveJwksUrl(options.url);
  const fetchImpl = options.fetchImpl || ((...args) => globalThis.fetch(...args));
  const refreshMs = options.refreshMs ?? DEFAULT_REFRESH_MS;
  const missCooldownMs = options.missCooldownMs ?? DEFAULT_MISS_COOLDOWN_MS;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxStaleMs = options.maxStaleMs ?? DEFAULT_MAX_STALE_MS;
  const onError = typeof options.onError === "function" ? options.onError : () => {};

  let keysByKid = new Map();
  let lastAttemptAt = 0;
  let lastSuccessAt = 0;
  let lastMissFetchAt = 0;
  let lastError = null;
  let inFlight = null;
  let timer = null;

  async function doRefresh() {
    try {
      if (!url) {
        throw new Error("沒有設定 JWKS 網址（需要 LETMEUSE_JWKS_URL 或 LETMEUSE_BASE_URL）");
      }
      const signal = timeoutMs > 0 && typeof AbortSignal?.timeout === "function"
        ? AbortSignal.timeout(timeoutMs)
        : undefined;
      const res = await withTimeout(fetchImpl(url, signal ? { signal } : undefined), timeoutMs);
      if (!res || !res.ok) {
        throw new Error(`JWKS HTTP ${res ? res.status : "no response"}`);
      }
      const data = await withTimeout(Promise.resolve(res.json()), timeoutMs);
      if (!Array.isArray(data?.keys)) {
        throw new Error("JWKS 回應格式不正確（keys 不是陣列）");
      }
      const next = new Map();
      for (const jwk of data.keys) {
        const key = toPublicKey(jwk);
        if (key) next.set(jwk.kid, key);
      }
      // 🔒 格式正確的 200 就是權威答案，**即使它是空的**，所以整批換掉。
      // 「空的不覆蓋」看似保守，實際會讓緊急撤銷永遠不生效：LetMeUse 私鑰若
      // 外洩、把它從 JWKS 下架，這邊卻還拿著舊公鑰繼續放行被盜金鑰簽的 token，
      // 直到有人想起來重啟 process（這個 process 會活好幾週）。
      // 真正該保留舊快取的只有「傳輸層失敗」——那些路徑在上面就 throw 了。
      keysByKid = next;
      lastSuccessAt = Date.now();
      lastError = null;
      if (next.size === 0) {
        lastError = new Error("JWKS 沒有任何可用的 ES256 公鑰——快取已清空，所有 token 會被拒絕");
        try { onError(lastError); } catch (ignored) { /* reporter 壞掉不該炸這裡 */ }
      }
    } catch (e) {
      // 網路/解析問題 → 保留舊快取，不拋出（呼叫端是背景任務，沒人 catch），
      // 但一定要讓外面看得到
      lastError = e;
      try { onError(e); } catch (ignored) { /* reporter 自己壞掉不該炸這裡 */ }
    }
  }

  /** 抓一次 JWKS。併發呼叫共用同一個 in-flight promise。 */
  function refresh() {
    if (inFlight) return inFlight;
    inFlight = doRefresh().finally(() => {
      inFlight = null;
      // 冷卻從「結束」算起：慢速或逾時的抓取若從開始算，等於完全沒冷卻
      lastAttemptAt = Date.now();
    });
    return inFlight;
  }

  /**
   * 同步取公鑰。kid 不在快取裡（可能剛輪換）就順手在背景重抓，但「這一次」
   * 仍然回 null —— 驗證必須是同步的，而且 fail-closed 比等網路安全。
   *
   * 未知 kid 的冷卻用獨立的 lastMissFetchAt（不跟定時刷新共用），否則剛跑完
   * 的定時刷新會把冷卻洗掉，金鑰輪換要等整個 cooldown 才跟得上。
   */
  function getKey(kid) {
    if (typeof kid !== "string" || !kid) return null;
    // 太久沒成功更新 → 當作沒有金鑰（仍然會往下觸發背景重抓）
    const stale = maxStaleMs > 0 && lastSuccessAt > 0
      && Date.now() - lastSuccessAt > maxStaleMs;
    const key = stale ? undefined : keysByKid.get(kid);
    if (!key && !inFlight && Date.now() - lastMissFetchAt >= missCooldownMs) {
      lastMissFetchAt = Date.now(); // 先卡住，擋掉一波未知 kid 同時湧進來
      refresh().finally(() => { lastMissFetchAt = Date.now(); });
    }
    return key || null;
  }

  /** 診斷用狀態：給 /api/health 與 log，別讓 fail-closed 變成無聲故障。 */
  function stats() {
    return {
      url,
      keys: keysByKid.size,
      lastSuccessAt: lastSuccessAt || null,
      lastAttemptAt: lastAttemptAt || null,
      lastError: lastError ? lastError.message : null,
    };
  }

  /** 等背景那次重抓結束（測試用）。有上限，免得未來改壞變成無聲掛住。 */
  async function whenIdle() {
    for (let i = 0; i < WHEN_IDLE_MAX_HOPS && inFlight; i += 1) {
      await inFlight;
    }
  }

  /** 啟動：先抓一次，之後定時刷新。unref 讓它不卡住 process 結束。 */
  function start() {
    refresh();
    if (refreshMs > 0 && !timer) {
      timer = setInterval(refresh, refreshMs);
      if (typeof timer.unref === "function") timer.unref();
    }
  }

  function stop() {
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
  }

  return { getKey, refresh, whenIdle, stats, start, stop, url };
}

module.exports = { createJwksCache };

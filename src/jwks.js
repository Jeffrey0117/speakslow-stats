// JWKS 公鑰快取。
//
// 2026-11-08：實作搬進 `jwks-verify-kit`，這裡只剩「網址怎麼來」這段本地決策。
// kit 已經包含這份原本自己寫的全部行為（逐項對照過）：
//   - `AbortSignal.timeout` **外加**一層 `Promise.race`（注入的 fetch 可能不理
//     signal），而且那個逾時計時器**不 unref**（unref 的計時器在沒別的事撐著
//     event loop 時不會觸發 → 等於沒逾時）
//   - 格式正確的 200 就是權威答案：**即使 keys 是空的也整批換掉**，否則緊急
//     撤銷金鑰永遠不生效；只有傳輸失敗才保留舊快取
//   - 未知 kid 觸發背景重抓，用**獨立**的冷卻計時（跟定時刷新共用會被洗掉），
//     且冷卻從「抓取結束」算起（從開始算的話慢速/逾時的抓取等於沒冷卻）
//   - 連續失敗超過 maxStaleMs 就算 stale，狀態從 stats() 露出來
//   - 只收 P-256 的 EC 公鑰、重複 kid 先到先贏、金鑰數上限
// kit 另外多了幾件這份沒有的：JWKS 走明文 http 直接 throw、JWK 帶私鑰材料
// （`d`）大聲拒絕、`redirect: "error"`。
//
// 刻意保留這個檔案而不是讓 server.js 直接接 kit：測試注入假快取的接縫
// （`createServer({ jwks })`）與「不把自架服務位址寫進公開 repo」這條都在這裡。

const { createJwksCache: createKitJwksCache } = require("jwks-verify-kit");

/**
 * 解析 JWKS 網址。
 *
 * 刻意不寫死任何主機：這個 repo 是公開的，自架服務的位址不該進公開原始碼。
 * 順序：明確傳入 → LETMEUSE_JWKS_URL → LETMEUSE_BASE_URL + /api/jwks → 空。
 */
function resolveJwksUrl(explicit) {
  if (explicit) return explicit;
  if (process.env.LETMEUSE_JWKS_URL) return process.env.LETMEUSE_JWKS_URL;
  const base = (process.env.LETMEUSE_BASE_URL || "").replace(/\/+$/, "");
  return base ? `${base}/api/jwks` : "";
}

/**
 * 建一個 JWKS 快取。回傳 `{ getKey, getKeyAsync, refresh, whenIdle, stats,
 * start, stop, url }`。
 *
 * ⚠️ 沒有網址就**直接 throw**，不再「靜默變成拒絕所有人」。
 * 理由是 areyoubot 的實案（見 infra-map）：那個服務半套設定跑了三個月，首頁
 * 和健檢一路 200、監控全綠，但沒有任何人登入得進來，而統計是 0 看起來像
 * 「還沒人用」。設定不全要在啟動時就壞，不要變成一個查不到的 401。
 */
function createJwksCache(options = {}) {
  const url = resolveJwksUrl(options.url);
  if (!url) {
    throw new Error(
      "speakslow-stats: 沒有設定 JWKS 網址（需要 LETMEUSE_JWKS_URL 或 "
      + "LETMEUSE_BASE_URL）。沒有網址的驗證器會永遠拒絕每一顆 token，而服務"
      + "照樣回 200、健檢全綠 —— 那種故障最難查，所以這裡選擇啟動就失敗。",
    );
  }
  return createKitJwksCache({
    url,
    algorithms: ["ES256"],
    fetchImpl: options.fetchImpl,
    refreshMs: options.refreshMs,
    missCooldownMs: options.missCooldownMs,
    timeoutMs: options.timeoutMs,
    maxStaleMs: options.maxStaleMs,
    onError: typeof options.onError === "function" ? options.onError : () => {},
  });
}

module.exports = { createJwksCache };

// 統計資料的純邏輯：驗證、合併、排名。
// 抽成純函式是為了能直接測，不必起伺服器或資料庫。

// 只接受這些欄位，而且全是「數字」——絕不收任何逐字稿內容。
// 這是隱私承諾的程式碼層保證：就算 app 端送了多餘欄位也會被丟掉。
const COUNTER_FIELDS = ["totalChars", "totalSessions", "totalSeconds", "activeDays"];

// 單次上傳的合理上限，擋住明顯灌水／送壞資料（例如 app 算錯送出天文數字）
const LIMITS = {
  totalChars: 500_000_000,
  totalSessions: 5_000_000,
  totalSeconds: 100_000_000,
  activeDays: 36_500, // 100 年
};

function toSafeInt(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.floor(n));
}

/**
 * 把上傳內容收斂成只含計數的乾淨物件。
 * @returns {{ok: true, stats: object} | {ok: false, error: string}}
 */
function sanitizeStats(body) {
  if (!body || typeof body !== "object") {
    return { ok: false, error: "payload must be an object" };
  }
  const stats = {};
  for (const field of COUNTER_FIELDS) {
    const n = toSafeInt(body[field]);
    if (n > LIMITS[field]) {
      return { ok: false, error: `${field} exceeds allowed maximum` };
    }
    stats[field] = n;
  }
  // 版本與平台只留短字串，方便看採用率；非字串就忽略
  stats.version = typeof body.version === "string" ? body.version.slice(0, 20) : null;
  stats.platform = typeof body.platform === "string" ? body.platform.slice(0, 20) : null;
  return { ok: true, stats };
}

/**
 * 合併既有紀錄與新上傳。
 *
 * 計數一律取「較大值」而不是相加——app 送的是累計總量，同一台重複上傳
 * 或多台裝置輪流上傳時相加會爆增。取大值讓重複上傳天然冪等。
 */
function mergeStats(existing, incoming) {
  const merged = {};
  for (const field of COUNTER_FIELDS) {
    merged[field] = Math.max(toSafeInt(existing?.[field]), toSafeInt(incoming?.[field]));
  }
  merged.version = incoming?.version ?? existing?.version ?? null;
  merged.platform = incoming?.platform ?? existing?.platform ?? null;
  return merged;
}

/** 排行榜排序欄位白名單：擋 SQL 注入，也避免排到無意義的欄位 */
const RANKABLE = new Set(["totalChars", "activeDays", "totalSessions"]);

function normalizeRankField(by) {
  return RANKABLE.has(by) ? by : "totalChars";
}

function normalizeLimit(limit, fallback = 50, max = 100) {
  const n = Number(limit);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return Math.min(Math.floor(n), max);
}

/**
 * 顯示名稱：沒給就用匿名，過長截斷，去掉換行避免破版。
 *
 * 🔒 一併拿掉 `<>&"'`：這個名字是使用者在 LetMeUse 自己設的，而它會出現在
 * 免登入的 /api/leaderboard JSON 裡。官網或任何取用這個 feed 的前端只要用
 * innerHTML 之類的方式渲染，`<svg onload=...>`（21 字，截斷擋不住）就是儲存型
 * XSS。渲染端本來也該轉義，這裡是第二道（公開 feed 不知道誰在用）。
 */
function displayName(name) {
  const s = typeof name === "string"
    ? name.replace(/[\r\n\t]/g, " ").replace(/[<>&"']/g, "").trim()
    : "";
  if (!s) return "匿名使用者";
  return s.slice(0, 24);
}

module.exports = {
  COUNTER_FIELDS,
  LIMITS,
  sanitizeStats,
  mergeStats,
  normalizeRankField,
  normalizeLimit,
  displayName,
};

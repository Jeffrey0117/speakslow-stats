// 聲聲慢統計服務：接收使用計數、提供排行榜與總量。
//
// 用 node:http 而非框架：只有四個端點，少一層相依、啟動更快、部署更單純。

const http = require("node:http");
const path = require("node:path");
const { verifyLetMeUseToken, extractBearerToken } = require("./auth");
const {
  sanitizeStats, mergeStats, normalizeRankField, normalizeLimit, displayName,
} = require("./stats");
const { createDb, getUser, upsertUser, leaderboard, summary } = require("./db");
const { handleDesktopLogin } = require("./desktopLogin");
const { createJwksCache } = require("./jwks");

const MAX_BODY = 8 * 1024; // 只收幾個數字，8KB 綽綽有餘；擋住灌爆 payload

function json(res, status, body) {
  const data = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(data),
    // 官網（GitHub Pages）要能直接讀排行榜與總量
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Cache-Control": "no-store",
  });
  res.end(data);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new Error("payload too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      try {
        const raw = Buffer.concat(chunks).toString("utf8");
        resolve(raw ? JSON.parse(raw) : {});
      } catch (e) {
        reject(new Error("invalid json"));
      }
    });
    req.on("error", reject);
  });
}

function createServer(options = {}) {
  const dbFile = options.dbFile || path.join(process.cwd(), "data", "stats.db");
  const db = options.db || createDb(dbFile);
  const appId = options.appId || process.env.LETMEUSE_APP_ID || "";
  // LetMeUse 的位址走環境變數，不寫死（公開 repo 不放自架服務位址）
  const lmuBaseUrl = (options.baseUrl || process.env.LETMEUSE_BASE_URL || "")
    .replace(/\/+$/, "");
  // 🔒 token 驗證只需要 LetMeUse 的公鑰（JWKS）——這台機器不持有 app secret。
  // 理由見 src/auth.js 開頭。
  //
  // 自己建的才自己收：注入 jwks 的呼叫端（測試、腳本）負責自己的生命週期，
  // 我們不去 stop 別人的。沒注入時這裡會起一個定時器＋發一次網路請求，所以
  // 測試一律注入假的，免得 npm test 去打 production LetMeUse。
  const ownsJwks = !options.jwks;
  const jwks = options.jwks || createJwksCache({
    onError: (e) => console.warn(`[speakslow-stats] JWKS 抓取失敗：${e.message}`),
  });
  if (ownsJwks) jwks.start();
  const getKey = (kid) => jwks.getKey(kid);

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");
    const route = `${req.method} ${url.pathname}`;

    if (req.method === "OPTIONS") return json(res, 204, {});

    try {
      // 桌面版登入中繼頁（Electron 用系統瀏覽器開這裡拿 token）
      if (route === "GET /desktop-login") {
        return handleDesktopLogin(url, res, { appId, baseUrl: lmuBaseUrl });
      }

      if (route === "GET /api/health") {
        // 刻意「一律回 200」：JWKS 抓不到時重啟這個服務救不了（問題在上游），
        // 而 CloudPipe 的 watchdog 探的就是這支 → 回 5xx 只會換來無用的重啟
        // 迴圈。但狀態一定要露出來，否則就是「全部 401 卻一片綠燈」。
        const s = typeof jwks.stats === "function" ? jwks.stats() : null;
        return json(res, 200, { ok: true, ...(s ? { jwks: s } : {}) });
      }

      // 官網首頁的社會證明：使用者數與累計字數
      if (route === "GET /api/summary") {
        return json(res, 200, summary(db));
      }

      // 排行榜：總字數 / 使用天數 / 次數
      if (route === "GET /api/leaderboard") {
        const field = normalizeRankField(url.searchParams.get("by"));
        const limit = normalizeLimit(url.searchParams.get("limit"));
        const rows = leaderboard(db, field, limit).map((r, i) => ({
          rank: i + 1,
          name: r.displayName || "匿名使用者",
          totalChars: r.totalChars,
          totalSessions: r.totalSessions,
          totalSeconds: r.totalSeconds,
          activeDays: r.activeDays,
        }));
        return json(res, 200, { by: field, entries: rows });
      }

      // 上傳統計（需登入）
      if (route === "POST /api/stats") {
        const token = extractBearerToken(req.headers.authorization);
        const payload = verifyLetMeUseToken(token, { getKey, appId });
        if (!payload) return json(res, 401, { error: "unauthorized" });

        let body;
        try {
          body = await readBody(req);
        } catch (e) {
          return json(res, 400, { error: e.message });
        }

        const clean = sanitizeStats(body);
        if (!clean.ok) return json(res, 400, { error: clean.error });

        const existing = getUser(db, payload.sub);
        // 取大值合併：app 送的是累計總量，重複上傳或多台裝置輪流送都不會灌爆
        const merged = mergeStats(existing, clean.stats);
        const saved = upsertUser(db, {
          userId: payload.sub,
          // 🔒 絕對不要 fallback 到 email：/api/leaderboard 免登入又開 CORS *，
          // 沒設暱稱的人（OAuth 註冊、清空名字的人）email 會被公開在排行榜上
          // 任人爬。displayName() 對空值本來就回「匿名使用者」。
          displayName: displayName(payload.name),
          stats: merged,
          leaderboardOptIn: body.leaderboardOptIn !== false,
        });

        return json(res, 200, {
          ok: true,
          stats: {
            totalChars: saved.totalChars,
            totalSessions: saved.totalSessions,
            totalSeconds: saved.totalSeconds,
            activeDays: saved.activeDays,
          },
        });
      }

      return json(res, 404, { error: "not found" });
    } catch (e) {
      return json(res, 500, { error: "internal error" });
    }
  });

  server.on("close", () => {
    if (ownsJwks) jwks.stop();
    try { db.close(); } catch (e) { /* ignore */ }
  });
  return server;
}

module.exports = { createServer };

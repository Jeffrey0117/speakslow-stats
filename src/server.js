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
  const secret = options.secret || process.env.LETMEUSE_APP_SECRET || "";
  const appId = options.appId || process.env.LETMEUSE_APP_ID || "";

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");
    const route = `${req.method} ${url.pathname}`;

    if (req.method === "OPTIONS") return json(res, 204, {});

    try {
      // 桌面版登入中繼頁（Electron 用系統瀏覽器開這裡拿 token）
      if (route === "GET /desktop-login") {
        return handleDesktopLogin(url, res, { appId });
      }

      if (route === "GET /api/health") {
        return json(res, 200, { ok: true });
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
        if (!secret) return json(res, 503, { error: "server not configured" });

        const token = extractBearerToken(req.headers.authorization);
        const payload = verifyLetMeUseToken(token, { secret, appId });
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
          displayName: displayName(payload.name || payload.email),
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

  server.on("close", () => { try { db.close(); } catch (e) { /* ignore */ } });
  return server;
}

module.exports = { createServer };

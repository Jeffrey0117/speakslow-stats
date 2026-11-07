// SQLite 儲存。選 SQLite 是因為 CloudPipe 部署會保留 data/ 目錄，
// 不必額外開資料庫服務，而且這份資料量很小（每個使用者一列）。

const Database = require("better-sqlite3");
const fs = require("node:fs");
const path = require("node:path");

function createDb(file) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const db = new Database(file);
  db.pragma("journal_mode = WAL");

  // 每個使用者一列，存的全是計數——沒有任何逐字稿內容。
  // leaderboardOptIn 預設 1：使用者得先在 app 明確開啟統計才會有資料送來，
  // 送來就代表他同意顯示；之後若要「只算總量、不上榜」再由 app 送 0。
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      userId        TEXT PRIMARY KEY,
      displayName   TEXT NOT NULL DEFAULT '',
      totalChars    INTEGER NOT NULL DEFAULT 0,
      totalSessions INTEGER NOT NULL DEFAULT 0,
      totalSeconds  INTEGER NOT NULL DEFAULT 0,
      activeDays    INTEGER NOT NULL DEFAULT 0,
      version       TEXT,
      platform      TEXT,
      leaderboardOptIn INTEGER NOT NULL DEFAULT 1,
      firstSeenAt   TEXT NOT NULL,
      updatedAt     TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_users_chars ON users(totalChars DESC);
    CREATE INDEX IF NOT EXISTS idx_users_days  ON users(activeDays DESC);
  `);

  return db;
}

function getUser(db, userId) {
  return db.prepare("SELECT * FROM users WHERE userId = ?").get(userId) || null;
}

function upsertUser(db, { userId, displayName, stats, leaderboardOptIn }) {
  const now = new Date().toISOString();
  const existing = getUser(db, userId);
  if (existing) {
    db.prepare(`
      UPDATE users SET displayName=@displayName, totalChars=@totalChars,
        totalSessions=@totalSessions, totalSeconds=@totalSeconds, activeDays=@activeDays,
        version=@version, platform=@platform, leaderboardOptIn=@leaderboardOptIn, updatedAt=@updatedAt
      WHERE userId=@userId
    `).run({ userId, displayName, ...stats, leaderboardOptIn: leaderboardOptIn ? 1 : 0, updatedAt: now });
  } else {
    db.prepare(`
      INSERT INTO users (userId, displayName, totalChars, totalSessions, totalSeconds,
        activeDays, version, platform, leaderboardOptIn, firstSeenAt, updatedAt)
      VALUES (@userId, @displayName, @totalChars, @totalSessions, @totalSeconds,
        @activeDays, @version, @platform, @leaderboardOptIn, @firstSeenAt, @updatedAt)
    `).run({ userId, displayName, ...stats, leaderboardOptIn: leaderboardOptIn ? 1 : 0, firstSeenAt: now, updatedAt: now });
  }
  return getUser(db, userId);
}

function leaderboard(db, field, limit) {
  // field 已由 normalizeRankField 以白名單收斂過，可安全內嵌
  return db.prepare(`
    SELECT userId, displayName, totalChars, totalSessions, totalSeconds, activeDays
    FROM users WHERE leaderboardOptIn = 1 AND ${field} > 0
    ORDER BY ${field} DESC, updatedAt ASC LIMIT ?
  `).all(limit);
}

function summary(db) {
  const r = db.prepare(`
    SELECT COUNT(*) AS users,
           COALESCE(SUM(totalChars), 0)    AS totalChars,
           COALESCE(SUM(totalSessions), 0) AS totalSessions,
           COALESCE(SUM(totalSeconds), 0)  AS totalSeconds
    FROM users
  `).get();
  return {
    users: Number(r.users) || 0,
    totalChars: Number(r.totalChars) || 0,
    totalSessions: Number(r.totalSessions) || 0,
    totalSeconds: Number(r.totalSeconds) || 0,
  };
}

module.exports = { createDb, getUser, upsertUser, leaderboard, summary };

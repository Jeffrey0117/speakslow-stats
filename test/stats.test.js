const assert = require("node:assert/strict");
const test = require("node:test");
const {
  sanitizeStats, mergeStats, normalizeRankField, normalizeLimit, displayName,
} = require("../src/stats");

test("🔒 只保留計數欄位——逐字稿內容絕不入庫", () => {
  const r = sanitizeStats({
    totalChars: 100,
    text: "我剛剛講的秘密內容",
    transcript: "更多內容",
    rawAudio: "...",
  });
  assert.ok(r.ok);
  assert.equal(r.stats.totalChars, 100);
  assert.equal(r.stats.text, undefined);
  assert.equal(r.stats.transcript, undefined);
  assert.equal(r.stats.rawAudio, undefined);
  assert.deepEqual(
    Object.keys(r.stats).sort(),
    ["activeDays", "platform", "totalChars", "totalSeconds", "totalSessions", "version"]
  );
});

test("負數與非數字一律歸零", () => {
  const r = sanitizeStats({ totalChars: -5, totalSessions: "abc", totalSeconds: null, activeDays: NaN });
  assert.ok(r.ok);
  assert.equal(r.stats.totalChars, 0);
  assert.equal(r.stats.totalSessions, 0);
  assert.equal(r.stats.totalSeconds, 0);
  assert.equal(r.stats.activeDays, 0);
});

test("明顯灌水的數字退回", () => {
  assert.equal(sanitizeStats({ totalChars: 1e12 }).ok, false);
  assert.equal(sanitizeStats({ activeDays: 99999999 }).ok, false);
});

test("合併取大值——重複上傳不會灌爆", () => {
  const existing = { totalChars: 1000, totalSessions: 50, totalSeconds: 600, activeDays: 10 };
  const same = mergeStats(existing, existing);
  assert.equal(same.totalChars, 1000, "重複送同一份不該變兩倍");

  const grown = mergeStats(existing, { totalChars: 1500, totalSessions: 60, totalSeconds: 900, activeDays: 12 });
  assert.equal(grown.totalChars, 1500);
  assert.equal(grown.activeDays, 12);
});

test("舊裝置送落後的數字不會把紀錄往回拉", () => {
  const existing = { totalChars: 5000, totalSessions: 200, totalSeconds: 3000, activeDays: 30 };
  const merged = mergeStats(existing, { totalChars: 100, totalSessions: 2, totalSeconds: 50, activeDays: 1 });
  assert.equal(merged.totalChars, 5000);
  assert.equal(merged.activeDays, 30);
});

test("排序欄位白名單——擋 SQL 注入", () => {
  assert.equal(normalizeRankField("totalChars"), "totalChars");
  assert.equal(normalizeRankField("activeDays"), "activeDays");
  assert.equal(normalizeRankField("totalChars; DROP TABLE users"), "totalChars");
  assert.equal(normalizeRankField(undefined), "totalChars");
});

test("limit 有上限，擋住一次撈爆整張表", () => {
  assert.equal(normalizeLimit(10), 10);
  assert.equal(normalizeLimit(99999), 100);
  assert.equal(normalizeLimit(-1), 50);
  assert.equal(normalizeLimit("abc"), 50);
});

test("顯示名稱：截斷、去換行、空值給匿名", () => {
  assert.equal(displayName(""), "匿名使用者");
  assert.equal(displayName(null), "匿名使用者");
  assert.equal(displayName("小明"), "小明");
  assert.equal(displayName("壞\n人\t名"), "壞 人 名");
  assert.equal(displayName("x".repeat(100)).length, 24);
});

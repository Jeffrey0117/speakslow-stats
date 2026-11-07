// 進入點：載入 .env.production（pm2 不會自動注入），啟動伺服器。
const fs = require("node:fs");
const path = require("node:path");

// 極簡 env 載入器：CloudPipe 把環境變數寫進 .env.production，但 pm2 不會注入，
// 所以 app 必須自己讀（這是 CloudPipe 部署的已知地雷）。
for (const name of [".env.production", ".env"]) {
  const file = path.join(__dirname, name);
  if (!fs.existsSync(file)) continue;
  for (const line of fs.readFileSync(file, "utf8").split("\n")) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/i);
    if (!m) continue;
    const key = m[1];
    let val = m[2].trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    if (process.env[key] === undefined) process.env[key] = val;
  }
}

const { createServer } = require("./src/server");

const port = Number(process.env.PORT) || 3210;
createServer().listen(port, () => {
  console.log(`[speakslow-stats] listening on ${port}`);
  if (!process.env.LETMEUSE_APP_SECRET) {
    console.warn("[speakslow-stats] LETMEUSE_APP_SECRET 未設定——上傳端點會回 503");
  }
});

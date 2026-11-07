# speakslow-stats

聲聲慢的使用統計與排行榜 API。

## 只收數字，不收內容

這個服務**只接收計數**——總字數、次數、總秒數、使用天數。**任何逐字稿內容都不會、也無法進到這裡**：`sanitizeStats()` 以白名單過濾欄位，app 就算多送了什麼也會被丟掉（見 `test/stats.test.js` 的第一個測試）。

聲聲慢的核心承諾是「辨識 100% 在本機、聲音不上雲」。這個服務不違反那個承諾：它拿到的只有數字，連你講了幾個字都是你自己的 app 算好才送來的。而且統計功能在 app 端**預設關閉**，要使用者明確開啟才會上傳。

## 端點

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/api/health` | 健康檢查 |
| GET | `/api/summary` | 使用者數與累計總量（官網首頁用） |
| GET | `/api/leaderboard?by=totalChars\|activeDays\|totalSessions&limit=50` | 排行榜 |
| POST | `/api/stats` | 上傳統計（需 LetMeUse Bearer token） |

`POST /api/stats` 的 body：

```json
{
  "totalChars": 12345,
  "totalSessions": 300,
  "totalSeconds": 7200,
  "activeDays": 42,
  "version": "1.0.30",
  "platform": "win32",
  "leaderboardOptIn": true
}
```

計數一律**取大值合併**而非累加——app 送的是累計總量，重複上傳或多台裝置輪流送都不會把數字灌爆。`leaderboardOptIn: false` 的人不出現在排行榜，但仍計入總量。

## 安全

- **一定驗簽章**：LetMeUse token 用 HS256 + app secret 驗證。只 decode 不驗簽的話，任何人自編一段 base64 payload 就能冒充別人灌爆排行榜。`alg: none`、過期、別的 app 的 token 都擋掉（見 `test/auth.test.js`）。
- 排序欄位走白名單，擋 SQL 注入。
- body 上限 8KB、`limit` 上限 100。

## 開發

```bash
npm install
npm test        # 25 個測試，含真的起伺服器打 API 的端到端測試
npm start       # 預設 port 3210
```

## 部署（CloudPipe）

1. 把 repo 設為 **public**（private 會讓部署機 `git fetch` 卡在認證）。
2. 註冊專案：`{ id: "speakslow-stats", deployMethod: "github", repoUrl, branch: "main", port, entryFile: "index.js" }`
3. 設環境變數（`set_project_env` → `.env.production`）：

```
LETMEUSE_APP_ID=app_xxx
LETMEUSE_APP_SECRET=<LetMeUse app secret，server-only，絕不外流>
PORT=3210
```

4. 部署。`index.js` 自己會讀 `.env.production`（pm2 不會注入環境變數，這是已知地雷）。

資料存在 `data/stats.db`（SQLite），CloudPipe 部署會保留未追蹤檔案，所以資料不會因部署消失。

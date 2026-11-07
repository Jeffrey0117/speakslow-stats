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

- **一定驗簽章，而且只收 ES256**：LetMeUse token 用 JWKS 公鑰驗（`/api/jwks`）。只 decode 不驗簽的話，任何人自編一段 base64 payload 就能冒充別人灌爆排行榜。`alg: none`、HS256、過期、別的 app、未知 `kid`、DER 格式簽章都擋掉（見 `test/auth.test.js`）。
- **這台伺服器不持有任何簽章金鑰**：驗證只需要公鑰，所以不需要、也不應該設 `LETMEUSE_APP_SECRET`。HS256 的要命之處是「驗證方必須握著簽發金鑰」——secret 一外洩，任何人都能自簽一顆 `sub` 隨便填的 token 冒充任何使用者（pokkit 2026-10-25 就是這樣被當成免費圖床）。LetMeUse 自 2026-10-30 起 access token 全面 ES256，HS256 過渡路徑已廢除，這裡跟著只收 ES256：**就算 secret 已經洩了，偽造的 token 一樣進不來**。
- **一定比對 `app`**：LetMeUse 所有 app 的 token 都用**同一把** ES256 金鑰簽，所以「簽章有效」不代表「這顆 token 是給這個 app 的」。沒設 `LETMEUSE_APP_ID`、或 token 的 `app` 不符、或根本沒帶 `app`，一律拒絕——不然任何 LetMeUse app 的使用者都能寫進這裡的排行榜。
- **公鑰快取會 fail-closed，而且看得見**（`src/jwks.js`）：抓不到金鑰就拒絕所有上傳；抓取逾時 5 秒（node 的 fetch 沒有預設逾時，卡住會讓快取永久鎖死）；傳輸失敗保留舊公鑰，但**格式正確的空 JWKS 會清空快取**，這樣緊急撤銷金鑰才真的生效；連續失敗超過 24 小時就當作沒有金鑰。狀態從 `GET /api/health` 的 `jwks` 欄位看（刻意一律回 200——JWKS 掛掉時重啟這個服務救不了，回 5xx 只會換來無用的重啟迴圈）。
- **排行榜只出現暱稱，不會出現 email**。沒設暱稱就是「匿名使用者」；暱稱裡的 `<>&"'` 會被清掉（這個 feed 免登入又開 CORS `*`，不知道誰在渲染）。
- **桌面登入頁的參數都經過轉義與字集檢查**：`state` 限 `[A-Za-z0-9_.-]{1,128}`，`redirect_uri` 必須是本機 `/callback` 且不得自帶 query/hash，嵌進 `<script>` 時 `<`、`>`、`&`、U+2028/9 一律轉成 `\uXXXX`。⚠️ 這頁的 localStorage 有 LetMeUse 的 access + refresh token，一個 `</script>` 跳脫就能把真 token 偷走——那會直接繞過上面整套簽章驗證。
- 排序欄位走白名單，擋 SQL 注入。
- body 上限 8KB、`limit` 上限 100。

## 開發

```bash
npm install
npm test        # 含真的起伺服器打 API 的端到端測試；不連外網（JWKS 一律注入假的）
npm start       # 預設 port 3210
```

## 部署（CloudPipe）

1. 把 repo 設為 **public**（private 會讓部署機 `git fetch` 卡在認證）。
2. 註冊專案：`{ id: "speakslow-stats", deployMethod: "github", repoUrl, branch: "main", port, entryFile: "index.js" }`
3. 設環境變數（`set_project_env` → `.env.production`）：

```
LETMEUSE_APP_ID=app_xxx
LETMEUSE_BASE_URL=https://<你的 letmeuse 位址>
PORT=3210
# 選填，不設就是 LETMEUSE_BASE_URL + /api/jwks
# LETMEUSE_JWKS_URL=http://localhost:4006/api/jwks
```

LetMeUse 的位址**刻意不寫死在原始碼裡**（這個 repo 是公開的）。`LETMEUSE_BASE_URL` 沒設的話：桌面登入頁回 503、JWKS 抓不到 → 上傳一律 401（fail-closed），原因會出現在 `GET /api/health` 的 `jwks.lastError`。

**不要設 `LETMEUSE_APP_SECRET`。** 驗證走 JWKS 公鑰，這台不需要 secret；放上去只是多一個外洩點（理由見上面「安全」那段）。

4. 部署。`index.js` 自己會讀 `.env.production`（pm2 不會注入環境變數，這是已知地雷）。

資料存在 `data/stats.db`（SQLite），CloudPipe 部署會保留未追蹤檔案，所以資料不會因部署消失。

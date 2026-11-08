// LetMeUse JWT 驗證（ES256，公鑰走 JWKS）。
//
// 2026-11-08：實作搬進 `jwks-verify-kit`，這個檔案只剩接線。那一百多行的驗章
// 邏輯原本在生態系裡有十份各自獨立的拷貝（pokkit / quickky / wemeet / upimg /
// pdfluv / takeenglish / plottr / areyoubot / selfize 加這裡），每份都踩到不同
// 的一半坑。現在是一份、81 個測試、二十個 fail-open 用「還原修復確認變紅」
// 驗證過；改一次全部升級。
//
// 🔒 為什麼只收 ES256、不收 HS256：
// HS256 用 app secret 當簽章金鑰，等於「驗證方必須握著簽發金鑰」——secret
// 一外洩，任何人都能自簽一顆 `sub` 隨便填的 token 冒充任何使用者。pokkit
// 2026-10-25 就是這樣被當成免費圖床（見 infra-map）。只收 ES256 的話驗證只需
// 公鑰 → 這台機器不必、也不該存 LETMEUSE_APP_SECRET（實際上也沒存）。
//
// ⚠️ 簽發端的現況要分清楚（letmeuse/src/lib/auth/jwt.ts）：
//   - `verifyAccessToken` 已經只收 ES256，HS256 路徑真的刪了
//   - 但 `signAccessToken` 是「`LETMEUSE_SIGN_ALG=ES256` 且金鑰載得起來才簽
//     ES256，否則退回 HS256」。萬一哪次 letmeuse 重新部署把 env 弄掉，它會
//     無聲退回 HS256 → 這裡就會「全部 401 且零線索」。所以 JWKS 的狀態一定
//     要能從 /api/health 看到（見 src/jwks.js 與 server.js）。

const { verifyJwt, bearerToken } = require("jwks-verify-kit");

/**
 * 驗證 LetMeUse token，通過回傳 payload，否則回傳 null（從不丟例外）。
 *
 * kit 負責的部分（每一條都是實際踩過的坑，細節見 jwks-verify-kit 的 README）：
 *   - alg 白名單（擋 alg:none / HS256 / 演算法混淆）、kid 必填
 *   - 簽章必須是 raw r||s 64 bytes = 86 字元 base64url（順手擋 DER）
 *   - 簽章段的正規化比對（同一顆 token 本來有 16 種等價寫法）
 *   - 金鑰曲線要跟 alg 相符
 *   - **先驗簽才解析 payload**
 *   - `exp` 必須存在且是數字（沒 exp 或字串 exp = 永不過期，而 4h 的 exp 是
 *     這套設計唯一的撤銷機制）、`nbf` 檢查
 *   - claims 不走原型鏈（prototype pollution + 無 exp token = 永久通行證）
 *   - `sub` 必須是非空字串（會直接當 DB 的 userId）
 *
 * `appId` 必填且由 kit 強制：LetMeUse 所有 app 的 token 都用**同一把** ES256
 * 金鑰簽，所以 `app` claim 是唯一的租戶邊界。appId 沒給的話 kit 的
 * requiredClaims 會直接回 null（fail-closed），不是「少一道檢查」。
 *
 * @param {string} token
 * @param {{
 *   getKey: (kid: string) => import("node:crypto").KeyObject | null,
 *   appId: string,
 *   now?: number,
 * }} opts getKey 通常來自 src/jwks.js 的快取。
 */
function verifyLetMeUseToken(token, opts) {
  return verifyJwt(token, {
    getKey: opts && opts.getKey,
    algorithms: ["ES256"],
    requiredClaims: { app: opts && opts.appId },
    now: opts && opts.now,
  });
}

/** 從 Authorization header 取 Bearer token（scheme 依 RFC 6750 不分大小寫）。 */
const extractBearerToken = bearerToken;

module.exports = { verifyLetMeUseToken, extractBearerToken };

// 桌面版登入的中繼頁。
//
// LetMeUse 的 SDK 只能在瀏覽器跑，Electron 不方便直接嵌，所以桌面 app 會用系統
// 瀏覽器開這一頁：使用者在這裡用 LetMeUse 登入 → 這頁把 token 帶回 app 本機
// 監聽的 127.0.0.1 回跳網址。
//
// 🔒 安全關鍵：redirect_uri **只准回跳本機**。不檢查的話這頁就是一個開放重導，
// 任何人做個連結就能把別人的登入 token 送到自己的伺服器。

function isLoopbackRedirect(value) {
  let u;
  try {
    u = new URL(value);
  } catch (e) {
    return false;
  }
  if (u.protocol !== "http:") return false; // 本機回跳不會有憑證，只允許 http
  if (!["127.0.0.1", "localhost", "[::1]"].includes(u.hostname)) return false;
  if (u.pathname !== "/callback") return false;
  // 🔒 不准自帶 query / hash：① handOff 會自己接 `?token=...`，原本就有 query
  // 的話會拼成 `?a=b?token=...` 這種壞網址 ② query/hash 是塞 `</script>` 的
  // 另一條路（見下面 jsonForScript 的說明）
  if (u.search !== "" || u.hash !== "") return false;
  return true;
}

// state 只允許網址安全字元。桌面 app 拿它防 CSRF，不需要任何標記語言字元；
// 收窄字集是擋 HTML/JS 注入最可靠的一層（不依賴後面的轉義寫對）。
const SAFE_STATE = /^[A-Za-z0-9_.-]{1,128}$/;

/**
 * 把值安全地嵌進 `<script>`。
 *
 * 🔒 為什麼不能直接用 JSON.stringify：它**不會轉義 `</script>`**。HTML 解析器
 * 看到 `</script>` 就關閉 script 元素，不管它在 JS 字串裡——所以
 * `state=</script><script>...` 可以在這一頁執行任意程式碼。而這一頁載入了
 * LetMeUse SDK，這個 origin 的 localStorage 存著 access token 與 **30 天的
 * refresh token**，被讀走等於帳號被接管（偷真 token 比偽造 token 容易太多，
 * 會直接繞過整套 ES256 驗證）。
 * U+2028/U+2029 是合法的 JS 行終止符，JSON.stringify 也不轉，一併處理。
 */
function jsonForScript(value) {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/[\u2028\u2029]/g, (c) => (c === "\u2028" ? "\\u2028" : "\\u2029"));
}

function escapeAttr(s) {
  return String(s).replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

function errorPage(message) {
  return `<!doctype html><meta charset="utf-8"><title>聲聲慢登入</title>
<body style="font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#0f172a;color:#fff">
<div style="text-align:center;max-width:420px;padding:24px">
<div style="font-size:48px">⚠️</div><p style="font-size:17px;line-height:1.6">${escapeAttr(message)}</p>
<p style="color:#94a3b8;font-size:14px">請回到聲聲慢重新點一次登入。</p></div>`;
}

function loginPage({ appId, baseUrl, redirectUri, state }) {
  return `<!doctype html><html lang="zh-TW"><head><meta charset="utf-8">
<title>登入聲聲慢</title>
<script src="${escapeAttr(baseUrl)}/letmeuse.js"
  data-app-id="${escapeAttr(appId)}" data-theme="dark" data-accent="#059669"
  data-locale="zh" data-mode="modal"></script>
</head>
<body style="font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#0f172a;color:#fff">
<div style="text-align:center;max-width:420px;padding:24px">
  <div style="font-size:44px">🎙️</div>
  <h1 style="font-size:20px;margin:12px 0 6px">登入聲聲慢</h1>
  <p id="msg" style="color:#94a3b8;font-size:14px;line-height:1.6">正在開啟登入視窗…</p>
  <button id="retry" style="display:none;margin-top:14px;padding:10px 20px;border:0;border-radius:10px;background:#059669;color:#fff;font-size:15px;cursor:pointer">重新登入</button>
</div>
<script>
(function () {
  var REDIRECT = ${jsonForScript(redirectUri)};
  var STATE = ${jsonForScript(state)};
  var msg = document.getElementById('msg');
  var retry = document.getElementById('retry');

  function handOff(user) {
    var token = window.letmeuse && window.letmeuse.getToken && window.letmeuse.getToken();
    if (!token) { fail('沒有取得登入憑證'); return; }
    msg.textContent = '登入成功，正在回到聲聲慢…';
    var url = REDIRECT + '?token=' + encodeURIComponent(token)
      + '&state=' + encodeURIComponent(STATE)
      + '&name=' + encodeURIComponent((user && user.name) || '')
      + '&email=' + encodeURIComponent((user && user.email) || '');
    location.replace(url);
  }

  function fail(text) {
    msg.textContent = text;
    retry.style.display = 'inline-block';
  }

  retry.onclick = function () {
    retry.style.display = 'none';
    msg.textContent = '正在開啟登入視窗…';
    if (window.letmeuse) window.letmeuse.login();
  };

  // SDK 的 ready / user 是屬性不是方法；載入有延遲，輪詢等它就緒
  var tries = 0;
  (function wait() {
    var sdk = window.letmeuse;
    if (!sdk || !sdk.ready) {
      if (++tries > 50) { fail('登入服務載入失敗，請檢查網路後重試'); return; }
      return setTimeout(wait, 100);
    }
    if (sdk.user) return handOff(sdk.user);
    sdk.onAuthChange(function (u) { if (u) handOff(u); });
    sdk.login();
  })();
})();
</script>`;
}

/**
 * 處理 GET /desktop-login。回傳 true 代表已處理。
 */
function handleDesktopLogin(url, res, { appId, baseUrl }) {
  const send = (status, html) => {
    const body = Buffer.from(html, "utf8");
    res.writeHead(status, {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Length": body.length,
      "Cache-Control": "no-store",
    });
    res.end(body);
  };

  // appId 與 LetMeUse 的位址都必須有設定才做得出可用的登入頁。
  // 位址不寫死在原始碼裡（這個 repo 是公開的），所以缺了就回 503。
  if (!appId || !baseUrl) return send(503, errorPage("登入服務尚未設定完成"));

  const redirectUri = url.searchParams.get("redirect_uri") || "";
  const state = url.searchParams.get("state") || "";
  if (!isLoopbackRedirect(redirectUri)) {
    // 不是本機回跳就直接拒絕——這是防開放重導的那道門
    return send(400, errorPage("回跳網址不合法，登入已中止"));
  }
  if (!state) return send(400, errorPage("缺少驗證參數，登入已中止"));
  if (!SAFE_STATE.test(state)) return send(400, errorPage("驗證參數格式不合法，登入已中止"));

  return send(200, loginPage({ appId, baseUrl, redirectUri, state }));
}

module.exports = { handleDesktopLogin, isLoopbackRedirect };

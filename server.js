
import express from "express";
import fetch from "node-fetch";
import fs from "fs";
import cookieParser from "cookie-parser";

const app = express();
app.disable("x-powered-by");

const PORT = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// PostgreSQL 接続
import pkg from "pg";
const { Pool } = pkg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// --------------------------------------
// 共通CSS（YouTube風サイドバー対応）
// --------------------------------------
const CSS = `
<style>
  body {
    font-family: "Segoe UI", sans-serif;
    background: #f0f6ff;
    margin: 0;
    padding: 0;
    color: #333;
  }

  h2 {
    margin-bottom: 20px;
    color: #2c3e50;
    text-align: center;
  }

  /* サイドバー（閉じた状態） */
  .sidebar {
    position: fixed;
    top: 0;
    left: 0;
    width: 50px;
    height: 100%;
    background: white;
    border-right: 1px solid #ddd;
    padding-top: 60px;
    transition: width 0.25s ease;
    overflow: hidden;
    z-index: 1000;
  }

  /* 開いた状態 */
  .sidebar.open {
    width: 220px;
  }

  .sidebar a {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 18px;
    font-size: 17px;
    color: #333;
    text-decoration: none;
    white-space: nowrap;
  }

  .sidebar a:hover {
    background: #eaf4ff;
  }

  .sidebar-icon {
    font-size: 20px;
  }

  /* メインコンテンツ */
  .main-content {
    margin-left: 80px;
    padding: 20px;
    transition: margin-left 0.25s ease;
  }

  .main-content.shift {
    margin-left: 240px;
  }

  /* カードレイアウト */
  .card-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 20px;
    padding: 20px;
  }

  .card {
    background: white;
    padding: 15px;
    border-radius: 12px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    transition: transform 0.25s ease, box-shadow 0.25s ease;
  }

  .card:hover {
    transform: translateY(-4px);
    box-shadow: 0 6px 16px rgba(0,0,0,0.15);
  }

  .thumb {
    width: 100%;
    border-radius: 10px;
  }

  .center-box {
    max-width: 380px;
    margin: 80px auto;
    background: white;
    padding: 30px;
    border-radius: 12px;
    box-shadow: 0 4px 16px rgba(0,0,0,0.15);
  }

  input, button {
    width: 100%;
    padding: 12px 14px;
    font-size: 16px;
    border-radius: 8px;
    border: 1px solid #ccc;
    margin-bottom: 15px;
  }

  button {
    background: #3498db;
    color: white;
    border: none;
    cursor: pointer;
    font-weight: bold;
  }

  button:hover {
    background: #2d89c6;
  }

  /* ★ 地域選択 UI 統一デザイン ★ */
  .region-select {
    width: 100%;
    padding: 12px 14px;
    font-size: 16px;
    border-radius: 8px;
    border: 1px solid #ccc;
    margin-bottom: 15px;
    background: white;
    cursor: pointer;
  }
  .region-select:hover {
    border-color: #3498db;
  }

</style>
`;


// --------------------------------------
// サイドバー HTML（全ページ共通）
// --------------------------------------
const SIDEBAR_HTML = `
<div id="sidebar" class="sidebar">
  <a href="/"><span class="sidebar-icon">🏠</span> <span class="sidebar-text">ホーム</span></a>
  <a href="/channel-search"><span class="sidebar-icon">📺</span> <span class="sidebar-text">チャンネル検索</span></a>
  <a href="/history"><span class="sidebar-icon">🕘</span> <span class="sidebar-text">履歴</span></a>
  <a href="/admin"><span class="sidebar-icon">⚙️</span> <span class="sidebar-text">管理者ページ</span></a>
  <a href="/logout"><span class="sidebar-icon">🚪</span> <span class="sidebar-text">ログアウト</span></a>
</div>
`;

// --------------------------------------
// ホーム（動画検索のみ・横幅広 UI）
// --------------------------------------
app.get("/", (req, res) => {
  const user = req.cookies.user;
  if (!user) return res.redirect("/login");

  res.send(`
    <html>
    <head>${CSS}</head>
    <body>

      ${SIDEBAR_HTML}

      <div id="main-content" class="main-content">

        <h2>動画検索</h2>

        <div style="max-width:800px;margin:0 auto;">
          <form action="/search" method="post">
            <input type="text" name="q" placeholder="検索ワードを入力">
            <select name="region" class="region-select">
              <option value="jp">日本のみ</option>
              <option value="global">全世界</option>
            </select>
            <button type="submit">動画を検索</button>
          </form>
        </div>

      </div>

      ${SIDEBAR_JS}

    </body>
    </html>
  `);
});

// --------------------------------------
// サイドバー JS（ホバーで開閉）
// --------------------------------------
const SIDEBAR_JS = `
<script>
const sidebar = document.getElementById("sidebar");
const main = document.getElementById("main-content");

sidebar.addEventListener("mouseenter", () => {
  sidebar.classList.add("open");
  main.classList.add("shift");
});

sidebar.addEventListener("mouseleave", () => {
  sidebar.classList.remove("open");
  main.classList.remove("shift");
});
</script>
`;


// --------------------------------------
// 固定ユーザー管理
// --------------------------------------
function loadUsers() {
  if (!fs.existsSync("users.json")) return [];
  return JSON.parse(fs.readFileSync("users.json", "utf8"));
}

async function saveHistory(user, keyword, videoId, title) {
  try {
    await pool.query(
      "INSERT INTO history (user_id, query, video_id, title) VALUES ($1, $2, $3, $4)",
      [user, keyword, videoId, title]
    );
  } catch (err) {
    console.error("履歴保存エラー:", err);
  }
}

function formatDateJP(date) {
  const d = new Date(date);

  const year = d.getFullYear();
  const month = d.getMonth() + 1;
  const day = d.getDate();

  const hours = String(d.getHours()).padStart(2, "0");
  const minutes = String(d.getMinutes()).padStart(2, "0");
  const seconds = String(d.getSeconds()).padStart(2, "0");

  const weekdays = ["日曜日", "月曜日", "火曜日", "水曜日", "木曜日", "金曜日", "土曜日"];
  const weekday = weekdays[d.getDay()];

  return `${year}/${month}/${day} ${hours}:${minutes}:${seconds} (${weekday})`;
}

// --------------------------------------
// ログイン画面
// --------------------------------------
app.get("/login", (req, res) => {
  res.send(`
    <html>
    <head>${CSS}</head>
    <body>

      <div class="center-box">
        <h2>ログイン</h2>
        <form method="POST" action="/login">
          <input name="user" placeholder="ユーザー名" required>
          <input name="pass" type="password" placeholder="パスワード" required>
          <button>ログイン</button>
        </form>
      </div>

    </body>
    </html>
  `);
});

app.post("/login", (req, res) => {
  const { user, pass } = req.body;
  const users = loadUsers();

  const found = users.find(u => u.user === user && u.pass === pass);
  if (!found) return res.send("ユーザー名またはパスワードが違います");

  res.cookie("user", user, { httpOnly: true });
  res.redirect("/");
});

// --------------------------------------
// ホーム
// --------------------------------------
app.get("/", (req, res) => {
  const user = req.cookies.user;

  if (!user) return res.redirect("/login");

  res.send(`
    <html>
    <head>${CSS}</head>
    <body>

      ${SIDEBAR_HTML}

      <div id="main-content" class="main-content">
        <h2>ようこそ ${user} さん</h2>
        <center>
          <form action="/search">
            <input type="text" name="q" placeholder="検索ワード" required style="max-width:400px;">
            <button style="width:200px;">検索</button>
          </form>
          <br>
          <a href="/logout">ログアウト</a>
        </center>
      </div>

      ${SIDEBAR_JS}

    </body>
    </html>
  `);
});

// --------------------------------------
// 動画検索（60件）
// --------------------------------------
app.post("/search", async (req, res) => {
  const user = req.cookies.user;
  if (!user) return res.redirect("/login");

  // ★ POST で受け取る（履歴に残らない）
  const q = req.body.q;
  const region = req.body.region || "jp";

  if (!q) return res.send("検索ワードがありません");

  // ★ 地域ごとに URL を切り替え
  let url;
  if (region === "global") {
    url = `https://www.youtube.com/results?search_query=${encodeURIComponent(q)}`;
  } else {
    url = `https://www.youtube.com/results?search_query=${encodeURIComponent(q)}&gl=JP&hl=ja`;
  }

  const html = await fetch(url).then(r => r.text());

  // ★ 正規表現は必ず1行（改行禁止）
  const videoMatches = [...html.matchAll(/"videoId":"(.*?)".*?"title":\{"runs":\[\{"text":"(.*?)"\}\]/gs)];

  const videos = videoMatches.slice(0, 60).map(m => ({
    id: m[1],
    title: m[2]
  }));

  // ★ HTML 出力
  let list = `
    <html>
    <head>${CSS}</head>
    <body>
      ${SIDEBAR_HTML}  

      <div id="main-content" class="main-content">
        <h2>動画検索結果: ${q}（${region === "jp" ? "日本" : "全世界"}）</h2>
        <div class="card-grid">
  `;

  // ★ 動画カード（POST 方式・履歴に残らない）
  list += videos.map(v => `
    <form action="/watch" method="post" style="display:inline;">
      <input type="hidden" name="id" value="${v.id}">
      <button style="all:unset;cursor:pointer;">
        <div class="card">
          <img class="thumb" src="https://i.ytimg.com/vi/${v.id}/hqdefault.jpg">
          <div style="margin-top:10px;font-weight:bold;">${v.title}</div>
        </div>
      </button>
    </form>
  `).join("");

  list += `
        </div>
      </div>

      ${SIDEBAR_JS}

    </body>
    </html>
  `;

  res.send(list);
});

// --------------------------------------
// チャンネル動画一覧（内部ページ）
// --------------------------------------
app.get("/channel-videos", async (req, res) => {
  const user = req.cookies.user;
  if (!user) return res.redirect("/login");

  const id = req.query.id;
  if (!id) return res.send("チャンネルIDがありません");

  // チャンネルの動画一覧ページを取得
  const url = `https://www.youtube.com/channel/${id}/videos?hl=ja&gl=JP`;
  const html = await fetch(url).then(r => r.text());

  // ytInitialData を抽出（複数パターン対応）
  let jsonText =
  html.match(/ytInitialData"\]\s*=\s*(\{.*?\});/) ||
  html.match(/var ytInitialData = (\{.*?\});/) ||
  html.match(/window\["ytInitialData"\]\s*=\s*(\{.*?\});/);

  if (!jsonText)
    return res.send("データを取得できませんでした（ytInitialData が見つかりません）");

  const data = JSON.parse(jsonText[1]);

function getTitle(v) {
  if (v.title?.simpleText) return v.title.simpleText;

  if (Array.isArray(v.title?.runs)) {
    return v.title.runs.map(r => r.text).join("") || "No Title";
  }

  return "No Title";
}
  
function findGridItems(obj) {
  if (!obj || typeof obj !== "object") return null;

  // gridRenderer.items
  if (obj.gridRenderer?.items) return obj.gridRenderer.items;

  // richGridRenderer.contents
  if (obj.richGridRenderer?.contents) return obj.richGridRenderer.contents;

  // 再帰的に探索
  for (const key in obj) {
    const found = findGridItems(obj[key]);
    if (found) return found;
  }

  return null;
}

const grid = findGridItems(data) || [];

// ★★★ videos はここで 1 回だけ生成する（これが正しい）★★★
const videos = grid
  .map(v => v.gridVideoRenderer || v.richItemRenderer?.content?.videoRenderer)
  .filter(v => v && v.videoId)
  .map(v => ({
    id: v.videoId,
    title:
      v.title?.simpleText ||
      v.title?.runs?.map(r => r.text).join("") ||
      "No Title",
    thumb: v.thumbnail?.thumbnails?.slice(-1)[0]?.url || ""
  }));

// 最大 60 件
const list60 = videos.slice(0, 60);

// チャンネル名
const title =
  data.metadata?.channelMetadataRenderer?.title ||
  "チャンネル名取得不可";

// HTML 出力
let list = `
  <html>
  <head>${CSS}</head>
  <body>

    ${SIDEBAR_HTML}

    <div id="main-content" class="main-content">
      <h2>${title} の動画一覧</h2>
      <div class="card-grid">
`;

list += list60.map(v => `
<div class="card">
  <form action="/watch" method="post" style="display:inline;">
    <input type="hidden" name="id" value="${v.id}">
    <button style="all:unset;cursor:pointer;">
      <img class="thumb" src="https://i.ytimg.com/vi/${v.id}/hqdefault.jpg">
      <div style="margin-top:10px;font-weight:bold;">${v.title}</div>
    </button>
  </form>
</div>
`).join("");

list += `
      </div>
    </div>

    ${SIDEBAR_JS}

  </body>
  </html>
`;

res.send(list);
});

// --------------------------------------
// チャンネル検索（横幅広 UI）
// --------------------------------------
app.get("/channel-search", (req, res) => {
  const user = req.cookies.user;
  if (!user) return res.redirect("/login");

  res.send(`
    <html>
    <head>${CSS}</head>
    <body>

      ${SIDEBAR_HTML}

      <div id="main-content" class="main-content">

        <h2>チャンネル検索</h2>

        <div style="max-width:800px;margin:0 auto;">
          <form action="/channel-search/result" method="get">
            <input type="text" name="q" placeholder="チャンネル名を入力">
            <select name="region" class="region-select">
              <option value="jp">日本のみ</option>
              <option value="global">全世界</option>
            </select>
            <button type="submit">検索</button>
          </form>
        </div>

      </div>

      ${SIDEBAR_JS}

    </body>
    </html>
  `);
});


// --------------------------------------
// チャンネル検索結果（60件）
// --------------------------------------
app.get("/channel-search/result", async (req, res) => {
  const user = req.cookies.user;
  if (!user) return res.redirect("/login");

  const q = req.query.q;
  const region = req.query.region || "jp";

  // ★ 地域で URL 切替
  let url;
  if (region === "global") {
    url = `https://www.youtube.com/results?search_query=${encodeURIComponent(q)}&sp=EgIQAg%253D%253D`;
  } else {
    url = `https://www.youtube.com/results?search_query=${encodeURIComponent(q)}&sp=EgIQAg%253D%253D&hl=ja&gl=JP`;
  }

  const html = await fetch(url).then(r => r.text());

  const jsonText = html.match(/var ytInitialData = (.*?);<\/script>/s);
  if (!jsonText) return res.send("データを取得できませんでした");

  const data = JSON.parse(jsonText[1]);

  const channels = [];
  function scan(obj) {
    if (typeof obj !== "object" || obj === null) return;

    if (obj.channelRenderer) {
      const c = obj.channelRenderer;
      channels.push({
        id: c.channelId,
        title: c.title?.simpleText || c.title?.runs?.[0]?.text || "No Title",
        icon: c.thumbnail?.thumbnails?.[0]?.url || ""
      });
    }

    for (const key in obj) scan(obj[key]);
  }
  scan(data);

  const list60 = channels.slice(0, 60);

  res.send(`
    <html>
    <head>${CSS}</head>
    <body>

      ${SIDEBAR_HTML}

      <div id="main-content" class="main-content">
        <h2>チャンネル検索結果: ${q}（${region === "jp" ? "日本" : "全世界"}）</h2>
        <div class="card-grid">
          ${list60.map(c => `
            <div class="card" onclick="location.href='/channel-videos?id=${c.id}'" style="cursor:pointer;">
              <img class="thumb" src="${c.icon}">
              <div style="margin-top:10px;font-weight:bold;">${c.title}</div>
            </div>
          `).join("")}
        </div>
      </div>

      ${SIDEBAR_JS}

    </body>
    </html>
  `);
});


app.post("/watch", async (req, res) => {
  const id = req.body.id;
  if (!id) return res.send("動画IDがありません");

  const user = req.cookies.user;
  const embedUrl = `https://www.youtube.com/embed/${id}`;
  const oembedUrl = `https://www.youtube.com/oembed?url=https://www.youtube.com/watch?v=${id}&format=json`;

  let embeddable = true;
  let title = "動画タイトル不明";

  try {
    const check = await fetch(oembedUrl);
    if (!check.ok) {
      embeddable = false;
    } else {
      const data = await check.json();
      title = data.title || title;
    }
  } catch {
    embeddable = false;
  }

  if (!embeddable) {
    return res.redirect(`https://www.youtube.com/watch?v=${id}`);
  }

  // ★★★ 履歴保存（POST 版）★★★
  if (user) {
    await saveHistory(user, "watch", id, title);
  }

  res.send(`
    <html>
    <head>${CSS}</head>
    <body>
      ${SIDEBAR_HTML}
      <div id="main-content" class="main-content">
        <h2>${title}</h2>
        <center>
          <iframe width="560" height="315"
            src="${embedUrl}"
            frameborder="0" allowfullscreen></iframe>
          <br><br>
          <a href="/">ホーム</a>
        </center>
      </div>
      ${SIDEBAR_JS}

      <!-- ★★★ POST 送信用スクリプト ★★★ -->
      <script>
      function postWatch(id) {
        const form = document.createElement("form");
        form.method = "POST";
        form.action = "/watch";

        const input = document.createElement("input");
        input.type = "hidden";
        input.name = "id";
        input.value = id;

        form.appendChild(input);
        document.body.appendChild(form);
        form.submit();
      }
      </script>
    </body>
    </html>
  `);
});

// --------------------------------------
// 履歴ページ（ユーザー用） PostgreSQL 版
// --------------------------------------
app.get("/history", async (req, res) => {
  const user = req.cookies.user;
  if (!user) return res.redirect("/login");

  const result = await pool.query(
    `SELECT query, video_id, title, created_at
     FROM history
     WHERE user_id = $1
     ORDER BY created_at DESC`,
    [user]
  );

  const data = result.rows;

  let html = `
    <html>
    <head>${CSS}</head>
    <body>

      ${SIDEBAR_HTML}

      <div id="main-content" class="main-content">
        <h2>${user} さんの検索履歴</h2>

        <form action="/history/delete" method="POST">
          <button class="danger" style="width:200px;">履歴をすべて削除</button>
        </form>
        <br>
  `;

  html += data.map((item, index) => `
    <div class="history-card">
      ${formatDateJP(item.created_at)}<br>
      <strong>${item.query}</strong><br>

      <a href="#" onclick="postWatch('${item.video_id}')">
        ${item.title}
      </a>

      <br><br>
      <a href="/history/delete-one?index=${index}" style="color:red;">この履歴を削除</a>
    </div>
  `).join("");

  html += `
        <br><center><a href="/">ホームへ戻る</a></center>
      </div>

      ${SIDEBAR_JS}

      <script>
      function postWatch(id) {
        const form = document.createElement("form");
        form.method = "POST";
        form.action = "/watch";

        const input = document.createElement("input");
        input.type = "hidden";
        input.name = "id";
        input.value = id;

        form.appendChild(input);
        document.body.appendChild(form);
        form.submit();
      }
      </script>

    </body>
    </html>
  `;   // ← ← ← ★★★ ここでテンプレート文字列が正しく閉じる ★★★

  res.send(html);
});
// --------------------------------------
// 履歴削除（ユーザー用・全削除）
// --------------------------------------
app.post("/history/delete", (req, res) => {
  const user = req.cookies.user;
  if (!user) return res.redirect("/login");

  const file = `history_user_${user}.json`;

  if (fs.existsSync(file)) fs.unlinkSync(file);

  res.redirect("/history");
});

// --------------------------------------
// 履歴削除（ユーザー用・1件削除）
// --------------------------------------
app.get("/history/delete-one", (req, res) => {
  const user = req.cookies.user;
  if (!user) return res.redirect("/login");

  const index = parseInt(req.query.index);
  const file = `history_user_${user}.json`;

  let data = [];
  if (fs.existsSync(file)) {
    data = JSON.parse(fs.readFileSync(file, "utf8"));
  }

  if (!isNaN(index) && data[index]) {
    data.splice(index, 1);
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
  }

  res.redirect("/history");
});
// --------------------------------------
// 管理者ページ（本物の履歴）
// --------------------------------------
const ADMIN_PASSWORD = "jagdyufr5t62";

// --------------------------------------
// GET /admin（ログイン画面 or パスワード確認）
// --------------------------------------
app.get("/admin", (req, res) => {
  const user = req.cookies.user;
  const pass = req.query.pass;

  // ① ログインしていない
  if (!user) return res.redirect("/login");

  // ② ユーザー名が hinata 以外
  if (user !== "hinata") {
    return res.send("あなたには管理者ページへのアクセス権がありません");
  }

  // ③ パスワードが違う → ログイン画面を表示
  if (pass !== ADMIN_PASSWORD) {
    return res.send(`
      <html>
      <head>${CSS}</head>
      <body>

        ${SIDEBAR_HTML}

        <div id="main-content" class="main-content">
          <div class="center-box">
            <h2>管理者ログイン</h2>
            <form>
              <input name="pass" type="password" placeholder="管理者パスワード" required>
              <button>ログイン</button>
            </form>
          </div>
        </div>

        ${SIDEBAR_JS}

      </body>
      </html>
    `);
  }

  // ④ パスワードが正しい → POST /admin に飛ばすフォームを自動送信
  res.send(`
    <form id="f" method="POST" action="/admin">
      <input type="hidden" name="pass" value="${ADMIN_PASSWORD}">
    </form>
    <script>document.getElementById("f").submit();</script>
  `);
});


// --------------------------------------
// POST /admin（本物の履歴表示）
// --------------------------------------
app.post("/admin", async (req, res) => {
  const pass = req.body.pass;
  if (pass !== ADMIN_PASSWORD) {
    return res.send("パスワードが違います");
  }

  // ★★★ PostgreSQL から履歴を取得 ★★★
  const result = await pool.query(`
    SELECT user_id, query, video_id, title, created_at
    FROM history
    ORDER BY created_at DESC
  `);

  // ユーザーごとにグループ化
  const historyByUser = {};
  for (const row of result.rows) {
    if (!historyByUser[row.user_id]) {
      historyByUser[row.user_id] = [];
    }
    historyByUser[row.user_id].push(row);
  }

  let allHistoryHTML = "";
  let deleteButtonsHTML = "";

  // ★★★ ユーザーごとに HTML を生成 ★★★
  for (const userName in historyByUser) {
    const data = historyByUser[userName];

    allHistoryHTML += `<h3>${userName}</h3>`;
    allHistoryHTML += data.map(item => `
      <div class="history-card">
        ${formatDateJP(item.created_at)}<br>
        <strong>${item.query}</strong><br>

        <a href="#" onclick="postWatch('${item.video_id}')">
          ${item.title}
        </a>
      </div>
    `).join("");

    // ★★★ 削除ボタンは for の中に置く ★★★
    deleteButtonsHTML += `
      <form method="POST" action="/admin/delete-user">
        <input type="hidden" name="user" value="${userName}">
        <input type="hidden" name="pass" value="${ADMIN_PASSWORD}">
        <button class="danger" style="width:200px;">${userName} の履歴を削除</button>
      </form>
      <br>
    `;
  }

  // ★★★ 管理者ページ HTML ★★★
  res.send(`
    <html>
    <head>${CSS}</head>
    <body>

      ${SIDEBAR_HTML}

      <div id="main-content" class="main-content">
        <h2>管理者ページ</h2>

        <div class="tabs">
          <div class="tab active" id="tab-all" onclick="openTab('all')">全履歴</div>
          <div class="tab" id="tab-delete" onclick="openTab('delete')">ユーザー削除</div>
        </div>

        <div class="tab-content active" id="content-all">
          ${allHistoryHTML}
        </div>

        <div class="tab-content" id="content-delete">
          ${deleteButtonsHTML}
        </div>

        <script>
          function openTab(name) {
            document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
            document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));

            document.getElementById("tab-" + name).classList.add("active");
            document.getElementById("content-" + name).classList.add("active");
          }

          function postWatch(id) {
            const form = document.createElement("form");
            form.method = "POST";
            form.action = "/watch";

            const input = document.createElement("input");
            input.type = "hidden";
            input.name = "id";
            input.value = id;

            form.appendChild(input);
            document.body.appendChild(form);
            form.submit();
          }
        </script>
      </div>

      ${SIDEBAR_JS}

    </body>
    </html>
  `);
});

// --------------------------------------
// POST /admin/delete-user（特定ユーザーの履歴削除）
// --------------------------------------
app.post("/admin/delete-user", async (req, res) => {
  const pass = req.body.pass;
  const user = req.body.user;

  // パスワードチェック
  if (pass !== ADMIN_PASSWORD) {
    return res.send("パスワードが違います");
  }

  // 履歴削除
  await pool.query(
    `DELETE FROM history WHERE user_id = $1`,
    [user]
  );

  // 管理者ページに戻る
  res.redirect(`/admin?pass=${ADMIN_PASSWORD}`);
});

// --------------------------------------
// ログアウト
// --------------------------------------
app.get("/logout", (req, res) => {
  res.clearCookie("user");
  res.redirect("/login");
});

// --------------------------------------
// サーバー起動
// --------------------------------------
app.listen(PORT, () => {
  console.log("Server running on port " + PORT);

});

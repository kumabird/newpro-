import express from "express";

const app = express();
app.disable("x-powered-by");

const PORT = process.env.PORT || 3000;

// -----------------------------
// 共通CSS（UIあり）
// -----------------------------
const CSS = `
<style>
body {
  font-family: "Segoe UI", sans-serif;
  margin: 0;
  background: #f5f7fb;
}

.sidebar {
  position: fixed;
  width: 200px;
  height: 100%;
  background: white;
  border-right: 1px solid #ddd;
  padding-top: 20px;
}

.sidebar a {
  display: block;
  padding: 12px 20px;
  text-decoration: none;
  color: #333;
}

.sidebar a:hover {
  background: #eaf2ff;
}

.main {
  margin-left: 220px;
  padding: 30px;
}

.card-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(250px,1fr));
  gap: 20px;
}

.card {
  background: white;
  padding: 12px;
  border-radius: 10px;
  box-shadow: 0 2px 8px rgba(0,0,0,0.1);
  transition: 0.2s;
}

.card:hover {
  transform: translateY(-4px);
}

.thumb {
  width: 100%;
  border-radius: 8px;
}

.search-box {
  max-width: 600px;
  margin-bottom: 30px;
}

input, button {
  padding: 10px;
  font-size: 15px;
}

button {
  cursor: pointer;
  background: #3498db;
  border: none;
  color: white;
  border-radius: 5px;
}
</style>
`;

const SIDEBAR = `
<div class="sidebar">
  <a href="/">🏠 ホーム</a>
  <a href="/">📺️ チャンネル検索</a>
  <a href="/">🕒️ 履歴</a>
  <a href="/">⚙ 管理者ページ</a>
  <a href="/">🚪 ログアウト</a>
</div>
`;

// -----------------------------
// タイトル
// -----------------------------
const titlePatterns = [
  "議員という大きなカテゴリーに比べたらアァァ！",
  "少子化問題、高齢ェェエエ者ッハアアア！！",
  "そういう問題ッヒョオッホーーー！！",
  "ウーハッフッハーン！！",
  "立候補して！文字通り！アハハーンッ！",
  "この世の中を！ウグッブーン！！",
  "ご指摘と受け止めデーーヒィッフウ！！"
];

// -----------------------------
// ホーム
// -----------------------------
app.get("/", (req, res) => {
  res.send(`
    <html>
    <head>${CSS}</head>
    <body>
      ${SIDEBAR}
      <div class="main">
        <h2>動画検索</h2>
        <div class="search-box">
          <form action="/search">
            <input type="text" name="q" placeholder="検索ワード" style="width:70%">
            <button>検索</button>
          </form>
        </div>
      </div>
    </body>
    </html>
  `);
});

// -----------------------------
// 検索（3% / 10%）
// -----------------------------
app.get("/search", (req, res) => {
  const q = req.query.q;
  if (!q) return res.redirect("/");

  const rand = Math.random();
  let videoId;
  let specialTitle = null;

  if (rand < 0.03) {
    videoId = "Nkg4J9AbIBM";
    specialTitle = "！！！？？？？？？";
  }
  else if (rand < 0.13) {
    videoId = "wBf47hGMch0";
    specialTitle = "何やってるんですか勉強してください";
  }
  else {
    videoId = "NfZsV6z48wE";
  }

  const getTitle = () =>
    specialTitle ||
    titlePatterns[Math.floor(Math.random() * titlePatterns.length)];

  let cards = Array.from({ length: 51 }).map(() => `
    <a href="/watch?v=${videoId}" style="text-decoration:none;color:inherit;">
      <div class="card">
        <img class="thumb" src="https://i.ytimg.com/vi/${videoId}/hqdefault.jpg">
        <div style="margin-top:8px;font-weight:bold;">
          ${getTitle()}
        </div>
      </div>
    </a>
  `).join("");

  res.send(`
    <html>
    <head>${CSS}</head>
    <body>
      ${SIDEBAR}
      <div class="main">
        <h2>検索結果: ${q}</h2>
        <div class="card-grid">
          ${cards}
        </div>
      </div>
    </body>
    </html>
  `);
});

// -----------------------------
// 18本再生
// -----------------------------
app.get("/watch", (req, res) => {
  const id = req.query.v;
  if (!id) return res.redirect("/");

  const players = Array.from({ length: 18 }).map(() => `
    <iframe width="300" height="170"
      src="https://www.youtube.com/embed/${id}"
      frameborder="0"
      allowfullscreen>
    </iframe>
  `).join("");

  res.send(`
    <html>
    <head>${CSS}</head>
    <body>
      ${SIDEBAR}
      <div class="main">
        <h2>動画再生（27本同時）</h2>
        <div style="
          display:grid;
          grid-template-columns: repeat(3, 1fr);
          gap:10px;
        ">
          ${players}
        </div>
      </div>
    </body>
    </html>
  `);
});

app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});

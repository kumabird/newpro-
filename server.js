import express from "express";
import fetch from "node-fetch";
import cookieParser from "cookie-parser";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import { randomBytes, timingSafeEqual } from "crypto";
import bcrypt from "bcrypt";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

// ======================================
// ■ 必須シークレットの検証（起動時チェック）
// ======================================
// SESSION_SECRETとADMIN_PASSが未設定のまま本番稼働することを防ぐ。
// デフォルト値へのフォールバックは推測可能な弱いシークレットに繋がるため廃止。
for (const key of ["SESSION_SECRET", "ADMIN_PASS"]) {
  if (!process.env[key]) {
    console.error(`[FATAL] 環境変数 ${key} が設定されていません。安全なランダム値を設定してください。`);
    process.exit(1);
  }
}

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(helmet({
  contentSecurityPolicy: false,   // インラインscript/styleを多用しているため個別に見直すまで無効化
  crossOriginEmbedderPolicy: false, // 有効だとYouTube/ニコニコの埋め込みiframeがブロックされ「エラー153」等の原因になるため無効化
  crossOriginResourcePolicy: false, // 同上。外部埋め込み・画像読み込みを妨げないようにする
  referrerPolicy: { policy: "strict-origin-when-cross-origin" }, // helmetの既定値 no-referrer だとYouTube埋め込みがReferer無しで拒否され「エラー153」の原因になるため、ブラウザ標準相当の値に変更
}));

const PORT = process.env.PORT || 3000;

if (!process.env.RECAPTCHA_SECRET_KEY) {
  console.warn("[WARN] RECAPTCHA_SECRET_KEY 未設定のため reCAPTCHA 検証はスキップされます。IPレート制限のみでブルートフォースを防いでいます。");
}

import pkg from "pg";
const { Pool } = pkg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // 自己署名証明書を使うホスティング環境向けに環境変数で切り替え可能にしつつ、デフォルトは検証を有効化
  ssl: { rejectUnauthorized: process.env.DB_SSL_REJECT_UNAUTHORIZED !== "false" }
});

const PgSession = connectPgSimple(session);

app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.json());
app.use(session({
  store: new PgSession({
    pool,
    tableName: "session",
    createTableIfMissing: true,
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  name: "sid",
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

// ======================================
// ■ ブルートフォース対策（レート制限）
// ======================================
// reCAPTCHAは環境変数未設定時に自動でスキップされる仕様のため、
// それに依存せず常に効くIPベースのレート制限を認証系エンドポイントに適用する。
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "試行回数が多すぎます。しばらくしてから再度お試しください" },
});

function timingSafeStrEqual(a, b) {
  const bufA = Buffer.from(String(a ?? ""));
  const bufB = Buffer.from(String(b ?? ""));
  if (bufA.length !== bufB.length) {
    // 長さが違う場合でも比較コストを揃えるため、ダミー比較を行ってから false を返す
    timingSafeEqual(bufA, bufA);
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}

const ADMIN_USER = process.env.ADMIN_USER || "hinata";
const ADMIN_PASS = process.env.ADMIN_PASS; // 起動時チェック済みなので必ず設定されている
const RECAPTCHA_SITE_KEY   = process.env.RECAPTCHA_SITE_KEY   || "";
const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY || "";
const GOOGLE_CLIENT_ID     = process.env.GOOGLE_CLIENT_ID     || "";
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "";
const GITHUB_CLIENT_ID     = process.env.GITHUB_CLIENT_ID     || "";
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET || "";
const APP_BASE_URL = process.env.APP_BASE_URL || "http://localhost:3000";
const BCRYPT_ROUNDS = 10;

// ======================================
// ■ ユーティリティ
// ======================================
function escHtml(str) {
  if (typeof str !== "string") return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function formatDateJP(date) {
  const d = new Date(date);
  const wk = ["日","月","火","水","木","金","土"];
  return `${d.getFullYear()}/${d.getMonth()+1}/${d.getDate()} `
       + `${String(d.getHours()).padStart(2,"0")}:${String(d.getMinutes()).padStart(2,"0")}`
       + ` (${wk[d.getDay()]}曜)`;
}

function getThumbUrl(videoId, size = "mq") {
  if (videoId.startsWith("nico:")) {
    const numId = videoId.replace("nico:", "").replace(/^[a-zA-Z]+/, "");
    return `https://nicovideo.cdn.nimg.jp/thumbnails/${numId}/${numId}`;
  }
  const map = { hq: "hqdefault", mq: "mqdefault", max: "maxresdefault" };
  return `https://i.ytimg.com/vi/${videoId}/${map[size]||"mqdefault"}.jpg`;
}

function getSessionUser(req) { return req.session?.user || null; }
function setSessionUser(req, username) { if (!req.session) req.session = {}; req.session.user = username; }
function destroySession(req, res) {
  if (!req.session) return res.redirect("/login");
  req.session.destroy((err) => {
    if (err) console.error("Session destroy error:", err);
    res.clearCookie("sid");
    res.redirect("/login");
  });
}

// ======================================
// ■ CSS
// ======================================
function buildCSS(platform = "yt") {
  const isNico = platform === "nico";
  const accent      = isNico ? "#e6242b" : "#ff0000";
  const accentDark  = isNico ? "#c41e24" : "#cc0000";
  const accentLight = isNico ? "#fff0f0" : "#fff5f5";
  const bgColor     = isNico ? "#fff8f8" : "#f0f6ff";
  return `
<style>
  :root {
    --accent:       ${accent};
    --accent-dark:  ${accentDark};
    --accent-light: ${accentLight};
    --bg:           ${bgColor};
    --sidebar-w:    54px;
    --sidebar-open: 230px;
    --bottom-nav-h: 60px;
  }
  * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
  body { font-family: "Segoe UI", "Hiragino Sans", "Noto Sans JP", sans-serif; background: var(--bg); margin: 0; padding: 0; color: #333; -webkit-text-size-adjust: 100%; }
  h2 { margin-bottom: 20px; color: #2c3e50; text-align: center; }
  .sidebar { position: fixed; top: 0; left: 0; width: var(--sidebar-w); height: 100%; background: #1a1a2e; transition: width 0.25s ease; overflow: hidden; z-index: 1000; display: flex; flex-direction: column; }
  .sidebar.open { width: var(--sidebar-open); }
  .platform-switcher { padding: 8px 5px; border-bottom: 1px solid rgba(255,255,255,0.1); flex-shrink: 0; display: flex; flex-direction: column; gap: 3px; }
  .platform-btn { display: flex; align-items: center; gap: 10px; padding: 9px; border-radius: 8px; cursor: pointer; border: none; background: transparent; color: rgba(255,255,255,0.5); font-size: 13px; font-weight: bold; white-space: nowrap; width: 100%; transition: background 0.18s, color 0.18s; text-align: left; min-height: 44px; }
  .platform-btn .p-icon { font-size: 20px; flex-shrink: 0; width: 28px; text-align: center; }
  .platform-btn .p-label { opacity: 0; transition: opacity 0.2s; }
  .sidebar.open .platform-btn .p-label { opacity: 1; }
  .platform-btn.yt-btn.active   { background: #ff0000; color: white; }
  .platform-btn.nico-btn.active { background: #e6242b; color: white; }
  .platform-btn.yt-btn:not(.active):hover   { background: rgba(255,0,0,0.2); color: white; }
  .platform-btn.nico-btn:not(.active):hover { background: rgba(230,36,43,0.2); color: white; }
  .sidebar-nav { flex: 1; overflow-y: auto; padding: 6px 5px; }
  .sidebar a { display: flex; align-items: center; gap: 12px; padding: 10px 9px; font-size: 14px; color: rgba(255,255,255,0.7); text-decoration: none; white-space: nowrap; border-radius: 8px; margin-bottom: 2px; min-height: 44px; transition: background 0.18s, color 0.18s; }
  .sidebar a:hover { background: rgba(255,255,255,0.1); color: white; }
  .sidebar a.active-link { background: rgba(255,255,255,0.15); color: white; }
  .sidebar-icon { font-size: 19px; flex-shrink: 0; width: 28px; text-align: center; }
  .sidebar-text { opacity: 0; transition: opacity 0.2s; }
  .sidebar.open .sidebar-text { opacity: 1; }
  .sidebar-divider { border: none; border-top: 1px solid rgba(255,255,255,0.1); margin: 5px 4px; }
  .sidebar-footer { padding: 6px 5px 10px; border-top: 1px solid rgba(255,255,255,0.1); flex-shrink: 0; }
  .main-content { margin-left: calc(var(--sidebar-w) + 20px); padding: 24px; transition: margin-left 0.25s ease; min-height: 100vh; }
  .main-content.shift { margin-left: calc(var(--sidebar-open) + 20px); }
  .bottom-nav { display: none; position: fixed; bottom: 0; left: 0; right: 0; height: var(--bottom-nav-h); background: #1a1a2e; border-top: 1px solid rgba(255,255,255,0.1); z-index: 1000; align-items: stretch; }
  .bottom-nav-item { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 3px; padding: 6px 4px; color: rgba(255,255,255,0.5); text-decoration: none; font-size: 10px; font-weight: bold; border: none; background: transparent; cursor: pointer; transition: color 0.15s, background 0.15s; -webkit-tap-highlight-color: transparent; }
  .bottom-nav-item .bn-icon { font-size: 20px; line-height: 1; }
  .bottom-nav-item.active { color: white; background: rgba(255,255,255,0.08); }
  .bottom-nav-item:active { background: rgba(255,255,255,0.12); }
  .platform-modal-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 2000; align-items: flex-end; justify-content: center; }
  .platform-modal-overlay.show { display: flex; }
  .platform-modal { background: #1a1a2e; border-radius: 16px 16px 0 0; width: 100%; padding: 16px 16px 32px; }
  .platform-modal h3 { color: rgba(255,255,255,0.7); font-size: 13px; text-align: center; margin: 0 0 12px; }
  .platform-modal-btn { display: flex; align-items: center; gap: 14px; width: 100%; padding: 14px 16px; border-radius: 10px; border: none; cursor: pointer; font-size: 15px; font-weight: bold; margin-bottom: 8px; color: white; background: rgba(255,255,255,0.08); transition: background 0.15s; }
  .platform-modal-btn .pm-icon { font-size: 22px; }
  .platform-modal-btn.yt-active   { background: #ff0000; }
  .platform-modal-btn.nico-active { background: #e6242b; }
  .platform-modal-cancel { display: block; width: 100%; padding: 14px; border-radius: 10px; border: none; background: rgba(255,255,255,0.05); color: rgba(255,255,255,0.6); font-size: 14px; cursor: pointer; margin-top: 4px; }
  @media (max-width: 767px) {
    .sidebar { display: none !important; }
    .bottom-nav { display: flex !important; }
    .main-content { margin-left: 0 !important; padding: 16px 12px; padding-bottom: calc(var(--bottom-nav-h) + 16px); }
    .main-content.shift { margin-left: 0 !important; }
  }
  .card-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 16px; }
  @media (max-width: 767px) { .card-grid { grid-template-columns: repeat(2, 1fr); gap: 10px; } }
  @media (max-width: 380px) { .card-grid { grid-template-columns: 1fr; } }
  .card { background: white; padding: 10px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); transition: transform 0.2s, box-shadow 0.2s; cursor: pointer; }
  @media (hover: hover) { .card:hover { transform: translateY(-3px); box-shadow: 0 6px 18px rgba(0,0,0,0.13); } }
  .card:active { transform: scale(0.97); }
  .card.nico-card { border-top: 3px solid #e6242b; }
  .card.yt-card   { border-top: 3px solid #ff0000; }
  .thumb { width: 100%; border-radius: 8px; aspect-ratio: 16/9; object-fit: cover; background: #eee; display: block; }
  .center-box { max-width: 400px; margin: 40px auto; background: white; padding: 28px 24px; border-radius: 14px; box-shadow: 0 4px 16px rgba(0,0,0,0.12); }
  @media (max-width: 767px) { .center-box { margin: 16px; max-width: none; border-radius: 12px; padding: 20px 16px; } }
  input[type=text], input[type=password], input[type=email], select.form-select { width: 100%; padding: 14px 14px; font-size: 16px; border-radius: 10px; border: 1px solid #ccc; margin-bottom: 12px; background: white; display: block; -webkit-appearance: none; appearance: none; }
  input[type=text]:focus, input[type=password]:focus, input[type=email]:focus, select.form-select:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px ${accentLight}; }
  .btn { display: inline-flex; align-items: center; gap: 6px; padding: 12px 18px; font-size: 14px; font-weight: bold; border-radius: 10px; border: none; cursor: pointer; text-decoration: none; transition: opacity 0.15s, transform 0.1s; margin-bottom: 8px; min-height: 44px; -webkit-tap-highlight-color: transparent; }
  .btn:active { transform: scale(0.96); }
  .btn-primary { background: var(--accent); color: white; }
  .btn-gray    { background: #95a5a6; color: white; }
  .btn-yellow  { background: #f1c40f; color: #333; }
  .btn-danger  { background: #e74c3c; color: white; }
  .btn-green   { background: #27ae60; color: white; }
  .btn-full    { width: 100%; justify-content: center; }
  .btn-google { display: flex; align-items: center; justify-content: center; gap: 10px; width: 100%; padding: 13px 16px; font-size: 15px; font-weight: 600; border-radius: 10px; border: 1px solid #dadce0; background: white; color: #3c4043; cursor: pointer; text-decoration: none; transition: background 0.15s; margin-bottom: 10px; min-height: 48px; -webkit-tap-highlight-color: transparent; }
  .btn-google:active { background: #f0f0f0; }
  .btn-github { display: flex; align-items: center; justify-content: center; gap: 10px; width: 100%; padding: 13px 16px; font-size: 15px; font-weight: 600; border-radius: 10px; border: none; background: #24292e; color: white; cursor: pointer; text-decoration: none; transition: background 0.15s; margin-bottom: 10px; min-height: 48px; -webkit-tap-highlight-color: transparent; }
  .btn-github:active { background: #1a1e22; }
  .divider-text { display: flex; align-items: center; gap: 12px; color: #aaa; font-size: 13px; margin: 16px 0; }
  .divider-text::before, .divider-text::after { content: ""; flex: 1; border-top: 1px solid #e0e0e0; }
  .search-wrap { max-width: 700px; margin: 0 auto 24px; background: white; border-radius: 14px; padding: 20px 22px; box-shadow: 0 2px 12px rgba(0,0,0,0.08); }
  @media (max-width: 767px) { .search-wrap { padding: 16px; border-radius: 12px; } }
  .page-header { display: flex; align-items: center; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
  .page-header h2 { margin: 0; text-align: left; font-size: 18px; }
  .platform-badge { display: inline-flex; align-items: center; gap: 4px; padding: 3px 10px; border-radius: 20px; font-size: 12px; font-weight: bold; color: white; }
  .platform-badge.yt   { background: #ff0000; }
  .platform-badge.nico { background: #e6242b; }
  .watch-layout { display: flex; gap: 20px; max-width: 1280px; margin: 0 auto; align-items: flex-start; }
  .watch-player { flex: 1; min-width: 0; }
  .watch-player video { width:100%; aspect-ratio:16/9; border-radius:12px; background:#000; }
  .iframe-wrap { position:relative; width:100%; aspect-ratio:16/9; }
  .iframe-wrap iframe { position:absolute; top:0; left:0; width:100%; height:100%; border-radius:12px; border:none; background:#000; }
  .watch-related { width:340px; flex-shrink:0; max-height:90vh; overflow-y:auto; }
  .watch-related h3 { font-size:13px; margin-bottom:12px; color:#888; }
  .action-bar { display:flex; gap:8px; flex-wrap:wrap; margin-bottom:10px; }
  .channel-info { font-size:14px; color:#555; margin:6px 0 10px; cursor:pointer; }
  .channel-info:hover { color: var(--accent); }
  @media (max-width: 900px) { .watch-layout { flex-direction:column; } .watch-related { width:100%; max-height:none; } }
  @media (max-width: 767px) { .watch-player h2 { font-size:15px !important; } .action-bar .btn { font-size:12px; padding:9px 12px; } }
  .settings-box { max-width:540px; margin:0 auto; background:white; padding:28px; border-radius:14px; box-shadow:0 4px 16px rgba(0,0,0,0.1); }
  @media (max-width: 767px) { .settings-box { padding: 18px 14px; } }
  .mode-card { border:2px solid #ddd; border-radius:10px; padding:14px 16px; margin-bottom:10px; cursor:pointer; transition:border-color 0.2s, background 0.2s; }
  .mode-card:active { background: var(--accent-light); }
  .mode-card.selected { border-color:var(--accent); background:var(--accent-light); }
  .mode-card label { display:flex; align-items:flex-start; gap:10px; cursor:pointer; }
  .mode-card input[type=radio] { width:auto; margin:3px 0 0; flex-shrink:0; }
  .mode-card strong { display:block; font-size:15px; margin-bottom:4px; color:#2c3e50; }
  .mode-card p { margin:0; font-size:13px; color:#666; line-height:1.5; }
  .current-badge { display:inline-block; background:var(--accent); color:white; font-size:11px; padding:2px 8px; border-radius:20px; margin-left:8px; vertical-align:middle; }
  .history-card { background:white; border-radius:10px; padding:10px 12px; margin-bottom:8px; display:flex; gap:10px; align-items:center; box-shadow:0 1px 4px rgba(0,0,0,0.07); cursor: pointer; transition: background 0.15s; }
  .history-card:active { background: #f5f5f5; }
  .history-card img { width:100px; height:56px; border-radius:7px; object-fit:cover; flex-shrink:0; background:#eee; }
  @media (max-width: 767px) { .history-card img { width:88px; height:50px; } .history-card { padding: 8px 10px; } }
  .tabs { display:flex; gap:6px; margin-bottom:20px; flex-wrap: wrap; }
  .tab { padding:10px 18px; border-radius:8px; min-height: 44px; cursor:pointer; background:#eee; font-weight:bold; border:none; font-size:14px; -webkit-tap-highlight-color: transparent; }
  .tab.active { background:var(--accent); color:white; }
  .tab-content { display:none; }
  .tab-content.active { display:block; }
  .badge-nico { display:inline-block; background:#e6242b; color:white; font-size:10px; padding:1px 5px; border-radius:3px; margin-left:4px; font-weight:bold; }
  .badge-yt   { display:inline-block; background:#ff0000; color:white; font-size:10px; padding:1px 5px; border-radius:3px; margin-left:4px; font-weight:bold; }
  .rank-badge { position:absolute; top:8px; left:8px; background:var(--accent); color:white; font-weight:bold; font-size:12px; padding:2px 7px; border-radius:5px; }
  .shorts-container { position: fixed; inset: 0; background: #000; display: flex; flex-direction: column; align-items: center; justify-content: center; overflow: hidden; z-index: 500; }
  .shorts-video-wrap { position: relative; width: 100%; max-width: 420px; height: 100vh; max-height: 100vh; display: flex; align-items: center; justify-content: center; }
  .shorts-video-wrap video { width: 100%; height: 100%; object-fit: contain; background: #000; display: block; }
  .shorts-overlay { position: absolute; bottom: 0; left: 0; right: 0; padding: 16px 14px 24px; background: linear-gradient(transparent, rgba(0,0,0,0.75)); color: white; pointer-events: none; }
  .shorts-title { font-size: 14px; font-weight: bold; line-height: 1.4; margin-bottom: 6px; text-shadow: 0 1px 3px rgba(0,0,0,0.6); }
  .shorts-actions { position: absolute; right: 10px; bottom: 80px; display: flex; flex-direction: column; gap: 18px; align-items: center; }
  .shorts-btn { display: flex; flex-direction: column; align-items: center; gap: 4px; color: white; border: none; background: transparent; cursor: pointer; font-size: 11px; font-weight: bold; -webkit-tap-highlight-color: transparent; pointer-events: all; }
  .shorts-btn .sb-icon { width: 44px; height: 44px; border-radius: 50%; background: rgba(255,255,255,0.2); display: flex; align-items: center; justify-content: center; font-size: 20px; backdrop-filter: blur(4px); }
  .shorts-nav-btns { position: absolute; top: 50%; right: 8px; transform: translateY(-50%); display: flex; flex-direction: column; gap: 10px; }
  .shorts-nav-btn { width: 40px; height: 40px; border-radius: 50%; background: rgba(255,255,255,0.15); border: none; color: white; font-size: 18px; cursor: pointer; display: flex; align-items: center; justify-content: center; backdrop-filter: blur(4px); -webkit-tap-highlight-color: transparent; }
  .shorts-top-bar { position: fixed; top: 0; left: 0; right: 0; padding: 10px 14px; z-index: 600; display: flex; align-items: center; gap: 10px; background: linear-gradient(rgba(0,0,0,0.5), transparent); }
  .shorts-top-bar a { color: white; text-decoration: none; font-size: 22px; line-height: 1; }
  .shorts-top-bar h2 { color: white; font-size: 16px; margin: 0; text-shadow: 0 1px 3px rgba(0,0,0,0.5); }
  .shorts-progress { position: absolute; bottom: 0; left: 0; right: 0; height: 3px; background: rgba(255,255,255,0.3); }
  .shorts-progress-bar { height: 100%; background: var(--accent); width: 0%; transition: width 0.25s linear; }
  @media (min-width: 768px) { .shorts-video-wrap { max-width: 390px; height: 90vh; } }
</style>
`;
}

// ======================================
// ■ サイドバー HTML
// ======================================
function buildSidebar(platform, currentPath = "") {
  const isNico = platform === "nico";
  const al = (p) => currentPath === p ? ' class="active-link"' : '';
  const abn = (p) => currentPath === p ? ' active' : '';
  const ytLinks = `
    <a href="/"${al("/")}><span class="sidebar-icon">🏠</span><span class="sidebar-text">ホーム</span></a>
    <a href="/shorts"${al("/shorts")}><span class="sidebar-icon">📱</span><span class="sidebar-text">Shorts</span></a>
    <a href="/channel-search"${al("/channel-search")}><span class="sidebar-icon">📺</span><span class="sidebar-text">チャンネル検索</span></a>
    <a href="/music"><span class="sidebar-icon">♫</span><span class="sidebar-text">Music</span></a>
    <hr class="sidebar-divider">
    <a href="/favorites"${al("/favorites")}><span class="sidebar-icon">⭐</span><span class="sidebar-text">お気に入り</span></a>
    <a href="/history"${al("/history")}><span class="sidebar-icon">🕘</span><span class="sidebar-text">履歴</span></a>
    <a href="/settings"${al("/settings")}><span class="sidebar-icon">⚙️</span><span class="sidebar-text">設定</span></a>
    <a href="/admin"><span class="sidebar-icon">🛡️</span><span class="sidebar-text">管理者ページ</span></a>
  `;
  const nicoLinks = `
    <a href="/nico"${al("/nico")}><span class="sidebar-icon">🏠</span><span class="sidebar-text">ホーム</span></a>
    <a href="/nico/ranking"${al("/nico/ranking")}><span class="sidebar-icon">🏆</span><span class="sidebar-text">ランキング</span></a>
    <hr class="sidebar-divider">
    <a href="/favorites"${al("/favorites")}><span class="sidebar-icon">⭐</span><span class="sidebar-text">お気に入り</span></a>
    <a href="/history"${al("/history")}><span class="sidebar-icon">🕘</span><span class="sidebar-text">履歴</span></a>
    <a href="/settings"${al("/settings")}><span class="sidebar-icon">⚙️</span><span class="sidebar-text">設定</span></a>
    <a href="/admin"><span class="sidebar-icon">🛡️</span><span class="sidebar-text">管理者ページ</span></a>
  `;
  const homeHref = isNico ? "/nico" : "/";
  const homeActive = (currentPath === "/" || currentPath === "/nico") ? " active" : "";
  return `
<div id="sidebar" class="sidebar">
  <div class="platform-switcher">
    <button class="platform-btn yt-btn${!isNico ? " active" : ""}" onclick="switchPlatform('yt')">
      <span class="p-icon">▶</span><span class="p-label">YouTube</span>
    </button>
    <button class="platform-btn nico-btn${isNico ? " active" : ""}" onclick="switchPlatform('nico')">
      <span class="p-icon">🎬</span><span class="p-label">ニコニコ動画</span>
    </button>
  </div>
  <div class="sidebar-nav">${isNico ? nicoLinks : ytLinks}</div>
  <div class="sidebar-footer">
    <a href="/logout"><span class="sidebar-icon">🚪</span><span class="sidebar-text">ログアウト</span></a>
  </div>
</div>
<nav class="bottom-nav" id="bottom-nav">
  <a href="${homeHref}" class="bottom-nav-item${homeActive}"><span class="bn-icon">🏠</span><span>ホーム</span></a>
  <a href="/shorts" class="bottom-nav-item${abn("/shorts")}"><span class="bn-icon">📱</span><span>Shorts</span></a>
  <a href="/favorites" class="bottom-nav-item${abn("/favorites")}"><span class="bn-icon">⭐</span><span>お気に入り</span></a>
  <a href="/history" class="bottom-nav-item${abn("/history")}"><span class="bn-icon">🕘</span><span>履歴</span></a>
  <button class="bottom-nav-item" onclick="openPlatformModal()">
    <span class="bn-icon">${isNico ? "🎬" : "▶"}</span>
    <span>${isNico ? "ニコニコ" : "YouTube"}</span>
  </button>
</nav>
<div class="platform-modal-overlay" id="platform-modal" onclick="closePlatformModal(event)">
  <div class="platform-modal">
    <h3>プラットフォームを切替</h3>
    <button class="platform-modal-btn${!isNico ? " yt-active" : ""}" onclick="switchPlatform('yt')"><span class="pm-icon">▶</span> YouTube</button>
    <button class="platform-modal-btn${isNico ? " nico-active" : ""}" onclick="switchPlatform('nico')"><span class="pm-icon">🎬</span> ニコニコ動画</button>
    <button class="platform-modal-cancel" onclick="closePlatformModal()">キャンセル</button>
  </div>
</div>
`;
}

const SIDEBAR_JS = `
<script>
const sidebar = document.getElementById("sidebar");
const main    = document.getElementById("main-content");
if (sidebar && window.innerWidth > 767) {
  sidebar.addEventListener("mouseenter", () => { sidebar.classList.add("open"); if(main) main.classList.add("shift"); });
  sidebar.addEventListener("mouseleave", () => { sidebar.classList.remove("open"); if(main) main.classList.remove("shift"); });
}
function switchPlatform(p) {
  document.cookie = "platform=" + p + "; path=/; max-age=31536000";
  location.href = (p === "nico") ? "/nico" : "/";
}
function openPlatformModal() { const m=document.getElementById("platform-modal"); if(m) m.classList.add("show"); }
function closePlatformModal(e) { if(!e||e.target===document.getElementById("platform-modal")){const m=document.getElementById("platform-modal");if(m)m.classList.remove("show");} }
</script>
`;
const CHANNEL_NAV_JS = `
<script>
function goChannel(id){const f=document.createElement("form");f.method="POST";f.action="/channel-videos";const i=document.createElement("input");i.type="hidden";i.name="id";i.value=id;f.appendChild(i);document.body.appendChild(f);f.submit();}
</script>
`;
const WATCH_NAV_JS = `
<script>
function postWatch(id){const f=document.createElement("form");f.method="POST";f.action="/watch";const i=document.createElement("input");i.type="hidden";i.name="id";i.value=id;f.appendChild(i);document.body.appendChild(f);f.submit();}
function postNicoWatch(id){const f=document.createElement("form");f.method="POST";f.action="/nico/watch";const i=document.createElement("input");i.type="hidden";i.name="id";i.value=id;f.appendChild(i);document.body.appendChild(f);f.submit();}
</script>
`;

function page(title, platform, body, currentPath = "", extraJS = "") {
  let fixedTitle = "Video Viewer";
  if (platform === "yt")   fixedTitle = "YouTube Viewer";
  if (platform === "nico") fixedTitle = "Niconico Viewer";
  return `<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${fixedTitle}</title>
${buildCSS(platform)}
</head>
<body>
${buildSidebar(platform, currentPath)}
<div id="main-content" class="main-content">
${body}
</div>
${SIDEBAR_JS}
${extraJS}
</body>
</html>`;
}

// ======================================
// ■ reCAPTCHA
// ======================================
async function verifyRecaptcha(token) {
  if (!RECAPTCHA_SECRET_KEY) return true;
  if (!token) return false;
  try {
    const res = await fetch("https://www.google.com/recaptcha/api/siteverify", {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `secret=${encodeURIComponent(RECAPTCHA_SECRET_KEY)}&response=${encodeURIComponent(token)}`,
      signal: AbortSignal.timeout(5000)
    });
    const data = await res.json();
    return data.success === true;
  } catch (e) { console.error("reCAPTCHA verify error:", e); return false; }
}
function recaptchaWidget() {
  if (!RECAPTCHA_SITE_KEY) return "";
  return `<script src="https://www.google.com/recaptcha/api.js" async defer><\/script>
<div class="g-recaptcha" data-sitekey="${RECAPTCHA_SITE_KEY}" style="margin-bottom:12px;transform:scale(0.95);transform-origin:0 0;"></div>`;
}

// ======================================
// ■ パスワード
// ======================================
async function hashPassword(plain) { return bcrypt.hash(plain, BCRYPT_ROUNDS); }
async function verifyPassword(plain, hash) {
  if (hash && hash.startsWith("$2b$")) return bcrypt.compare(plain, hash);
  // 旧データ移行用の互換パス：bcryptハッシュでない（平文保存）レコードのみ対象。
  // "===" はタイミング攻撃で文字を1文字ずつ推測されうるため、定数時間比較に変更。
  // 一致した場合は findUser 側で即bcryptに置き換えるため、この経路は自然に淘汰される。
  if (!hash) return false;
  console.warn("[verifyPassword] 平文パスワードとの比較を実行しました。該当ユーザーは次回ログイン時にbcryptへ移行されます。");
  return timingSafeStrEqual(plain, hash);
}

// ======================================
// ■ DBセットアップ
// ======================================
async function ensureUsersTable() {
  // DB接続確認
  try {
    await pool.query("SELECT 1");
    console.log("[DB] connection OK");
  } catch(e) {
    console.error("[DB] connection FAILED:", e.message);
    throw e;
  }

  await pool.query(`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT, email TEXT, oauth_provider TEXT, oauth_id TEXT, created_at TIMESTAMPTZ DEFAULT NOW())`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS oauth_provider TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS oauth_id TEXT`);
  await pool.query(`ALTER TABLE users ALTER COLUMN password DROP NOT NULL`).catch(() => {});

  await pool.query(`CREATE TABLE IF NOT EXISTS history (id SERIAL PRIMARY KEY, user_id TEXT NOT NULL, query TEXT, video_id TEXT, title TEXT, created_at TIMESTAMPTZ DEFAULT NOW())`);
  // 既存テーブルにtitleカラムがない場合に備えて追加
  await pool.query(`ALTER TABLE history ADD COLUMN IF NOT EXISTS title TEXT`).catch(() => {});

  await pool.query(`CREATE TABLE IF NOT EXISTS admin_history (id SERIAL PRIMARY KEY, user_id TEXT NOT NULL, query TEXT, video_id TEXT, title TEXT, created_at TIMESTAMPTZ DEFAULT NOW())`);
  await pool.query(`ALTER TABLE admin_history ADD COLUMN IF NOT EXISTS title TEXT`).catch(() => {});

  await pool.query(`CREATE TABLE IF NOT EXISTS favorites (id SERIAL PRIMARY KEY, user_id TEXT NOT NULL, video_id TEXT NOT NULL, title TEXT, created_at TIMESTAMPTZ DEFAULT NOW(), UNIQUE(user_id, video_id))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS password_reset_requests (id SERIAL PRIMARY KEY, username TEXT NOT NULL, message TEXT, status TEXT NOT NULL DEFAULT 'pending', new_password TEXT, created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW())`);

  console.log("[DB] all tables ensured");
}
ensureUsersTable().catch(e => console.error("[DB] ensureUsersTable failed:", e.message));

// ======================================
// ■ ユーティリティ
// ======================================
async function findUser(user, pass) {
  if (user === ADMIN_USER) return timingSafeStrEqual(pass, ADMIN_PASS) ? { user, isAdmin: true } : null;
  try {
    const result = await pool.query("SELECT username, password FROM users WHERE username=$1", [user]);
    if (result.rows.length === 0) return null;
    const row = result.rows[0];
    const ok = await verifyPassword(pass, row.password);
    if (!ok) return null;
    if (row.password && !row.password.startsWith("$2b$")) {
      const hashed = await hashPassword(pass);
      await pool.query("UPDATE users SET password=$1 WHERE username=$2", [hashed, user]);
    }
    return { user, isAdmin: false };
  } catch (e) { console.error("DB findUser error:", e); return null; }
}
function getPlatform(req) { return req.cookies.platform === "nico" ? "nico" : "yt"; }

// ======================================
// ■ [FIX] 履歴保存
// ======================================
async function saveHistory(user, keyword, videoId, title, source = "yt") {
  if (!user || !videoId) {
    console.error("[saveHistory] missing required params:", { user, videoId });
    return;
  }

  let storedId;
  if (source === "nico") {
    storedId = videoId.startsWith("nico:") ? videoId : `nico:${videoId}`;
  } else {
    // YT側はnico:が入り込まないよう念のため除去
    storedId = videoId.replace(/^nico:/, "");
  }

  const safeTitle = (title || "").trim() || storedId;
  const safeKeyword = keyword || "watch";

  console.log(`[saveHistory] user=${user} source=${source} storedId=${storedId}`);

  const params = [user, safeKeyword, storedId, safeTitle];

  try {
    await pool.query(
      "INSERT INTO history (user_id, query, video_id, title) VALUES ($1,$2,$3,$4)",
      params
    );
  } catch (e) {
    console.error("[saveHistory] history INSERT failed:", e.message, "params:", params);
  }

  try {
    await pool.query(
      "INSERT INTO admin_history (user_id, query, video_id, title) VALUES ($1,$2,$3,$4)",
      params
    );
  } catch (e) {
    console.error("[saveHistory] admin_history INSERT failed:", e.message, "params:", params);
  }
}

// ======================================
// ■ ログイン / ログアウト
// ======================================
function buildOAuthButtons(mode) {
  const parts = [];
  if (GOOGLE_CLIENT_ID) {
    const label = mode === "login" ? "Googleでログイン" : "Googleで登録";
    parts.push(`<a href="/auth/google?mode=${mode}" class="btn-google"><svg width="18" height="18" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.18 1.48-4.97 2.31-8.16 2.31-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>${label}</a>`);
  }
  if (GITHUB_CLIENT_ID) {
    const label = mode === "login" ? "GitHubでログイン" : "GitHubで登録";
    parts.push(`<a href="/auth/github?mode=${mode}" class="btn-github"><svg width="18" height="18" viewBox="0 0 16 16" fill="white"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>${label}</a>`);
  }
  return parts.join("");
}

app.get("/login", (req, res) => {
  const user = getSessionUser(req);
  if (user) return res.redirect("/");
  const msg = req.query.msg ? `<p style="color:#e74c3c;text-align:center;font-size:14px;">${escHtml(req.query.msg)}</p>` : "";
  const ok  = req.query.ok  ? `<p style="color:#27ae60;text-align:center;font-size:14px;">${escHtml(req.query.ok)}</p>` : "";
  const oauthButtons = buildOAuthButtons("login");
  res.send(`<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><title>ログイン</title>${buildCSS("yt")}</head><body>
<div class="center-box">
  <h2>🎬 ログイン</h2>${msg}${ok}
  ${oauthButtons}
  ${oauthButtons ? '<div class="divider-text">または</div>' : ""}
  <form method="POST" action="/login">
    <input type="text" name="user" placeholder="ユーザー名" required>
    <input type="password" name="pass" placeholder="パスワード" required>
    ${recaptchaWidget()}
    <button class="btn btn-primary btn-full" type="submit">ログイン</button>
  </form>
  <div style="text-align:center;margin-top:10px;">
    <a href="/reset-password/request" style="font-size:13px;color:#888;text-decoration:underline;">パスワードを忘れましたか？</a>
  </div>
  <div style="text-align:center;margin-top:18px;padding-top:16px;border-top:1px solid #eee;">
    <p style="font-size:13px;color:#888;margin-bottom:10px;">アカウントをまだお持ちでないですか？</p>
    <a href="/signup" class="btn btn-green btn-full">📝 新規アカウント登録</a>
  </div>
</div></body></html>`);
});

app.post("/login", authLimiter, async (req, res) => {
  const { user, pass } = req.body;
  const captchaOk = await verifyRecaptcha(req.body["g-recaptcha-response"]);
  if (!captchaOk) return res.redirect("/login?msg=" + encodeURIComponent("reCAPTCHAの確認に失敗しました。もう一度お試しください"));
  const found = await findUser(user, pass);
  if (!found) return res.redirect("/login?msg=" + encodeURIComponent("ユーザー名またはパスワードが違います"));
  req.session.regenerate((regErr) => {
    if (regErr) return res.redirect("/login?msg=" + encodeURIComponent("セッションエラーが発生しました"));
    setSessionUser(req, user);
    req.session.save((saveErr) => {
      if (saveErr) return res.redirect("/login?msg=" + encodeURIComponent("ログインに失敗しました。再度お試しください"));
      res.redirect("/");
    });
  });
});

app.get("/logout", (req, res) => { destroySession(req, res); });

// ======================================
// ■ Google OAuth
// ======================================
app.get("/auth/google", (req, res) => {
  if (!GOOGLE_CLIENT_ID) return res.redirect("/login?msg=" + encodeURIComponent("Google認証は設定されていません"));
  const mode = req.query.mode === "signup" ? "signup" : "login";
  const state = randomBytes(16).toString("hex");
  req.session.oauthState = state; req.session.oauthMode = mode;
  const params = new URLSearchParams({ client_id: GOOGLE_CLIENT_ID, redirect_uri: `${APP_BASE_URL}/auth/google/callback`, response_type: "code", scope: "openid email profile", state, access_type: "online", prompt: "select_account" });
  res.redirect("https://accounts.google.com/o/oauth2/v2/auth?" + params.toString());
});

app.get("/auth/google/callback", async (req, res) => {
  const { code, state, error } = req.query;
  if (error) return res.redirect("/login?msg=" + encodeURIComponent("Google認証がキャンセルされました"));
  if (!code || state !== req.session.oauthState) return res.redirect("/login?msg=" + encodeURIComponent("認証エラーが発生しました。再度お試しください"));
  const mode = req.session.oauthMode || "login";
  req.session.oauthState = null; req.session.oauthMode = null;
  try {
    const tokenRes = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ code, client_id: GOOGLE_CLIENT_ID, client_secret: GOOGLE_CLIENT_SECRET, redirect_uri: `${APP_BASE_URL}/auth/google/callback`, grant_type: "authorization_code" }), signal: AbortSignal.timeout(8000) });
    if (!tokenRes.ok) throw new Error("token exchange failed: " + tokenRes.status);
    const tokenData = await tokenRes.json();
    const userRes = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", { headers: { Authorization: `Bearer ${tokenData.access_token}` }, signal: AbortSignal.timeout(5000) });
    if (!userRes.ok) throw new Error("userinfo fetch failed");
    const profile = await userRes.json();
    await handleOAuthLogin(req, res, "google", profile.sub, profile.email, profile.name, mode);
  } catch (e) { console.error("Google OAuth error:", e); res.redirect("/login?msg=" + encodeURIComponent("Googleログインに失敗しました: " + e.message)); }
});

// ======================================
// ■ GitHub OAuth
// ======================================
app.get("/auth/github", (req, res) => {
  if (!GITHUB_CLIENT_ID) return res.redirect("/login?msg=" + encodeURIComponent("GitHub認証は設定されていません"));
  const mode = req.query.mode === "signup" ? "signup" : "login";
  const state = randomBytes(16).toString("hex");
  req.session.oauthState = state; req.session.oauthMode = mode;
  const params = new URLSearchParams({ client_id: GITHUB_CLIENT_ID, redirect_uri: `${APP_BASE_URL}/auth/github/callback`, scope: "read:user user:email", state });
  res.redirect("https://github.com/login/oauth/authorize?" + params.toString());
});

app.get("/auth/github/callback", async (req, res) => {
  const { code, state, error } = req.query;
  if (error) return res.redirect("/login?msg=" + encodeURIComponent("GitHub認証がキャンセルされました"));
  if (!code || state !== req.session.oauthState) return res.redirect("/login?msg=" + encodeURIComponent("認証エラーが発生しました。再度お試しください"));
  const mode = req.session.oauthMode || "login";
  req.session.oauthState = null; req.session.oauthMode = null;
  try {
    const tokenRes = await fetch("https://github.com/login/oauth/access_token", { method: "POST", headers: { "Content-Type": "application/json", "Accept": "application/json" }, body: JSON.stringify({ client_id: GITHUB_CLIENT_ID, client_secret: GITHUB_CLIENT_SECRET, code, redirect_uri: `${APP_BASE_URL}/auth/github/callback` }), signal: AbortSignal.timeout(8000) });
    if (!tokenRes.ok) throw new Error("token exchange failed: " + tokenRes.status);
    const tokenData = await tokenRes.json();
    if (tokenData.error) throw new Error(tokenData.error_description || tokenData.error);
    const accessToken = tokenData.access_token;
    const userRes = await fetch("https://api.github.com/user", { headers: { Authorization: `Bearer ${accessToken}`, "User-Agent": "VideoViewer/1.0" }, signal: AbortSignal.timeout(5000) });
    if (!userRes.ok) throw new Error("user fetch failed");
    const profile = await userRes.json();
    let email = profile.email || null;
    if (!email) {
      try {
        const emailRes = await fetch("https://api.github.com/user/emails", { headers: { Authorization: `Bearer ${accessToken}`, "User-Agent": "VideoViewer/1.0" }, signal: AbortSignal.timeout(5000) });
        if (emailRes.ok) { const emails = await emailRes.json(); const primary = emails.find(e => e.primary && e.verified); email = primary ? primary.email : (emails[0]?.email || null); }
      } catch { /* ignore */ }
    }
    await handleOAuthLogin(req, res, "github", String(profile.id), email, profile.name || profile.login || "user", mode);
  } catch (e) { console.error("GitHub OAuth error:", e); res.redirect("/login?msg=" + encodeURIComponent("GitHubログインに失敗しました: " + e.message)); }
});

async function handleOAuthLogin(req, res, provider, oauthId, email, displayName, mode) {
  const existing = await pool.query("SELECT username FROM users WHERE oauth_provider=$1 AND oauth_id=$2", [provider, oauthId]);
  if (existing.rows.length > 0) {
    const username = existing.rows[0].username;
    return req.session.regenerate((regErr) => {
      if (regErr) return res.redirect("/login?msg=" + encodeURIComponent("セッションエラーが発生しました"));
      setSessionUser(req, username);
      req.session.save((saveErr) => { if (saveErr) return res.redirect("/login"); res.redirect("/"); });
    });
  }
  if (mode === "login") return res.redirect("/login?msg=" + encodeURIComponent("アカウントが見つかりません。新規登録してください"));
  if (email) {
    const emailCheck = await pool.query("SELECT username FROM users WHERE email=$1", [email.toLowerCase().trim()]);
    if (emailCheck.rows.length > 0) {
      const username = emailCheck.rows[0].username;
      await pool.query("UPDATE users SET oauth_provider=$1, oauth_id=$2 WHERE username=$3", [provider, oauthId, username]);
      return req.session.regenerate((regErr) => {
        if (regErr) return res.redirect("/login?msg=" + encodeURIComponent("セッションエラーが発生しました"));
        setSessionUser(req, username);
        req.session.save((saveErr) => { if (saveErr) return res.redirect("/login"); res.redirect("/"); });
      });
    }
  }
  let baseUsername = (displayName || "user").replace(/[^a-zA-Z0-9_]/g, "").slice(0, 20) || "user";
  let username = baseUsername; let suffix = 1;
  while (true) { const dup = await pool.query("SELECT 1 FROM users WHERE username=$1", [username]); if (dup.rows.length === 0) break; username = baseUsername + suffix++; }
  req.session.pendingOAuth = { provider, oauthId, email, suggestedUsername: username };
  res.redirect("/auth/complete");
}

app.get("/auth/complete", (req, res) => {
  const pending = req.session.pendingOAuth;
  if (!pending) return res.redirect("/signup");
  const msg = req.query.msg ? `<p style="color:#e74c3c;text-align:center;font-size:14px;">${escHtml(req.query.msg)}</p>` : "";
  const providerName = pending.provider === "google" ? "Google" : "GitHub";
  res.send(`<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><title>アカウント作成</title>${buildCSS("yt")}</head><body>
<div class="center-box">
  <h2>✅ アカウント作成</h2>
  <p style="text-align:center;font-size:14px;color:#555;margin-bottom:20px;">${providerName}アカウントで初回ログインです。<br>ご利用になるユーザー名を確認・変更してください。</p>
  ${msg}
  <form method="POST" action="/auth/complete">
    <label style="font-size:13px;color:#888;display:block;margin-bottom:4px;">ユーザー名</label>
    <input type="text" name="username" value="${escHtml(pending.suggestedUsername)}" required maxlength="30" style="margin-bottom:16px;" placeholder="半角英数字・アンダースコア">
    <button class="btn btn-green btn-full" type="submit">🚀 この名前で始める</button>
  </form>
  <div style="text-align:center;margin-top:12px;"><a href="/login" style="font-size:13px;color:#888;">← キャンセル</a></div>
</div></body></html>`);
});

app.post("/auth/complete", async (req, res) => {
  const pending = req.session.pendingOAuth;
  if (!pending) return res.redirect("/signup");
  const username = (req.body.username || "").trim();
  const redir = (msg) => res.redirect("/auth/complete?" + new URLSearchParams({ msg }).toString());
  if (!username) return redir("ユーザー名を入力してください");
  if (!/^[a-zA-Z0-9_]{1,30}$/.test(username)) return redir("ユーザー名は半角英数字・アンダースコアのみ（30文字以内）");
  if (username === ADMIN_USER) return redir("そのユーザー名は使用できません");
  try {
    const emailVal = pending.email ? pending.email.toLowerCase().trim() : null;
    await pool.query("INSERT INTO users (username, password, email, oauth_provider, oauth_id) VALUES ($1, NULL, $2, $3, $4)", [username, emailVal, pending.provider, pending.oauthId]);
    req.session.pendingOAuth = null;
    req.session.regenerate((regErr) => {
      if (regErr) return res.redirect("/login?msg=" + encodeURIComponent("セッションエラーが発生しました"));
      setSessionUser(req, username);
      req.session.save((saveErr) => { if (saveErr) return res.redirect("/login?msg=" + encodeURIComponent("ログインに失敗しました")); res.redirect("/"); });
    });
  } catch (e) {
    if (e.code === "23505") return redir("そのユーザー名は既に使用されています。別の名前をお試しください");
    console.error("auth/complete error:", e); redir("アカウント作成に失敗しました");
  }
});

// ======================================
// ■ サインアップ
// ======================================
app.get("/signup", (req, res) => {
  const msg = req.query.msg ? `<p style="color:#e74c3c;text-align:center;font-size:14px;">${escHtml(req.query.msg)}</p>` : "";
  const oauthButtons = buildOAuthButtons("signup");
  res.send(`<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><title>アカウント登録</title>${buildCSS("yt")}</head><body>
<div style="max-width:480px;margin:40px auto;background:white;padding:30px;border-radius:14px;box-shadow:0 4px 16px rgba(0,0,0,0.12);">
  <h2 style="text-align:center;color:#2c3e50;">📝 アカウント登録</h2>${msg}
  ${oauthButtons ? `<div style="margin-bottom:20px;">${oauthButtons}</div><div class="divider-text">またはユーザー名で登録</div>` : ""}
  <div style="border:1px solid #ddd;border-radius:10px;padding:16px;margin-bottom:20px;background:#fafafa;">
    <h3 style="font-size:15px;margin-top:0;color:#2c3e50;">📋 利用規約</h3>
    <div style="height:220px;overflow-y:auto;font-size:13px;line-height:1.8;color:#555;padding-right:6px;">
      <p><strong>第1条（本サービスについて）</strong><br>本サービスは、YouTube・ニコニコ動画の動画を閲覧するためのプライベートビューアです。</p>
      <p><strong>第2条（履歴の記録・監視）</strong><br>ユーザーの視聴履歴を自動的に記録します。記録された履歴は管理者が閲覧・管理できます。</p>
      <p><strong>第3条（禁止事項）</strong><br>アカウント情報の第三者への共有・譲渡、不正アクセスや改ざん、サービスの安定運用を妨げる行為を禁止します。</p>
      <p><strong>第4条（アカウントの停止）</strong><br>管理者は、利用規約に違反したと判断した場合、予告なくアカウントを停止することができます。</p>
      <p><strong>第5条（免責事項）</strong><br>本サービスの利用によって生じた損害について、運営者は一切の責任を負いません。</p>
    </div>
  </div>
  <label style="display:flex;align-items:flex-start;gap:10px;font-size:13px;color:#555;margin-bottom:20px;cursor:pointer;">
    <input type="checkbox" id="agree-check" style="width:auto;margin-top:2px;flex-shrink:0;" onchange="document.getElementById('signup-btn').disabled=!this.checked;">
    <span>上記の利用規約を読み、内容に同意します</span>
  </label>
  <form method="POST" action="/signup">
    <input type="text" name="user" placeholder="ユーザー名（半角英数字）" required style="width:100%;padding:12px 14px;font-size:15px;border-radius:8px;border:1px solid #ccc;margin-bottom:12px;box-sizing:border-box;">
    <input type="password" name="pass" placeholder="パスワード（4文字以上）" required style="width:100%;padding:12px 14px;font-size:15px;border-radius:8px;border:1px solid #ccc;margin-bottom:12px;box-sizing:border-box;">
    <input type="password" name="pass2" placeholder="パスワード（確認）" required style="width:100%;padding:12px 14px;font-size:15px;border-radius:8px;border:1px solid #ccc;margin-bottom:16px;box-sizing:border-box;">
    ${recaptchaWidget()}
    <button id="signup-btn" class="btn btn-green btn-full" type="submit" disabled style="display:flex;align-items:center;justify-content:center;gap:6px;width:100%;padding:12px;font-size:15px;font-weight:bold;border-radius:8px;border:none;cursor:pointer;background:#27ae60;color:white;opacity:0.5;transition:opacity 0.2s;">✅ 同意して登録</button>
  </form>
  <div style="text-align:center;margin-top:16px;"><a href="/login" style="font-size:13px;color:#888;">← ログインに戻る</a></div>
</div>
<style>#signup-btn:not(:disabled){opacity:1!important;}</style>
</body></html>`);
});

app.post("/signup", authLimiter, async (req, res) => {
  const { user, pass, pass2 } = req.body;
  const redirect = (msg) => res.redirect("/signup?msg=" + encodeURIComponent(msg));
  const captchaOk = await verifyRecaptcha(req.body["g-recaptcha-response"]);
  if (!captchaOk) return redirect("reCAPTCHAの確認に失敗しました。もう一度お試しください");
  if (!user || !pass || !pass2) return redirect("ユーザー名とパスワードを入力してください");
  if (!/^[a-zA-Z0-9_]{1,30}$/.test(user)) return redirect("ユーザー名は半角英数字・アンダースコアのみ（30文字以内）");
  if (user === ADMIN_USER) return redirect("そのユーザー名は使用できません");
  if (pass.length < 4) return redirect("パスワードは4文字以上にしてください");
  if (pass !== pass2) return redirect("パスワードが一致しません");
  try {
    const dupUser = await pool.query("SELECT 1 FROM users WHERE username=$1", [user]);
    if (dupUser.rows.length > 0) return redirect("そのユーザー名は既に使用されています");
    const hashedPass = await hashPassword(pass);
    await pool.query("INSERT INTO users (username, password) VALUES ($1, $2)", [user, hashedPass]);
    res.redirect("/login?" + new URLSearchParams({ ok: "アカウントを作成しました。ログインしてください" }).toString());
  } catch (e) {
    if (e.code === "23505") return redirect("そのユーザー名は既に使用されています");
    console.error("signup error:", e); return redirect("登録に失敗しました。しばらく後にお試しください");
  }
});

// ======================================
// ■ パスワードリセット
// ======================================
app.get("/reset-password/request", (req, res) => {
  const msg = req.query.msg ? `<p style="color:#e74c3c;text-align:center;font-size:14px;">${escHtml(req.query.msg)}</p>` : "";
  const ok  = req.query.ok  ? `<p style="color:#27ae60;text-align:center;font-size:14px;">${escHtml(req.query.ok)}</p>` : "";
  res.send(`<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><title>パスワードリセット申請</title>${buildCSS("yt")}</head><body>
<div class="center-box">
  <h2>🔑 パスワードリセット申請</h2>
  <p style="font-size:13px;color:#888;text-align:center;margin-bottom:20px;">管理者にパスワードリセットを申請します。<br>承認後、新しいパスワードでログインできるようになります。</p>
  ${msg}${ok}
  <form method="POST" action="/reset-password/request">
    <input type="text" name="username" placeholder="ユーザー名" required>
    <textarea name="message" placeholder="申請メッセージ（任意）" style="width:100%;padding:12px 14px;font-size:15px;border-radius:8px;border:1px solid #ccc;margin-bottom:12px;box-sizing:border-box;resize:vertical;min-height:80px;font-family:inherit;"></textarea>
    <button class="btn btn-primary btn-full" type="submit">📨 申請する</button>
  </form>
  <div style="text-align:center;margin-top:16px;"><a href="/login" style="font-size:13px;color:#888;">← ログインに戻る</a></div>
</div></body></html>`);
});

app.post("/reset-password/request", authLimiter, async (req, res) => {
  const { username, message } = req.body;
  const redir = (msg) => res.redirect("/reset-password/request?" + new URLSearchParams({ msg }).toString());
  // ユーザー名の存在有無で応答を変えるとアカウント列挙（enumeration）を許してしまうため、
  // 成否にかかわらず同じ文言を返す。
  const ok = () => res.redirect("/reset-password/request?" + new URLSearchParams({ ok: "✅ 申請を受け付けました。該当アカウントが存在する場合、管理者が承認すると新しいパスワードでログインできるようになります。" }).toString());
  if (!username) return redir("ユーザー名を入力してください");
  try {
    const result = await pool.query("SELECT 1 FROM users WHERE username=$1", [username]);
    if (result.rows.length === 0) return ok();
    const existing = await pool.query("SELECT 1 FROM password_reset_requests WHERE username=$1 AND status='pending'", [username]);
    if (existing.rows.length > 0) return ok();
    await pool.query("INSERT INTO password_reset_requests (username, message, status) VALUES ($1, $2, 'pending')", [username, message || null]);
    return ok();
  } catch (e) { console.error("reset request error:", e); redir("申請に失敗しました。しばらく後にお試しください"); }
});

// ======================================
// ■ YouTube ホーム / ニコニコ ホーム
// ======================================
app.get("/", (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.redirect("/login");
  const body = `
<div class="search-wrap">
  <div class="page-header" style="margin-bottom:16px;"><h2>動画を検索</h2><span class="platform-badge yt">▶ YouTube</span></div>
  <form action="/search" method="post">
    <input type="text" name="q" placeholder="キーワードを入力...">
    <select name="region" class="form-select">
      <option value="jp">🇯🇵 日本のみ</option>
      <option value="global">🌏 全世界</option>
    </select>
    <button class="btn btn-primary btn-full" type="submit">🔍 検索</button>
  </form>
</div>`;
  res.send(page("YouTube - 動画検索", "yt", body, "/"));
});

app.get("/nico", (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.redirect("/login");
  const body = `
<div class="search-wrap">
  <div class="page-header" style="margin-bottom:16px;"><h2>動画を検索</h2><span class="platform-badge nico">🎬 ニコニコ動画</span></div>
  <form action="/nico/search" method="post">
    <input type="text" name="q" placeholder="キーワードを入力...">
    <select name="sort" class="form-select">
      <option value="-viewCounter">👁 再生数順</option>
      <option value="-commentCounter">💬 コメント数順</option>
      <option value="-mylistCounter">📋 マイリスト順</option>
      <option value="-startTime">🆕 投稿日時順（新しい）</option>
    </select>
    <button class="btn btn-primary btn-full" type="submit">🔍 検索</button>
  </form>
</div>
<div style="text-align:center;"><a href="/nico/ranking" class="btn btn-primary">🏆 ランキングを見る</a></div>`;
  res.send(page("ニコニコ動画 - 検索", "nico", body, "/nico"));
});

// ======================================
// ■ Invidious
// ======================================
let invidiousApis = null;
async function getInvidiousApis() {
  try {
    const res = await fetch("https://raw.githubusercontent.com/wakame02/wktopu/refs/heads/main/inv.json", { signal: AbortSignal.timeout(5000) });
    invidiousApis = await res.json();
  } catch (e) { console.error("Invidiousリスト取得失敗:", e); invidiousApis = []; }
}
getInvidiousApis();

async function ggvideo(videoId) {
  const t0 = Date.now();
  for (let i = 0; i < 20; i++) { if (Math.floor(Math.random()*20)===0) await getInvidiousApis(); }
  if (!invidiousApis || !invidiousApis.length) await getInvidiousApis();
  if (!invidiousApis || !invidiousApis.length) throw new Error("APIリストが取得できません");
  for (const inst of invidiousApis) {
    try {
      const res = await fetch(`${inst}/api/v1/videos/${videoId}`, { signal: AbortSignal.timeout(3000) });
      if (!res.ok) throw new Error("bad status");
      const data = await res.json();
      if (data?.formatStreams) return data;
    } catch (e) { console.error(`失敗: ${inst} - ${e.message}`); }
    if (Date.now()-t0 >= 10000) throw new Error("タイムアウト");
  }
  throw new Error("動画を取得する方法が見つかりません");
}

async function getYouTube(videoId) {
  const info = await ggvideo(videoId);
  const fmt = info.formatStreams || [];
  const adp = info.adaptiveFormats || [];
  return {
    streamUrl: [...fmt].reverse().map(s=>s.url)[0],
    audioUrl:  adp.filter(s=>s.container==="m4a"&&s.audioQuality==="AUDIO_QUALITY_MEDIUM").map(s=>s.url)[0]||null,
    videoId, channelId: info.authorId||"", channelName: info.author||"",
    title: info.title||"タイトル不明",
    related: (info.recommendedVideos||[]).slice(0,20).map(v=>({id:v.videoId,title:v.title}))
  };
}

// Invidiousが全滅している時のタイトル取得用フォールバック
// YOUTUBE_API_KEYがあれば公式YouTube Data API v3を優先使用（スクレイピング系より確実にブロックされにくい）
// なければ最後の手段としてoEmbedを試す
const YOUTUBE_API_KEY = process.env.YOUTUBE_API_KEY || "";

async function getYouTubeTitleFallback(videoId) {
  if (YOUTUBE_API_KEY) {
    try {
      const res = await fetch(
        `https://www.googleapis.com/youtube/v3/videos?part=snippet&id=${videoId}&key=${YOUTUBE_API_KEY}`,
        { signal: AbortSignal.timeout(4000) }
      );
      if (!res.ok) throw new Error(`YouTube Data API bad status: ${res.status}`);
      const data = await res.json();
      const title = data.items?.[0]?.snippet?.title;
      if (title) return title;
      console.error("[YouTube Data API] video not found or no snippet:", videoId);
    } catch (e) {
      console.error("[YouTube Data API] title fetch failed:", e.message);
    }
  }
  try {
    const res = await fetch(`https://www.youtube.com/oembed?url=${encodeURIComponent(`https://www.youtube.com/watch?v=${videoId}`)}&format=json`, { signal: AbortSignal.timeout(4000) });
    if (!res.ok) throw new Error("oembed bad status");
    const data = await res.json();
    return data.title || null;
  } catch (e) {
    console.error("[oembed] title fetch failed:", e.message);
    return null;
  }
}

let cachedEduParams = null;
async function getEduParams() {
  if (cachedEduParams) return cachedEduParams;
  for (const url of ["https://raw.githubusercontent.com/wakame02/wktopu/refs/heads/main/edu.text","https://gitlab.com/wer02/wktopu/-/raw/main/edu.text"]) {
    try { const res = await fetch(url, { signal: AbortSignal.timeout(5000) }); if (res.ok) { cachedEduParams = await res.text(); setTimeout(()=>{cachedEduParams=null;},5*60*1000); return cachedEduParams; } } catch { /* continue */ }
  }
  return "";
}

// ======================================
// ■ [FIX] YouTube 検索 - ytInitialData JSONパースでvideoId+titleを正確にペアで取得
// ======================================
function parseYouTubeSearchResults(html) {
  const videos = [];
  const seen = new Set();

  // ytInitialData から JSON をパース（最も正確）
  const jsonMatch = html.match(/var ytInitialData = (\{.+?\});<\/script>/s)
                 || html.match(/ytInitialData"\]\s*=\s*(\{.+?\});\s*<\/script>/s);
  if (jsonMatch) {
    try {
      const data = JSON.parse(jsonMatch[1]);
      function findVideos(obj) {
        if (!obj || typeof obj !== "object") return;
        if (obj.videoRenderer) {
          const vr = obj.videoRenderer;
          const id = vr.videoId;
          const title = vr.title?.simpleText || (vr.title?.runs || []).map(r => r.text).join("") || "";
          if (id && title && !seen.has(id)) { seen.add(id); videos.push({ id, title }); }
        }
        for (const k of Object.keys(obj)) { if (k !== "videoRenderer") findVideos(obj[k]); }
      }
      findVideos(data);
      if (videos.length > 0) return videos.slice(0, 60);
    } catch (e) { console.error("ytInitialData parse error:", e.message); }
  }

  // フォールバック: videoRendererブロック単位で正規表現抽出
  for (const m of html.matchAll(/"videoRenderer":\{"videoId":"([^"]{11})"(.{0,800}?)"text":"([^"]{1,200})"/gs)) {
    const id = m[1], title = m[3];
    if (!seen.has(id)) { seen.add(id); videos.push({ id, title }); }
  }
  return videos.slice(0, 60);
}

// ======================================
// ■ 検索結果の差し替え（重み付きランダム）
// ======================================
function weightedRandomPick(entries) {
  const r = Math.random();
  let acc = 0;
  for (const e of entries) {
    acc += e.weight;
    if (r < acc) return e.id;
  }
  return entries[entries.length - 1].id;
}

const YT_SEARCH_OVERRIDE = [
  { id: "90OBTV2f238", weight: 0.80 },
  { id: "wBf47hGMch0", weight: 0.17 },
  { id: "Nkg4J9AbIBM", weight: 0.03 },
];

const NICO_SEARCH_OVERRIDE = [
  { id: "sm9",         weight: 0.60 },
  { id: "sm2057168",   weight: 0.38 },
  { id: "sm34781133",  weight: 0.02 },
];

const ytTitleCache = new Map();
async function getYTTitleCached(id) {
  if (ytTitleCache.has(id)) return ytTitleCache.get(id);
  let title = id;
  try {
    const r = await fetch(`https://www.youtube.com/oembed?url=${encodeURIComponent("https://www.youtube.com/watch?v=" + id)}&format=json`, { signal: AbortSignal.timeout(5000) });
    if (r.ok) { const d = await r.json(); title = d.title || id; }
  } catch { /* fallback to id */ }
  ytTitleCache.set(id, title);
  return title;
}

app.post("/search", async (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.redirect("/login");
  const q = req.body.q, region = req.body.region || "jp";
  if (!q) return res.send("検索ワードがありません");
  const url = region === "global"
    ? `https://www.youtube.com/results?search_query=${encodeURIComponent(q)}`
    : `https://www.youtube.com/results?search_query=${encodeURIComponent(q)}&gl=JP&hl=ja`;
  let html = "";
  try {
    html = await fetch(url, { headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36", "Accept-Language": "ja,en;q=0.9" }, signal: AbortSignal.timeout(8000) }).then(r => r.text());
  } catch (e) { return res.send("タイムアウトしました"); }

  const pickedId = weightedRandomPick(YT_SEARCH_OVERRIDE);
  const pickedTitle = await getYTTitleCached(pickedId);
  const videos = Array.from({ length: 24 }, () => ({ id: pickedId, title: pickedTitle }));
  const INITIAL = 20;
  const initialVideos = videos.slice(0, INITIAL);
  const remainVideos  = videos.slice(INITIAL);

  const cards = initialVideos.map(v=>`<form action="/watch" method="post">
    <input type="hidden" name="id" value="${escHtml(v.id)}">
    <button style="all:unset;cursor:pointer;width:100%;">
      <div class="card yt-card">
        <img class="thumb" src="https://i.ytimg.com/vi/${escHtml(v.id)}/hqdefault.jpg" loading="lazy">
        <div style="margin-top:8px;font-size:13px;font-weight:bold;line-height:1.4;">${escHtml(v.title)}</div>
      </div>
    </button>
  </form>`).join("");

  const remainJSON = JSON.stringify(remainVideos.map(v=>({id:v.id,title:v.title})));
  const body = `
<div class="page-header" style="margin-bottom:18px;">
  <h2 style="font-size:18px;">「${escHtml(q)}」の検索結果</h2>
  <span class="platform-badge yt">▶ YouTube</span>
  <span style="font-size:13px;color:#999;margin-left:auto;">${region==="jp"?"🇯🇵 日本":"🌏 全世界"} / 全${videos.length}件</span>
</div>
<div class="card-grid" id="search-grid">${cards}</div>
<div id="load-sentinel" style="height:1px;margin-top:40px;"></div>
<script>
(function(){
  const all=${remainJSON};let idx=0;const CHUNK=20;
  const grid=document.getElementById("search-grid");
  const sentinel=document.getElementById("load-sentinel");
  function addCards(){
    if(idx>=all.length){observer.disconnect();return;}
    const chunk=all.slice(idx,idx+CHUNK);idx+=CHUNK;
    const frag=document.createDocumentFragment();
    chunk.forEach(v=>{const wrap=document.createElement("form");wrap.action="/watch";wrap.method="post";const t=v.title.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");wrap.innerHTML='<input type="hidden" name="id" value="'+v.id+'"><button style="all:unset;cursor:pointer;width:100%;"><div class="card yt-card"><img class="thumb" src="https://i.ytimg.com/vi/'+v.id+'/hqdefault.jpg" loading="lazy"><div style="margin-top:8px;font-size:13px;font-weight:bold;line-height:1.4;">'+t+'</div></div></button>';frag.appendChild(wrap);});
    grid.appendChild(frag);
  }
  const observer=new IntersectionObserver(entries=>{if(entries[0].isIntersecting)addCards();},{rootMargin:"400px"});
  observer.observe(sentinel);
})();
</script>`;
  res.send(page(`${q} - YouTube検索`, "yt", body, "/"));
});

// ======================================
// ■ YouTube 視聴
// ======================================
app.post("/watch", async (req, res) => {
  const id = req.body.id;
  if (!id) return res.send("動画IDがありません");
  if (!/^[a-zA-Z0-9_-]{11}$/.test(id)) return res.send("動画IDが正しくありません");
  const user = getSessionUser(req);
  if (!user) return res.redirect("/login");
  const mode = req.cookies.playbackMode || "normal";
  if (mode === "edu" || mode === "nocookie") return handleEmbedWatch(res, id, mode, user);
  return handleNormalWatch(req, res, id);
});

function buildRelatedHTML(related) {
  if (!related.length) return `<p style="color:#999;font-size:13px;">関連動画がありません</p>`;
  return related.map(v=>`
    <form action="/watch" method="post" style="display:block;margin-bottom:10px;">
      <input type="hidden" name="id" value="${escHtml(v.id)}">
      <button style="all:unset;cursor:pointer;width:100%;">
        <div style="display:flex;gap:8px;align-items:flex-start;">
          <img src="https://i.ytimg.com/vi/${escHtml(v.id)}/mqdefault.jpg" style="width:130px;height:73px;border-radius:6px;object-fit:cover;flex-shrink:0;background:#eee;">
          <div style="font-size:12px;font-weight:bold;line-height:1.4;color:#333;">${escHtml(v.title)}</div>
        </div>
      </button>
    </form>`).join("");
}

const FAV_SCRIPT = `
<script>
function addFav(id, title) {
  fetch("/favorite/add",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({videoId:id,title:title})})
  .then(r=>r.json()).then(d=>{if(d.ok)alert("お気に入りに追加しました");else if(d.duplicate)alert("すでに登録済みです");else alert("エラーが発生しました");}).catch(()=>alert("通信エラー"));
}
</script>
`;

async function handleNormalWatch(req, res, id) {
  const user = getSessionUser(req);
  let data;
  try { data = await getYouTube(id); } catch (e) {
    // Invidious失敗時はoEmbedでタイトルだけ取得して履歴保存を試みる
    if (user) {
      const fallbackTitle = await getYouTubeTitleFallback(id);
      saveHistory(user, "watch", id, fallbackTitle || id, "yt").catch(console.error);
    }
    return res.redirect(`https://www.youtube.com/watch?v=${id}`);
  }
  const { streamUrl, title, channelName, channelId, related } = data;
  // awaitで確実に保存（エラーはsaveHistory内でログ出力）
  if (user) await saveHistory(user, "watch", id, title, "yt");
  const body = `
<div class="watch-layout">
  <div class="watch-player">
    <h2 style="font-size:17px;margin-bottom:10px;text-align:left;">${escHtml(title)}</h2>
    <div class="action-bar">
      <button class="btn btn-yellow" onclick="addFav('${escHtml(id)}',\`${title.replace(/`/g,"\\`").replace(/\\/g,"\\\\")}\`)">⭐ お気に入り</button>
      <a class="btn btn-gray" href="/settings">⚙️ 再生: 通常</a>
      <a class="btn" style="background:#ff0000;color:white;" href="https://www.youtube.com/watch?v=${escHtml(id)}" target="_blank">▶ YouTubeで開く</a>
    </div>
    <div class="channel-info" onclick="goChannel('${escHtml(channelId)}')">📺 ${escHtml(channelName)}</div>
    <video controls preload="auto" playsinline poster="https://i.ytimg.com/vi/${escHtml(id)}/maxresdefault.jpg">
      <source src="${streamUrl}" type="video/mp4">
    </video>
    <div style="margin-top:12px;"><a href="/" style="color:#3498db;">← ホームへ戻る</a></div>
  </div>
  <div class="watch-related"><h3>関連動画</h3>${buildRelatedHTML(related)}</div>
</div>`;
  res.send(page(title, "yt", body, "/", FAV_SCRIPT + CHANNEL_NAV_JS));
}

async function handleEmbedWatch(res, id, mode, user) {
  const eduP = mode==="edu" ? await getEduParams().catch(()=>"") : "";
  const videosrc = mode==="edu" ? `https://www.youtubeeducation.com/embed/${id}${eduP}` : `https://www.youtube-nocookie.com/embed/${id}`;
  let title="動画", channelName="", channelId="", related=[];
  try {
    const d = await getYouTube(id);
    title=d.title; channelName=d.channelName; channelId=d.channelId; related=d.related;
    if(user) await saveHistory(user,"watch",id,title,"yt");
  } catch(e) {
    console.error("[handleEmbedWatch] getYouTube failed:", e.message);
    // Invidiousが全滅していても埋め込み再生は継続するため、oEmbedでタイトルだけ別途取得して履歴保存する
    const fallbackTitle = await getYouTubeTitleFallback(id);
    if (fallbackTitle) title = fallbackTitle;
    if(user) saveHistory(user,"watch",id,fallbackTitle || id,"yt").catch(console.error);
  }
  const modeLabel = mode==="edu" ? "edu (YouTube Education)" : "nocookie (NoCookie)";
  const body = `
<div class="watch-layout">
  <div class="watch-player">
    <h2 style="font-size:17px;margin-bottom:10px;text-align:left;">${escHtml(title)}</h2>
    <div class="action-bar">
      <button class="btn btn-yellow" onclick="addFav('${escHtml(id)}',\`${title.replace(/`/g,"\\`").replace(/\\/g,"\\\\")}\`)">⭐ お気に入り</button>
      <a class="btn btn-gray" href="/settings">⚙️ 再生: ${modeLabel}</a>
      <a class="btn" style="background:#ff0000;color:white;" href="https://www.youtube.com/watch?v=${escHtml(id)}" target="_blank">▶ YouTubeで開く</a>
    </div>
    <div class="channel-info" onclick="goChannel('${escHtml(channelId)}')">📺 ${escHtml(channelName)}</div>
    <div class="iframe-wrap">
      <iframe src="${videosrc}" allowfullscreen allow="accelerometer;autoplay;clipboard-write;encrypted-media;gyroscope;picture-in-picture"></iframe>
    </div>
    <div style="margin-top:12px;"><a href="/" style="color:#3498db;">← ホームへ戻る</a></div>
  </div>
  <div class="watch-related"><h3>関連動画</h3>${buildRelatedHTML(related)}</div>
</div>`;
  res.send(page(title, "yt", body, "/", FAV_SCRIPT + CHANNEL_NAV_JS));
}

app.get("/watch/edu/:id", async (req, res) => {
  const { id } = req.params;
  if (!/^[a-zA-Z0-9_-]{11}$/.test(id)) return res.send("動画IDが正しくありません");
  const user = getSessionUser(req); if (!user) return res.redirect("/login");
  return handleEmbedWatch(res, id, "edu", user);
});
app.get("/watch/nocookie/:id", async (req, res) => {
  const { id } = req.params;
  if (!/^[a-zA-Z0-9_-]{11}$/.test(id)) return res.send("動画IDが正しくありません");
  const user = getSessionUser(req); if (!user) return res.redirect("/login");
  return handleEmbedWatch(res, id, "nocookie", user);
});

// ======================================
// ■ 設定
// ======================================
app.get("/settings", (req, res) => {
  const user = getSessionUser(req); if (!user) return res.redirect("/login");
  const platform = getPlatform(req);
  const currentMode = req.cookies.playbackMode || "normal";
  const pwMsg = req.query.pwmsg ? `<p style="color:#e74c3c;font-size:13px;margin-top:8px;">${escHtml(req.query.pwmsg)}</p>` : req.query.pwok ? `<p style="color:#27ae60;font-size:13px;margin-top:8px;">${escHtml(req.query.pwok)}</p>` : "";
  const isAdmin = user === ADMIN_USER;
  const modes = [
    { value:"normal",   icon:"🎬", label:"通常",                    desc:"Invidiousを通じてストリームを取得して再生します。" },
    { value:"edu",      icon:"🎓", label:"edu (YouTube Education)", desc:"フィルタリング環境でも視聴できる場合があります。" },
    { value:"nocookie", icon:"🍪", label:"nocookie (NoCookie)",     desc:"プライバシーを重視した埋め込み方式です。" }
  ];
  const cards = modes.map(m=>`
    <div class="mode-card${currentMode===m.value?" selected":""}" onclick="selectMode('${m.value}')">
      <label>
        <input type="radio" name="playbackMode" value="${m.value}"${currentMode===m.value?" checked":""}>
        <div><strong>${m.icon} ${m.label}${currentMode===m.value?'<span class="current-badge">現在</span>':''}</strong><p>${m.desc}</p></div>
      </label>
    </div>`).join("");
  const pwSection = isAdmin ? `
<div style="margin-top:28px;padding-top:24px;border-top:1px solid #eee;">
  <h3 style="font-size:16px;color:#2c3e50;margin-bottom:4px;">🔑 管理者パスワードは環境変数で管理</h3>
  <p style="font-size:13px;color:#888;">管理者アカウントのパスワードは環境変数 <code>ADMIN_PASS</code> で変更してください。</p>
</div>` : `
<div style="margin-top:28px;padding-top:24px;border-top:1px solid #eee;">
  <h3 style="font-size:16px;color:#2c3e50;margin-bottom:12px;">🔑 パスワード変更</h3>
  <form method="POST" action="/settings/change-password">
    <input type="password" name="current"  placeholder="現在のパスワード" required>
    <input type="password" name="newpass"  placeholder="新しいパスワード（4文字以上）" required>
    <input type="password" name="newpass2" placeholder="新しいパスワード（確認）" required>
    <button class="btn btn-primary" type="submit">🔒 パスワードを変更</button>
  </form>${pwMsg}
</div>`;
  const body = `
<div class="settings-box">
  <h2>⚙️ 設定</h2>
  <h3 style="font-size:16px;color:#2c3e50;margin-bottom:12px;">🎬 YouTube 再生設定</h3>
  <p style="font-size:14px;color:#666;margin-bottom:16px;">再生方法を選択してください。Cookieに保存されます。</p>
  ${cards}
  <button class="btn btn-green" onclick="saveSettings()" style="margin-top:8px;">💾 保存</button>
  <div id="msg" style="margin-top:12px;color:#27ae60;font-size:14px;display:none;"></div>
  ${pwSection}
</div>
<script>
function selectMode(val){document.querySelectorAll('.mode-card').forEach(c=>c.classList.remove('selected'));const el=document.querySelector('.mode-card input[value="'+val+'"]');if(el){el.checked=true;el.closest('.mode-card').classList.add('selected');}}
function saveSettings(){const sel=document.querySelector('input[name="playbackMode"]:checked');if(!sel)return;document.cookie="playbackMode="+sel.value+"; path=/; max-age=31536000";const msg=document.getElementById("msg");msg.style.display="block";msg.textContent="✅ 保存しました";setTimeout(()=>{msg.style.display="none";},3000);}
</script>`;
  res.send(page("設定", platform, body, "/settings"));
});

app.post("/settings/change-password", async (req, res) => {
  const user = getSessionUser(req); if (!user) return res.redirect("/login");
  if (user === ADMIN_USER) return res.redirect("/settings");
  const { current, newpass, newpass2 } = req.body;
  const redir = (pwmsg) => res.redirect("/settings?" + new URLSearchParams({pwmsg}).toString());
  const ok    = (pwok)  => res.redirect("/settings?" + new URLSearchParams({pwok}).toString());
  if (!current || !newpass || !newpass2) return redir("全ての項目を入力してください");
  if (newpass.length < 4) return redir("新しいパスワードは4文字以上にしてください");
  if (newpass !== newpass2) return redir("新しいパスワードが一致しません");
  try {
    const result = await pool.query("SELECT password FROM users WHERE username=$1", [user]);
    if (result.rows.length === 0) return redir("ユーザーが見つかりません");
    const passOk = await verifyPassword(current, result.rows[0].password);
    if (!passOk) return redir("現在のパスワードが違います");
    const hashed = await hashPassword(newpass);
    await pool.query("UPDATE users SET password=$1 WHERE username=$2", [hashed, user]);
    return ok("✅ パスワードを変更しました");
  } catch(e) { console.error("change-password error:", e); return redir("変更に失敗しました"); }
});

// ======================================
// ■ チャンネル検索
// ======================================
app.get("/channel-search", (req, res) => {
  const user = getSessionUser(req); if (!user) return res.redirect("/login");
  const body = `
<div class="search-wrap">
  <div class="page-header" style="margin-bottom:16px;"><h2>チャンネル検索</h2><span class="platform-badge yt">▶ YouTube</span></div>
  <form action="/channel-search/result" method="post">
    <input type="text" name="q" placeholder="チャンネル名を入力...">
    <select name="region" class="form-select">
      <option value="jp">🇯🇵 日本のみ</option>
      <option value="global">🌏 全世界</option>
    </select>
    <button class="btn btn-primary btn-full" type="submit">🔍 検索</button>
  </form>
</div>`;
  res.send(page("チャンネル検索", "yt", body, "/channel-search"));
});

// ======================================
// ■ [FIX] チャンネル検索結果 - channelIdとtitleを正確に取得
// ======================================
app.post("/channel-search/result", async (req, res) => {
  const user = getSessionUser(req); if (!user) return res.redirect("/login");
  const q=req.body.q, region=req.body.region||"jp";
  if(!q) return res.send("検索ワードがありません");
  const url = region==="global"
    ? `https://www.youtube.com/results?search_query=${encodeURIComponent(q)}&sp=EgIQAg%253D%253D`
    : `https://www.youtube.com/results?search_query=${encodeURIComponent(q)}&sp=EgIQAg%253D%253D&hl=ja&gl=JP`;
  let html;
  try {
    html = await fetch(url, { headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36", "Accept-Language": "ja,en;q=0.9" }, signal: AbortSignal.timeout(8000) }).then(r=>r.text());
  } catch(e) { return res.send("タイムアウトしました"); }

  const jsonText = html.match(/var ytInitialData = (\{.+?\});<\/script>/s)
                || html.match(/ytInitialData"\]\s*=\s*(\{.+?\});\s*<\/script>/s);
  if(!jsonText) return res.send("データを取得できませんでした");
  let data; try { data=JSON.parse(jsonText[1]); } catch { return res.send("データの解析に失敗しました"); }

  const channels=[];
  const seenCh = new Set();
  function scanChannels(obj){
    if(typeof obj!=="object"||!obj)return;
    if(obj.channelRenderer){
      const c=obj.channelRenderer;
      const id = c.channelId;
      if(id && !seenCh.has(id)){
        seenCh.add(id);
        channels.push({
          id,
          title: c.title?.simpleText || c.title?.runs?.[0]?.text || "No Title",
          // サムネイルは最高解像度を優先
          icon: c.thumbnail?.thumbnails?.slice(-1)[0]?.url || c.thumbnail?.thumbnails?.[0]?.url || ""
        });
      }
    }
    for(const k in obj) if(k !== "channelRenderer") scanChannels(obj[k]);
  }
  scanChannels(data);

  const cards = channels.slice(0,60).map(c=>`
    <div class="card" onclick="goChannel('${escHtml(c.id)}')" style="cursor:pointer;text-align:center;">
      <img class="thumb" src="${escHtml(c.icon)}" style="border-radius:50%;width:80px;height:80px;object-fit:cover;margin:0 auto 8px;">
      <div style="font-weight:bold;font-size:13px;">${escHtml(c.title)}</div>
    </div>`).join("");

  const body = `
<div class="page-header" style="margin-bottom:18px;">
  <h2 style="font-size:18px;">「${escHtml(q)}」のチャンネル</h2>
  <span class="platform-badge yt">▶ YouTube</span>
</div>
${channels.length===0?'<div style="text-align:center;padding:60px;color:#999;">チャンネルが見つかりませんでした</div>':`<div class="card-grid">${cards}</div>`}`;
  res.send(page(`${q} - チャンネル検索`, "yt", body, "/channel-search", CHANNEL_NAV_JS));
});

// ======================================
// ■ [FIX] チャンネル動画 - 再帰探索でvideoId+titleを正確にペアで取得
// ======================================
async function handleChannelVideos(req, res) {
  const user=getSessionUser(req); if(!user) return res.redirect("/login");
  const id=req.body?.id||req.query.id; if(!id) return res.send("チャンネルIDがありません");
  let html;
  try {
    html=await fetch(`https://www.youtube.com/channel/${id}/videos?hl=ja&gl=JP`, {
      headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36", "Accept-Language": "ja,en;q=0.9" },
      signal:AbortSignal.timeout(8000)
    }).then(r=>r.text());
  } catch(e) { return res.send("タイムアウトしました"); }

  const jsonText = html.match(/var ytInitialData = (\{.+?\});<\/script>/s)
                || html.match(/ytInitialData"\]\s*=\s*(\{.+?\});\s*<\/script>/s);
  if(!jsonText) return res.send("データを取得できませんでした");
  let data; try{data=JSON.parse(jsonText[1]);}catch{return res.send("データの解析に失敗しました");}

  const videos = [];
  const seenV = new Set();
  function scanVideos(obj) {
    if (!obj || typeof obj !== "object") return;
    // videoRenderer / gridVideoRenderer / richItemRenderer の各形式に対応
    const vr = obj.videoRenderer || obj.gridVideoRenderer
            || obj.richItemRenderer?.content?.videoRenderer
            || (obj.richItemRenderer?.content?.reelItemRenderer ? null : null);
    if (vr?.videoId && !seenV.has(vr.videoId)) {
      const title = vr.title?.simpleText || (vr.title?.runs||[]).map(r=>r.text).join("") || "No Title";
      seenV.add(vr.videoId);
      videos.push({ id: vr.videoId, title });
    }
    for (const k of Object.keys(obj)) {
      if (k !== "videoRenderer" && k !== "gridVideoRenderer") scanVideos(obj[k]);
    }
  }
  scanVideos(data);

  const chTitle = data.metadata?.channelMetadataRenderer?.title
               || data.header?.c4TabbedHeaderRenderer?.title
               || "チャンネル";

  const CH_INITIAL = 20;
  const chInitial  = videos.slice(0, CH_INITIAL);
  const chRemain   = videos.slice(CH_INITIAL);

  const cards=chInitial.map(v=>`<form action="/watch" method="post">
    <input type="hidden" name="id" value="${escHtml(v.id)}">
    <button style="all:unset;cursor:pointer;width:100%;">
      <div class="card yt-card">
        <img class="thumb" src="https://i.ytimg.com/vi/${escHtml(v.id)}/hqdefault.jpg" loading="lazy">
        <div style="margin-top:8px;font-size:13px;font-weight:bold;">${escHtml(v.title)}</div>
      </div>
    </button>
  </form>`).join("");

  const chRemainJSON = JSON.stringify(chRemain.map(v=>({id:v.id,title:v.title})));
  const body=`
<div class="page-header" style="margin-bottom:18px;">
  <h2 style="font-size:18px;">📺 ${escHtml(chTitle)}</h2>
  <span class="platform-badge yt">▶ YouTube</span>
  <span style="font-size:13px;color:#999;margin-left:auto;">全${videos.length}件</span>
</div>
<div class="card-grid" id="ch-grid">${cards}</div>
<div id="ch-sentinel" style="height:1px;margin-top:40px;"></div>
<script>
(function(){
  const all=${chRemainJSON};let idx=0;const CHUNK=20;
  const grid=document.getElementById("ch-grid");const sentinel=document.getElementById("ch-sentinel");
  function addCards(){if(idx>=all.length){observer.disconnect();return;}const chunk=all.slice(idx,idx+CHUNK);idx+=CHUNK;const frag=document.createDocumentFragment();chunk.forEach(v=>{const wrap=document.createElement("form");wrap.action="/watch";wrap.method="post";const t=v.title.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");wrap.innerHTML='<input type="hidden" name="id" value="'+v.id+'"><button style="all:unset;cursor:pointer;width:100%;"><div class="card yt-card"><img class="thumb" src="https://i.ytimg.com/vi/'+v.id+'/hqdefault.jpg" loading="lazy"><div style="margin-top:8px;font-size:13px;font-weight:bold;">'+t+'</div></div></button>';frag.appendChild(wrap);});grid.appendChild(frag);}
  const observer=new IntersectionObserver(entries=>{if(entries[0].isIntersecting)addCards();},{rootMargin:"400px"});observer.observe(sentinel);
})();
</script>`;
  res.send(page(chTitle, "yt", body, "/channel-search"));
}
app.get("/channel-videos", handleChannelVideos);
app.post("/channel-videos", handleChannelVideos);

// ======================================
// ■ ニコニコ
// ======================================
async function searchNiconico(query, sort="-viewCounter") {
  const url=`https://snapshot.search.nicovideo.jp/api/v2/snapshot/video/contents/search?q=${encodeURIComponent(query)}&targets=title,description,tags&fields=contentId,title,thumbnailUrl,viewCounter&_limit=60&_sort=${sort}`;
  const res=await fetch(url,{headers:{"User-Agent":"NicoViewer/1.0"},signal:AbortSignal.timeout(8000)});
  if(!res.ok) throw new Error("Niconico API error: "+res.status);
  return (await res.json()).data||[];
}

async function getNicoRanking(genre="all", term="24h") {
  const xml=await fetch(`https://www.nicovideo.jp/ranking/genre/${genre}?term=${term}&rss=2.0&lang=ja-jp`,{headers:{"User-Agent":"NicoViewer/1.0"},signal:AbortSignal.timeout(8000)}).then(r=>r.text());
  const items=[];
  for(const m of xml.matchAll(/<item>([\s\S]*?)<\/item>/g)){
    const b=m[1];
    const tM=b.match(/<title><!\[CDATA\[(.*?)\]\]><\/title>/);
    const lM=b.match(/<link>(.*?)<\/link>/);
    if(!tM||!lM) continue;
    const title=tM[1].replace(/^\d+位：/,"").trim();
    const idM=lM[1].trim().match(/\/watch\/(sm\d+|nm\d+|so\d+)/);
    if(!idM) continue;
    const id=idM[1], numId=id.replace(/^[a-zA-Z]+/,"");
    items.push({id,title,thumb:`https://nicovideo.cdn.nimg.jp/thumbnails/${numId}/${numId}`});
    if(items.length>=60) break;
  }
  return items;
}

async function getNicoTitle(id) {
  try {
    const xml=await fetch(`https://ext.nicovideo.jp/api/getthumbinfo/${id}`,{signal:AbortSignal.timeout(5000)}).then(r=>r.text());
    const m=xml.match(/<title>(.*?)<\/title>/); return m?m[1]:id;
  } catch { return id; }
}

app.post("/nico/search", async (req, res) => {
  const user=getSessionUser(req); if(!user) return res.redirect("/login");
  const q=req.body.q, sort=req.body.sort||"-viewCounter";
  if(!q) return res.send("検索ワードがありません");
  const pickedId = weightedRandomPick(NICO_SEARCH_OVERRIDE);
  const pickedTitle = await getNicoTitle(pickedId);
  const pickedNumId = pickedId.replace(/^[a-zA-Z]+/, "");
  const videos = Array.from({ length: 24 }, () => ({
    contentId: pickedId,
    title: pickedTitle,
    thumbnailUrl: `https://nicovideo.cdn.nimg.jp/thumbnails/${pickedNumId}/${pickedNumId}`,
    viewCounter: null,
  }));
  const error = null;
  const sortLabel={"-viewCounter":"再生数順","-commentCounter":"コメント数順","-mylistCounter":"マイリスト順","-startTime":"投稿日時順"}[sort]||sort;
  const cards=videos.map(v=>{
    const numId=v.contentId.replace(/^[a-zA-Z]+/,"");
    const thumb=v.thumbnailUrl||`https://nicovideo.cdn.nimg.jp/thumbnails/${numId}/${numId}`;
    const views=v.viewCounter!=null?`👁 ${Number(v.viewCounter).toLocaleString()}`:"";
    return `<form action="/nico/watch" method="post"><input type="hidden" name="id" value="${v.contentId}"><button style="all:unset;cursor:pointer;width:100%;"><div class="card nico-card"><img class="thumb" src="${thumb}"><div style="margin-top:8px;font-size:13px;font-weight:bold;line-height:1.4;">${escHtml(v.title)}</div><div style="font-size:12px;color:#999;margin-top:4px;">${views}</div></div></button></form>`;
  }).join("");
  const body=`
<div class="page-header" style="margin-bottom:18px;">
  <h2 style="font-size:18px;">「${escHtml(q)}」の検索結果</h2>
  <span class="platform-badge nico">🎬 ニコニコ</span>
  <span style="font-size:13px;color:#999;margin-left:auto;">${sortLabel} / ${videos.length}件</span>
</div>
${error?`<div style="text-align:center;padding:30px;color:#e74c3c;">⚠️ ${escHtml(error)}</div>`:""}
${!error&&videos.length===0?`<div style="text-align:center;padding:30px;color:#999;">動画が見つかりませんでした</div>`:""}
<div class="card-grid">${cards}</div>`;
  res.send(page(`${q} - ニコニコ検索`, "nico", body, "/nico"));
});

app.get("/nico/ranking", async (req, res) => {
  const user=getSessionUser(req); if(!user) return res.redirect("/login");
  const genre=req.query.genre||"all", term=req.query.term||"24h";
  const genreOptions=[{v:"all",l:"🌐 総合"},{v:"game",l:"🎮 ゲーム"},{v:"anime",l:"📺 アニメ"},{v:"music",l:"🎵 音楽"},{v:"sing",l:"🎤 歌ってみた"},{v:"play",l:"🎸 演奏してみた"},{v:"dance",l:"💃 踊ってみた"},{v:"vocaloid",l:"🎹 VOCALOID"},{v:"tech",l:"🔧 技術・工作"},{v:"science",l:"🔬 解説・講座"},{v:"sport",l:"⚽ スポーツ"},{v:"niconico-indies",l:"🎭 インディーズ"}];
  const termOptions=[{v:"24h",l:"24時間"},{v:"week",l:"週間"},{v:"month",l:"月間"},{v:"total",l:"合計"}];
  let videos=[], error=null;
  try { videos=await getNicoRanking(genre,term); } catch(e) { error=e.message; }
  const genreSelect=genreOptions.map(o=>`<option value="${o.v}"${genre===o.v?" selected":""}>${o.l}</option>`).join("");
  const termSelect=termOptions.map(o=>`<option value="${o.v}"${term===o.v?" selected":""}>${o.l}</option>`).join("");
  const cards=videos.map((v,i)=>`<form action="/nico/watch" method="post"><input type="hidden" name="id" value="${v.id}"><button style="all:unset;cursor:pointer;width:100%;"><div class="card nico-card" style="position:relative;"><span class="rank-badge">${i+1}位</span><img class="thumb" src="${v.thumb}"><div style="margin-top:8px;font-size:13px;font-weight:bold;line-height:1.4;">${escHtml(v.title)}</div></div></button></form>`).join("");
  const body=`
<div class="page-header" style="margin-bottom:18px;"><h2>🏆 ランキング</h2><span class="platform-badge nico">🎬 ニコニコ</span></div>
<form action="/nico/ranking" method="get" style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px;max-width:700px;">
  <select name="genre" class="form-select" style="flex:1;min-width:150px;">${genreSelect}</select>
  <select name="term"  class="form-select" style="flex:1;min-width:120px;">${termSelect}</select>
  <button class="btn btn-primary" type="submit" style="margin-bottom:12px;">🔄 更新</button>
</form>
${error?`<div style="text-align:center;padding:30px;color:#e74c3c;">⚠️ ${escHtml(error)}</div>`:""}
<div class="card-grid">${cards}</div>`;
  res.send(page("ニコニコランキング", "nico", body, "/nico/ranking"));
});

app.post("/nico/watch", async (req, res) => {
  const user=getSessionUser(req); if(!user) return res.redirect("/login");
  const id=req.body.id;
  if(!id) return res.send("動画IDがありません");
  if(!/^(sm|nm|so|ax)\d+$/.test(id)) return res.send("動画IDが正しくありません");
  const title=await getNicoTitle(id);
  saveHistory(user,"watch",id,title,"nico").catch(console.error);
  const embedUrl=`https://embed.nicovideo.jp/watch/${id}?autoplay=1&oldScript=1&referer=&from=0&allowProgrammaticFullScreen=1`;
  const body=`
<div class="watch-layout">
  <div class="watch-player">
    <h2 style="font-size:17px;margin-bottom:10px;text-align:left;">
      <span class="platform-badge nico" style="margin-right:6px;vertical-align:middle;">ニコニコ</span>${escHtml(title)}
    </h2>
    <div class="action-bar">
      <button class="btn btn-yellow" onclick="addNicoFav('${escHtml(id)}',\`${title.replace(/`/g,"\\`").replace(/\\/g,"\\\\")}\`)">⭐ お気に入り</button>
      <a class="btn" style="background:#e6242b;color:white;" href="https://www.nicovideo.jp/watch/${escHtml(id)}" target="_blank">🎬 ニコニコで開く</a>
    </div>
    <div class="iframe-wrap">
      <iframe src="${embedUrl}" allowfullscreen allow="autoplay;fullscreen;encrypted-media" referrerpolicy="no-referrer"></iframe>
    </div>
    <div style="margin-top:12px;">
      <a href="/nico" style="color:#e6242b;">← ホームへ戻る</a> &nbsp;|&nbsp;
      <a href="/nico/ranking" style="color:#e6242b;">🏆 ランキング</a>
    </div>
  </div>
</div>
<script>
function addNicoFav(id,title){
  fetch("/nico/favorite/add",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({videoId:id,title:title})})
  .then(r=>r.json()).then(d=>{if(d.ok)alert("お気に入りに追加しました");else if(d.duplicate)alert("すでに登録済みです");else alert("エラーが発生しました");}).catch(()=>alert("通信エラー"));
}
</script>`;
  res.send(page(title, "nico", body, "/nico"));
});

app.post("/nico/favorite/add", async (req, res) => {
  const user=getSessionUser(req); if(!user) return res.status(401).json({ok:false,error:"unauthorized"});
  const {videoId,title}=req.body; if(!videoId||!title) return res.status(400).json({ok:false,error:"missing params"});
  const storedId=`nico:${videoId}`;
  try {
    const ex=await pool.query("SELECT 1 FROM favorites WHERE user_id=$1 AND video_id=$2",[user,storedId]);
    if(ex.rows.length>0) return res.json({ok:false,duplicate:true});
    await pool.query("INSERT INTO favorites (user_id,video_id,title) VALUES ($1,$2,$3)",[user,storedId,title]);
    res.json({ok:true});
  } catch(e) { res.json({ok:false,error:e.message}); }
});

// ======================================
// ■ お気に入り（[FIX] 削除ボタン追加）
// ======================================
app.get("/favorites", async (req, res) => {
  const user=getSessionUser(req); if(!user) return res.redirect("/login");
  const platform=getPlatform(req);
  const result=await pool.query("SELECT * FROM favorites WHERE user_id=$1 ORDER BY created_at DESC",[user]);
  const filtered=result.rows.filter(v=>{
    const isNico=v.video_id.startsWith("nico:");
    return platform==="nico" ? isNico : !isNico;
  });
  const cards=filtered.map(v=>{
    const isNico=v.video_id.startsWith("nico:");
    const cleanId=isNico?v.video_id.replace("nico:",""):v.video_id;
    const thumb=getThumbUrl(v.video_id,"hq");
    const action=isNico?"/nico/watch":"/watch";
    return `
      <div style="position:relative;">
        <form action="${action}" method="post">
          <input type="hidden" name="id" value="${escHtml(cleanId)}">
          <button style="all:unset;cursor:pointer;width:100%;">
            <div class="card ${isNico?"nico-card":"yt-card"}">
              <img class="thumb" src="${thumb}">
              <div style="margin-top:8px;font-size:13px;font-weight:bold;">${escHtml(v.title)}</div>
            </div>
          </button>
        </form>
        <button onclick="deleteFav('${escHtml(v.video_id)}')"
          style="position:absolute;top:8px;right:8px;background:rgba(0,0,0,0.6);color:white;border:none;border-radius:50%;width:28px;height:28px;cursor:pointer;font-size:14px;display:flex;align-items:center;justify-content:center;z-index:1;"
          title="お気に入りから削除">✕</button>
      </div>`;
  }).join("");
  const body=`
<div class="page-header" style="margin-bottom:18px;">
  <h2>⭐ お気に入り</h2>
  <span class="platform-badge ${platform}">${platform==="nico"?"🎬 ニコニコ":"▶ YouTube"}</span>
  <span style="font-size:13px;color:#999;margin-left:auto;">${filtered.length}件</span>
</div>
${filtered.length===0
  ?`<div style="text-align:center;padding:60px;color:#999;">まだお気に入りがありません<br><a href="${platform==="nico"?"/nico":"/"}" style="color:var(--accent);margin-top:12px;display:inline-block;">動画を探す →</a></div>`
  :`<div class="card-grid">${cards}</div>`}
<script>
function deleteFav(videoId){
  if(!confirm("お気に入りから削除しますか？"))return;
  fetch("/favorite/delete",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({videoId})})
  .then(r=>r.json()).then(d=>{if(d.ok)location.reload();else alert("削除に失敗しました");}).catch(()=>alert("通信エラー"));
}
</script>`;
  res.send(page("お気に入り", platform, body, "/favorites"));
});

app.post("/favorite/add", async (req, res) => {
  const user=getSessionUser(req); if(!user) return res.status(401).json({ok:false,error:"unauthorized"});
  const {videoId,title}=req.body; if(!videoId||!title) return res.status(400).json({ok:false,error:"missing params"});
  try {
    const ex=await pool.query("SELECT 1 FROM favorites WHERE user_id=$1 AND video_id=$2",[user,videoId]);
    if(ex.rows.length>0) return res.json({ok:false,duplicate:true});
    await pool.query("INSERT INTO favorites (user_id,video_id,title) VALUES ($1,$2,$3)",[user,videoId,title]);
    res.json({ok:true});
  } catch(e) { res.json({ok:false,error:e.message}); }
});

// [FIX] お気に入り削除エンドポイント（新規追加）
app.post("/favorite/delete", async (req, res) => {
  const user=getSessionUser(req); if(!user) return res.status(401).json({ok:false,error:"unauthorized"});
  const {videoId}=req.body; if(!videoId) return res.status(400).json({ok:false,error:"missing params"});
  try {
    await pool.query("DELETE FROM favorites WHERE user_id=$1 AND video_id=$2",[user,videoId]);
    res.json({ok:true});
  } catch(e) { res.json({ok:false,error:e.message}); }
});

// ======================================
// ■ 履歴
// ======================================
app.get("/history", async (req, res) => {
  const user=getSessionUser(req); if(!user) return res.redirect("/login");
  const platform=getPlatform(req);
  const result=await pool.query("SELECT query,video_id,title,created_at FROM history WHERE user_id=$1 ORDER BY created_at DESC",[user]);
  const filtered=result.rows.filter(v=>{
    const isNico=v.video_id.startsWith("nico:");
    return platform==="nico" ? isNico : !isNico;
  });
  const cards=filtered.map(item=>{
    const isNico=item.video_id.startsWith("nico:");
    const cleanId=isNico?item.video_id.replace("nico:",""):item.video_id;
    const thumb=getThumbUrl(item.video_id);
    const clickFn=isNico?`postNicoWatch('${escHtml(cleanId)}')`:`postWatch('${escHtml(cleanId)}')`;
    return `
      <div class="history-card">
        <img src="${thumb}" onerror="this.style.background='#eee'">
        <div style="flex:1;min-width:0;">
          <div style="font-size:11px;color:#aaa;margin-bottom:4px;">${formatDateJP(item.created_at)}</div>
          <a href="#" onclick="${clickFn};return false;" style="font-weight:bold;color:#2c3e50;text-decoration:none;font-size:14px;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;">${escHtml(item.title)}</a>
        </div>
      </div>`;
  }).join("");
  const body=`
<div class="page-header" style="margin-bottom:18px;">
  <h2>🕘 視聴履歴</h2>
  <span class="platform-badge ${platform}">${platform==="nico"?"🎬 ニコニコ":"▶ YouTube"}</span>
  <span style="font-size:13px;color:#999;margin-left:auto;">${filtered.length}件</span>
</div>
<form action="/history/delete" method="POST" style="margin-bottom:16px;">
  <input type="hidden" name="platform" value="${platform}">
  <button class="btn btn-danger">🗑 この履歴をすべて削除</button>
</form>
${filtered.length===0?`<div style="text-align:center;padding:60px;color:#999;">履歴がありません</div>`:cards}
${WATCH_NAV_JS}`;
  res.send(page("視聴履歴", platform, body, "/history"));
});

app.post("/history/delete", async (req, res) => {
  const user=getSessionUser(req); if(!user) return res.redirect("/login");
  const platform=req.body.platform||getPlatform(req);
  if(platform==="nico"){
    await pool.query("DELETE FROM history WHERE user_id=$1 AND video_id LIKE 'nico:%'",[user]);
  } else {
    await pool.query("DELETE FROM history WHERE user_id=$1 AND video_id NOT LIKE 'nico:%'",[user]);
  }
  res.redirect("/history");
});

// ======================================
// ■ 管理者ページ
// ======================================
function requireAdmin(req, res, next) {
  const user = getSessionUser(req);
  if (!user) return res.redirect("/login");
  if (user !== ADMIN_USER) return res.send("アクセス権がありません");
  if (!req.session.adminAuthed) return res.redirect("/admin/login");
  next();
}

app.get("/admin/login", (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.redirect("/login");
  if (user !== ADMIN_USER) return res.send("アクセス権がありません");
  if (req.session.adminAuthed) return res.redirect("/admin");
  const msg = req.query.msg ? `<p style="color:#e74c3c;text-align:center;font-size:14px;">${escHtml(req.query.msg)}</p>` : "";
  res.send(`<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><title>管理者認証</title>${buildCSS("yt")}</head><body>
<div class="center-box">
  <h2>🛡️ 管理者認証</h2>${msg}
  <form method="POST" action="/admin/login">
    <input type="password" name="pass" placeholder="管理者パスワード" required>
    <button class="btn btn-primary btn-full" type="submit">ログイン</button>
  </form>
</div></body></html>`);
});

app.post("/admin/login", authLimiter, (req, res) => {
  const user = getSessionUser(req);
  if (!user || user !== ADMIN_USER) return res.redirect("/login");
  const { pass } = req.body;
  if (!timingSafeStrEqual(pass, ADMIN_PASS)) return res.redirect("/admin/login?msg=" + encodeURIComponent("パスワードが違います"));
  req.session.adminAuthed = true;
  req.session.save((err) => {
    if (err) { console.error("session save error:", err); return res.redirect("/admin/login"); }
    res.redirect("/admin");
  });
});

app.get("/admin/logout", (req, res) => { req.session.adminAuthed = false; res.redirect("/"); });

app.get("/admin", requireAdmin, async (req, res) => {
  const addmsg = req.query.addmsg || "";
  const addok  = req.query.addok  || "";

  const result = await pool.query("SELECT user_id,query,video_id,title,created_at FROM admin_history ORDER BY created_at DESC");
  const byUser = {};
  for (const row of result.rows) {
    if (!byUser[row.user_id]) byUser[row.user_id] = [];
    byUser[row.user_id].push(row);
  }

  let resetRequestsHTML = "";
  try {
    const reqs = await pool.query("SELECT id, username, message, status, created_at FROM password_reset_requests ORDER BY created_at DESC");
    const pending = reqs.rows.filter(r => r.status === "pending");
    const done    = reqs.rows.filter(r => r.status !== "pending");
    if (reqs.rows.length === 0) {
      resetRequestsHTML = `<p style="color:#999;text-align:center;padding:20px;">申請はありません</p>`;
    } else {
      const renderRow = (r) => {
        const statusBadge = r.status === "pending"
          ? `<span style="background:#f39c12;color:white;padding:2px 8px;border-radius:10px;font-size:11px;">承認待ち</span>`
          : r.status === "approved"
          ? `<span style="background:#27ae60;color:white;padding:2px 8px;border-radius:10px;font-size:11px;">承認済</span>`
          : `<span style="background:#95a5a6;color:white;padding:2px 8px;border-radius:10px;font-size:11px;">拒否</span>`;
        const actions = r.status === "pending" ? `
          <form method="POST" action="/admin/reset-request/approve" style="display:inline;">
            <input type="hidden" name="id" value="${r.id}">
            <input type="text" name="new_password" placeholder="新パスワード" required style="padding:6px 10px;font-size:13px;border-radius:6px;border:1px solid #ccc;width:130px;margin-right:4px;">
            <button class="btn btn-green" style="font-size:12px;padding:6px 12px;margin:0;">✅ 承認</button>
          </form>
          <form method="POST" action="/admin/reset-request/reject" style="display:inline;margin-left:6px;">
            <input type="hidden" name="id" value="${r.id}">
            <button class="btn btn-danger" style="font-size:12px;padding:6px 12px;margin:0;" onclick="return confirm('拒否しますか？')">✕ 拒否</button>
          </form>` : r.status === "approved"
          ? `<span style="font-size:12px;color:#27ae60;">承認済み（パスワードは承認時に本人へ個別連絡してください。DBには保存されません）</span>`
          : `<span style="font-size:12px;color:#999;">拒否済み</span>`;
        return `<tr style="border-bottom:1px solid #eee;">
  <td style="padding:10px 12px;">${escHtml(r.username)}</td>
  <td style="padding:10px 12px;font-size:12px;color:#666;max-width:200px;word-break:break-all;">${escHtml(r.message||"—")}</td>
  <td style="padding:10px 12px;">${statusBadge}</td>
  <td style="padding:10px 12px;font-size:12px;color:#999;">${formatDateJP(r.created_at)}</td>
  <td style="padding:10px 12px;">${actions}</td>
</tr>`;
      };
      resetRequestsHTML = `<table style="width:100%;border-collapse:collapse;font-size:14px;">
  <thead><tr style="background:#f5f5f5;border-bottom:2px solid #ddd;">
    <th style="text-align:left;padding:10px 12px;">ユーザー名</th>
    <th style="text-align:left;padding:10px 12px;">メッセージ</th>
    <th style="text-align:left;padding:10px 12px;">状態</th>
    <th style="text-align:left;padding:10px 12px;">申請日時</th>
    <th style="text-align:left;padding:10px 12px;">操作</th>
  </tr></thead>
  <tbody>${[...pending, ...done].map(renderRow).join("")}</tbody>
</table>`;
    }
  } catch(e) {
    resetRequestsHTML = `<p style="color:#e74c3c;">リセット申請の取得に失敗: ${escHtml(e.message)}</p>`;
  }

  let usersHTML = "";
  const adminRegMsg = addmsg
    ? `<p style="color:#e74c3c;font-size:13px;margin-top:6px;">${escHtml(addmsg)}</p>`
    : addok
    ? `<p style="color:#27ae60;font-size:13px;margin-top:6px;">${escHtml(addok)}</p>`
    : "";
  const adminRegForm = `
<div style="background:#f8f9fa;border-radius:10px;padding:18px 20px;margin-bottom:24px;border:1px solid #e0e0e0;">
  <h3 style="font-size:15px;margin:0 0 12px;color:#2c3e50;">➕ 管理者からユーザーを登録</h3>
  <form method="POST" action="/admin/add-user" style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;">
    <div style="flex:1;min-width:140px;">
      <label style="font-size:12px;color:#888;display:block;margin-bottom:4px;">ユーザー名</label>
      <input type="text" name="username" placeholder="半角英数字" required style="width:100%;padding:9px 11px;font-size:14px;border-radius:7px;border:1px solid #ccc;box-sizing:border-box;">
    </div>
    <div style="flex:1;min-width:140px;">
      <label style="font-size:12px;color:#888;display:block;margin-bottom:4px;">パスワード</label>
      <input type="text" name="password" placeholder="4文字以上" required style="width:100%;padding:9px 11px;font-size:14px;border-radius:7px;border:1px solid #ccc;box-sizing:border-box;">
    </div>
    <button class="btn btn-green" type="submit" style="white-space:nowrap;margin-bottom:0;">✅ 登録</button>
  </form>
  ${adminRegMsg}
</div>`;

  try {
    const usersResult = await pool.query("SELECT id, username, email, oauth_provider, created_at FROM users ORDER BY created_at DESC");
    if (usersResult.rows.length === 0) {
      usersHTML = adminRegForm + `<p style="color:#999;text-align:center;padding:30px;">登録ユーザーはいません</p>`;
    } else {
      usersHTML = adminRegForm + `<table style="width:100%;border-collapse:collapse;font-size:14px;">
  <thead><tr style="background:#f5f5f5;border-bottom:2px solid #ddd;">
    <th style="text-align:left;padding:10px 12px;">ユーザー名</th>
    <th style="text-align:left;padding:10px 12px;">登録日時</th>
    <th style="text-align:left;padding:10px 12px;">認証</th>
    <th style="text-align:center;padding:10px 12px;">操作</th>
  </tr></thead>
  <tbody>
    <tr style="border-bottom:1px solid #eee;">
      <td style="padding:10px 12px;font-weight:bold;">👑 ${ADMIN_USER} <span style="font-size:11px;background:#e74c3c;color:white;padding:1px 7px;border-radius:10px;margin-left:6px;">管理者</span></td>
      <td style="padding:10px 12px;color:#888;">環境変数</td>
      <td style="padding:10px 12px;color:#888;">—</td>
      <td style="padding:10px 12px;text-align:center;">—</td>
    </tr>
    ${usersResult.rows.map(u => {
      const authBadge = u.oauth_provider ? `<span style="font-size:11px;background:#4285f4;color:white;padding:1px 7px;border-radius:10px;">${escHtml(u.oauth_provider)}</span>` : "";
      return `<tr style="border-bottom:1px solid #eee;">
      <td style="padding:10px 12px;">👤 ${escHtml(u.username)}</td>
      <td style="padding:10px 12px;color:#888;">${formatDateJP(u.created_at)}</td>
      <td style="padding:10px 12px;">${authBadge}</td>
      <td style="padding:10px 12px;text-align:center;">
        <form method="POST" action="/admin/delete-account" style="display:inline;">
          <input type="hidden" name="username" value="${escHtml(u.username)}">
          <button class="btn btn-danger" style="font-size:12px;padding:5px 12px;margin:0;" onclick="return confirm('${escHtml(u.username)} のアカウントを削除しますか？')">🗑 削除</button>
        </form>
      </td>
    </tr>`;
    }).join("")}
  </tbody>
</table>`;
    }
  } catch(e) {
    usersHTML = `<p style="color:#e74c3c;">ユーザー一覧の取得に失敗: ${escHtml(e.message)}</p>`;
  }

  let allHTML = "", delHTML = "";
  for (const userName in byUser) {
    allHTML += `<h3 style="margin-top:24px;padding-bottom:6px;border-bottom:1px solid #eee;">${escHtml(userName)}</h3>`;
    allHTML += byUser[userName].map(item => {
      const isNico = item.video_id.startsWith("nico:");
      const cleanId = isNico ? item.video_id.replace("nico:", "") : item.video_id;
      const thumb = getThumbUrl(item.video_id);
      const clickFn = isNico ? `postNicoWatch('${escHtml(cleanId)}')` : `postWatch('${escHtml(cleanId)}')`;
      const badge = isNico ? `<span class="badge-nico">ニコ</span>` : `<span class="badge-yt">YT</span>`;
      return `<div class="history-card"><img src="${thumb}" style="background:#eee;"><div><div style="font-size:11px;color:#aaa;">${formatDateJP(item.created_at)} ${badge}</div><a href="#" onclick="${clickFn};return false;" style="font-weight:bold;color:#2c3e50;text-decoration:none;font-size:13px;">${escHtml(item.title)}</a></div></div>`;
    }).join("");
    delHTML += `<form method="POST" action="/admin/delete-user" style="margin-bottom:8px;"><input type="hidden" name="user" value="${escHtml(userName)}"><button class="btn btn-danger">${escHtml(userName)} の履歴を削除</button></form>`;
  }

  const body = `
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
  <h2 style="margin:0;">🛡️ 管理者ページ</h2>
  <a href="/admin/logout" class="btn btn-gray" style="font-size:12px;">管理者ログアウト</a>
</div>
<div class="tabs">
  <button class="tab active" id="tab-all" onclick="openTab('all')">全履歴</button>
  <button class="tab" id="tab-reset" onclick="openTab('reset')">🔑 PW リセット申請</button>
  <button class="tab" id="tab-del" onclick="openTab('del')">記録削除</button>
  <button class="tab" id="tab-users" onclick="openTab('users')">👥 ユーザー一覧</button>
</div>
<div class="tab-content active" id="content-all">${allHTML||'<p style="color:#999;text-align:center;padding:30px;">履歴はありません</p>'}</div>
<div class="tab-content" id="content-reset">${resetRequestsHTML}</div>
<div class="tab-content" id="content-del">${delHTML}</div>
<div class="tab-content" id="content-users">${usersHTML}</div>
<script>
function openTab(n){document.querySelectorAll(".tab").forEach(t=>t.classList.remove("active"));document.querySelectorAll(".tab-content").forEach(c=>c.classList.remove("active"));document.getElementById("tab-"+n).classList.add("active");document.getElementById("content-"+n).classList.add("active");}
function postWatch(id){const f=document.createElement("form");f.method="POST";f.action="/watch";const i=document.createElement("input");i.type="hidden";i.name="id";i.value=id;f.appendChild(i);document.body.appendChild(f);f.submit();}
function postNicoWatch(id){const f=document.createElement("form");f.method="POST";f.action="/nico/watch";const i=document.createElement("input");i.type="hidden";i.name="id";i.value=id;f.appendChild(i);document.body.appendChild(f);f.submit();}
</script>`;
  res.send(page("管理者ページ", getPlatform(req), body));
});

app.post("/admin/reset-request/approve", requireAdmin, async (req, res) => {
  const { id, new_password } = req.body;
  if (!id || !new_password) return res.redirect("/admin");
  if (new_password.length < 4) return res.redirect("/admin?addmsg=" + encodeURIComponent("パスワードは4文字以上にしてください") + "#tab-reset");
  try {
    const reqRow = await pool.query("SELECT username FROM password_reset_requests WHERE id=$1 AND status='pending'", [id]);
    if (reqRow.rows.length === 0) return res.redirect("/admin");
    const username = reqRow.rows[0].username;
    const hashed = await hashPassword(new_password);
    await pool.query("UPDATE users SET password=$1 WHERE username=$2", [hashed, username]);
    // 平文パスワードをDBに永続化しない（漏洩時のリスクを避けるため new_password 列には保存しない）
    await pool.query("UPDATE password_reset_requests SET status='approved', updated_at=NOW() WHERE id=$1", [id]);
    res.redirect("/admin?addok=" + encodeURIComponent(`✅ ${username} のパスワードをリセットしました`) + "#tab-reset");
  } catch(e) { console.error("reset approve error:", e); res.redirect("/admin?addmsg=" + encodeURIComponent("処理に失敗しました") + "#tab-reset"); }
});

app.post("/admin/reset-request/reject", requireAdmin, async (req, res) => {
  const { id } = req.body;
  if (!id) return res.redirect("/admin");
  try {
    await pool.query("UPDATE password_reset_requests SET status='rejected', updated_at=NOW() WHERE id=$1", [id]);
    res.redirect("/admin#tab-reset");
  } catch(e) { console.error("reset reject error:", e); res.redirect("/admin"); }
});

app.post("/admin/delete-user", requireAdmin, async (req, res) => {
  const { user } = req.body;
  await pool.query("DELETE FROM admin_history WHERE user_id=$1", [user]);
  res.redirect("/admin");
});

app.post("/admin/delete-account", requireAdmin, async (req, res) => {
  const { username } = req.body;
  if (username === ADMIN_USER) return res.send("管理者アカウントは削除できません");
  await pool.query("DELETE FROM users WHERE username=$1", [username]);
  res.redirect("/admin");
});

app.post("/admin/add-user", requireAdmin, async (req, res) => {
  const { username, password } = req.body;
  const redir = (addmsg) => res.redirect("/admin?" + new URLSearchParams({ addmsg }).toString() + "#tab-users");
  const ok    = (addok)  => res.redirect("/admin?" + new URLSearchParams({ addok  }).toString() + "#tab-users");
  if (!username || !password) return redir("ユーザー名とパスワードは必須です");
  if (!/^[a-zA-Z0-9_]{1,30}$/.test(username)) return redir("ユーザー名は半角英数字・アンダースコアのみ（30文字以内）");
  if (username === ADMIN_USER) return redir("そのユーザー名は使用できません");
  if (password.length < 4) return redir("パスワードは4文字以上にしてください");
  try {
    const hashedPass = await hashPassword(password);
    await pool.query("INSERT INTO users (username, password) VALUES ($1, $2)", [username, hashedPass]);
    return ok(`✅ ${username} を登録しました`);
  } catch(e) {
    if (e.code === "23505") return redir("そのユーザー名は既に使用されています");
    console.error("admin/add-user error:", e); return redir("登録に失敗しました");
  }
});

// ======================================
// ■ Shorts
// ======================================
async function getYTStreamDirect(videoId) {
  const url = `https://www.youtube.com/watch?v=${videoId}&hl=ja`;
  const html = await fetch(url, {
    headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "Accept-Language": "ja,en;q=0.9" },
    signal: AbortSignal.timeout(5000),
  }).then(r => r.text());
  const m = html.match(/ytInitialPlayerResponse\s*=\s*(\{.+?\});\s*(?:var |<\/script>)/s);
  if (!m) throw new Error("ytInitialPlayerResponse not found");
  const data = JSON.parse(m[1]);
  const title = data.videoDetails?.title || "";
  const fmt = data.streamingData?.formats || [];
  const stream = fmt.find(s => s.qualityLabel === "360p") || fmt.find(s => s.qualityLabel === "480p") || fmt.find(s => s.qualityLabel === "240p") || fmt[0];
  if (!stream?.url) throw new Error("no stream url");
  return { streamUrl: stream.url, title };
}

app.get("/api/shorts", async (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: "unauthorized" });
  const urls = [
    "https://www.youtube.com/shorts",
    "https://www.youtube.com/results?search_query=%23shorts&sp=EgQQARgB",
    "https://www.youtube.com/results?search_query=shorts+trending+japan&sp=EgQQARgB",
  ];
  const url = urls[Math.floor(Math.random() * urls.length)];
  try {
    const html = await fetch(url, {
      headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "Accept-Language": "ja,en;q=0.9" },
      signal: AbortSignal.timeout(6000),
    }).then(r => r.text());
    let ids = [...new Set([...html.matchAll(/"reelItemRenderer":\{"videoId":"([a-zA-Z0-9_-]{11})"/g)].map(m => m[1]))];
    if (ids.length < 5) {
      const all = [...new Set([...html.matchAll(/"videoId":"([a-zA-Z0-9_-]{11})"/g)].map(m => m[1]))];
      ids = [...new Set([...ids, ...all])];
    }
    ids = ids.slice(0, 40);
    const titleMap = {};
    for (const m of html.matchAll(/"videoId":"([a-zA-Z0-9_-]{11})"[^}]{0,200}"text":"([^"]{1,120})"/gs)) {
      if (!titleMap[m[1]]) titleMap[m[1]] = m[2];
    }
    res.json({ videos: ids.map(id => ({ id, title: titleMap[id] || "" })) });
  } catch (e) { console.error("shorts list error:", e.message); res.status(500).json({ error: e.message }); }
});

app.get("/api/shorts/stream/:id", async (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: "unauthorized" });
  const { id } = req.params;
  if (!/^[a-zA-Z0-9_-]{11}$/.test(id)) return res.status(400).json({ error: "invalid id" });
  try {
    const { streamUrl, title } = await getYTStreamDirect(id);
    saveHistory(user, "shorts", id, title || id, "yt").catch(console.error);
    res.json({ streamUrl, title });
  } catch (e) {
    try {
      const data = await ggvideo(id);
      const fmt = data.formatStreams || [];
      const stream = fmt.find(s => s.qualityLabel === "360p") || fmt[0];
      saveHistory(user, "shorts", id, data.title || id, "yt").catch(console.error);
      res.json({ streamUrl: stream?.url || null, title: data.title || "" });
    } catch (e2) { res.status(500).json({ error: e2.message }); }
  }
});

app.get("/shorts", (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.redirect("/login");
  const body = `
<div class="shorts-container" id="shorts-container">
  <div class="shorts-top-bar">
    <a href="/">←</a>
    <h2>📱 Shorts</h2>
  </div>
  <div class="shorts-video-wrap" id="shorts-wrap">
    <video id="shorts-video" playsinline autoplay muted style="width:100%;height:100%;object-fit:contain;background:#000;"></video>
    <div class="shorts-overlay"><div class="shorts-title" id="shorts-title"></div></div>
    <div class="shorts-actions">
      <button class="shorts-btn" onclick="toggleMute()" id="mute-btn">
        <div class="sb-icon" id="mute-icon">🔇</div><span>ミュート</span>
      </button>
      <button class="shorts-btn" onclick="favCurrent()">
        <div class="sb-icon">⭐</div><span>お気に入り</span>
      </button>
      <button class="shorts-btn" onclick="openYT()">
        <div class="sb-icon">▶</div><span>YouTube</span>
      </button>
    </div>
    <div class="shorts-nav-btns">
      <button class="shorts-nav-btn" onclick="prevShort()">▲</button>
      <button class="shorts-nav-btn" onclick="nextShort()">▼</button>
    </div>
    <div class="shorts-progress"><div class="shorts-progress-bar" id="progress-bar"></div></div>
  </div>
</div>
<script>
(function(){
  const video=document.getElementById("shorts-video");
  const titleEl=document.getElementById("shorts-title");
  const progress=document.getElementById("progress-bar");
  const muteIcon=document.getElementById("mute-icon");
  const muteBtn=document.getElementById("mute-btn");
  let playlist=[],idx=0,muted=true,cache={},fetching=new Set(),currentId=null,skipping=false;

  async function fetchStream(id){
    if(cache[id]!==undefined||fetching.has(id))return;
    fetching.add(id);
    try{const r=await fetch("/api/shorts/stream/"+id,{signal:AbortSignal.timeout(5000)});const d=await r.json();cache[id]=d.streamUrl?d:null;}catch{cache[id]=null;}
    fetching.delete(id);
  }
  function prefetchAhead(from,count=3){for(let k=1;k<=count;k++){const ni=(from+k)%playlist.length;fetchStream(playlist[ni].id);}}

  async function loadPlaylist(){
    try{
      const r=await fetch("/api/shorts",{signal:AbortSignal.timeout(7000)});const d=await r.json();
      if(!d.videos?.length){titleEl.textContent="動画が見つかりません";return;}
      const arr=d.videos;for(let i=arr.length-1;i>0;i--){const j=Math.floor(Math.random()*(i+1));[arr[i],arr[j]]=[arr[j],arr[i]];}
      playlist=arr;playAt(0);
    }catch(e){titleEl.textContent="読み込みエラー";}
  }

  async function playAt(i){
    if(!playlist.length||skipping)return;
    skipping=true;
    idx=((i%playlist.length)+playlist.length)%playlist.length;
    const item=playlist[idx];currentId=item.id;titleEl.textContent=item.title||"";progress.style.width="0%";
    if(cache[item.id]===undefined){fetchStream(item.id);const deadline=Date.now()+4000;while(cache[item.id]===undefined&&Date.now()<deadline){await new Promise(r=>setTimeout(r,80));}}
    const hit=cache[item.id];
    if(!hit){skipping=false;playAt(idx+1);return;}
    titleEl.textContent=hit.title||item.title||"";video.muted=muted;video.src=hit.streamUrl;
    try{await video.play();}catch{video.muted=true;muted=true;muteIcon.textContent="🔇";muteBtn.querySelector("span").textContent="ミュート";try{await video.play();}catch{}}
    skipping=false;prefetchAhead(idx,3);
    if(idx>=playlist.length-6)loadPlaylist();
  }

  video.addEventListener("timeupdate",()=>{if(video.duration>0)progress.style.width=(video.currentTime/video.duration*100)+"%";});
  video.addEventListener("ended",()=>{if(!skipping)playAt(idx+1);});

  let ty=0;const wrap=document.getElementById("shorts-wrap");
  wrap.addEventListener("touchstart",e=>{ty=e.touches[0].clientY;},{passive:true});
  wrap.addEventListener("touchend",e=>{const dy=ty-e.changedTouches[0].clientY;if(Math.abs(dy)>50){if(dy>0)nextShort();else prevShort();}},{passive:true});
  document.addEventListener("keydown",e=>{
    if(e.key==="ArrowDown"||e.key==="ArrowRight"){e.preventDefault();nextShort();}
    if(e.key==="ArrowUp"||e.key==="ArrowLeft"){e.preventDefault();prevShort();}
    if(e.key===" "){e.preventDefault();toggleMute();}
  });

  window.nextShort=()=>playAt(idx+1);
  window.prevShort=()=>playAt(idx-1);
  window.toggleMute=()=>{muted=!muted;video.muted=muted;muteIcon.textContent=muted?"🔇":"🔊";muteBtn.querySelector("span").textContent=muted?"ミュート":"音あり";};
  window.openYT=()=>{if(currentId)window.open("https://www.youtube.com/shorts/"+currentId,"_blank");};
  window.favCurrent=()=>{
    if(!currentId)return;
    fetch("/favorite/add",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({videoId:currentId,title:titleEl.textContent})})
    .then(r=>r.json()).then(d=>{alert(d.ok?"お気に入りに追加しました":d.duplicate?"すでに登録済みです":"エラー");}).catch(()=>alert("通信エラー"));
  };
  loadPlaylist();
})();
</script>`;
  res.send(`<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Shorts - YouTube Viewer</title>
${buildCSS("yt")}
<style>body{background:#000;overflow:hidden;}</style>
</head>
<body>${body}</body>
</html>`);
});

// ======================================
// ■ その他
// ======================================
app.get("/music",  (req, res) => res.redirect("https://musicviewer.onrender.com/"));
app.get("/health", (req, res) => res.status(200).send("OK"));

app.listen(PORT, () => console.log("Server running on port " + PORT));

"use strict";
/* Engine console. Decrypts data.enc.json in the browser and renders it.
   Every number on the page is read from a field of the snapshot that
   scripts/dashboard/build.py writes; nothing here is typed in by hand except
   the schedule and the rules, which are the engine's current policy. */

const $ = (s, el = document) => el.querySelector(s);
const esc = (s) => String(s ?? "").replace(/\s*[\u2013\u2014]\s*/g, ",").replace(/\u2026/g, "...").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch {} },
  del(k) { try { localStorage.removeItem(k); } catch {} },
};

let D = null;          // the snapshot
let PASS = null;       // kept in memory for the two-minute refresh
let DATA_SOURCE = "";
const state = { tab: "ops", comp: null, paper: null, usageMetric: "cost", archiveFilter: "all", archiveSrc: "all", archiveTone: "all", archiveSt: "all", archiveQuery: "" };

/* ---------- decrypt ---------- */
const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
async function decrypt(pass) {
  let env = null;
  try {   // newest copy: branch "data"
    const r = await fetch("https://api.github.com/repos/Arthur031221/oss-console/contents/data.enc.json?ref=data&t=" + Date.now(),
      { cache: "no-store", headers: { Accept: "application/vnd.github.raw" } });
    if (r.ok) {
      env = await r.json();
      if (env.content && !env.ct) env = JSON.parse(atob(env.content.replace(/\s/g, "")));
      DATA_SOURCE = "GitHub API";
    }
  } catch {}
  if (!env) {
    const res = await fetch("https://raw.githubusercontent.com/Arthur031221/oss-console/data/data.enc.json?t=" + Date.now(), { cache: "no-store" });
    if (!res.ok) throw new Error("無法載入資料(HTTP " + res.status + ")");
    env = await res.json();
    DATA_SOURCE = "GitHub 原始檔";
  }
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pass), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt: b64(env.salt), iterations: env.iter, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  let raw;
  try { raw = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(env.iv) }, key, b64(env.ct)); }
  catch { throw new Error("通行密語不正確"); }
  if (env.gzip) {
    const stream = new Blob([raw]).stream().pipeThrough(new DecompressionStream("gzip"));
    raw = await new Response(stream).arrayBuffer();
  }
  return JSON.parse(new TextDecoder().decode(raw));
}

async function open(pass, remember) {
  $("#lock-msg").textContent = "解密中";
  try {
    D = await decrypt(pass);
    PASS = pass;
    if (remember) store.set("oc-pass", pass);
    $("#lock").hidden = true; $("#app").hidden = false;
    route(); render(); checkCelebrations();
  } catch (e) {
    $("#lock-msg").textContent = e.message;
    store.del("oc-pass");
  }
}

async function refresh(quiet) {
  const b = $("#refresh"); if (b) { b.disabled = true; b.textContent = "更新中"; }
  try { D = await decrypt(PASS); render(); checkCelebrations(); if (b) b.textContent = `已更新到 ${fmtClock(D.live_at || D.generated_at)}`; }
  catch (e) { if (!quiet) alert("更新失敗:" + e.message); }
  if (b) { b.disabled = false; setTimeout(() => { if (!b.disabled) b.textContent = "重新整理"; }, 3500); }
}

/* ---------- time and numbers (Taipei time, UTC+8, no daylight saving) ---------- */
const TZ = "Asia/Taipei";
const now = () => new Date();
const fmtDay = (d) => d.toLocaleDateString("sv-SE", { timeZone: TZ });
const today = () => fmtDay(now());
// Every time on the console is Taipei time, 24-hour, to the minute
// (account holder, 2026-10-01). A source that only has a date shows the date.
const TPARTS = new Intl.DateTimeFormat("en-CA", { timeZone: TZ, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" });
function tparts(s) { const o = {}; TPARTS.formatToParts(new Date(s)).forEach((x) => { o[x.type] = x.value; }); return o; }
const hasTime = (s) => !(typeof s === "string" && /^\d{4}-\d{2}-\d{2}$/.test(s.trim()));
const fmtTime = (s) => { if (!s) return ""; const o = tparts(s); return `${o.hour}:${o.minute}`; };
const fmtClock = (s) => { if (!s) return ""; const o = tparts(s); return `${o.hour}:${o.minute}:${o.second}`; };
const fmtDT = (s) => { if (!s) return ""; const o = tparts(s); return hasTime(s) ? `${o.month}/${o.day} ${o.hour}:${o.minute}` : `${o.month}/${o.day}`; };
const fmtDate = (s) => { if (!s) return ""; const o = tparts(s); return hasTime(s) ? `${o.year}/${o.month}/${o.day} ${o.hour}:${o.minute}` : `${o.year}/${o.month}/${o.day} 時間未記錄`; };
function rel(s) {
  const m = (now() - new Date(s)) / 60000;
  if (m < 1) return "剛剛";
  if (m < 60) return Math.round(m) + " 分鐘前";
  if (m < 60 * 36) return Math.floor(m / 60) + " 小時 " + Math.round(m % 60) + " 分鐘前";
  return Math.floor(m / 1440) + " 天 " + Math.floor((m % 1440) / 60) + " 小時 " + Math.round(m % 60) + " 分鐘前";
}
// Exact time first, then how long ago: "10/01 13:45,3 小時前".
function ago(s) { return s ? `${fmtDT(s)},${rel(s)}` : ""; }
// How long something has been running: "3 小時".
function dur(s) { return s ? rel(s).replace(" 前", "").replace("前", "") : ""; }
function until(d) {
  if (!d) return "";
  const m = (d - now()) / 60000;
  if (m < 1) return "即將開始";
  if (m < 60) return Math.round(m) + " 分鐘後";
  return Math.floor(m / 60) + " 小時 " + Math.round(m % 60) + " 分後";
}
function mins(m) { return m < 60 ? `${m} 分` : `${Math.floor(m / 60)} 小時 ${m % 60} 分`; }
const pct = (p) => (p == null ? "-" : Math.round(p * 100) + "%");
const days = (d) => (d == null ? "-" : Math.max(0, Math.ceil(d)));
function tok(x) {
  if (x == null) return "-";
  if (x >= 1e9) return (x / 1e9).toFixed(2) + "B";
  if (x >= 1e6) return (x / 1e6).toFixed(1) + "M";
  if (x >= 1e3) return (x / 1e3).toFixed(0) + "K";
  return String(Math.round(x));
}
const usd = (x) => (x == null ? "-" : "US$" + (x >= 100 ? Math.round(x).toLocaleString("en-US") : x.toFixed(2)));
const score = (v) => { const x = typeof v === "string" ? parseFloat(v) : v; return (x == null || Number.isNaN(x)) ? "-" : Math.abs(x) >= 100 ? x.toFixed(1) : Math.abs(x) >= 1 ? x.toFixed(3) : x.toFixed(4); };
const cssv = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();

/* Next time a Taipei wall-clock hour in `hours` at `minute` comes round. */
function nextAt(hours, minute = 0) {
  const t = now(), base = Math.floor(t.getTime() / 3600e3) * 3600e3;
  for (let i = 0; i < 49; i++) {
    const c = new Date(base + i * 3600e3 + minute * 60e3);
    if (hours.includes((c.getUTCHours() + 8) % 24) && c > t) return c;
  }
  return null;
}
const OSS_HOURS = [1, 4, 7, 10, 13, 16, 19, 22];
const DAILY_HOURS = [10, 14, 18];
const ossSlots = () => { const n = Number(D?.ops?.runtime_config?.slots); return Number.isInteger(n) && n > 0 ? n : "未提供"; };
const nextOss = () => nextAt(OSS_HOURS, 0);
function nextDispatch() { const d = now(); d.setSeconds(0, 0); d.setMinutes(Math.floor(d.getMinutes() / 30) * 30 + 30); return d; }
const todayStatus = () => (D.daily_status || {})[today()] || null;
const nextDaily = () => (todayStatus()?.done ? null : nextAt(DAILY_HOURS, 15));

/* ---------- lookups ---------- */
const AREA = { oss: "開源", comps: "競賽", papers: "論文", quick: "每日任務", other: "其他" };
const comp = (id) => (D.competitions || []).find((c) => String(c.id) === String(id));
const paper = (slug) => (D.papers || []).find((p) => p.slug === slug);
const nameOf = (id) => { const c = comp(id); if (c) return c.name || c.title; const p = paper(id); if (p) return p.name || p.venue; return String(id); };
const jobs = (area) => (D.live?.claude || []).filter((x) => !area || x.area === area);
const worker = (id) => (D.live?.workers || {})[String(id)] || null;
const gpuJobs = (id) => (D.live?.gpu_queue || []).filter((x) => String(x.item) === String(id));
const focusCompIds = () => (D.focus3?.competitions || []).map((f) => String(f.id));
const focusPaperIds = () => (D.focus3?.papers || []).map((f) => String(f.slug));
const USER_RE = /帳號持有人|等你|你決定|申請人|本人經歷/;
function gpu() {
  const [u, m, t] = String(D.live?.gpu || "").split(",").map((s) => parseFloat(s));
  return Number.isFinite(u) ? { util: u, used: m / 1024, total: t / 1024 } : null;
}
function contributors() {
  const prs = new Map();   // url -> repo, every merged pull request we know of
  (D.contributions || []).filter((c) => (c.kind === "pr" || c.kind === "pull_request") && c.outcome === "merged").forEach((c) => prs.set(c.url, { repo: c.repo, at: c.closed_at }));
  (D.celebrations || []).filter((e) => e.kind === "merged" && e.link).forEach((e) => {
    const m = e.link.match(/github\.com\/([^/]+\/[^/]+)\/pull\//); if (m && !prs.has(e.link)) prs.set(e.link, { repo: m[1], at: e.at });
  });
  const repos = new Map();
  prs.forEach(({ repo, at }) => { const r = repos.get(repo) || { repo, prs: 0, first: at }; r.prs += 1; if (at && (!r.first || at < r.first)) r.first = at; repos.set(repo, r); });
  (D.celebrations || []).filter((e) => e.kind === "contributor").forEach((e) => {
    const repo = e.id.replace(/^contributor:/, ""); if (!repos.has(repo)) repos.set(repo, { repo, prs: 0, first: e.at });
  });
  return { repos: [...repos.values()].sort((a, b) => (a.first || "") < (b.first || "") ? 1 : -1), prs: prs.size };
}
const inPrizeZone = (c) => { const k = c.prize_ranks || 3; return c.rank && c.rank <= k && (c.board_size || 0) >= k + 2 && (c.days_left ?? 1) > 0; };

/* ---------- small building blocks ---------- */
const chip = (text, cls = "", title = "") => `<span class="chip ${cls}"${title ? ` title="${esc(title)}"` : ""}>${text}</span>`;
const link = (url, text) => url ? `<a href="${esc(url)}" target="_blank" rel="noopener">${text}</a>` : text;
const sec = (title, aside, body, id = "") => `<section class="section"${id ? ` id="${id}"` : ""}><div class="sec-head"><h2>${title}</h2>${aside ? `<span class="aside">${aside}</span>` : ""}</div>${body}</section>`;
const fold = (title, aside, body, openIt = false) => `<details class="fold section"${openIt ? " open" : ""}><summary>${title}${aside ? `<span class="aside">${aside}</span>` : ""}</summary><div class="fold-body">${body}</div></details>`;
const rules = (items) => fold("運作規則", "", `<ul class="rules">${items.map((x) => `<li>${x}</li>`).join("")}</ul>`);
function jobRow(x) {
  const main = x.area === "comps" || x.area === "papers" ? nameOf(x.item) : x.label;
  const item = x.area === "comps" || x.area === "papers" ? "" : x.item;
  return `<li class="job" title="PID ${x.pid}"><span class="live-dot" aria-hidden="true"></span><span class="t">${esc(main)}</span><span class="min num">${mins(x.minutes)}</span>
    <span class="m">${item ? `<span class="item">${esc(item)}</span>` : ""}<span>${esc(x.model)}${x.effort ? " " + esc(x.effort) : ""}</span></span></li>`;
}

/* What an item's worker is doing now: Claude, GPU, background processes, and its last note. */
function nowBox(id, focus) {
  const lines = [];
  const cj = (D.live?.claude || []).filter((x) => String(x.item) === String(id) && (x.area === "comps" || x.area === "papers"));
  cj.forEach((x) => lines.push(`<div class="now-line"><span class="live-dot"></span><span><b>模型執行中</b> ${mins(x.minutes)},${esc(x.model)} ${esc(x.effort)}</span></div>`));
  const gq = gpuJobs(id);
  gq.filter((x) => x.status === "running").forEach((x) => lines.push(`<div class="now-line"><span class="live-dot"></span><span><b>GPU 訓練中</b> ${esc(x.name)},已 ${dur(x.started)}(${fmtTime(x.started)} 開始)</span></div>`));
  gq.filter((x) => x.status === "queued").forEach((x) => lines.push(`<div class="now-line"><span class="idle-dot"></span><span>GPU 排隊第 ${x.position} 位:${esc(x.name)}${x.mem_gb ? `,需要 ${x.mem_gb} GB` : ""}</span></div>`));
  const bg = (D.live?.training || []).filter((t) => String(t.id) === String(id) && !gq.some((g) => g.status === "running" && g.name === t.run));
  bg.forEach((t) => lines.push(`<div class="now-line"><span class="live-dot"></span><span><b>背景程序</b> ${esc(t.run)}${t.log_tail ? `<span class="since"> 最新輸出:${esc(t.log_tail.slice(0, 90))}</span>` : ""}</span></div>`));
  const w = worker(id);
  if (w && w.doing) {
    const user = USER_RE.test(w.doing);
    lines.push(`<div class="now-line">${user ? '<span class="warn-dot"></span>' : '<span class="idle-dot"></span>'}<span>${w.stage ? chip(esc(w.stage)) + " " : ""}${user ? chip("需要你", "warn") + " " : ""}<span class="doing">${esc(w.doing)}</span> <span class="since">${ago(w.since)}</span></span></div>`);
  }
  if (!cj.length) lines.push(`<div class="now-line since">${focus ? `下一次派工 ${fmtTime(nextDispatch())}` : "已暫停,不派工也不分配 GPU"}</div>`);
  return `<div class="now-box">${lines.join("")}</div>`;
}

/* ---------- charts ---------- */
function strip(c, w = 560, h = 50) {
  const sc = (c.board || []).map((b) => b.score), est = c.estimate || {}, ours = ourScore(c);
  if (!sc.length && ours == null) return `<div class="empty">排行榜還沒有分數</div>`;
  const all = sc.concat(ours != null ? [ours] : []).concat(est.cutoff != null ? [est.cutoff] : []);
  let lo = Math.min(...all), hi = Math.max(...all);
  if (hi === lo) { hi += 1; lo -= 1; }
  const hb = c.higher_is_better !== false;
  const X = (v) => { const t = (v - lo) / (hi - lo); return 22 + (hb ? t : 1 - t) * (w - 44); };
  let s = `<svg width="100%" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" role="img" aria-label="排行榜分數分布,右側較佳">`;
  s += `<line x1="8" x2="${w - 8}" y1="22" y2="22" stroke="var(--line-2)"/>`;
  sc.forEach((v, i) => { s += `<circle cx="${X(v).toFixed(1)}" cy="22" r="3.4" fill="var(--ink-3)" opacity=".45"><title>第 ${i + 1} 名 ${esc(c.board[i].owner)} ${score(v)}</title></circle>`; });
  if (est.cutoff != null) { const x = X(est.cutoff).toFixed(1); s += `<line x1="${x}" x2="${x}" y1="6" y2="38" stroke="var(--good)" stroke-width="1.6" stroke-dasharray="3 2"/><text x="${x}" y="48" text-anchor="middle">得獎線</text>`; }
  if (ours != null) s += `<circle cx="${X(ours).toFixed(1)}" cy="22" r="7" fill="var(--a-comps)" stroke="var(--surface)" stroke-width="2.5"><title>我們 ${score(ours)}</title></circle>`;
  s += `<text x="${w - 8}" y="10" text-anchor="end">右側較佳</text></svg>`;
  return s;
}
function lines(series, w = 640, h = 180, opts = {}) {
  const pts = series.flatMap((s) => s.points);
  if (pts.length < 2) return `<div class="empty">歷史紀錄還不夠畫出走勢</div>`;
  const xs = pts.map((p) => +new Date(p[0])), ys = pts.map((p) => p[1]);
  let x0 = Math.min(...xs), x1 = Math.max(...xs), y0 = Math.min(...ys), y1 = Math.max(...ys);
  if (x1 === x0) x1 = x0 + 1; if (y1 === y0) { y1 += 1; y0 -= 1; }
  const L = 46, R = 10, T = 10, B = 22;
  const X = (x) => L + ((x - x0) / (x1 - x0)) * (w - L - R);
  const Y = (y) => (opts.invert ? T + ((y - y0) / (y1 - y0)) * (h - T - B) : h - B - ((y - y0) / (y1 - y0)) * (h - T - B));
  let s = `<svg width="100%" viewBox="0 0 ${w} ${h}" role="img" aria-label="${esc(opts.label || "走勢")}">`;
  for (let i = 0; i <= 3; i++) { const y = y0 + ((y1 - y0) * i) / 3; s += `<line x1="${L}" x2="${w - R}" y1="${Y(y)}" y2="${Y(y)}" stroke="var(--line)"/><text x="${L - 6}" y="${Y(y) + 3}" text-anchor="end">${opts.int ? Math.round(y) : score(y)}</text>`; }
  [x0, (x0 + x1) / 2, x1].forEach((x) => { s += `<text x="${X(x)}" y="${h - 6}" text-anchor="middle">${new Date(x).toLocaleDateString("zh-TW", { timeZone: TZ, month: "numeric", day: "numeric" })}</text>`; });
  series.forEach((sr) => {
    s += `<polyline points="${sr.points.map((q) => `${X(+new Date(q[0])).toFixed(1)},${Y(q[1]).toFixed(1)}`).join(" ")}" fill="none" stroke="${sr.color}" stroke-width="${sr.width || 2}" ${sr.dash ? `stroke-dasharray="${sr.dash}"` : ""}/>`;
    sr.points.forEach((q) => { s += `<circle cx="${X(+new Date(q[0])).toFixed(1)}" cy="${Y(q[1]).toFixed(1)}" r="2.2" fill="${sr.color}"><title>${esc(sr.name)} ${fmtDT(q[0])}:${opts.int ? q[1] : score(q[1])}</title></circle>`; });
  });
  return s + "</svg>";
}
const AREA_OF_JOB = { hunt: "oss", ship: "oss", reply: "oss", compete: "comps", plateau: "comps", scan: "comps", papers: "papers", quickwins: "quick", daily: "other" };
const AREA_ORDER = ["oss", "comps", "papers", "quick", "other"];
function stacked(daysArr, metric, w = 900, h = 220) {
  if (!daysArr.length) return `<div class="empty">沒有用量紀錄</div>`;
  const val = (j) => (!j ? 0 : metric === "cost" ? j.cost : metric === "output" ? j.output : j.input + j.cache_write + j.cache_read + j.output);
  const byArea = daysArr.map((d) => { const o = {}; Object.entries(d.jobs).forEach(([j, v]) => { const a = AREA_OF_JOB[j] || "other"; o[a] = (o[a] || 0) + val(v); }); return o; });
  const tot = byArea.map((o) => Object.values(o).reduce((a, b) => a + b, 0));
  const max = Math.max(1e-9, ...tot), L = 58, B = 22, T = 8, bw = (w - L - 8) / daysArr.length;
  const f = (v) => (metric === "cost" ? usd(v) : tok(v));
  let s = `<svg width="100%" viewBox="0 0 ${w} ${h}" role="img" aria-label="每日用量">`;
  for (let i = 0; i <= 3; i++) { const v = (max * i) / 3, y = h - B - (v / max) * (h - B - T); s += `<line x1="${L}" x2="${w - 8}" y1="${y}" y2="${y}" stroke="var(--line)"/><text x="${L - 6}" y="${y + 3}" text-anchor="end">${f(v)}</text>`; }
  daysArr.forEach((d, i) => {
    let y = h - B;
    AREA_ORDER.forEach((a) => { const v = byArea[i][a] || 0; if (!v) return; const hh = (v / max) * (h - B - T); y -= hh;
      s += `<rect x="${(L + i * bw + 1).toFixed(1)}" y="${y.toFixed(1)}" width="${Math.max(1, bw - 2).toFixed(1)}" height="${hh.toFixed(1)}" fill="var(--a-${a})"><title>${d.day} ${AREA[a]}:${f(v)}</title></rect>`; });
    if (i % Math.ceil(daysArr.length / 10) === 0) s += `<text x="${(L + i * bw + bw / 2).toFixed(1)}" y="${h - 6}" text-anchor="middle">${d.day.slice(5)}</text>`;
  });
  return s + "</svg>";
}

/* ---------- overview ---------- */
function needsYou() {
  const out = [], h = D.health || {};
  if (h.paused) out.push({ what: "<b>引擎已暫停</b>", why: "PAUSE 檔案存在,所有排程都不會開始新工作。" });
  const fresh = D.live_at || D.generated_at;
  const age = (now() - new Date(fresh)) / 60000;
  if (age > 10) out.push({ what: "<b>監控資料沒有更新</b>", why: `最後一次是 ${ago(fresh)},正常每 2 分鐘一次。` });
  const seen = new Set();
  Object.entries(D.live?.workers || {}).forEach(([id, w]) => {
    if (!w.doing || !USER_RE.test(w.doing)) return;
    seen.add(id);
    const tab = w.kind === "paper" ? "papers" : "comps";
    out.push({ what: `<a href="#${tab}/${esc(id)}">${esc(nameOf(id))}</a>`, why: esc(w.doing), when: ago(w.since) });
  });
  (D.papers || []).filter((p) => p.ready_for_go && !p.submitted && !seen.has(p.slug)).forEach((p) =>
    out.push({ what: `<a href="#papers/${esc(p.slug)}">${esc(p.name || p.venue)}</a>`, why: "稿件已備妥,等你說投。" }));
  return out;
}
function viewOverview() {
  const J = jobs(), g = gpu(), gq = D.live?.gpu_queue || [];
  const h = D.health || {}, lim = h.limit?.until && new Date(h.limit.until) > now();
  const byArea = AREA_ORDER.map((a) => [a, J.filter((x) => x.area === a).length]).filter(([, n]) => n);
  const takeover = h.codex_takeover?.status === "running";
  const line = h.paused ? "引擎已暫停" : takeover ? "Codex 正依序接手工作" : lim ? `Claude 額度已滿，${fmtTime(h.limit.until)} 重置` : J.length ? `<span class="n num">${J.length}</span> 個模型工作正在執行` : "目前沒有模型工作在執行";
  const gRun = gq.filter((x) => x.status === "running").length, gQ = gq.filter((x) => x.status === "queued").length;
  const sub = [byArea.length ? byArea.map(([a, n]) => `${AREA[a]} <b class="num">${n}</b>`).join(",") : "",
    g ? `GPU 使用率 <b class="num">${Math.round(g.util)}%</b>,${gRun ? `${gRun} 個訓練中` : "沒有訓練"}${gQ ? `,${gQ} 個排隊` : ""}` : ""].filter(Boolean).join(";");
  const K = contributors(), ts = todayStatus();
  const zone = (D.competitions || []).filter(inPrizeZone).length;
  const tally = `<div class="tally">
    <div><span class="v num">${K.repos.length}</span><span class="k">貢獻專案</span></div>
    <div><span class="v num">${K.prs}</span><span class="k">合併 PR</span></div>
    <div><span class="v num">${zone}</span><span class="k">比賽在得獎區</span></div>
    <div><span class="v" style="color:${ts?.done ? "var(--k-daily)" : "var(--ink-3)"}">${ts?.done ? "已確認" : "未確認"}</span><span class="k">今天的每日任務</span></div></div>`;

  const lane = (a) => {
    const js = J.filter((x) => x.area === a);
    let idle = "";
    if (!js.length) {
      if (a === "oss") { const n = nextOss(); idle = `下一輪 <span class="when num">${fmtTime(n)}</span><span class="dim small">${until(n)}</span>`; }
      else if (a === "comps" || a === "papers") { const n = nextDispatch(); idle = `下一次派工 <span class="when num">${fmtTime(n)}</span>`; }
      else if (a === "quick") { const n = nextDaily(); idle = ts?.done ? `<span class="when">今天已確認</span>` : `下一次 <span class="when num">${fmtTime(n)}</span><span class="dim small">${until(n)}</span>`; }
    }
    const note = { oss: `每 3 小時一輪 ${ossSlots()} 個名額,回覆每 5 分鐘偵測`, comps: "只派 3 個焦點比賽,每 30 分鐘", papers: "只派 3 篇焦點論文,每 30 分鐘", quick: "10:15、14:15、18:15,確認後停止" }[a];
    return `<div class="lane${js.length ? " busy" : ""}" style="--area:var(--a-${a})"><div class="lane-head"><span class="lane-name">${AREA[a]}</span><span class="lane-count">${js.length ? `${js.length} 個執行中` : "閒置"}</span></div>
      ${js.length ? `<ul class="jobs">${js.map(jobRow).join("")}</ul>` : `<div class="lane-idle"><span class="idle-dot"></span><span>${idle}</span></div>`}
      <div class="lane-note">${note}</div></div>`;
  };
  const other = J.filter((x) => x.area === "other");
  const gRunJ = gq.filter((x) => x.status === "running"), gQJ = gq.filter((x) => x.status === "queued");
  const bg = (D.live?.training || []).filter((t) => !gRunJ.some((x) => x.name === t.run));
  const gpuLane = `<div class="lane${gRunJ.length ? " busy" : ""}" style="--area:var(--a-other)"><div class="lane-head"><span class="lane-name">GPU</span><span class="lane-count">${gRunJ.length ? `${gRunJ.length} 個訓練中` : "閒置"}</span></div>
    ${g ? `<div class="gpu-meter"><div class="flex small" style="display:flex;justify-content:space-between"><span>使用率 <b class="num">${Math.round(g.util)}%</b></span><span class="dim num">${g.used.toFixed(1)} / ${g.total.toFixed(0)} GB</span></div><div class="meter"><i style="width:${Math.round(g.util)}%"></i></div></div>` : ""}
    ${gRunJ.length ? `<ul class="jobs">${gRunJ.map((x) => `<li class="job"><span class="live-dot"></span><span class="t">${esc(nameOf(x.item))}</span><span class="min num">${dur(x.started)}</span><span class="m"><span class="item">${esc(x.name)}</span>${x.mem_gb ? `<span>${x.mem_gb} GB</span>` : ""}</span></li>`).join("")}</ul>` : ""}
    ${gQJ.length ? `<ul class="rows small">${gQJ.map((x) => `<li><span class="what">第 ${x.position} 位 ${esc(nameOf(x.item))}<span class="why">${esc(x.name)}</span></span><span class="when">${x.mem_gb ?? "-"} GB</span></li>`).join("")}</ul>` : ""}
    ${bg.length ? `<div class="lane-note">背景程序:${bg.map((t) => `${esc(nameOf(t.id))} ${esc(t.run)}`).join(",")}</div>` : ""}
    <div class="lane-note">只分配給焦點項目</div>
    ${other.length ? `<div class="lane-note">其他工作(不使用 GPU)</div><ul class="jobs">${other.map(jobRow).join("")}</ul>` : ""}</div>`;

  const N = needsYou();
  const C = (D.celebrations || []).slice().sort((a, b) => ((a.at || a.detected) < (b.at || b.detected) ? 1 : -1)).slice(0, 4);
  return `
  <div class="hero"><div><div class="hero-line">${line}</div>${sub ? `<div class="hero-sub">${sub}</div>` : ""}</div>${tally}</div>
  <div class="lanes">${["oss", "comps", "papers", "quick"].map(lane).join("")}${gpuLane}</div>
  <div class="split section">
    <div class="panel"><div class="sec-head"><h2>需要你</h2><span class="aside">${N.length ? `${N.length} 件` : ""}</span></div>
      ${N.length ? `<ul class="rows">${N.map((x) => `<li><span class="what">${x.what}<span class="why">${x.why}</span></span><span class="when">${x.when || ""}</span></li>`).join("")}</ul>` : `<div class="empty">目前沒有需要你處理的事。</div>`}</div>
    <div class="panel"><div class="sec-head"><h2>最近的成果</h2><a class="aside" href="#wall">全部成就</a></div>
      ${C.length ? `<ul class="rows">${C.map((e) => `<li><span class="what"><span class="kind-t" style="--kind:var(${(KIND[e.kind] || KIND.achievement)[1]})">${(KIND[e.kind] || KIND.achievement)[0]}</span> ${link(e.link, esc(e.title))}<span class="why">${esc(e.detail || "")}</span></span><span class="when">${fmtDate(e.at || e.detected)} ${e.share_url ? `<a class="btn tiny" href="${esc(e.share_url)}" target="_blank" rel="noopener" title="打開 GitHub 發布頁,內容已填好,按 Publish 就會出現在動態">分享</a>` : ""}</span></li>`).join("")}</ul>` : `<div class="empty">還沒有成果紀錄。</div>`}</div>
  </div>
  ${mergeReview()}`;
}

/* ---------- what each merged pull request is worth ---------- */
function mergeReview() {
  const A = D.merge_assessments || {};
  const when = {};
  (D.celebrations || []).forEach((e) => { if (e.kind === "merged" && e.link) when[e.link] = e.at || e.detected; });
  const rows = Object.entries(A).sort((a, b) => ((when[a[0]] || "") < (when[b[0]] || "") ? 1 : -1));
  if (!rows.length) return "";
  const tone = { 頂級: "top", 高: "good", 中: "info", 低: "" };
  const onProfile = rows.filter(([, a]) => a.profile).length;
  return `<div class="panel section"><div class="sec-head"><h2>合併的貢獻與價值</h2><span class="aside">${rows.length} 個 PR,${onProfile} 個放上個人主頁</span></div>
    <ul class="rows merge-review">${rows.map(([url, a]) => { const m = url.match(/github\.com\/([^/]+\/[^/]+)\/pull\/(\d+)/);
      return `<li><span class="what">${link(url, esc(m ? `${m[1]} #${m[2]}` : url))}
        <span class="why">${esc(a.summary_zh || "")}</span>
        <span class="why">價值 <span class="chip ${tone[a.value] || ""}">${esc(a.value || "")}</span> ${esc(a.reason_zh || "")}</span>
        ${a.value === "頂級" && a.brag_zh ? `<span class="why brag">值得炫耀:${esc(a.brag_zh)}</span>` : ""}
        <span class="why">${esc(a.judge_model || "評估模型未記錄")} 評估於 ${fmtDT(a.assessed)}</span>
        <span class="why">${a.profile ? '<span class="chip good">放上個人主頁</span>' : '<span class="chip">不放上個人主頁</span>'}</span></span>
        <span class="when">${fmtDate(when[url])}</span></li>`; }).join("")}</ul>
    <div class="lane-note">評估由沒有參與撰寫的模型讀過 PR 內容與改動後給出；Claude 額度用盡時改由 Codex 接手。個人主頁只列出評為高價值的項目。</div></div>`;
}

/* ---------- open source ---------- */
const PR_STATE = { review: ["等審查", "info"], approved: ["審查通過", "good"], changes: ["要求修改", "warn"], conflict: ["有衝突", "warn"], reply: ["待回覆", "warn"], noted: ["留言已處理", "info"], unknown: ["查不到狀態", ""] };
const MERGEABLE = { clean: ["可合併", "good"], blocked: ["等必要的審查或檢查", ""], unstable: ["CI 未全過", "warn"], behind: ["落後主線", ""], dirty: ["與主線衝突", "warn"] };
function prNext(c) {
  const idle = Math.floor(c.idle_days || 0);
  if (c.owed) return ["ours", "回覆對方", `${esc(c.last_word?.by || "")} ${ago(c.last_word?.at)}留言`];
  if (c.draft) return ["ours", "轉為可審查", "目前是草稿"];
  if (c.mergeable_state === "dirty") return ["ours", "rebase 解衝突", "與主線衝突"];
  const oursLast = String(c.last_word?.by || "").toLowerCase() === "arthur031221";
  if (c.state_code === "changes") return oursLast ? ["theirs", "等維護者再審", "我們已在修改後回應"] : ["ours", "依審查修改", "維護者要求修改"];
  if (idle >= 30) return ["ours", "詢問要調整還是關閉", `${idle} 天沒有動靜`];
  if (idle >= 14) return ["ours", "發一次提醒", `${idle} 天沒有動靜`];
  if (c.state_code === "approved") return ["theirs", "等維護者合併", "審查已通過"];
  return ["theirs", "等維護者", idle ? `${idle} 天沒有動靜` : "今天有動靜"];
}
function roundLabel(r) { const m = String(r).match(/(\d{4})-(\d\d)-(\d\d)T(\d\d)(\d\d)/); return m ? `${+m[2]}/${+m[3]} ${m[4]}:${m[5]}` : esc(r); }
const pips = (n, goal) => `<span class="pips" aria-label="${n} / ${goal}">${Array.from({ length: Math.max(goal, n) }, (_, i) => `<i class="${i < n ? "on" : ""}"></i>`).join("")}</span>`;
function roundBoard() {
  const live = jobs("oss");
  const limit = D.health?.limit?.until;
  const limited = limit && new Date(limit) > now();
  const status = live.length
    ? `<div class="now-line"><span class="live-dot"></span><b>一件開源工作進行中</b></div><ul class="jobs">${live.map(jobRow).join("")}</ul>`
    : limited
      ? `<div class="small dim">Claude 用量暫停至 ${fmtDT(limit)}；Codex 接手輪次會先檢查主機容量與回覆，再依序工作。</div>`
      : `<div class="small dim">目前沒有開源工作執行中。下一輪 ${fmtTime(nextOss())}；有維護者回覆時先處理回覆。</div>`;
  const old = (D.hunt_rounds || []).slice(-5).reverse();
  const history = old.length ? `<div class="sub-h">先前回合紀錄</div><div class="history">${old.map((r) => `<div class="hrow"><span class="num">${roundLabel(r.round)}</span><span class="small num">${r.verified}/${r.goal} 筆已查核</span><span class="prs">${(r.prs || []).map((p) => link(p.url, esc(p.repo))).join("") || '<span class="dim">沒有 PR</span>'}</span></div>`).join("")}</div>` : "";
  return `<div class="panel">${status}${history}</div>`;
}

function viewOss() {
  const K = contributors(), C = D.contributions || [];
  const open = C.filter((c) => (c.kind === "pr" || c.kind === "pull_request") && c.outcome === "open").map((c) => ({ c, n: prNext(c) }))
    .sort((a, b) => (a.n[0] === b.n[0] ? (b.c.idle_days || 0) - (a.c.idle_days || 0) : a.n[0] === "ours" ? -1 : 1));
  const ours = open.filter((x) => x.n[0] === "ours").length;
  const issues = C.filter((c) => c.kind === "issue" && c.outcome === "open");
  const B = (D.bank || []).filter((b) => !/SUBMITTED|DROPPED|SUPERSEDED|POSTED|MERGED|CLOSED|ANSWERED|REJECT/.test(b.status) && String(b.submitted).toUpperCase() !== "YES");
  const hero = `<div class="panel" style="--area:var(--a-oss)"><div class="figure"><span class="big num" style="color:var(--k-contributor)">${K.repos.length}</span>
      <span class="lbl">個專案的 Contributors 名單有你。共 <b class="num">${K.prs}</b> 個 PR 合併,<b class="num">${open.length}</b> 個 PR 開啟中。</span></div>
    <div class="repo-list">${K.repos.map((r) => `<a href="https://github.com/${esc(r.repo)}/graphs/contributors" target="_blank" rel="noopener">${esc(r.repo)} <small>${r.prs ? `${r.prs} 個 PR` : ""}${r.first ? ` 自 ${fmtDate(r.first)}` : ""}</small></a>`).join("") || '<span class="empty">還沒有合併的 PR。</span>'}</div></div>`;
  const prs = open.length ? `<div class="panel"><div class="prs-list">${open.map(({ c, n }) => {
    const st = PR_STATE[c.state_code] || [esc(c.state_code || ""), ""], mg = MERGEABLE[c.mergeable_state];
    return `<div class="pr"><div><div class="pr-title">${link(c.url, esc(c.title))}</div><div class="pr-repo">${esc(c.repo)}#${c.number},${c.submitted ? fmtDate(c.submitted) : "-"} 送出</div>
      <div class="pr-state">${chip(st[0], st[1])}${c.draft ? chip("草稿", "warn") : ""}${mg && !(c.state_code === "conflict" && c.mergeable_state === "dirty") ? chip(mg[0], mg[1]) : ""}${c.additions != null ? `<span class="num xs dim">+${c.additions} / -${c.deletions}</span>` : ""}${c.last_word ? `<span class="xs dim">最後發言 ${esc(c.last_word.by)},${ago(c.last_word.at)}</span>` : ""}</div></div>
      <div class="pr-next ${n[0]}"><b>${n[1]}</b><span class="xs dim">${n[2]}</span></div></div>`;
  }).join("")}</div></div>` : `<div class="panel empty">沒有開啟中的 PR。</div>`;
  return `
  ${hero}
  ${sec("開源回合", `每 3 小時一輪,${ossSlots()} 個名額並行,優先接手舊 PR 並標註原作者為共同作者`, roundBoard())}
  ${(() => { const P = D.pair || {}, m = P.merged || [], o = P.open || [], lost = P.lost || [], tiers = [1, 10, 24, 48];
    const bar = tiers.map((t) => `<span class="chip ${P.count >= t ? "top" : ""}">x${tiers.indexOf(t) + 1}:${t} 個</span>`).join(" ");
    const row = (x, done) => `<li><span class="what">${link(x.url, esc(x.url.replace("https://github.com/", "")))}<span class="why">${esc(x.title)}</span><span class="why">共同作者:${x.coauthors.map((c) => esc(c)).join(",")}</span></span><span class="when">${done === "lost" ? chip("不計入", "warn") : done ? chip("已計入", "good") : chip("審查中", "info")} ${fmtDate(x.at)}</span></li>`;
    return sec("Pair Extraordinaire", `目前 ${P.count ?? "?"} 個${P.next ? `,距離下一級 ${P.next} 個還差 ${P.next - (P.count || 0)} 個` : ""}`,
      `<div class="panel"><div>${bar}</div>
       <p class="xs dim">算法和 GitHub 一致:只看合併後實際進入主分支的 commit。squash 或 rebase 合併時,那個 commit 要同時列出你和另一位作者;一般 merge commit 合併時,PR 裡要有一個 commit 同時列出你們兩人。分支上有共同作者、但合併後被拿掉的列在「不計入」。</p>
       <ul class="rows">${m.map((x) => row(x, true)).join("")}${o.map((x) => row(x, false)).join("")}${lost.map((x) => row(x, "lost")).join("")}</ul></div>`); })()}
  ${sec("開啟中的 PR", ours ? `${ours} 件該由我們跟進,其餘等維護者` : "都在等維護者", prs)}
  ${issues.length ? fold("開啟中的 issue", `${issues.length} 件,只作為自己 PR 的前置`, `<ul class="rows">${issues.map((c) => `<li><span class="what">${link(c.url, esc(c.title))}<span class="why">${esc(c.repo)}#${c.number},${esc(c.status_zh || "")}</span></span><span class="when">${c.idle_days != null ? Math.floor(c.idle_days) + " 天" : ""}</span></li>`).join("")}</ul>`) : ""}
  ${B.length ? fold("佇列中的項目", `${B.length} 項,依序處理`, `<ul class="rows">${B.slice().sort((a, b) => (b.updated > a.updated ? 1 : -1)).map((b) => `<li><span class="what">${esc(b.repo || b.item)}<span class="why">${esc(b.item)}</span></span><span class="when">${chip(esc(b.status), "info")} ${ago(b.updated)}</span></li>`).join("")}</ul>`) : ""}
  ${rules([
    "目標是有合併 commit 的專案數(Contributors 名單)。只有合併的 PR 算數。",
    `每天 01:00、04:00、07:00、10:00、13:00、16:00、19:00、22:00 各開一輪,${ossSlots()} 個名額同時跑,每輪至少送出 10 個通過雙人審查的高品質 PR,最多持續 12 小時,另以接手 25 個 PR 為目標。候選不足時記錄原因並挑選有價值的具有真人共同作者的 PR,名額結束就補位。`,
    "第一優先:接手別人放棄的舊 PR 完成它,並把原作者列為共同作者(Pair Extraordinaire)。每輪開始前先掃描候選專案與整個 GitHub,由 Codex 排序後分給名額。",
    "模型:開源工作由 Codex gpt-6.1-sol high執行;送出前第一關由 Codex gpt-6.1-sol high 審查,通過後第二關由 Claude Sonnet 5.5 審查。",
    "每個 PR 送出前:政策檢查、兩位互不知情的審查者通過、去除 AI 痕跡檢查;送出後在 GitHub 讀回確認。沒有符合價值門檻的修正就不送。",
    "目標依實測速度挑選:外部 PR 合併時間中位數 7 天以內、合併率至少一半;已合併過的專案排在新專案之後;NVIDIA 與 RAPIDS 排在其他專案之後;每個專案同時最多一件我們的項目在等。候選池自動擴充。" + (D.merge_stats_summary?.pool ? `目前候選池 ${D.merge_stats_summary.pool} 個專案。` : ""),
    "不審查別人的 PR。issue 只作為自己 PR 的前置步驟。Discussions 的回答只是附帶成果。",
    "跟進:每 5 分鐘偵測回覆,每 15 分鐘處理;草稿轉為可審查;有衝突立刻 rebase;安靜 14 天提醒一次;30 天詢問要調整還是關閉。",
  ])}`;
}

/* ---------- competitions ---------- */
function ourScore(c) {
  const b = c.estimate?.best;
  if (b != null) return b;
  if (c.rank && c.board?.[c.rank - 1]) return c.board[c.rank - 1].score;
  return null;
}
function rankTrack(c) {
  const n = c.board_size, k = c.prize_ranks || 3, r = c.rank || c.would_rank;
  if (!n || !r) return "";
  const pos = Math.min(100, Math.max(0, ((r - 0.5) / n) * 100)), zone = Math.min(100, (k / n) * 100);
  return `<div><div class="track" role="img" aria-label="第 ${r} 名,共 ${n} 隊,前 ${k} 名得獎"><div class="bar"></div><div class="zone" style="width:${zone}%"></div><div class="me" style="left:${pos}%"></div></div>
    <div class="track-l"><span>第 1 名</span><span>得獎區前 ${k} 名</span><span>第 ${n} 名</span></div></div>`;
}
function gapLine(c) {
  const ours = ourScore(c), cut = c.estimate?.cutoff;
  if (ours == null || cut == null) return "";
  const hb = c.higher_is_better !== false, gap = hb ? ours - cut : cut - ours;
  return `<div class="small">我們 <b class="num">${score(ours)}</b>,得獎線 <b class="num">${score(cut)}</b>,${Math.abs(gap) < 1e-9 ? `<span style="color:var(--good)">與得獎線同分</span>` : gap > 0 ? `<span style="color:var(--good)">高於得獎線 ${score(Math.abs(gap))}</span>` : `還差 <b class="num">${score(Math.abs(gap))}</b>`}</div>`;
}
function compCard(id) {
  const c = comp(id);
  if (!c) return `<div class="fcard" style="--area:var(--a-comps)"><h3>${esc(nameOf(id))}</h3><div class="empty">這個比賽沒有排行榜資料。</div>${nowBox(id, true)}</div>`;
  const k = c.prize_ranks || 3, r = c.rank || c.would_rank;
  return `<div class="fcard" data-comp="${esc(c.id)}" tabindex="0" role="link" style="--area:var(--a-comps)">
    <div><h3>${esc(c.name || c.title)}</h3><div class="venue">${esc(c.status?.venue || c.title || "")}</div></div>
    <div class="stats">
      <div class="stat"><div class="k">${c.not_on_board ? "名次(未上榜,估計)" : "名次"}</div><div class="v num ${r && r <= k ? "good" : ""}">${r ?? "-"}<small>/ ${c.board_size || "-"}</small></div></div>
      <div class="stat"><div class="k">得獎名次</div><div class="v num">前 ${k}</div></div>
      <div class="stat"><div class="k">剩餘</div><div class="v num">${days(c.days_left)}<small>天</small></div></div>
    </div>
    ${rankTrack(c)}${gapLine(c)}
    ${nowBox(c.id, true)}</div>`;
}
function viewComps() {
  if (state.comp) return viewComp(state.comp);
  const F = focusCompIds(), Q = (D.focus3?.competition_queue || []).map(String);
  const rest = (D.competitions || []).filter((c) => !F.includes(String(c.id)))
    .sort((a, b) => { const qa = Q.indexOf(String(a.id)), qb = Q.indexOf(String(b.id)); return (qa < 0 ? 99 : qa) - (qb < 0 ? 99 : qb) || (a.days_left ?? 999) - (b.days_left ?? 999); });
  const row = (c) => {
    const qi = Q.indexOf(String(c.id)), live = (D.live?.claude || []).some((x) => x.area === "comps" && String(x.item) === String(c.id)) || gpuJobs(c.id).some((x) => x.status === "running");
    const st = live ? chip('<span class="live-dot"></span>暫停中但仍有工作在跑', "warn") : c.participant_status === "pending" ? chip("等主辦方核准") : (c.days_left ?? 1) <= 0 ? chip("已結束") : chip("暫停", "paused");
    const w = worker(c.id);
    return `<tr class="click" data-comp="${esc(c.id)}"><td class="num">${qi >= 0 ? qi + 1 : ""}</td><td>${esc(c.name || c.title)}${w?.doing ? `<div class="xs dim">${esc(w.doing)}</div>` : ""}</td><td class="num">${c.rank || (c.would_rank ? "約 " + c.would_rank : "-")} / ${c.board_size || "-"}</td><td class="num">${days(c.days_left)}</td><td>${st}</td></tr>`;
  };
  return `
  ${sec("焦點比賽", "只有這 3 個有 Codex 工作者與 GPU", `<div class="focus">${F.map(compCard).join("") || '<div class="empty">focus3.json 沒有列出比賽。</div>'}</div>`)}
  ${fold("其餘比賽", `${rest.length} 個,已暫停`, `<div class="tablewrap"><table><thead><tr><th>候補</th><th>比賽</th><th>名次</th><th>剩餘天數</th><th>狀態</th></tr></thead><tbody>${rest.map(row).join("")}</tbody></table></div>
    <p class="xs dim" style="margin-top:8px">候補欄是焦點比賽結束時遞補的順序。</p>`)}
  ${rules(["所有資源集中在 3 個比賽與 3 篇論文。只有焦點項目會派工作者(每 30 分鐘派工一次,Codex gpt-6-luna high)並分配 GPU(A 級)。", "其餘項目全部暫停;焦點項目結束時,由候補的第一個遞補。"])}`;
}
function viewComp(id) {
  const c = comp(id);
  if (!c) { state.comp = null; return viewComps(); }
  const est = c.estimate || {}, st = c.status || {}, hist = c.history || [];
  const focus = focusCompIds().includes(String(c.id));
  const series = [
    { name: "我們最佳", color: "var(--a-comps)", points: hist.filter((h) => h.best != null).map((h) => [h.at, h.best]) },
    { name: "得獎線", color: "var(--good)", dash: "4 3", points: hist.filter((h) => h.cutoff != null).map((h) => [h.at, h.cutoff]) },
    { name: "第一名", color: "var(--ink-3)", width: 1.2, points: hist.filter((h) => h.top != null).map((h) => [h.at, h.top]) },
  ];
  const subPts = (c.submissions || []).filter((s) => s.score != null).map((s) => [s.at, s.score]);
  if (subPts.length) series.push({ name: "每次提交", color: "var(--info)", width: 1, points: subPts });
  const rankS = [{ name: "名次", color: "var(--a-comps)", points: hist.filter((h) => h.rank).map((h) => [h.at, h.rank]) }];
  const cost = (D.attribution?.items || []).find((b) => b.kind === "comp" && String(b.key) === String(c.id));
  const appr = st.approaches || [], k = c.prize_ranks || 3;
  const ours = new Set(["maxwelleq", "arthur031221", "nthuxnycu2024"]);
  return `<button class="btn back" data-go="comps" type="button">返回比賽列表</button>
  <div class="panel" style="--area:var(--a-comps)">
    <div class="detail-head"><div><h2>${esc(c.name || c.title)}</h2><div class="small dim">${esc(c.title || "")},${link(c.url, "比賽頁面")}</div>
      <div class="small dim">指標 ${esc(c.metric_key || st.metric || "主分數")},${c.higher_is_better === false ? "越低越好" : "越高越好"}${c.current_phase ? `;目前階段 ${esc(c.current_phase)}${c.phase_end ? `,${fmtDT(c.phase_end)} 結束` : ""}` : ""}</div></div>
      ${focus ? chip("焦點比賽", "info") : chip("已暫停", "paused")}</div>
    <div class="stats" style="grid-template-columns:repeat(auto-fit,minmax(120px,1fr));margin:20px 0">
      <div class="stat"><div class="k">名次</div><div class="v num">${c.rank ?? (c.would_rank ? "約 " + c.would_rank : "-")}<small>/ ${c.board_size ?? "-"}</small></div></div>
      <div class="stat"><div class="k">我們最佳</div><div class="v num">${score(ourScore(c))}</div></div>
      <div class="stat"><div class="k">得獎線(前 ${k})</div><div class="v num">${score(est.cutoff)}</div></div>
      <div class="stat"><div class="k">第一名</div><div class="v num">${score(c.board?.[0]?.score)}</div></div>
      <div class="stat"><div class="k">剩餘天數</div><div class="v num">${days(c.days_left)}</div></div>
      <div class="stat"><div class="k">估計得獎機率</div><div class="v num">${pct(est.p)}</div></div>
    </div>
    ${strip(c)}
    <div class="sub-h">現在</div>${nowBox(c.id, focus)}
    ${st.summary_zh ? `<div class="sub-h">比賽內容</div><p class="prose">${esc(st.summary_zh)}</p>` : ""}
    ${st.reward_zh ? `<div class="sub-h">得獎可以拿到</div><p class="prose">${esc(st.reward_zh)}</p>` : ""}
    ${st.progress_zh ? `<div class="sub-h">工作紀錄 <span class="xs dim">${c.status_updated_at ? `更新於 ${fmtDT(c.status_updated_at)}` : "未記錄更新時間"}</span></div><p class="prose">${esc(st.progress_zh)}</p>` : ""}
  </div>
  <div class="grid g2 section">
    <div class="panel"><h2 style="font-size:var(--t-lg)">分數走勢</h2>${lines(series, 640, 190, { label: "分數走勢" })}
      <div class="legend">${series.map((s) => `<span><i style="background:${s.color}"></i>${s.name}</span>`).join("")}</div>
      <div class="sub-h">名次走勢</div>${lines(rankS, 640, 140, { invert: true, int: true, label: "名次走勢" })}</div>
    <div class="panel"><h2 style="font-size:var(--t-lg)">得獎機率怎麼估</h2>
      <dl class="kv" style="margin-top:12px">
        <dt>方法</dt><dd>${esc(est.why || "")}</dd>
        <dt>得獎線</dt><dd>${esc(est.note || "")}</dd>
        <dt>我們每日進步</dt><dd class="num">${est.rate_per_day != null ? score(est.rate_per_day) : "-"} <span class="dim">${esc(est.rate_basis || "")}</span></dd>
        <dt>得獎線每日移動</dt><dd class="num">${est.cutoff_rate_per_day != null ? score(est.cutoff_rate_per_day) : "-"}</dd>
        <dt>截止時的我們</dt><dd class="num">${score(est.projected_best)}</dd>
        <dt>截止時的得獎線</dt><dd class="num">${score(est.projected_cutoff)}</dd>
        <dt>不確定度</dt><dd class="num">${score(est.sigma)}</dd>
      </dl>
      <div class="sub-h">研究</div>
      <dl class="kv">
        <dt>領域專家</dt><dd>${st.expert?.dossier ? `已建立,讀了 ${st.expert.papers_read ?? "?"} 篇論文` : "尚未建立"}</dd>
        <dt>本地驗證</dt><dd>${st.local_validation ? `${esc(st.local_validation.metric)} <span class="dim">${esc(st.local_validation.note || "")}</span>` : "-"}</dd>
        <dt>花費</dt><dd>${cost ? `${usd(cost.cost)},${tok(cost.tokens)} tokens,${cost.runs} 次執行${cost.split ? "(與其他比賽平分)" : ""}` : "-"}</dd>
        ${c.quota_today ? `<dt>今日提交</dt><dd class="num">${c.quota_today.used} / ${c.quota_today.max ?? "不限"}</dd>` : ""}
      </dl>
      ${(st.expert?.key_ideas || []).length ? `<div class="sub-h">專家重點</div><ul class="small">${st.expert.key_ideas.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}
      ${(st.next_steps || []).length ? `<div class="sub-h">下一步</div><ol class="small">${st.next_steps.map((x) => `<li>${esc(x)}</li>`).join("")}</ol>` : ""}
      ${(st.risks || []).length ? `<div class="sub-h">風險</div><ul class="small">${st.risks.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}
    </div>
  </div>
  ${appr.length ? sec("嘗試過的方法", `${appr.length} 項`, `<div class="panel"><div class="tablewrap"><table><thead><tr><th>方法</th><th>狀態</th><th class="r">本地</th><th class="r">排行榜</th><th>備註</th></tr></thead><tbody>
    ${appr.map((a) => `<tr><td>${esc(a.name)}</td><td>${chip(esc({ tried: "試過", running: "進行中", planned: "計畫中", dropped: "放棄" }[a.status] || a.status), a.status === "running" ? "live" : a.status === "dropped" ? "bad" : "")}</td><td class="num r">${score(a.local)}</td><td class="num r">${score(a.leaderboard)}</td><td class="small">${esc(a.note || "")}</td></tr>`).join("")}</tbody></table></div></div>`) : ""}
  <div class="grid g2 section">
    <div class="panel"><h2 style="font-size:var(--t-lg)">我們的提交 <span class="dim small num">${(c.submissions || []).length}</span></h2>
      <div class="tablewrap"><table><thead><tr><th>時間</th><th>檔案</th><th>狀態</th><th class="r">分數</th></tr></thead><tbody>
      ${(c.submissions || []).slice().reverse().map((s) => `<tr><td class="num">${fmtDT(s.at)}</td><td class="small wrap-any">${esc(s.file || "")}<div class="xs dim">${esc(s.phase)}</div></td><td>${chip(esc(s.status), s.status === "Finished" ? "good" : s.status === "Failed" ? "bad" : "info")}</td><td class="num r">${score(s.score)}</td></tr>`).join("") || '<tr><td colspan="4" class="empty">還沒有提交</td></tr>'}
      </tbody></table></div>
      ${(c.phases || []).length ? `<div class="sub-h">階段</div>${c.phases.map((p) => `<div class="small" style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap"><span>${esc(p.name)}</span><span class="dim num">${fmtDT(p.start)} 到 ${fmtDT(p.end)},每日 ${p.max_per_day ?? "不限"} 次</span></div>`).join("")}` : ""}</div>
    <div class="panel"><h2 style="font-size:var(--t-lg)">排行榜 <span class="dim small num">${c.board_size || 0} 隊</span></h2>
      <div class="tablewrap"><table><thead><tr><th>名次</th><th>隊伍</th><th class="r">分數</th></tr></thead><tbody>
      ${(c.board || []).slice(0, 50).map((b, i) => `<tr class="${ours.has(String(b.owner).toLowerCase()) ? "me" : ""}"><td class="num">${i + 1} ${i < k ? chip("得獎區", "good") : ""}</td><td class="wrap-any">${esc(b.owner)}</td><td class="num r">${score(b.score)}</td></tr>`).join("") || '<tr><td colspan="3" class="empty">排行榜是空的</td></tr>'}
      </tbody></table></div></div>
  </div>`;
}

/* ---------- papers ---------- */
const STAGE_P = ["徵稿", "定題", "實驗", "寫稿", "待投"];
const PSTATUS = { ACTIVE: ["進行中", "info"], HELD: ["擱置,等你", "warn"], SKIPPED: ["已跳過", ""], SUBMITTED: ["已投稿", "good"], READY: ["可投稿", "good"] };
function steps(stage) {
  return `<div><div class="steps">${STAGE_P.map((_, i) => `<span class="${i < stage ? "on" : ""}"></span>`).join("")}</div>
    <div class="steps-l">${STAGE_P.map((l, i) => `<span class="${i === stage - 1 ? "cur" : ""}">${l}</span>`).join("")}</div></div>`;
}
function paperCard(slug) {
  const p = paper(slug);
  if (!p) return `<div class="fcard" style="--area:var(--a-papers)"><h3>${esc(slug)}</h3><div class="empty">paper_targets.json 沒有這篇。</div>${nowBox(slug, true)}</div>`;
  const s = PSTATUS[p.submitted ? "SUBMITTED" : p.ready_for_go ? "READY" : p.status_word] || null;
  return `<div class="fcard" data-paper="${esc(p.slug)}" tabindex="0" role="link" style="--area:var(--a-papers)">
    <div style="display:flex;justify-content:space-between;gap:8px;align-items:flex-start"><div><h3>${esc(p.name || p.venue)}</h3><div class="venue">${esc(p.venue || "")}</div></div>${s ? chip(s[0], s[1]) : ""}</div>
    <div class="stats">
      <div class="stat"><div class="k">截止</div><div class="v num">${days(p.days_left)}<small>${p.days_left != null ? "天" : "滾動"}</small></div></div>
      <div class="stat"><div class="k">截止日</div><div class="v num" style="font-size:var(--t-md)">${esc(p.deadline || "-")}</div></div>
      <div class="stat"><div class="k">階段</div><div class="v" style="font-size:var(--t-md)">${esc(p.stage_label)}</div></div>
    </div>
    ${steps(p.stage)}
    ${nowBox(p.slug, true)}</div>`;
}
function viewPapers() {
  if (state.paper) return viewPaper(state.paper);
  const F = focusPaperIds(), rest = (D.papers || []).filter((p) => !F.includes(p.slug));
  return `
  ${sec("焦點論文", "只有這 3 篇有 Codex 工作者", `<div class="focus">${F.map(paperCard).join("") || '<div class="empty">focus3.json 沒有列出論文。</div>'}</div>`)}
  ${rest.length ? fold("其餘論文", `${rest.length} 篇,已暫停`, `<ul class="rows">${rest.map((p) => { const s = PSTATUS[p.status_word]; const w = worker(p.slug);
      return `<li><span class="what"><a href="#papers/${esc(p.slug)}">${esc(p.name || p.venue)}</a><span class="why">${esc(w?.doing || p.venue || "")}</span></span><span class="when">${s ? chip(s[0], s[1]) : ""} ${chip("暫停", "paused")}</span></li>`; }).join("")}</ul>`) : ""}
  ${rules(["所有資源集中在 3 個比賽與 3 篇論文。只有焦點項目會派工作者(每 30 分鐘派工一次,Codex gpt-6-luna high)。", "其餘項目全部暫停;焦點項目結束時,由候補的第一個遞補。"])}`;
}
function viewPaper(slug) {
  const p = paper(slug);
  if (!p) { state.paper = null; return viewPapers(); }
  const focus = focusPaperIds().includes(p.slug), s = PSTATUS[p.submitted ? "SUBMITTED" : p.ready_for_go ? "READY" : p.status_word];
  const cost = (D.attribution?.items || []).find((b) => b.kind === "paper" && b.key === p.slug);
  return `<button class="btn back" data-go="papers" type="button">返回論文列表</button>
  <div class="grid g2">
    <div class="panel" style="--area:var(--a-papers)"><div class="detail-head"><div><h2>${esc(p.name || p.venue)}</h2><div class="small dim">${esc(p.venue || "")}</div></div>
      <div>${focus ? chip("焦點論文", "info") : chip("已暫停", "paused")} ${s ? chip(s[0], s[1]) : ""}</div></div>
      <div class="section" style="margin-top:20px">${steps(p.stage)}</div>
      <div class="sub-h">現在</div>${nowBox(p.slug, focus)}
      ${p.topic ? `<div class="sub-h">研究內容</div><p class="prose">${esc(p.topic)}</p>` : ""}
      <div class="sub-h">投稿資訊</div>
      <dl class="kv">
        <dt>截止</dt><dd>${esc(p.deadline || "滾動")}${p.days_left != null ? `,還有 ${days(p.days_left)} 天` : ""}</dd>
        <dt>格式</dt><dd>${esc(p.format || "-")}</dd><dt>出席</dt><dd>${esc(p.in_person || "-")}</dd>
        <dt>接受率</dt><dd>${p.acceptance_rate != null ? pct(p.acceptance_rate) : "官方未公布"}</dd>
        <dt>花費</dt><dd>${cost ? `${usd(cost.cost)},${tok(cost.tokens)} tokens` : "-"}</dd></dl></div>
    <div class="panel"><h2 style="font-size:var(--t-lg)">工作紀錄</h2><p class="xs dim" style="margin:4px 0 12px">${p.status_updated_at ? `更新於 ${fmtDT(p.status_updated_at)}；` : ""}papers/${esc(p.slug)}/STATUS.md 的開頭</p>${p.status_excerpt ? `<pre class="log">${esc(p.status_excerpt)}</pre>` : '<div class="empty">沒有 STATUS.md</div>'}</div>
  </div>`;
}

/* ---------- daily task ---------- */
const qDay = (q) => (q.date && q.date.length > 10 ? fmtDay(new Date(q.date)) : q.date);
function qChip(q) {
  if (q.verified === true && q.counts !== false) return chip("已確認", "good");
  if (q.verified === false) return chip("第二模型確認不通過", "bad");
  if (q.counts === false) return chip("未達標準", "");
  return chip("等第二模型確認", "info");
}
function qRow(q) {
  const ev = q.verified_evidence || q.why_counts || q.note_zh || q.note || "";
  return `<li><span class="what">${link(q.link || q.url, esc(q.title))}<span class="why">${esc([q.where, q.result].filter(Boolean).join(",")) || ""}</span>${ev ? `<span class="why"><b>${q.verified_evidence ? "查核" : "說明"}</b> ${esc(ev)}</span>` : ""}</span><span class="when">${qChip(q)} ${q.date ? `<span class="num dim">${fmtDate(q.date)}</span>` : ""}</span></li>`;
}
function viewDaily() {
  const t = today(), ts = todayStatus(), Q = (D.quickwins || []).filter((q) => q.kind !== "answer");
  const todayQ = Q.filter((q) => qDay(q) === t);
  const n = nextDaily();
  const hero = `<div class="panel" style="--area:var(--a-quick)"><div class="figure"><span class="big" style="color:${ts?.done ? "var(--k-daily)" : "var(--ink-3)"};font-size:var(--t-3xl)">${ts?.done ? "今天已確認" : "今天還沒有確認"}</span>
    <span class="lbl">${ts?.done ? `${esc((ts.items || []).join(","))}。第二模型查核於 ${fmtTime(ts.checked_at)}。` : n ? `下一次執行 <b class="num">${fmtTime(n)}</b>,${until(n)}。${jobs("quick").length ? "目前正在執行。" : ""}` : "今天的時段已結束。"}</span></div></div>`;
  const pastDays = [...new Set([...Object.keys(D.daily_status || {}), ...Q.map(qDay)])].filter((d) => d && d < t).sort().reverse();
  return `${hero}
  ${sec("今天試過的", `${todayQ.length} 件`, `<div class="panel">${todayQ.length ? `<ul class="rows">${todayQ.map(qRow).join("")}</ul>` : '<div class="empty">今天還沒有嘗試紀錄。</div>'}</div>`)}
  ${pastDays.length ? fold("過去幾天", `${pastDays.length} 天`, pastDays.map((d) => { const s = (D.daily_status || {})[d]; const list = Q.filter((q) => qDay(q) === d);
      return `<div class="sub-h" style="margin-top:12px">${esc(d)} ${s?.done ? chip("已確認", "good") : chip("沒有確認", "")}</div>${list.length ? `<ul class="rows">${list.map(qRow).join("")}</ul>` : `<div class="empty">${esc((s?.items || []).join(",")) || "沒有紀錄"}</div>`}`; }).join("")) : ""}
  ${rules(["每天一個能寫進履歷的小成就,不能和其他五類重複;要附連結、截圖或獎項紀錄。", "每天 10:15、14:15、18:15 執行,當天確認後就停止。", "由 Codex gpt-6-luna high 執行與獨立查核;只有查核通過的結果才算數。"])}`;
}

/* ---------- achievements wall and the celebration effect ---------- */
const KIND = { star: ["作品獲得 Star", "--k-star"], contributor: ["新專案貢獻者", "--k-contributor"], merged: ["PR 已合併", "--k-merged"], prize: ["競賽得獎", "--k-prize"],
  achievement: ["新成就", "--k-achievement"], paper: ["論文投稿", "--k-paper"], daily: ["每日任務完成", "--k-daily"],
  coauthor: ["成為共同作者", "--k-coauthor"], accepted: ["解答被採納", "--k-accepted"], invite: ["新的邀請", "--k-invite"], follower: ["新的追蹤者", "--k-follower"] };
function achievementProgress() {
  const events = D.celebrations || [], gh = D.gh_achievements || {}, current = gh.current || {};
  const answers = (D.quickwins || []).filter((q) => q.kind === "answer" && !/withdrawn|撤回/i.test(q.status || ""));
  const mergedCount = contributors().prs;
  const mergedHistory = events.filter((e) => e.kind === "merged");
  const mergedSeen = new Set(mergedHistory.map((e) => e.link || e.url));
  (D.contributions || []).filter((c) => (c.kind === "pr" || c.kind === "pull_request") && c.outcome === "merged" && !mergedSeen.has(c.url))
    .forEach((c) => { mergedSeen.add(c.url); mergedHistory.push({ kind: "merged", link: c.url, title: c.title, at: c.closed_at }); });
  const stars = [ ...(D.personal?.projects || []).map((p) => ({ name: p.name, count: +p.stars || 0, url: p.repo })),
    ...Object.values(D.stars?.repos || {}).map((r) => ({ name: r.name, count: +r.count || 0, url: r.url, at: r.last_seen })) ];
  const best = stars.sort((a, b) => b.count - a.count)[0] || { count: 0 };
  const specs = [
    ["Pull Shark", [2, 16, 128, 1024], mergedCount, "已合併的 Pull Request", mergedHistory],
    ["Pair Extraordinaire", [1, 10, 24, 48], events.filter((e) => e.kind === "coauthor" && !e.revoked).length, "合併後的 commit 仍保留共同作者的 Pull Request(和 GitHub 算法一致)", events.filter((e) => e.kind === "coauthor" && !e.revoked)],
    ["Galaxy Brain", [2, 8, 16, 32], events.filter((e) => e.kind === "accepted" && !e.revoked).length, `討論解答獲採納；已發出 ${answers.length} 則,已採納 ${events.filter((e) => e.kind === "accepted" && !e.revoked).length} 則`, events.filter((e) => e.kind === "accepted" && !e.revoked)],
    ["Starstruck", [16, 128, 512, 4096], best.count, `個人專案單一儲存庫的最高 Star 數${best.name ? `: ${esc(best.name)}` : ""}`, events.filter((e) => e.kind === "star")],
  ];
  for (const name of ["Quickdraw", "YOLO", "Public Sponsor"]) {
    const first = (gh.history || []).find((h) => h.earned?.[name]);
    specs.push([name, [1], first ? 1 : 0, "一次性成就", first ? [{ title: "首次記錄", at: first.date }] : []]);
  }
  const cards = specs.map(([name, thresholds, count, what, history]) => {
    const idx = thresholds.reduce((n, t) => count >= t ? n + 1 : n, 0);
    const tier = idx ? ["徽章", "銅", "銀", "金"][idx - 1] : "尚未取得";
    const target = thresholds[Math.min(idx, thresholds.length - 1)];
    const shown = current[name];
    const mismatch = shown == null ? (idx ? "GitHub 尚未顯示" : "") : shown !== idx ? `GitHub 顯示 x${shown}` : "";
    const sorted = history.slice().sort((a, b) => String(b.at || b.detected || b.date).localeCompare(String(a.at || a.detected || a.date)));
    const extra = name === "Pull Shark" ? '<p class="xs dim">GitHub 尚未顯示此徽章；客服案件 #4810264 處理中。</p>' : "";
    return `<details class="badge-card"><summary><span class="badge-head"><span class="badge-name">${name}</span><span class="badge-tier">${tier}${mismatch ? ` <small>${esc(mismatch)}</small>` : ""}</span></span>
      <span class="badge-count num">${count} / ${target}</span><progress value="${Math.min(count, target)}" max="${target}"></progress>
      <span class="small dim">${what}</span>${extra}</summary><div class="badge-body"><div class="sub-h">完整紀錄</div>
      ${sorted.length ? `<ul class="rows">${sorted.map((e) => `<li><span class="what">${link(e.link || e.url, esc(e.title || "首次記錄"))}</span><span class="when num">${fmtDate(e.at || e.detected || e.date)}</span></li>`).join("")}</ul>` : '<p class="small dim">尚無紀錄</p>'}</div></details>`;
  }).join("");
  return sec("GitHub 成就進度", "", `<div class="badge-grid">${cards}</div>`);
}
function viewWall() {
  const E = (D.celebrations || []).slice().sort((a, b) => ((a.at || a.detected) < (b.at || b.detected) ? 1 : -1));
  const counts = Object.keys(KIND).map((k) => [k, E.filter((e) => e.kind === k).length]).filter(([, n]) => n);
  return achievementProgress() + sec("成就", counts.map(([k, n]) => `${KIND[k][0]} ${n}`).join(","), E.length ? `<div class="wall">${E.map((e) => { const kd = KIND[e.kind] || KIND.achievement;
    return `<article class="ach" style="--kind:var(${kd[1]})"><div class="ach-kind"><span class="kind-t">${kd[0]}</span><span><button class="btn tiny" type="button" data-replay="${esc(e.id)}">重播</button> ${e.share_url ? `<a class="btn tiny" href="${esc(e.share_url)}" target="_blank" rel="noopener" title="打開 GitHub 發布頁,內容已填好,按 Publish 就會出現在動態">分享</a>` : ""}</span></div>
      <h3>${link(e.link, esc(e.title))}</h3>${e.detail ? `<p>${esc(e.detail)}</p>` : ""}
      <div class="foot-l"><span class="num">${fmtDate(e.at || e.detected)}</span>${e.backfill ? "<span>首次掃描時補記</span>" : ""}</div></article>`; }).join("")}</div>` : '<div class="panel empty">還沒有成就紀錄。</div>')
    + archiveView()
    + rules(["每 5 分鐘偵測一次新成就:合併的 PR、第一次成為某專案的貢獻者、成為共同作者(Pair Extraordinaire)、解答被採納(Galaxy Brain)、新的追蹤者、競賽得獎或前 3 名、論文投稿、每日任務確認。", "每項新成就在這台裝置播放一次全螢幕特效,同時寄出一封 Gmail 通知。", "分享:打開 GitHub 發布頁,標題和內文已填好,按 Publish 後會出現在追蹤你的人的首頁動態(展示 repo:Arthur031221/open-source-contributions)。論文在審稿結果出來前不提供分享,以免破壞匿名審查。"]);
}
const archiveEsc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const ARCHIVE_TONE = { thanks: "感謝", approve: "核准", neutral: "一般", change: "要求修改", unfriendly: "不友善", special: "值得注意" };
const ARCHIVE_ASSOC = { OWNER: "擁有者", MEMBER: "成員", COLLABORATOR: "協作者", CONTRIBUTOR: "貢獻者", ASKER: "提問者", MODERATOR: "版主動作" };
function archiveRows() { return D.thanks_archive?.rows || []; }
function archiveView() {
  const rows = archiveRows(), tones = (t) => rows.filter((r) => r.tone === t).length;
  const projects = new Set(rows.map((r) => r.repo)).size;
  const totals = `共 ${rows.length} 則回覆，${projects} 個專案。感謝 ${tones("thanks")}，核准 ${tones("approve")}，要求修改 ${tones("change")}，不友善 ${tones("unfriendly")}，值得注意 ${tones("special")}`;
  const isG = (r) => r.kind === "discussion" || r.kind === "moderation";
  const cnt = (f) => rows.filter(f).length;
  const groups = [
    ["src", "來源", [["all", "全部", rows.length], ["code", "PR 與 issue", cnt((r) => !isG(r))], ["galaxy", "Galaxy 解答", cnt(isG)]]],
    ["tone", "語氣", [["all", "全部", rows.length], ["thanks", "感謝", tones("thanks")], ["approve", "核准", tones("approve")], ["neutral", "一般", tones("neutral")],
      ["change", "要求修改", tones("change")], ["unfriendly", "不友善", tones("unfriendly")], ["special", "值得注意", tones("special")]]],
    ["st", "解答狀態", [["all", "全部", cnt(isG)], ["accepted", "已被採納", cnt((r) => r.item_state === "accepted")], ["open", "待採納", cnt((r) => isG(r) && ["open", "answered"].includes(r.item_state))],
      ["hidden", "被版主隱藏", cnt((r) => r.item_state === "hidden")], ["withdrawn", "已撤下", cnt((r) => isG(r) && r.item_state === "withdrawn")]]]];
  const key = { src: "archiveSrc", tone: "archiveTone", st: "archiveSt" };
  const filterHtml = groups.map(([g, label, opts]) => `<div class="archive-filters" role="group" aria-label="${label}"><span class="xs dim archive-flabel">${label}</span>${opts.map(([k, l, c]) =>
    `<button type="button" class="archive-filter${state[key[g]] === k ? " active" : ""}" data-archive-filter="${g}:${k}" aria-pressed="${state[key[g]] === k}">${l} <span class="num">${c}</span></button>`).join("")}</div>`).join("");
  const controls = `<p class="archive-summary">${totals}</p><p class="archive-updated">更新於 ${D.thanks_archive?.updated_at ? fmtDate(D.thanks_archive.updated_at) : "尚未更新"}，台北時間</p>
    <div class="archive-controls">${filterHtml}
    <label class="archive-search"><span class="sr-only">搜尋專案與回覆內容</span><input type="search" id="archive-search" placeholder="搜尋專案或回覆" value="${archiveEsc(state.archiveQuery)}" autocomplete="off"></label></div>
    <div id="thanks-archive-body">${archiveBody()}</div>`;
  return sec("維護者與社群的回覆紀錄", "PR、issue 的維護者回覆,以及 Galaxy Brain 解答收到的回覆", controls, "thanks-archive");
}
function archiveBody() {
  const q = state.archiveQuery.trim().toLocaleLowerCase();
  const isG = (r) => r.kind === "discussion" || r.kind === "moderation";
  const allowed = (r) => (state.archiveSrc === "all" || (state.archiveSrc === "galaxy") === isG(r)) &&
    (state.archiveTone === "all" || r.tone === state.archiveTone) &&
    (state.archiveSt === "all" || (isG(r) && (state.archiveSt === "open" ? ["open", "answered"].includes(r.item_state) : r.item_state === state.archiveSt)));
  const rows = archiveRows().filter((r) => allowed(r) && (!q || [r.repo, r.text, r.zh].some((v) => String(v || "").toLocaleLowerCase().includes(q))));
  if (!rows.length) return '<div class="panel empty">沒有符合條件的回覆。</div>';
  const groups = new Map();
  rows.forEach((r) => { if (!groups.has(r.repo)) groups.set(r.repo, []); groups.get(r.repo).push(r); });
  return [...groups].sort((a, b) => String(b[1][0].at).localeCompare(String(a[1][0].at))).map(([repo, replies], index) => {
    const repoUrl = `https://github.com/${repo.split("/").map(encodeURIComponent).join("/")}`;
    return `<details class="archive-project"${index < 5 ? " open" : ""}><summary><a class="archive-project-name" href="${archiveEsc(repoUrl)}" target="_blank" rel="noopener">${archiveEsc(repo)}</a><span class="archive-project-count">${replies.length} 則回覆</span></summary>
      <div class="archive-project-body">${replies.map(archiveReply).join("")}</div></details>`;
  }).join("");
}
function archiveReply(r) {
  const tone = ARCHIVE_TONE[r.tone] || "待分類", assoc = ARCHIVE_ASSOC[r.association];
  const flagged = ["unfriendly", "special"].includes(r.tone);
  const copy = (content, lang) => `<div class="archive-copy-wrap"><div class="archive-copy-label">${lang}</div><p class="archive-copy clamp">${archiveEsc(content)}</p><button type="button" class="archive-expand" data-expand hidden>展開</button></div>`;
  return `<article class="archive-reply tone-${archiveEsc(r.tone || "neutral")}">
    <div class="archive-reply-head"><span class="archive-author">${archiveEsc(r.author)}</span>${assoc ? `<span class="archive-assoc">${assoc}</span>` : ""}<time datetime="${archiveEsc(r.at)}">${fmtDate(r.at)}</time><span class="archive-tone">${tone}</span></div>
    <div class="archive-item">${r.kind === "discussion" || r.kind === "moderation" ? `<span class="chip ${({ accepted: "good", hidden: "bad", withdrawn: "warn" })[r.item_state] || "info"}">Galaxy 解答${({ accepted: " 已被採納", hidden: " 被版主隱藏", withdrawn: " 已撤下" })[r.item_state] || ""}</span> ` : ""}${link(r.item_url, archiveEsc(r.item_title))}</div>
    ${flagged && r.flag_zh ? `<strong class="archive-flag">${archiveEsc(r.flag_zh)}</strong>` : ""}
    ${copy(r.text, "English")}${r.zh ? copy(r.zh, "繁體中文") : '<p class="archive-pending">翻譯排程中</p>'}
    <a class="archive-github" href="${archiveEsc(r.url)}" target="_blank" rel="noopener">在 GitHub 開啟</a>
  </article>`;
}
function updateArchiveExpand() {
  document.querySelectorAll("#thanks-archive .archive-copy-wrap").forEach((wrap) => {
    const copy = wrap.querySelector(".archive-copy"), button = wrap.querySelector(".archive-expand");
    if (copy.classList.contains("clamp")) button.hidden = copy.scrollHeight <= copy.clientHeight + 1;
  });
}
function renderArchiveBody() {
  const body = $("#thanks-archive-body"); if (!body) return;
  body.innerHTML = archiveBody();
  requestAnimationFrame(updateArchiveExpand);
}
const cele = { q: [], cur: null, timer: null, raf: null, shown: new Set() };
function seen() { try { return new Set(JSON.parse(localStorage.getItem("oc-cele-seen") || "[]")); } catch { return new Set(); } }
function markSeen(id) { cele.shown.add(id); try { const s = seen(); s.add(id); localStorage.setItem("oc-cele-seen", JSON.stringify([...s].slice(-500))); } catch {} }
function checkCelebrations() {
  const s = seen();
  // A fresh device would otherwise replay every old event; only the last day plays.
  const old = Date.now() - 864e5;
  (D.celebrations || []).forEach((e) => { if (e.id && !s.has(e.id) && Date.parse(e.at || e.detected || 0) < old) { markSeen(e.id); s.add(e.id); } });
  (D.celebrations || []).filter((e) => e.id && !e.backfill && !s.has(e.id) && !cele.shown.has(e.id) && !cele.q.some((x) => x.id === e.id) && cele.cur?.id !== e.id)
    .sort((a, b) => ((a.at || a.detected) < (b.at || b.detected) ? -1 : 1)).forEach((e) => cele.q.push(e));
  if (!cele.cur) nextCele();
}
function nextCele() {
  clearTimeout(cele.timer); cancelAnimationFrame(cele.raf);
  const el = $("#cele");
  cele.cur = cele.q.shift() || null;
  if (!cele.cur) { el.hidden = true; return; }
  const e = cele.cur, kd = KIND[e.kind] || KIND.achievement;
  markSeen(e.id);
  el.style.setProperty("--kind", `var(${kd[1]})`);
  $("#cele-kind").textContent = kd[0];
  $("#cele-title").textContent = e.title || "";
  $("#cele-detail").textContent = e.detail || "";
  const a = $("#cele-link"); if (e.link) { a.href = e.link; a.hidden = false; } else a.hidden = true;
  const sh = $("#cele-share"); if (e.share_url) { sh.href = e.share_url; sh.hidden = false; } else sh.hidden = true;
  $("#cele-count").textContent = cele.q.length ? `還有 ${cele.q.length} 項` : "";
  el.hidden = false;
  const card = $(".cele-card"); card.style.animation = "none"; void card.offsetWidth; card.style.animation = "";
  if (!matchMedia("(prefers-reduced-motion: reduce)").matches) fireworks(cssv(kd[1]) || "#ffc933");
  cele.timer = setTimeout(nextCele, 8000);
}
function fireworks(color) {
  const cv = $("#cele-canvas"), ctx = cv.getContext("2d"), dpr = Math.min(2, window.devicePixelRatio || 1);
  const W = cv.clientWidth, H = cv.clientHeight; cv.width = W * dpr; cv.height = H * dpr; ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  const pal = [color, color, "#ffffff", "#ffd166", "#ff6b6b", "#7cc4ff"], pick = () => pal[(Math.random() * pal.length) | 0];
  const P = [], t0 = performance.now();
  const burst = (x, y) => { const n = 90 + ((Math.random() * 40) | 0), c1 = pick(); for (let i = 0; i < n; i++) { const a = (i / n) * Math.PI * 2 + Math.random() * .2, sp = 2.5 + Math.random() * 5.5;
    P.push({ k: 0, x, y, vx: Math.cos(a) * sp, vy: Math.sin(a) * sp, life: 70 + Math.random() * 40, age: 0, c: Math.random() < .7 ? c1 : pick(), s: 1.6 + Math.random() * 1.8 }); } };
  const rockets = [0, 280, 620, 950, 1350, 1800, 2300, 2900, 3500, 4200].map((d) => ({ at: d, x: W * (.12 + Math.random() * .76), y: H * (.12 + Math.random() * .32), done: false }));
  for (let i = 0; i < 180; i++) P.push({ k: 1, x: Math.random() * W, y: -20 - Math.random() * H * .8, vx: (Math.random() - .5) * 2.2, vy: 1.6 + Math.random() * 2.6, r: Math.random() * 6, vr: (Math.random() - .5) * .3, w: 6 + Math.random() * 6, h: 9 + Math.random() * 8, c: pick(), age: 0, life: 1e9 });
  const step = (t) => {
    const el = t - t0;
    rockets.forEach((r) => { if (!r.done && el >= r.at) { r.done = true; burst(r.x, r.y); } });
    ctx.clearRect(0, 0, W, H);
    for (let i = P.length - 1; i >= 0; i--) {
      const p = P[i]; p.age++;
      if (p.k === 0) { p.vx *= .982; p.vy = p.vy * .982 + .07; p.x += p.vx; p.y += p.vy; const a = 1 - p.age / p.life; if (a <= 0) { P.splice(i, 1); continue; }
        ctx.globalAlpha = a; ctx.fillStyle = p.c; ctx.beginPath(); ctx.arc(p.x, p.y, p.s, 0, 6.283); ctx.fill(); }
      else { p.vy += .02; p.x += p.vx + Math.sin((p.age + i) / 12) * .6; p.y += p.vy; p.r += p.vr; if (p.y > H + 30) { P.splice(i, 1); continue; }
        ctx.globalAlpha = el > 6500 ? Math.max(0, 1 - (el - 6500) / 1000) : 1; ctx.save(); ctx.translate(p.x, p.y); ctx.rotate(p.r); ctx.fillStyle = p.c; ctx.fillRect(-p.w / 2, -p.h / 2, p.w, p.h * Math.abs(Math.cos(p.age / 9))); ctx.restore(); }
    }
    ctx.globalAlpha = 1;
    if (el < 7800 && !$("#cele").hidden) cele.raf = requestAnimationFrame(step); else ctx.clearRect(0, 0, W, H);
  };
  cele.raf = requestAnimationFrame(step);
}

/* ---------- social posts and replies ---------- */
const SOCIAL = {
  hn: { name: "Hacker News", path: "M0 24V0h24v24H0zM6.951 5.896l4.112 7.708v5.064h1.583v-4.972l4.148-7.799h-1.749l-2.457 4.875c-.372.745-.688 1.434-.688 1.434s-.297-.708-.651-1.434L8.831 5.896h-1.88z" },
  reddit: { name: "Reddit", path: "M12 0C5.373 0 0 5.373 0 12c0 3.314 1.343 6.314 3.515 8.485l-2.286 2.286C.775 23.225 1.097 24 1.738 24H12c6.627 0 12-5.373 12-12S18.627 0 12 0Zm4.388 3.199c1.104 0 1.999.895 1.999 1.999 0 1.105-.895 2-1.999 2-.946 0-1.739-.657-1.947-1.539v.002c-1.147.162-2.032 1.15-2.032 2.341v.007c1.776.067 3.4.567 4.686 1.363.473-.363 1.064-.58 1.707-.58 1.547 0 2.802 1.254 2.802 2.802 0 1.117-.655 2.081-1.601 2.531-.088 3.256-3.637 5.876-7.997 5.876-4.361 0-7.905-2.617-7.998-5.87-.954-.447-1.614-1.415-1.614-2.538 0-1.548 1.255-2.802 2.803-2.802.645 0 1.239.218 1.712.585 1.275-.79 2.881-1.291 4.64-1.365v-.01c0-1.663 1.263-3.034 2.88-3.207.188-.911.993-1.595 1.959-1.595Zm-8.085 8.376c-.784 0-1.459.78-1.506 1.797-.047 1.016.64 1.429 1.426 1.429.786 0 1.371-.369 1.418-1.385.047-1.017-.553-1.841-1.338-1.841Zm7.406 0c-.786 0-1.385.824-1.338 1.841.047 1.017.634 1.385 1.418 1.385.785 0 1.473-.413 1.426-1.429-.046-1.017-.721-1.797-1.506-1.797Zm-3.703 4.013c-.974 0-1.907.048-2.77.135-.147.015-.241.168-.183.305.483 1.154 1.622 1.964 2.953 1.964 1.33 0 2.47-.81 2.953-1.964.057-.137-.037-.29-.184-.305-.863-.087-1.795-.135-2.769-.135Z" },
  x: { name: "X", path: "M14.234 10.162 22.977 0h-2.072l-7.591 8.824L7.251 0H.258l9.168 13.343L.258 24H2.33l8.016-9.318L16.749 24h6.993zm-2.837 3.299-.929-1.329L3.076 1.56h3.182l5.965 8.532.929 1.329 7.754 11.09h-3.182z" },
  linkedin: { name: "LinkedIn", path: "M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z" },
  devto: { name: "dev.to", path: "M7.42 10.05c-.18-.16-.46-.23-.84-.23H6l.02 2.44.04 2.45.56-.02c.41 0 .63-.07.83-.26.24-.24.26-.36.26-2.2 0-1.91-.02-1.96-.29-2.18zM0 4.94v14.12h24V4.94H0zM8.56 15.3c-.44.58-1.06.77-2.53.77H4.71V8.53h1.4c1.67 0 2.16.18 2.6.9.27.43.29.6.32 2.57.05 2.23-.02 2.73-.47 3.3zm5.09-5.47h-2.47v1.77h1.52v1.28l-.72.04-.75.03v1.77l1.22.03 1.2.04v1.28h-1.6c-1.53 0-1.6-.01-1.87-.3l-.3-.28v-3.16c0-3.02.01-3.18.25-3.48.23-.31.25-.31 1.88-.31h1.64v1.3zm4.68 5.45c-.17.43-.64.79-1 .79-.18 0-.45-.15-.67-.39-.32-.32-.45-.63-.82-2.08l-.9-3.39-.45-1.67h.76c.4 0 .75.02.75.05 0 .06 1.16 4.54 1.26 4.83.04.15.32-.7.73-2.3l.66-2.52.74-.04c.4-.02.73 0 .73.04 0 .14-1.67 6.38-1.8 6.68z" }
};
function platformKey(x) { const k = String(x || "").toLowerCase(); return /hn|hacker/.test(k) ? "hn" : /reddit/.test(k) ? "reddit" : /^(x|twitter)$/.test(k) ? "x" : /linkedin/.test(k) ? "linkedin" : /dev\.?to/.test(k) ? "devto" : "other"; }
function platformChip(k) { const p = SOCIAL[k]; return p ? `<span class="platform-chip platform-${k}"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="${p.path}"/></svg>${p.name}</span>` : `<span class="platform-chip">${esc(k)}</span>`; }
function localJson(key) { try { return JSON.parse(store.get(key) || "{}"); } catch { return {}; } }
function socialPending() { const hidden = localJson("oc-replied-comments"); return (D.social_replies || []).filter((r) => r.needs_reply && !r.replied && !hidden[r.id]); }
function manualPost(p, k) { return localJson("oc-manual-posts")[`${p.name}:${k}`] || null; }
function socialMonitor() {
  const pending = socialPending();
  const checks = D.social_backoff?.checked || {};
  const times = ["devto", "hn", "reddit"].map((k) => `${SOCIAL[k].name} ${checks[k] ? fmtDT(checks[k]) : "尚未檢查"}`);
  const untilAt = D.social_backoff?.until && new Date(D.social_backoff.until * 1000) > now() ? `；Reddit 限流中,下次檢查 ${fmtDT(new Date(D.social_backoff.until * 1000))}` : "";
  const empty = `<div class="panel empty">目前沒有需要你回覆的留言<div class="xs dim">${times.join("；")}${untilAt}</div></div>`;
  const cards = pending.map((r) => `<article class="panel reply-card platform-row platform-${esc(r.platform)}">
    <div class="reply-head">${platformChip(r.platform)} <b>${esc(r.project)}</b> <span>${esc(r.author)}</span> <span class="dim">${fmtDate(r.at)}</span></div>
    <div class="reply-text">${esc(r.text)}</div>
    ${r.draft ? `<div class="reply-draft"><span class="xs dim">回覆草稿</span><p>${esc(r.draft)}</p></div>` : `<div class="xs dim">草稿產生中</div>`}
    <div class="reply-actions">${r.draft ? `<button class="btn primary" type="button" data-reply-open="${esc(r.id)}">一鍵回覆</button><button class="btn" type="button" data-copy="${esc(r.draft)}">複製</button>` : ""}<button class="btn" type="button" data-replied="${esc(r.id)}">已回覆</button><a class="btn ghost" href="${esc(r.comment_url)}" target="_blank" rel="noopener">查看留言</a></div>
    <div class="xs dim">${esc(r.reply_reason || "")}</div></article>`).join("");
  return sec("需要你回覆的留言", pending.length ? `${pending.length} 則,依時間排序` : "", pending.length ? `<div class="reply-list">${cards}</div>` : empty);
}
/* ---------- personal open source ---------- */
function copyText(text, btn) {
  const done = () => { if (btn) { const o = btn.textContent; btn.textContent = "已複製"; setTimeout(() => (btn.textContent = o), 1500); } };
  const fallback = () => {
    const ta = document.createElement("textarea"); ta.value = text; ta.style.cssText = "position:fixed;opacity:0";
    document.body.appendChild(ta); ta.select(); try { document.execCommand("copy"); done(); } catch {} ta.remove();
  };
  if (navigator.clipboard?.writeText) navigator.clipboard.writeText(text).then(done, fallback); else fallback();
}
const copyBtn = (text) => `<button class="btn tiny" type="button" data-copy="${esc(text)}">複製</button>`;
function viewPersonal() {
  const P = (D.personal?.projects || []).map((p) => ({ ...p, posts: (p.posts || []).map((x) => ({ ...x, body: x.body || x.body_markdown || "" })) })).sort((a, b) => (b.launch_ready ? 1 : 0) - (a.launch_ready ? 1 : 0)), S = D.social_accounts || [], stars = P.reduce((a, p) => a + (p.stars || 0), 0);
  const REC = ["Hacker News", "Reddit", "X"];
  const plat = (x) => platformKey(x.platform);
  const enc = encodeURIComponent;
  const composeUrl = (x) => { const k = plat(x), u = x.url || "", t = x.title || "", b = x.body || "", r = (x.subreddit || "").replace(/^\/?r\//i, "");
    if (k === "hn") return `https://news.ycombinator.com/submitlink?u=${enc(u)}&t=${enc(t)}`;
    if (k === "reddit" && r) return x.kind === "link" ? `https://www.reddit.com/r/${enc(r)}/submit?title=${enc(t)}&url=${enc(u)}` : `https://www.reddit.com/r/${enc(r)}/submit?selftext=true&title=${enc(t)}&text=${enc(b)}`;
    if (k === "x") return `https://x.com/intent/post?text=${enc(b.includes(u) || !u ? b : b + " " + u)}`;
    if (k === "linkedin") return `https://www.linkedin.com/feed/?shareActive=true&text=${enc(b)}`;
    if (k === "devto") return `https://dev.to/new?prefill=${enc(`---\ntitle: ${t}\npublished: false\n---\n\n${b}`)}`;
    return ""; };
  const PL = [["hn", "Hacker News"], ["reddit", "Reddit"], ["x", "X"], ["linkedin", "LinkedIn"], ["devto", "dev.to"]];
  const PLN = Object.fromEntries(PL);
  const retrying = (x) => plat(x) === "devto" && x.skip_reason === "dev.to post lacks a title or a real article body" && x.title && (x.body || "").trim().split(/\s+/).length >= 80;
  const stOf = (p, x, i) => x.removed_at ? "removed" : x.skip_reason && !retrying(x) ? "skip" : (x.posted_url || manualPost(p, plat(x))) ? "done" : "ready";
  const dlBtns = (p, k) => { const m = p.media || {}; if (!(m.card || m.gif) || !/^(x|linkedin|devto)$/.test(k)) return "";
    return `${m.card ? `<a class="btn" href="${esc(m.card)}" download="social-card.png" target="_blank" rel="noopener">下載圖片</a>` : ""}${m.gif ? `<a class="btn" href="${esc(m.gif)}" download="demo.gif" target="_blank" rel="noopener">下載 GIF</a>` : ""}`; };
  const stChip = (p, x, i, k) => { const status = stOf(p, x, i), mark = manualPost(p, k);
    if (status === "removed") return `<a class="chip bad" href="${esc(x.posted_url || "#")}" target="_blank" rel="noopener">已被移除 ${x.removed_at ? fmtDT(x.removed_at) : ""}</a>`;
    if (status === "skip") return `<span class="chip warn">已略過</span><span class="xs dim">${esc(x.skip_reason)}</span>`;
    if (status === "done") return `<a class="chip good" href="${esc(x.posted_url || mark.url)}" target="_blank" rel="noopener">已發文 ${x.posted_at || mark.at ? fmtDT(x.posted_at || mark.at) : ""}</a>`;
    return `<span class="chip post-wait">${retrying(x) ? "等待自動重試" : "未發文"}</span>`; };
  const postRow = (p, x, i) => { const cu = composeUrl(x), k = plat(x), st = stOf(p, x, i), sub = (x.subreddit || "").replace(/^\/?r\//i, "");
    const txt = x.body || x.title || "", long = txt.length > 90 || txt.includes("\n");
    const count = socialPending().filter((r) => r.project === p.name && r.platform === k && r.post_url?.replace(/\/$/, "") === (x.posted_url || manualPost(p, k)?.url || "").replace(/\/$/, "")).length;
    return `<div class="prow platform-row platform-${k}" data-plat="${k}" data-st="${st}">
      <div class="prow-h">${platformChip(k)}${k === "reddit" && sub ? ` <span class="dim xs">r/${esc(sub)}</span>` : ""}<span class="pst">${stChip(p, x, i, k)}</span>${count ? `<span class="chip bad">需要你回覆 ${count}</span>` : ""}</div>
      ${x.title && x.body ? `<div class="prow-t">${esc(x.title)}</div>` : ""}
      <div class="prow-b"><pre class="post-body clamp">${esc(txt)}</pre>${long ? `<button class="btn ghost tiny" type="button" data-expand>展開</button>` : ""}</div>
      ${k === "reddit" && x.rules ? `<div class="xs dim">規則:${esc(x.rules)}</div>` : ""}
      ${k === "reddit" && x.removed_at ? `<div class="rule-check rc-blocked"><b>版主移除原因</b><div>${esc(x.removed_reason || "")}</div></div>` : ""}
      ${k === "reddit" && (x.alternatives || []).length && (st === "ready" || st === "removed") ? `<div class="alt-subs"><div class="alt-h"><b>改投這些版,現在就能發</b> <span class="xs dim">內容已依各版規則改寫;同一篇只挑一個版發,避免被當成洗版</span></div>
        ${x.alternatives.map((a) => { const au = composeUrl({ platform: "reddit", subreddit: a.subreddit, title: a.title, body: a.body, url: a.url });
          return `<div class="alt-row"><div class="alt-top"><span class="chip good">r/${esc(a.subreddit)}</span>${a.flair ? `<span class="xs dim">需選 flair:${esc(a.flair)}</span>` : ""}
            <a class="btn primary tiny" href="${esc(au)}" target="_blank" rel="noopener">一鍵發文到 r/${esc(a.subreddit)}</a>
            <button class="btn tiny" type="button" data-copy="${esc(a.title + "\n\n" + a.body)}">複製內容</button></div>
            <div class="xs">${esc(a.why_zh || "")}</div><div class="prow-t">${esc(a.title)}</div>
            <pre class="post-body clamp">${esc(a.body)}</pre>
            ${(a.sources || []).length ? `<div class="xs">${a.sources.map((u, n) => `<a href="${esc(u)}" target="_blank" rel="noopener">版規 ${n + 1}</a>`).join(" ")}</div>` : ""}</div>`; }).join("")}</div>` : ""}
      ${k === "reddit" && x.rule_check && st === "ready" ? (() => { const v = x.rule_check, L = { ok: ["現在可以發", "good"], fix: ["修改後可發", "info"], wait: ["暫時不能發", "warn"], blocked: ["這個版不適合", "bad"] }[v.verdict] || ["未知", ""];
        return `<div class="rule-check rc-${esc(v.verdict)}"><span class="chip ${L[1]}">發文前檢查:${L[0]}</span> <span class="xs dim">${fmtDT(v.checked_at)} 查核</span>
          <div>${esc(v.reasons_zh || "")}</div>${v.fix_zh ? `<div><b>怎麼做</b> ${esc(v.fix_zh)}</div>` : ""}${(v.better_subreddits || []).length ? `<div><b>可以改發</b> ${v.better_subreddits.map((b) => esc(b)).join("、")}</div>` : ""}
          ${(v.sources || []).length ? `<div class="xs">${v.sources.map((u, n) => `<a href="${esc(u)}" target="_blank" rel="noopener">來源 ${n + 1}</a>`).join(" ")}</div>` : ""}</div>`; })() : ""}
      <div class="prow-a">${cu && st === "ready" && k !== "devto" ? `<a class="btn primary" href="${esc(cu)}" target="_blank" rel="noopener">一鍵發文</a>` : ""}${(k === "x" || k === "linkedin") && st === "ready" ? `<button class="btn" type="button" data-manual-post="${esc(p.name)}:${k}">我已發文</button>` : ""}<button class="btn" type="button" data-copy="${esc(k === "devto" ? `# ${x.title || ""}\n\n${x.body || ""}` : (x.title && x.body && k !== "x" && k !== "linkedin" ? `${x.title}\n\n${x.body}` : txt))}">複製內容</button>${k === "hn" && x.first_comment ? `<button class="btn" type="button" data-copy="${esc(x.first_comment)}">複製第一則留言</button>` : ""}${dlBtns(p, k)}</div>
      ${(k === "x" || k === "linkedin") && !x.posted_url ? `<div class="xs dim">手動標記只儲存在這個瀏覽器。</div>` : ""}</div>`; };
  const queueTime = (p) => { const created = Date.parse(p.created || ""); if (Number.isFinite(created)) return created;
    return Math.max(0, ...(p.posts || []).map((x) => Date.parse(x.posted_at || "") || 0)); };
  const RP = P.filter((p) => p.launch_ready && (p.posts || []).length)
    .sort((a, b) => queueTime(b) - queueTime(a) || String(a.name || "").localeCompare(String(b.name || ""), "zh-Hant"));
  const NP = P.filter((p) => !(p.launch_ready && (p.posts || []).length));
  const queueOpen = localJson("oc-queue-open") || {};
  const pendingReplies = socialPending();
  const queueLogo = (p, k) => { const posts = (p.posts || []).filter((x) => plat(x) === k);
    const x = posts.find((v, i) => stOf(p, v, i) === "done") || posts.find((v, i) => stOf(p, v, i) === "removed") || posts[0];
    const status = x ? stOf(p, x, 0) : "ready", mark = manualPost(p, k);
    const postedAt = x && (x.posted_at || mark?.at);
    const label = `${SOCIAL[k].name}：${status === "done" ? `已發文${postedAt ? " " + fmtDT(postedAt) : ""}` : status === "removed" ? "已被移除" : status === "skip" ? "已略過" : "未發文"}`;
    const icon = `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="${SOCIAL[k].path}"/></svg>`;
    const cls = `queue-logo platform-${k} is-${status}`, attrs = `class="${cls}" title="${esc(label)}" aria-label="${esc(label)}"`;
    return status === "done" && (x.posted_url || mark?.url) ? `<a ${attrs} href="${esc(x.posted_url || mark.url)}" target="_blank" rel="noopener">${icon}</a>` : `<span ${attrs}>${icon}</span>`; };
  const postCard = (p, index) => { const al = p.awesome_lists || [], key = p.repo || p.name;
    const replies = pendingReplies.filter((r) => r.project === p.name).length;
    const opened = Object.prototype.hasOwnProperty.call(queueOpen, key) ? queueOpen[key] === true : index === 0 || replies > 0;
    const done = PL.filter(([k]) => (p.posts || []).some((x, i) => plat(x) === k && stOf(p, x, i) === "done")).length;
    return `<article class="panel qcard${opened ? " is-open" : ""}" data-queue-key="${esc(key)}"><div class="qcard-h" data-queue-toggle>
      <h3 class="qcard-title">${link(p.repo, esc(p.name))}</h3>
      <span class="qcard-date num">${p.created ? `建立 ${fmtDate(p.created)}` : "建立時間未記錄"}</span>
      <span class="qcard-logos">${PL.map(([k]) => queueLogo(p, k)).join("")}</span>
      <span class="qcard-count num">${done}/5 已發</span>
      ${replies ? `<span class="chip bad qcard-replies">需要回覆 ${replies}</span>` : ""}
      <button class="qcard-toggle" type="button" aria-expanded="${opened}" aria-label="${esc(p.name)}${opened ? "收合" : "展開"}"><span class="qcard-chevron" aria-hidden="true"></span><span class="qcard-toggle-label">${opened ? "收合" : "展開"}</span></button></div>
      <div class="qcard-body"${opened ? "" : " hidden"}>
      ${(p.media || {}).card || p.summary_zh ? `<div class="qcard-intro">${(p.media || {}).card ? `<img class="qthumb" src="${esc(p.media.card)}" alt="" loading="lazy">` : ""}${p.summary_zh ? `<p class="small dim">${esc(p.summary_zh)}</p>` : ""}</div>` : ""}
      ${(p.posts || []).map((x, i) => postRow(p, x, i)).join("")}
      ${al.length ? `<details class="pfold"><summary>Awesome 清單 <span class="xs dim">${al.length} 項</span></summary>${al.map((a) => { const t = typeof a === "string" ? a : (a.line || a.text || ""); const n = typeof a === "string" ? "" : (a.list || a.name || a.repo || "");
        return `<div class="post"><div class="post-h"><span>${a.url ? link(a.url, esc(n || a.url)) : esc(n)}</span>${copyBtn(t)}</div><pre class="log post-body">${esc(t)}</pre></div>`; }).join("")}</details>` : ""}</div></article>`; };
  const qcells = () => PL.map(([k, n]) => { let r = 0, d = 0, sk = 0; RP.forEach((p) => (p.posts || []).forEach((x, i) => { if (plat(x) !== k) return; const s = stOf(p, x, i); if (s === "skip") sk++; else if (s === "done") d++; else r++; }));
    return `<div class="qcell" data-q="${k}"><div class="qcell-n">${platformChip(k)}</div><div class="qcell-v"><span><b class="num" data-n="ready">${r}</b> 未發文</span><span><b class="num" data-n="done">${d}</b> 已發文</span><span><b class="num" data-n="skip">${sk}</b> 已略過</span></div></div>`; }).join("");
  const postsHtml = sec("發文佇列", RP.length ? `${RP.length} 個專案可推廣;Hacker News、Reddit、X、LinkedIn 一鍵開啟,dev.to 自動排程` : "目前沒有可發文的專案",
    `<div class="qsum">${qcells()}</div>${RP.length ? `<div class="qlist">${RP.map((p, i) => postCard(p, i)).join("")}</div>` : ""}
    ${NP.length ? `<details class="panel pfold"><summary>尚未準備推廣 <span class="xs dim">${NP.length} 個專案</span></summary><ul class="rows">${NP.map((p) => `<li><span class="what">${link(p.repo, esc(p.name))}<span class="why">${esc(p.launch_gaps_zh || ((p.posts || []).length ? "尚未標記為可推廣" : "尚無發文內容"))}</span></span></li>`).join("")}</ul></details>` : ""}`);
  const card = (p) => `<article class="panel pcard"><h3>${link(p.repo, esc(p.name))}</h3>
    <div class="pstats"><span>Star <b class="num">${p.stars ?? "-"}</b></span><span>Fork <b class="num">${p.forks ?? "-"}</b></span><span class="dim num">建立 ${p.created ? fmtDate(p.created) : "-"}</span></div>
    <p class="small">${esc(p.summary_zh || p.description || "")}</p>${p.summary_zh && p.description ? `<p class="xs dim">${esc(p.description)}</p>` : ""}
    ${p.why_zh ? `<p class="xs dim">${esc(p.why_zh)}</p>` : ""}${p.value ? `<p class="xs"><span class="chip ${{ 頂級: "top", 高: "good", 中: "info", 低: "" }[p.value] || ""}">${esc(p.value)}</span> ${esc(p.value_reason_zh || "")}</p>` : ""}${p.value === "頂級" && p.brag_zh ? `<p class="xs brag">值得炫耀:${esc(p.brag_zh)}</p>` : ""}<div>${chip(esc(p.status || "未標記"))}</div></article>`;
  const CY = (D.personal_cycles || []).slice().reverse().slice(0, 12);
  const OUT = { built: ["推出新專案", "good"], improved: ["改進舊專案", "info"], research_only: ["只做調研", ""], failed: ["未完成", "warn"] };
  const cyclesHtml = sec("每輪紀錄", CY.length ? `最近 ${CY.length} 輪,推出 ${CY.filter((c) => c.outcome === "built").length} 個新專案` : "每 3 小時做一個新專案",
    CY.length ? `<div class="panel"><ul class="rows">${CY.map((c) => { const o = OUT[c.outcome] || [c.outcome, ""];
      return `<li><span class="what">${chip(o[0], o[1])} ${c.repo ? link(c.repo, esc(c.project || c.repo)) : ""}<span class="why">${esc(c.summary_zh || "")}</span>${(c.ideas || []).length ? `<span class="why">調研:${esc(c.ideas.join(","))}</span>` : ""}</span><span class="when">${esc(String(c.stamp || "").replace("T", " ").replace(/(\d\d)(\d\d)$/, "$1:$2"))}</span></li>`; }).join("")}</ul></div>` : '<div class="panel empty">還沒有紀錄。</div>');
  return socialMonitor() + cyclesHtml + `<div class="panel" style="--area:var(--a-oss)"><div class="figure"><span class="big num" style="color:var(--k-contributor)">${P.length}</span>
      <span class="lbl">個人開源專案,共 <b class="num">${stars}</b> 顆 Star。每 3 小時做一個新專案。</span></div></div>
  ${postsHtml}
  ${sec("專案", "", P.length ? `<div class="wall">${P.map(card).join("")}</div>` : '<div class="panel empty">還沒有個人專案。</div>')}
  ${sec("社群帳號(請本人註冊)", "推薦先註冊 Hacker News、Reddit、X", `<div class="panel"><ul class="rows">${S.map((a) => `<li><span class="what">${platformChip(platformKey(a.platform))} ${link(a.signup_url, "註冊")}${REC.includes(a.platform) ? " " + chip("推薦", "good") : ""}</span><span class="when">${a.done ? chip("已註冊", "good") : "尚未註冊"}</span></li>`).join("")}</ul>
    <p class="xs dim" style="margin-top:8px">帳號必須由帳號持有人親自註冊。dev.to 由引擎排程發文,其他平台由你確認後手動送出。</p></div>`)}`;
}

/* ---------- system ---------- */
const JOB_LABEL = { hunt: "開源回合", ship: "開源補送", reply: "回覆處理", compete: "競賽工作者", papers: "論文工作者", quickwins: "每日任務", plateau: "瓶頸分析", scan: "競賽搜尋", daily: "報告" };
const FAIL_LABEL = { short_round: "先前回合的 PR 查核不足", empty_cycle: "這一輪沒有對外動作" };
function usageSum(from, to) {
  const s = { cost: 0, tokens: 0, output: 0, runs: 0 };
  (D.usage?.days || []).forEach((d) => { if (d.day < from || d.day > to) return; Object.values(d.jobs).forEach((j) => { s.cost += j.cost; s.output += j.output; s.tokens += j.input + j.cache_write + j.cache_read + j.output; s.runs += j.runs; }); });
  return s;
}
function weekStart() { const d = new Date(today() + "T12:00:00+08:00"); d.setUTCDate(d.getUTCDate() - ((d.getUTCDay() + 6) % 7)); return fmtDay(d); }
function viewSystem() {
  const h = D.health || {}, lr = h.last_runs || {}, t = today();
  const periods = [["今天", t, t], ["本週", weekStart(), t], ["本月", t.slice(0, 8) + "01", t], ["全部", "0000", "9999"]];
  const seg = (v, l) => `<button type="button" class="btn tiny${state.usageMetric === v ? " primary" : ""}" data-metric="${v}" aria-pressed="${state.usageMetric === v}">${l}</button>`;
  const A = (D.attribution?.items || []).slice(0, 12), amax = Math.max(1e-9, ...A.map((b) => b.cost));
  const runtime = D.ops?.runtime_config || {};
  const sched = [["開源回合", `每天 01:00、04:00、07:00、10:00、13:00、16:00、19:00、22:00，每輪 ${runtime.slots ?? "未知"} 個名額，Claude 限額時依設定接手`], ["回覆偵測", "通知每 5 分鐘檢查,GraphQL 每 10 分鐘掃描,回覆每 15 分鐘處理"],
    ["比賽與論文派工", "每 30 分鐘檢查六個焦點項目"], ["每日任務", "每天 10:15、14:15、18:15,當天確認後停止"], ["成就通知", "每 5 分鐘;Star 每 15 分鐘"], ["競賽搜尋", "每天 09:00"], ["監控台資料", "每 2 分鐘即時發布;每 5 分鐘快速更新;每 30 分鐘完整更新"]];
  const models = [["最關鍵約 5%", "Claude Sonnet 5.5 high(PR 第二關審查、卡關最終決策)"], ["接續約 25%（全體 5 至 30%）", "Codex gpt-6.1-sol high"], ["一般研究與例行工作", "Codex gpt-6-luna high"], ["Claude 額度用完", "開源工作由 Codex 繼續準備,待 Claude 審查後送出"], ["開源回合", `每 3 小時 ${ossSlots()} 個名額，優先接手舊 PR`], ["個人開源", "每 3 小時做新專案;建置由 Codex gpt-6.1-sol high 主導,研究維護使用 gpt-6-luna high"], ["Galaxy Brain", (D.ops_rules?.lines || []).find((r) => r.key === "galaxy")?.schedule || "尚無排程資料"], ["同時工作上限", `一般模型工作者上限 ${runtime.worker_cap ?? "未知"} 個，必要工作上限 ${runtime.priority_worker_cap ?? "未知"} 個，引擎限 ${runtime.engine_cpu_cores ?? "未知"} 核與 ${runtime.engine_memory_gib ?? "未知"} GiB 記憶體`]];
  return `
  <div class="grid g3">
    <div class="panel"><h2 style="font-size:var(--t-lg);margin-bottom:12px">引擎</h2><dl class="kv">
      <dt>排程狀態</dt><dd>${h.paused ? chip("已暫停", "warn") : chip('<span class="live-dot"></span>排程運作中', "live")}</dd>
      <dt>資料產生</dt><dd class="num">${fmtDT(D.generated_at)},${ago(D.generated_at)}</dd>
      <dt>通知偵測</dt><dd>${h.poller_last ? ago(h.poller_last) : "-"}</dd>
      <dt>回覆佇列</dt><dd class="num">${h.queue ?? 0} 則</dd>
      <dt>Claude 額度</dt><dd>${h.limit?.until && new Date(h.limit.until) > now() ? chip(`${fmtTime(h.limit.until)} 重置`, "bad") : "正常"}</dd>
      <dt>Codex 接手</dt><dd>${esc(({running:"執行中",finished:"已完成",budget_stopped:"成本守門已停止",failed:"執行失敗",paused:"依使用者要求暫停"})[h.codex_takeover?.status] || "待命")}${h.codex_takeover?.round ? ` (${esc(h.codex_takeover.round)})` : ""}${h.codex_takeover?.reason ? `<div class="small dim">${esc(h.codex_takeover.reason)}</div>` : ""}</dd>
      <dt>OmniRoute</dt><dd>${esc(h.omniroute?.status || "未確認")}${h.omniroute?.checked_at ? `，${ago(h.omniroute.checked_at)} 檢查` : ""}</dd>
      <dt>GitHub 貢獻資料</dt><dd>${D.source_freshness?.contributions ? ago(D.source_freshness.contributions) : "未記錄"}</dd>
      <dt>合併評估資料</dt><dd>${D.source_freshness?.merge_assessments ? ago(D.source_freshness.merge_assessments) : "未記錄"}</dd></dl></div>
    <div class="panel"><h2 style="font-size:var(--t-lg);margin-bottom:12px">排程</h2><dl class="kv">${sched.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl></div>
    <div class="panel"><h2 style="font-size:var(--t-lg);margin-bottom:12px">模型分工</h2><dl class="kv">${models.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl></div>
  </div>
  ${sec("用量", "引擎的無頭執行,不含互動對話", `<div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(160px,1fr))">${periods.map(([l, f, to]) => { const u = usageSum(f, to); return `<div class="panel tight"><div class="xs dim">${l}</div><div style="font-size:var(--t-xl);font-weight:600" class="num">${usd(u.cost)}</div><div class="xs dim num">${tok(u.tokens)} tokens,${u.runs} 次執行</div></div>`; }).join("")}</div>
    <div class="panel section"><div class="sec-head"><h2>每日用量</h2><span style="display:flex;gap:6px">${seg("cost", "美元")}${seg("tokens", "總 token")}${seg("output", "輸出 token")}</span></div>
      ${stacked((D.usage?.days || []).slice(-45), state.usageMetric)}
      <div class="legend">${AREA_ORDER.map((a) => `<span><i style="background:var(--a-${a})"></i>${a === "other" ? "報告與其他" : AREA[a]}</span>`).join("")}</div>
      <p class="xs dim" style="margin-top:8px">美元是依定價換算的數字,訂閱方案實際扣的是額度。總 token 大多是快取讀取,單價約為新輸入的十分之一。</p></div>
    <div class="panel section"><div class="sec-head"><h2>依專案與比賽累計</h2><span class="aside">多項目的執行平均分攤</span></div>
      ${A.map((b) => `<div class="hbar"><span class="l" title="${esc(b.label)}">${esc(b.label)}</span><div class="meter"><i style="width:${(b.cost / amax) * 100}%"></i></div><span class="num r small" style="text-align:right">${usd(b.cost)}</span></div>`).join("")}</div>`)}
  <div class="grid g2 section">
    <div class="panel"><h2 style="font-size:var(--t-lg);margin-bottom:8px">各類工作最近一次</h2><div class="tablewrap"><table><thead><tr><th>工作</th><th>時間</th><th class="r">分鐘</th><th class="r">美元</th><th>結果</th></tr></thead><tbody>
      ${Object.entries(lr).map(([j, r]) => `<tr><td>${JOB_LABEL[j] || esc(j)}</td><td class="num">${fmtDT(r.at)}</td><td class="num r">${r.minutes ?? "-"}</td><td class="num r">${usd(r.cost)}</td><td>${r.error ? chip("錯誤", "bad") : r.end ? chip("完成", "good") : chip("紀錄不完整")}</td></tr>`).join("")}
      </tbody></table></div></div>
    <div class="panel"><h2 style="font-size:var(--t-lg);margin-bottom:8px">異常紀錄</h2>
      ${(h.failures || []).slice(-8).reverse().map((f) => `<div class="small" style="padding:6px 0;border-top:1px solid var(--line)">${chip(esc(FAIL_LABEL[f.kind] || f.kind || "失敗"), "bad")} <span class="num dim">${esc(f.date)} ${esc(f.time || "")}</span><div class="xs dim">${esc(f.reason || "")}</div></div>`).join("") || '<div class="empty">沒有異常。</div>'}
      ${(h.limit?.history || []).length ? `<div class="sub-h">用量上限</div>${h.limit.history.slice(-5).reverse().map((x) => `<div class="small"><span class="num">${fmtDT(x.hit)}</span> ${JOB_LABEL[x.job] || esc(x.job)} 碰到上限,${fmtDT(x.until)} 重置</div>`).join("")}` : ""}</div>
  </div>
  ${fold("報告", `${(D.reports || []).length} 份`, `<ul class="rows">${(D.reports || []).map((r, i) => `<li><span class="what"><a href="#" data-report="${i}">${esc(r.title)}</a></span><span class="when num">${fmtDT(r.at)}</span></li>`).join("")}</ul>`)}
  ${fold("最近的對外動作", "GitHub 事件", `<ul class="rows">${(D.activity || []).slice(-30).reverse().map((e) => `<li><span class="what">${link(e.url, `${esc(e.repo)}${e.number ? "#" + e.number : ""}`)}<span class="why">${esc({ IssuesEvent: "Issue", PullRequestEvent: "PR", IssueCommentEvent: "留言", PullRequestReviewEvent: "審查", PullRequestReviewCommentEvent: "審查留言" }[e.type] || e.type)} ${esc(e.action || "")},${esc(e.title)}</span></span><span class="when num">${fmtDT(e.at)}</span></li>`).join("")}</ul>`)}`;
}

/* ---------- 運作: rules and live state of the six lines ---------- */
const OPS_AREA = { oss: "oss", focus: "comps", personal: "papers", galaxy: "quick", daily: "quick", promo: "other" };
const OPS_HEALTH = { ok: ["正常", "good"], warn: ["注意", "warn"], fail: ["異常", "bad"] };
const OPS_WORKERS = { oss: "開源", focus: "競賽論文", personal: "個人", quick: "解答與每日", reply: "回覆", other: "其他" };
state.opsOpen = new Set();

function opsDot(L) {
  if (L.health === "fail") return `<span class="bad-dot" title="異常"></span>`;
  if (L.health === "warn") return `<span class="warn-dot" title="注意"></span>`;
  return L.running ? `<span class="live-dot" title="執行中"></span>` : `<span class="idle-dot" title="待命"></span>`;
}
function opsNow(L) {
  const rows = L.now || [];
  if (!rows.length) return `<span class="dim">沒有資料</span>`;
  const line = (t) => `<div class="ops-line">${esc(t)}</div>`;
  if (rows.length <= 4) return rows.map(line).join("");
  const id = "now-" + L.key, open = state.opsOpen.has(id);
  return rows.slice(0, 3).map(line).join("") +
    `<details class="ops-more" data-keep="${id}"${open ? " open" : ""}><summary>另外 ${rows.length - 3} 項</summary>${rows.slice(3).map(line).join("")}</details>`;
}
function opsLast(L) {
  const links = (L.last_links || []).filter((x) => x.url);
  const id = "last-" + L.key, open = state.opsOpen.has(id);
  const body = links.length
    ? `<div class="ops-links">${links.map((x) => `<a class="chip info" href="${esc(x.url)}" target="_blank" rel="noopener" title="${esc(x.label)}">${esc(x.label)}</a>`).join("")}</div>` : "";
  const txt = `<div class="ops-line">${esc(L.last || "還沒有紀錄")}${L.last_at ? ` <span class="dim xs">(${ago(L.last_at)})</span>` : ""}</div>`;
  if (links.length > 4) return txt + `<details class="ops-more" data-keep="${id}"${open ? " open" : ""}><summary>${links.length} 個連結</summary>${body}</details>`;
  return txt + body;
}
function opsScheduleLabel(value) {
  return String(value || "")
    .replace(/((?:\d{1,2}、)*\d{1,2}) 點/g, (_, hours) =>
      hours.split("、").map((hour) => `${hour.padStart(2, "0")}:00`).join("、"))
    .replace(/每小時\s*:(\d{2})/g, "每小時 00:$1 至 23:$1")
    .replace(/\b(\d):(\d{2})\b/g, "0$1:$2");
}
function opsCard(rule, L) {
  const models = D.ops?.runtime_config?.models || {};
  const keys = { oss: "hunt", focus: "compete", daily: "quickwins", personal: "personal", galaxy: "galaxy" };
  if (models[keys[rule.key]]) {
    const suffix = { oss: "，送出前審查:第一關 Codex gpt-6.1-sol high,第二關 Claude Sonnet 5.5 high", focus: "，卡關初判 gpt-6.1-sol high,最終決策 Claude Sonnet 5.5 high", galaxy: "，gpt-6.1-sol high 確認並把關" };
    rule = { ...rule, model: models[keys[rule.key]] + (suffix[rule.key] || "") };
  }
  const [hl, hc] = OPS_HEALTH[L.health] || ["未知", ""];
  const run = L.running ? chip(`執行中${L.workers > 1 ? " " + L.workers : ""}`, "live") : chip("待命", "paused");
  return `<article class="ops-card" data-h="${esc(L.health)}" data-run="${L.running ? 1 : 0}" style="--area:var(--a-${OPS_AREA[rule.key] || "other"})">
    <header class="ops-head">
      <div class="ops-title">${opsDot(L)}<h3>${esc(rule.name)}</h3>${run}${rule.key === "promo" && socialPending().length ? chip(`需要你回覆 ${socialPending().length}`, "bad") : ""}${L.engine ? chip(esc(L.engine), "info", "最近實際使用的模型") : ""}</div>
      <div class="ops-sub"><span>排程:${esc(opsScheduleLabel(rule.schedule))}</span><span>模型:${esc(rule.model)}</span></div>
    </header>
    <div class="ops-rules"><div class="ops-lbl">${"帳號規則原文，含歷次設定"}</div><ul>${(rule.rules || []).map((r) => `<li>${esc(r)}</li>`).join("")}</ul></div>
    <div class="ops-live">
      <div class="ops-lbl live">${opsDot(L)}<span>即時狀態</span><span class="dim xs">更新於 ${fmtTime(L.updated_at)}</span></div>
      <dl class="ops-kv">
        <dt>正在做</dt><dd>${opsNow(L)}</dd>
        <dt>進度</dt><dd>${esc(L.progress || "沒有資料")}</dd>
        <dt>上一輪</dt><dd>${opsLast(L)}</dd>
        <dt>下次執行</dt><dd>${L.next_run ? `${fmtTime(L.next_run)}<span class="dim xs">(${until(new Date(L.next_run))})</span>` : "未知"}</dd>
        <dt>健康</dt><dd>${chip(hl, hc)} ${esc(L.health_reason || "")}</dd>
      </dl>
    </div>
  </article>`;
}
function opsStrip(O) {
  const S = O.summary || {}, bad = S.fail || 0, warn = S.warn || 0, lim = O.limit || {}, H = O.host || {};
  const overall = bad ? chip(`${bad} 項異常${warn ? `、${warn} 項注意` : ""}`, "bad") : warn ? chip(`${warn} 項注意`, "warn") : chip("全部正常", "good");
  const claude = lim.in_force ? chip(`額度用到 ${fmtTime(lim.until)}`, "warn") + ` <span class="xs dim">Codex 接手中</span>` : chip("正常", "good");
  const stale = (now() - new Date(O.generated_at)) / 60000 > 10;
  const num = (v, d = 1) => (v == null ? "?" : Number(v).toFixed(d));
  const cell = (k, v) => `<div class="ops-cell"><div class="k">${k}</div><div class="v">${v}</div></div>`;
  const diskLow = H.disk_free_gb != null && H.disk_free_gb < 40;
  const B = O.runtime_config?.budget || {}, P = O.runtime_config?.budget_plan || {};
  const budgetNote = B.used_percent != null ? `<p class="xs dim ops-note">Codex 配額:已用 ${num(B.used_percent)}%,目前預算 ${num(B.allowed_percent)}%,計畫 ${esc(P.hours ?? "未知")} 小時。PR 設定 ${esc(O.runtime_config.slots)} 個名額,目前上限 ${esc(O.runtime_config.effective_slots ?? "未知")} 個${B.hold_non_priority ? ",暫停新工作,回覆與跟進繼續" : ""}。</p>` : "";
  return `<div class="panel ops-strip">
    ${cell("整體", overall)}
    ${cell("Claude 用量", claude)}
    ${cell("主機負載", `<span class="num">${num(H.load)}</span><span class="xs dim"> / ${H.cores || "?"} 核</span>`)}
    ${cell("可用記憶體", `<span class="num">${num(H.mem_avail_gb, 0)}</span><span class="xs dim"> GB</span>`)}
    ${cell("磁碟剩餘", `<span class="num"${diskLow ? ' style="color:var(--warn)"' : ""}>${num(H.disk_free_gb, 0)}</span><span class="xs dim"> GB</span>`)}
    ${cell("更新於", `<span class="num"${stale ? ' style="color:var(--bad)"' : ""}>${fmtTime(O.generated_at)}</span>`)}
  </div>${budgetNote}${H.blocked ? `<p class="xs dim ops-note">主機守門:${esc(H.blocked)}</p>` : ""}`;
}

/* ---------- 回覆追蹤: every reply owed, per line, with the detectors (2026-10-03) ---------- */
const RT_TYPE = { pr: ["PR", "rt-pr"], galaxy: ["Galaxy", "rt-galaxy"], other: ["其他", "rt-other"] };
const RT_STATUS = { replying: ["執行中", "live"], pending: ["還沒回覆", "warn"], replied: ["已回覆", "good"], retrying: ["重試中", "info"], needs_decision: ["需你決定", "warn"], recorded: ["已記錄", "live"],
  no_reply_needed: ["不需回覆", ""], blocked: ["黑名單不回", "bad"] };
const fmtSec = (iso) => { if (!iso) return "—"; const d = new Date(iso); if (isNaN(d)) return esc(String(iso)); return d.toLocaleString("zh-TW", { timeZone: "Asia/Taipei", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }); };
function rtRow(i) {
  const [tl, tc] = RT_TYPE[i.type] || ["?", ""], [sl, sc] = RT_STATUS[i.status] || [i.status, ""];
  const where = i.number ? `${esc(i.repo || "")}#${i.number}` : esc(i.repo || i.platform || "");
  const eta = i.status === "replying" ? `開始於 ${fmtSec(i.since)},已執行 ${i.minutes} 分鐘` : i.status === "pending" ? (i.eta ? `預計 ${fmtSec(i.eta)}` : "") : "";
  return `<li class="rt-row ${tc}"><span class="what"><span class="rt-tags"><span class="chip rt-type">${tl}</span>${chip(sl, sc)}</span>
    ${i.url ? link(i.url, where) : where}
    <span class="why"><b>${esc(i.by || "對方")}</b>:${esc((i.said || "(沒有擷取到內容)").slice(0, 220))}</span>
    <span class="why">${esc(i.why || "")}${eta ? ` · ${eta}` : ""}</span></span>
    <span class="when">${fmtSec(i.at)}</span></li>`;
}
function replyTracker() {
  const T = D.reply_tracker || {};
  if (!T.items) return sec("回覆追蹤", "", `<div class="panel"><p class="dim">回覆追蹤資料尚未產生,每 5 分鐘更新。</p></div>`);
  const det = (T.detectors || []).map((d) => `<li><span class="what"><b>${esc(d.label)}</b> <span class="small dim">每 ${d.every_min} 分鐘</span>
      ${d.repair ? `<span class="why">自動修復:${esc(d.repair)}</span>` : ""}${d.note ? `<span class="why">${esc(d.note)}</span>` : ""}${d.error ? `<span class="why">最後錯誤:${esc(d.error)}</span>` : ""}</span>
      <span class="when">${chip(d.status === "ok" ? "正常" : d.status === "stale" ? "逾時,已補跑" : "失敗", d.status === "ok" ? "good" : "bad")} 上次偵測 ${fmtSec(d.last_at)}</span></li>`).join("");
  const blocks = ["pr", "galaxy", "other"].map((k) => {
    const all = T.items.filter((i) => i.type === k), pend = all.filter((i) => ["pending", "replying", "needs_decision"].includes(i.status)), done = all.filter((i) => !["pending", "replying", "needs_decision"].includes(i.status));
    const c = T.counts?.[k] || {};
    const aside = `${c.replying ? `執行中 ${c.replying} · ` : ""}還沒回覆 ${c.pending || 0} · 已回覆 ${c.replied || 0} · 不需回覆 ${c.no_reply_needed || 0}${c.retrying ? ` · 重試中 ${c.retrying}` : ""}${c.needs_decision ? ` · 需你決定 ${c.needs_decision}` : ""}${c.blocked ? ` · 黑名單 ${c.blocked}` : ""}`;
    const body = (pend.length ? `<ul class="rows">${pend.map(rtRow).join("")}</ul>` : `<p class="small dim">目前沒有待回覆的。</p>`)
      + (done.length ? `<details class="fold"><summary>已處理 ${done.length} 則(近 48 小時)</summary><ul class="rows">${done.slice().reverse().map(rtRow).join("")}</ul></details>` : "");
    return `<details class="fold section rt-block ${RT_TYPE[k][1]}" data-keep="rt-${k}"${pend.length || state.opsOpen?.has?.("rt-" + k) ? " open" : ""}><summary>${RT_TYPE[k][0]} 回覆<span class="aside">${aside}</span></summary><div class="fold-body">${body}</div></details>`;
  }).join("");
  return sec("回覆追蹤", `更新於 ${fmtSec(T.generated_at)}${T.missed_found ? ` · 交叉檢查補回 ${T.missed_found} 則漏偵測` : ""}`,
    `<details class="fold section" data-keep="rt-det"${state.opsOpen?.has?.("rt-det") ? " open" : ""}><summary>偵測器<span class="aside">${(T.detectors || []).filter((d) => d.status === "ok").length}/${(T.detectors || []).length} 正常</span></summary><div class="fold-body"><ul class="rows">${det}</ul>
      <p class="small dim">通知信偵測不耗 GitHub API 額度;API 偵測被拒時由通知信接手,通知信異常時改由 API 偵測每 5 分鐘補偵測;每 15 分鐘交叉檢查一次,漏掉的自動補進佇列。</p></div></details>${blocks}`);
}
function viewOps() {
  const O = D.ops, R = D.ops_rules;
  if (!O || !O.lines || !R || !R.lines) return `<div class="panel"><p class="dim">運作資料尚未產生,下一次收集(最多 5 分鐘)後會出現。</p></div>`;
  const lim = O.limit || {};
  const banner = lim.in_force ? `<div class="panel ops-banner"><b>Claude 額度用到 ${fmtDT(lim.until)} 才恢復。</b> 這段時間由 Codex 依各工作模型設定接手,PR 只準備不送出,額度恢復後由 Claude 審查再送。</div>` : "";
  const live = (O.liveness || []).slice(-6).reverse();
  const reps = (O.repairs || []).slice(-10).reverse();
  const audits = (D.audits || O.audits || []).slice().sort((a, b) => String(b.at).localeCompare(String(a.at)));
  const audit6hEnabled = O.runtime_config?.audit_6h_enabled === true;
  const auditCards = ["6h", "12h"].map((scope) => {
    const a = audits.find((x) => x.scope === scope);
    const next = scope === "6h" ? (audit6hEnabled ? nextAt([2, 8, 14, 20], 50) : null) : nextAt([11, 23], 40);
    const fixed = (a?.findings || []).filter((f) => f.status === "fixed").length;
    const open = (a?.findings || []).filter((f) => ["open", "external"].includes(f.status)).length;
    return `<div class="panel audit-card"><h3>${scope === "6h" ? (audit6hEnabled ? "每 6 小時" : "6 小時巡檢已停用") : "每 12 小時"}</h3>
      <p class="small dim">${a ? `${fmtDate(a.at)} · ${esc(a.engine)}` : "尚無巡檢紀錄"}</p>
      <p>${a ? esc(a.summary_zh || "") : "等待首次巡檢"}</p>
      <div class="small">檢查 ${a?.checked ?? 0} 項，已修復 ${fixed} 項，待處理 ${open} 項</div>
      <div class="small dim">${next ? `下次執行 ${fmtDT(next)}` : "已由每小時管理員、回覆稽核與 12 小時巡檢涵蓋"}</div></div>`;
  }).join("");
  const auditHistory = audits.slice(0, 10).map((a) => `<details class="audit-entry"><summary>${fmtDate(a.at)} · ${esc(a.scope)} · ${esc(a.engine)} · ${esc(a.summary_zh || "")}</summary>
    ${(a.findings || []).length ? `<ul class="rows">${a.findings.map((f) => `<li><span class="what"><b>${esc(f.area)}</b> ${esc(f.problem_zh)}<span class="why">處置：${esc(f.fix_zh)}</span></span><span class="when">${chip(f.status === "fixed" ? "已修復" : f.status === "external" ? "外部因素" : "待處理", f.status === "fixed" ? "good" : "warn")}</span></li>`).join("")}</ul>` : '<p class="small dim">未發現問題</p>'}</details>`).join("");
  const alwaysOn = (R.always_on || []).map((rule) => rule.startsWith("管理員巡檢:")
    ? `管理員巡檢:每小時 00:25 至 23:25 執行管理員檢查,每 5 分鐘檢查回覆,${audit6hEnabled ? "每 6 小時巡檢啟用," : "6 小時巡檢已停用,"}每 12 小時(11:40、23:40)由 ${O.runtime_config?.models?.hunt || "設定未取得"} 檢查近 12 小時。發現問題就修復並重啟該線,結果記錄在監控台。`
    : rule);
  const wk = (w) => Object.entries(OPS_WORKERS).filter(([k]) => w && w[k] != null).map(([k, l]) => `<span class="ops-w${w[k] ? " on" : ""}">${l} <b class="num">${w[k]}</b></span>`).join("");
  return `${banner}${opsStrip(O)}
  ${sec("模型分工", "目前實際設定", `<div class="panel"><p>${esc(O.runtime_config?.models ? `例行工作與委派步驟:${O.runtime_config.models.compete}，建立新個人專案:${O.runtime_config.models.personal}，關鍵判斷與最後把關:${O.runtime_config.models.hunt}。` : "設定尚未收集")}</p>${fold("帳戶原始規則", "原文保留,模型以目前實際設定為準", `<ul class="ops-plan">${(R.model_plan || []).map((t) => `<li>${esc(t)}</li>`).join("")}</ul>`)}</div>`)}
  ${replyTracker()}
  ${sec("六條線", "每張卡片上半是規則,下半是即時狀態", `<div class="ops-cards">${R.lines.map((r) => (O.lines[r.key] ? opsCard(r, O.lines[r.key]) : "")).join("")}</div>`)}
  ${sec("常駐機制", "", `<div class="panel"><ul class="ops-plan">${alwaysOn.map((t) => `<li>${esc(t)}</li>`).join("")}</ul></div>`)}
  ${sec("管理員巡檢", "", `<div class="audit-grid">${auditCards}</div>${fold("最近十次巡檢", `${audits.length} 次`, auditHistory || '<p class="small dim">尚無巡檢紀錄</p>')}`)}
  <div class="grid g2 section">
    <div class="panel"><h2 class="ops-h2">最近自動修復</h2>${reps.length ? `<ul class="rows">${reps.map((x) => `<li><span class="what"><b>${esc(x.line || "")}</b> ${esc(x.problem || "")}<span class="why">修法:${esc(x.fix || "")}</span></span><span class="when">${chip(esc(x.result || ""), /ok|success|成功|fixed|已/i.test(x.result || "") ? "good" : "warn")}<br>${fmtDT(x.at)}</span></li>`).join("")}</ul>` : `<p class="small dim">還沒有自動修復紀錄,代表監督機制沒有發現需要修的故障。</p>`}</div>
    <div class="panel"><h2 class="ops-h2">最近監督檢查</h2>${live.length ? `<ul class="rows">${live.map((x) => `<li><span class="what"><span class="ops-ws">${wk(x.workers)}</span>${(x.gaps || []).length ? `<span class="why">缺口:${esc(x.gaps.join("、"))}</span>` : ""}${(x.actions || []).length ? `<span class="why">處置:${esc(x.actions.join("、"))}</span>` : ""}${x.blocked ? `<span class="why">暫緩:${esc(x.blocked)}</span>` : ""}</span><span class="when num">${fmtTime(x.at)}</span></li>`).join("")}</ul>` : `<p class="small dim">沒有檢查紀錄</p>`}</div>
  </div>`;
}
document.addEventListener("toggle", (e) => {
  const d = e.target; if (!d || !d.dataset || !d.dataset.keep) return;
  d.open ? state.opsOpen.add(d.dataset.keep) : state.opsOpen.delete(d.dataset.keep);
}, true);
(function addOpsTab() {
  const nav = document.querySelector(".tabs");
  if (!nav || nav.querySelector('[data-tab="ops"]')) return;
  const b = document.createElement("button"); b.type = "button"; b.dataset.tab = "ops"; b.textContent = "運作"; nav.prepend(b);
})();

/* tiny markdown for reports */
function md(src) {
  const ls = src.split("\n"); let out = "", inCode = false, table = [];
  const inline = (s) => esc(s).replace(/`([^`]+)`/g, "<code>$1</code>").replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>")
    .replace(/\[([^\]]+)\]\((https?:[^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>')
    .replace(/(^|[\s(])(https?:\/\/[^\s)<]+)/g, '$1<a href="$2" target="_blank" rel="noopener">$2</a>');
  const flush = () => {
    if (!table.length) return;
    const rows = table.filter((r) => !/^\s*\|?\s*:?-{2,}/.test(r)).map((r) => r.trim().replace(/^\||\|$/g, "").split("|"));
    out += `<div class="tablewrap"><table>${rows.map((r, i) => `<tr>${r.map((c) => `<${i ? "td" : "th"}>${inline(c.trim())}</${i ? "td" : "th"}>`).join("")}</tr>`).join("")}</table></div>`;
    table = [];
  };
  for (const l of ls) {
    if (l.startsWith("```")) { flush(); out += inCode ? "</code></pre>" : "<pre><code>"; inCode = !inCode; continue; }
    if (inCode) { out += esc(l) + "\n"; continue; }
    if (l.trim().startsWith("|")) { table.push(l); continue; } else flush();
    const hh = l.match(/^(#{1,4})\s+(.*)/);
    if (hh) out += `<h${hh[1].length + 1}>${inline(hh[2])}</h${hh[1].length + 1}>`;
    else if (/^\s*[-*]\s+/.test(l)) out += `<li style="margin-left:${(l.match(/^\s*/)[0].length) * 6 + 18}px">${inline(l.replace(/^\s*[-*]\s+/, ""))}</li>`;
    else if (l.trim()) out += `<p>${inline(l)}</p>`;
  }
  flush();
  return out;
}

/* ---------- router, header, events ---------- */
const TABS = ["ops", "overview", "oss", "personal", "comps", "papers", "daily", "wall", "system"];
const LEGACY = { contrib: "oss", quick: "daily", achievements: "wall", usage: "system" };
function route() {
  const [t0, id] = location.hash.replace(/^#/, "").split("/");
  const tab = LEGACY[t0] || t0;
  state.tab = TABS.includes(tab) ? tab : "ops";
  state.comp = state.tab === "comps" && id ? decodeURIComponent(id) : null;
  state.paper = state.tab === "papers" && id ? decodeURIComponent(id) : null;
}
function hostChip() {
  const x = D.host; if (!x) return "";
  const low = x.disk_free_gb < x.disk_min_gb;
  const tip = `磁碟剩 ${Math.round(x.disk_free_gb)} GB,低於 ${x.disk_min_gb} GB 會自動清理\n記憶體可用 ${x.mem_avail_gb} GB,負載 ${x.load}(12 核)\n${x.blocked ? "暫緩派新工作:" + x.blocked : "可以派新工作"}`;
  return `<span title="${esc(tip)}" style="${low ? "color:var(--bad)" : x.blocked ? "color:var(--warn)" : ""}">磁碟 <b class="num">${Math.round(x.disk_free_gb)}</b> GB${x.blocked ? ",主機忙,暫緩派工" : ""}</span>`;
}
function header() {
  const h = D.health || {}, J = jobs(), fresh = D.live_at || D.generated_at, stale = (now() - new Date(fresh)) / 60000 > 10;
  const lim = h.limit?.until && new Date(h.limit.until) > now();
  $("#status").innerHTML = [
    h.paused ? chip("已暫停", "warn") : h.codex_takeover?.status === "running" ? chip("Codex 接手中", "live") : lim ? chip(`Claude 額度滿,${fmtTime(h.limit.until)} 重置`, "warn") : `<span style="display:inline-flex;align-items:center;gap:6px"><span class="live-dot"></span><b>運作中</b></span>`,
    `<span>${J.length ? `<b class="num">${J.length}</b> 個工作執行中` : "沒有工作在執行"}</span>`,
    `<span class="${stale ? "" : "dim"}" style="${stale ? "color:var(--bad)" : ""}">資料 ${fmtClock(fresh)} 更新,${Math.max(0, Math.floor((now() - new Date(fresh)) / 1000))} 秒前 <small>(${esc(DATA_SOURCE)})</small></span>`,
    hostChip(),
  ].join("");
  const n = needsYou().length;
  document.querySelectorAll(".tabs button").forEach((b) => {
    b.setAttribute("aria-selected", b.dataset.tab === state.tab);
    if (b.dataset.tab === "ops") { const f = D.ops?.summary?.fail || 0; b.innerHTML = `運作${f ? `<span class="badge" style="background:var(--bad)" aria-label="${f} 項異常">${f}</span>` : ""}`; }
    if (b.dataset.tab === "personal") { const c = socialPending().length; b.innerHTML = `個人開源${c ? `<span class="badge" style="background:var(--bad)" aria-label="${c} 則需要回覆">${c}</span>` : ""}`; }
    if (b.dataset.tab === "overview") b.innerHTML = `總覽${n ? `<span class="badge" aria-label="${n} 件需要你">${n}</span>` : ""}`;
  });
}
function render() {
  header();
  const v = { ops: viewOps, overview: viewOverview, oss: viewOss, personal: viewPersonal, comps: viewComps, papers: viewPapers, daily: viewDaily, wall: viewWall, system: viewSystem }[state.tab];
  $("#view").innerHTML = v();
  if (state.tab === "wall") requestAnimationFrame(updateArchiveExpand);
  $("#foot").textContent = `資料產生於 ${fmtDT(D.generated_at)}(台北時間),每 2 分鐘即時發布,頁面會自動更新。所有數字來自引擎紀錄與各平台 API。`;
}
function showReport(r) { if (!r) return; $("#modal-body").innerHTML = `<div class="md"><div class="xs dim">${esc(r.name)},${fmtDT(r.at)}</div>${md(r.text)}</div>`; $("#modal").hidden = false; $("#modal-close").focus(); }
document.addEventListener("click", (e) => {
  if (!$("#cele").hidden && e.target.closest("#cele")) { if (!e.target.closest("#cele-link, #cele-share")) nextCele(); return; }
  const t = e.target;
  const af = t.closest("[data-archive-filter]"); if (af) { const [g, v] = af.dataset.archiveFilter.split(":"); state[{ src: "archiveSrc", tone: "archiveTone", st: "archiveSt" }[g]] = v;
    af.parentElement.querySelectorAll("button").forEach((b) => { const on = b === af; b.classList.toggle("active", on); b.setAttribute("aria-pressed", on); });
    renderArchiveBody(); return; }
  const rp = t.closest("[data-replay]"); if (rp) { const ev = (D.celebrations || []).find((x) => x.id === rp.dataset.replay); if (ev) { cele.q.unshift(ev); if (!cele.cur) nextCele(); } return; }
  const queueHead = t.closest("[data-queue-toggle]"); if (queueHead) {
    if (t.closest("a")) return;
    const card = queueHead.closest(".qcard"), body = card.querySelector(".qcard-body"), opened = body.hidden;
    body.hidden = !opened; card.classList.toggle("is-open", opened);
    const button = queueHead.querySelector(".qcard-toggle");
    button.setAttribute("aria-expanded", String(opened));
    button.setAttribute("aria-label", `${card.querySelector(".qcard-title").textContent}${opened ? "收合" : "展開"}`);
    button.querySelector(".qcard-toggle-label").textContent = opened ? "收合" : "展開";
    const saved = localJson("oc-queue-open") || {}; saved[card.dataset.queueKey] = opened;
    store.set("oc-queue-open", JSON.stringify(saved)); return;
  }
  const manual = t.closest("[data-manual-post]"); if (manual) {
    const [project, platform] = manual.dataset.manualPost.split(":");
    const value = prompt("請貼上已發布貼文的網址");
    if (value === null) return;
    let url; try { url = new URL(value.trim()); } catch { alert("請輸入有效的貼文網址"); return; }
    const hosts = platform === "x" ? ["x.com", "twitter.com"] : ["linkedin.com", "www.linkedin.com"];
    if (url.protocol !== "https:" || !hosts.includes(url.hostname) || !url.pathname || url.pathname === "/") { alert("請輸入對應平台的貼文網址"); return; }
    const marks = localJson("oc-manual-posts"); marks[`${project}:${platform}`] = { url: url.href, at: new Date().toISOString() };
    store.set("oc-manual-posts", JSON.stringify(marks)); render(); return;
  }
  const replied = t.closest("[data-replied]"); if (replied) { const marks = localJson("oc-replied-comments"); marks[replied.dataset.replied] = true; store.set("oc-replied-comments", JSON.stringify(marks)); render(); return; }
  const reply = t.closest("[data-reply-open]"); if (reply) {
    const row = (D.social_replies || []).find((r) => r.id === reply.dataset.replyOpen);
    if (!row || !row.draft) return;
    copyText(row.draft); window.open(row.reply_url, "_blank", "noopener"); reply.textContent = "已複製回覆,貼上後送出"; return;
  }
  const ex = t.closest("[data-expand]"); if (ex) { const o = ex.previousElementSibling.classList.toggle("clamp"); ex.textContent = o ? "展開" : "收合"; return; }
  const cp = t.closest("[data-copy]"); if (cp) { copyText(cp.dataset.copy, cp); return; }
  const tb = t.closest(".tabs [data-tab]"); if (tb) { location.hash = tb.dataset.tab; return; }
  const go = t.closest("[data-go]"); if (go) { location.hash = go.dataset.go; return; }
  const rep = t.closest("[data-report]"); if (rep) { e.preventDefault(); showReport(D.reports[+rep.dataset.report]); return; }
  const mt = t.closest("[data-metric]"); if (mt) { state.usageMetric = mt.dataset.metric; store.set("oc-usageMetric", mt.dataset.metric); render(); return; }
  if (t.closest("a")) return;
  const pc = t.closest("[data-paper]"); if (pc) { location.hash = "papers/" + encodeURIComponent(pc.dataset.paper); return; }
  const cc = t.closest("[data-comp]"); if (cc) { location.hash = "comps/" + encodeURIComponent(cc.dataset.comp); return; }
});
document.addEventListener("input", (e) => {
  if (e.target.id === "archive-search") { state.archiveQuery = e.target.value; renderArchiveBody(); }
});
document.addEventListener("toggle", (e) => {
  if (e.target.matches(".archive-project") && e.target.open) requestAnimationFrame(updateArchiveExpand);
}, true);
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") { if (!$("#cele").hidden) nextCele(); else $("#modal").hidden = true; }
  if (e.key === "Enter" && e.target.dataset) {
    if (e.target.dataset.comp) location.hash = "comps/" + encodeURIComponent(e.target.dataset.comp);
    else if (e.target.dataset.paper) location.hash = "papers/" + encodeURIComponent(e.target.dataset.paper);
  }
});
$("#modal-close").onclick = () => ($("#modal").hidden = true);
$("#modal").onclick = (e) => { if (e.target.id === "modal") $("#modal").hidden = true; };
$("#cele-close").onclick = (e) => { e.stopPropagation(); nextCele(); };
window.addEventListener("hashchange", () => { if (D) { route(); render(); window.scrollTo(0, 0); } });
$("#unlock").onsubmit = (e) => { e.preventDefault(); open($("#pass").value, $("#remember").checked); };
$("#refresh").onclick = () => { if (PASS) refresh(false); };
$("#logout").onclick = () => { store.del("oc-pass"); D = null; PASS = null; $("#app").hidden = true; $("#lock").hidden = false; $("#pass").value = ""; $("#lock-msg").textContent = ""; };
$("#theme").onclick = () => {
  const cur = document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  const nx = cur === "dark" ? "light" : "dark"; document.documentElement.dataset.theme = nx; store.set("oc-theme", nx); if (D) render();
};
(function init() {
  const th = store.get("oc-theme"); if (th) document.documentElement.dataset.theme = th;
  const um = store.get("oc-usageMetric"); if (um) state.usageMetric = um;
  const p = store.get("oc-pass"); if (p) { $("#remember").checked = true; open(p, true); }
  setInterval(() => { if (D && PASS) refresh(true); }, 2 * 60 * 1000);
  setInterval(() => { if (D) header(); }, 30 * 1000);
})();

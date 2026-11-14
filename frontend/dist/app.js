/* FoxyVPN frontend — vanilla JS, talks to Wails bindings */
"use strict";

const App = window.go && window.go.main && window.go.main.App;
const runtime = window.runtime;

const I18N = {
  fa: {
    appName: "FoxyVPN",
    loginSubtitle: "برای اتصال به سرویس Mozilla VPN، با حساب فایرفاکس خود وارد شوید",
    signIn: "ورود با حساب فایرفاکس",
    loginProgress: "در حال تکمیل ورود… پنجره مرورگر را دنبال کنید",
    modeTunnel: "تانل VPN",
    modeProxy: "فقط پروکسی",
    systemProxy: "اعمال روی پروکسی سیستم ویندوز",
    navHome: "خانه", navRegions: "ریجن‌ها", navSettings: "تنظیمات", navLogs: "لاگ‌ها",
    region: "ریجن", exitIp: "IP خروجی", latency: "تأخیر", speed: "سرعت",
    dataUsed: "حجم نشست", quota: "سهمیه ماهانه", realIp: "IP واقعی شما",
    usage: "مصرف و سهمیه ماهانه", usedOf: "مصرف", leftLabel: "مانده",
    searchRegion: "جستجوی کشور یا شهر…",
    recommended: "پیشنهادی",
    all: "همه", copy: "کپی", clear: "پاک کردن", signOut: "خروج از حساب",
    save: "ذخیره تنظیمات", saved: "ذخیره شد",
    disconnected: "قطع", connecting: "در حال اتصال…", connected: "متصل",
    reconnecting: "اتصال مجدد…",
    proxyActive: "پروکسی فعال",
    healthChecking: "در حال بررسی", healthHealthy: "سلامت", healthNoNetwork: "بدون شبکه",
    healthUnreachable: "غیرقابل دسترس", healthUnknown: "—",
    unlimited: "نامحدود",
    retry: "تلاش دوباره", loadFail: "دریافت لیست ناموفق بود",
    tunnelElevate: "برای حالت تانل، تأیید UAC را انجام دهید…",
    connectErr: "خطای اتصال",
    loginCanceled: "ورود لغو شد",
    noRegions: "لیست ریجن‌ها خالی است",
    settingsConn: "اتصال", settingsDns: "DNS", settingsAdvanced: "پیشرفته",
    settingsSplit: "Split Tunnel (بر اساس برنامه)",
    autoRecovery: "بازیابی خودکار",
    bypassLan: "دور زدن شبکه محلی",
    proxyOnly: "فقط پروکسی (بدون تانل سیستم)",
    mtu: "MTU تونل",
    httpVersion: "نسخه HTTP",
    utls: "اثر انگشت uTLS",
    tlsFragment: "TLS Fragment",
    customEdge: "Edge سرور سفارشی",
    dnsProvider: "سرویس DNS", customDoh: "آدرس DoH سفارشی",
    bootstrapDns: "DNS بوت‌استرپ", customBootstrapDoh: "DoH بوت‌استرپ سفارشی",
    ipMode: "حالت IP",
    socksPort: "پورت پروکسی محلی",
    socksBind: "آدرس شنیدن پروکسی",
    localProxyAuth: "احراز هویت پروکسی محلی",
    upstreamProxy: "پروکسی بالادستی",
    upstreamHost: "آدرس پروکسی بالادستی",
    splitMode: "حالت", splitExclude: "استثنا (بدون VPN)", splitInclude: "فقط این‌ها (با VPN)",
    pickProcesses: "انتخاب برنامه…",
    latencyProbe: "آدرس تست تأخیر",
    fragmentOff: "خاموش", fragmentRecord: "Record", fragmentPacket: "Packet", fragmentCombined: "ترکیبی",
    loading: "در حال بارگذاری…",
  },
  en: {
    appName: "FoxyVPN",
    loginSubtitle: "Sign in with your Firefox account to connect to the Mozilla VPN service",
    signIn: "Sign in with Firefox",
    loginProgress: "Completing sign-in… follow the browser window",
    modeTunnel: "VPN Tunnel",
    modeProxy: "Proxy only",
    systemProxy: "Apply to the Windows system proxy",
    navHome: "Home", navRegions: "Regions", navSettings: "Settings", navLogs: "Logs",
    region: "Region", exitIp: "Exit IP", latency: "Latency", speed: "Speed",
    dataUsed: "Session data", quota: "Monthly quota", realIp: "Your real IP",
    usage: "Monthly usage & quota", usedOf: "Used", leftLabel: "left",
    searchRegion: "Search country or city…",
    recommended: "Recommended",
    all: "All", copy: "Copy", clear: "Clear", signOut: "Sign out",
    save: "Save settings", saved: "Saved",
    disconnected: "Disconnected", connecting: "Connecting…", connected: "Connected",
    reconnecting: "Reconnecting…",
    proxyActive: "Proxy active",
    healthChecking: "Checking", healthHealthy: "Healthy", healthNoNetwork: "No network",
    healthUnreachable: "Unreachable", healthUnknown: "—",
    unlimited: "Unlimited",
    retry: "Retry", loadFail: "Failed to load the list",
    tunnelElevate: "Confirm the UAC prompt to enable tunnel mode…",
    connectErr: "Connection error",
    loginCanceled: "Sign-in canceled",
    noRegions: "No regions available",
    settingsConn: "Connection", settingsDns: "DNS", settingsAdvanced: "Advanced",
    settingsSplit: "Split Tunnel (per app)",
    autoRecovery: "Automatic recovery",
    bypassLan: "Bypass local network",
    proxyOnly: "Proxy-only mode (no system tunnel)",
    mtu: "Tunnel MTU",
    httpVersion: "HTTP version",
    utls: "uTLS fingerprint",
    tlsFragment: "TLS Fragment",
    customEdge: "Custom edge server",
    dnsProvider: "DNS provider", customDoh: "Custom DoH URL",
    bootstrapDns: "Bootstrap DNS", customBootstrapDoh: "Custom bootstrap DoH",
    ipMode: "IP mode",
    socksPort: "Local proxy port",
    socksBind: "Proxy listen address",
    localProxyAuth: "Proxy authentication",
    upstreamProxy: "Upstream proxy",
    upstreamHost: "Upstream proxy address",
    splitMode: "Mode", splitExclude: "Exclude (no VPN)", splitInclude: "Include only (VPN)",
    pickProcesses: "Pick programs…",
    latencyProbe: "Latency probe URL",
    fragmentOff: "Off", fragmentRecord: "Record", fragmentPacket: "Packet", fragmentCombined: "Combined",
    loading: "Loading…",
  },
};

const S = {
  lang: "fa",
  theme: "dark",
  mode: "tunnel",
  snapshot: null,
  auth: { loggedIn: false },
  account: null,
  regions: [],
  selectedRegion: null,
  settings: null,
  settingsCreds: null,
  logs: [],
  logsFilter: "",
  search: "",
};

const $ = (id) => document.getElementById(id);
const t = (k) => (I18N[S.lang] && I18N[S.lang][k]) || I18N.fa[k] || k;

function applyLang() {
  document.documentElement.lang = S.lang;
  document.documentElement.dir = S.lang === "fa" ? "rtl" : "ltr";
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    el.textContent = t(el.getAttribute("data-i18n"));
  });
  document.querySelectorAll("[data-i18n-ph]").forEach((el) => {
    el.placeholder = t(el.getAttribute("data-i18n-ph"));
  });
  $("btn-lang").textContent = S.lang === "fa" ? "EN" : "FA";
  $("btn-lang-login").textContent = S.lang === "fa" ? "EN" : "FA";
}

function toast(msg) {
  let el = $("toast");
  if (!el) {
    el = document.createElement("div");
    el.id = "toast";
    document.body.appendChild(el);
  }
  el.textContent = msg;
  el.classList.add("show");
  setTimeout(() => el.classList.remove("show"), 2600);
}

function fmtBytes(n) {
  if (n == null) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return v.toFixed(v >= 100 || i === 0 ? 0 : 1) + " " + units[i];
}
function fmtRate(n) {
  if (n == null) return "—";
  return fmtBytes(n) + "/s"; // 0 is a real value while connected
}
function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;",
  }[c]));
}

/* ================= views ================= */
function showView(name) {
  document.querySelectorAll(".nav-btn").forEach((b) =>
    b.classList.toggle("active", b.dataset.view === name));
  ["home", "regions", "settings", "logs"].forEach((v) => {
    $("view-" + v).classList.toggle("hidden", v !== name);
  });
  if (name === "logs") renderLogs();
  if (name === "settings") renderSettings();
  if (name === "regions") loadRegions();
}

/* ================= auth ================= */
function renderAuth() {
  $("view-login").classList.toggle("hidden", S.auth.loggedIn);
  $("view-main").classList.toggle("hidden", !S.auth.loggedIn);
}

/* ================= home ================= */
function renderHome() {
  const snap = S.snapshot;
  if (!snap) return;
  const ring = $("btn-connect");
  ring.classList.remove("connected", "connecting", "error");
  const dot = $("status-dot");
  dot.className = "status-dot";
  let status = t("disconnected");
  if (snap.state === "CONNECTED") {
    ring.classList.add("connected");
    dot.classList.add("dot-ok");
    status = snap.proxyOnly
      ? t("proxyActive") + " • " + (snap.socksEndpoint || "")
      : t("connected");
  } else if (snap.state === "CONNECTING") {
    ring.classList.add("connecting");
    dot.classList.add("dot-warn");
    status = snap.reconnecting ? t("reconnecting") : t("connecting");
  } else if (snap.lastError) {
    ring.classList.add("error");
    dot.classList.add("dot-err");
    status = t("disconnected");
  }
  $("home-status").textContent = status;
  const healthChip = $("home-health");
  if (snap.state === "CONNECTED") {
    const key = { CHECKING: "healthChecking", HEALTHY: "healthHealthy", NO_NETWORK: "healthNoNetwork", UNREACHABLE: "healthUnreachable" }[snap.health];
    healthChip.textContent = key ? t(key) : "";
    healthChip.className = "chip chip-health-" + (snap.health || "");
  } else {
    healthChip.textContent = "";
    healthChip.className = "chip";
  }
  const errEl = $("home-error");
  if (snap.state !== "CONNECTED" && snap.lastError) {
    errEl.textContent = snap.lastError;
    errEl.classList.remove("hidden");
  } else {
    errEl.classList.add("hidden");
  }
  $("home-exitip").textContent = snap.exitIp
    ? snap.exitIp + (snap.exitCountry ? " (" + snap.exitCountry + ")" : "")
    : "—";
  const pingText = snap.pingMs != null ? snap.pingMs + " ms" : "— ms";
  $("home-ping").textContent = pingText;
  $("home-ping2").textContent = snap.pingMs != null ? snap.pingMs + " ms" : "—";
  const connected = snap.state === "CONNECTED";
  $("home-speed").textContent = connected
    ? "↓ " + fmtRate(snap.rxRate) + " · ↑ " + fmtRate(snap.txRate)
    : "—";
  $("home-bytes").textContent = connected ? fmtBytes(snap.sessionBytes) : "—";

  // Usage & quota — always visible; merge the live snapshot with the
  // account fetch (Guardian) so values show before connecting too.
  // Values are wrapped in LTR spans so Persian labels read correctly.
  const acc = S.account || {};
  const remaining = snap.quotaRemaining != null ? snap.quotaRemaining : acc.quotaRemaining;
  const max = snap.quotaMax != null ? snap.quotaMax : acc.quotaMax;
  const unlimited = snap.unlimited || acc.unlimited;
  const fill = $("quota-fill");
  const ltr = (s) => "<span class='mono' dir='ltr'>" + s + "</span>";
  if (unlimited) {
    fill.style.width = "0%";
    fill.style.background = "var(--color-accent)";
    $("home-quota").textContent = t("unlimited");
  } else if (max != null && max > 0 && remaining != null) {
    const used = Math.max(0, max - remaining);
    const pct = Math.min(100, (used / max) * 100);
    fill.style.width = pct + "%";
    fill.style.background = pct > 90 ? "var(--color-destructive)" : "var(--color-accent)";
    $("home-quota").innerHTML =
      esc(t("usedOf")) + ": " + ltr(fmtBytes(used)) + " / " + ltr(fmtBytes(max)) +
      " · " + esc(t("leftLabel")) + ": " + ltr(fmtBytes(remaining)) + " " + ltr("(" + pct.toFixed(0) + "%)");
  } else if (remaining != null) {
    fill.style.width = "0%";
    fill.style.background = "var(--color-accent)";
    $("home-quota").innerHTML = esc(t("leftLabel")) + ": " + ltr(fmtBytes(remaining));
  } else {
    fill.style.width = "0%";
    $("home-quota").textContent = "—";
  }
  renderRegionCurrent();
}

function renderRegionCurrent() {
  const el = $("region-current");
  const snap = S.snapshot;
  const code = (snap && snap.regionCode) || (S.selectedRegion && S.selectedRegion.countryCode) || "";
  let label = "—";
  if (snap && (snap.state === "CONNECTED" || snap.state === "CONNECTING") && snap.region) {
    label = snap.regionCode === "REC" ? t("recommended") : snap.region;
  } else if (S.selectedRegion) {
    const r = S.selectedRegion;
    if (r.countryCode === "REC" || r.countryName === "Recommended") {
      // "Recommended" has no real city — don't repeat the label.
      label = t("recommended");
    } else {
      label = r.countryName || r.countryCode;
      const city = r.cityName && r.cityName !== r.countryName ? " • " + r.cityName : "";
      label += city;
    }
  }
  el.innerHTML = flagImg(code, "flag-img") + "<span>" + esc(label) + "</span>";
}

/* ================= regions ================= */
async function loadRegions() {
  const list = $("regions-list");
  const retry = $("btn-regions-retry");
  retry.classList.add("hidden");
  list.innerHTML = `<div class="muted" style="text-align:center;padding:24px">${t("loading")}</div>`;
  try {
    S.regions = (await App.GetRegions()) || [];
  } catch (e) {
    S.regions = [];
    list.innerHTML = `<div class="muted" style="text-align:center;padding:24px">${t("loadFail")}</div>`;
    retry.classList.remove("hidden");
  }
  try {
    S.selectedRegion = await App.GetSelectedRegion();
  } catch (e) { /* ignore */ }
  renderRegions();
  renderRegionCurrent();
}

function flagOf(code) {
  if (!code || code.length !== 2 || code === "REC") return "🌍";
  const A = 0x1f1e6;
  const c = code.toUpperCase();
  return String.fromCodePoint(A + c.charCodeAt(0) - 65, A + c.charCodeAt(1) - 65);
}

function flagSrc(code) {
  if (!code || code.length !== 2 || code === "REC") return "flags/rec.svg";
  return "flags/" + code.toLowerCase() + ".svg";
}
function flagImg(code, cls) {
  return `<img class="${cls || "flag"}" src="${flagSrc(code)}" alt="" loading="lazy" onerror="this.style.visibility='hidden'">`;
}
function localName(c) {
  if (c.code === "REC") return t("recommended");
  return c.name || c.code;
}

function renderRegions() {
  const list = $("regions-list");
  const q = S.search.trim().toLowerCase();
  const countries = S.regions.filter((c) => {
    if (!q) return true;
    if ((c.name || "").toLowerCase().includes(q) || (c.code || "").toLowerCase().includes(q)) return true;
    return (c.cities || []).some((ci) => (ci.name || "").toLowerCase().includes(q));
  });
  if (!countries.length) {
    list.innerHTML = `<div class="muted" style="text-align:center;padding:24px">${t("noRegions")}</div>`;
    return;
  }
  countries.sort((a, b) => (b.recommended ? 1 : 0) - (a.recommended ? 1 : 0) ||
    (a.name || "").localeCompare(b.name || ""));
  list.innerHTML = countries.map((c, idx) => {
    const cities = (c.cities || []).map((ci) => {
      const rawCity = String(ci.name || ci.code);
      const cityName = /^Recomended/i.test(rawCity) ? t("recommended") : rawCity;
      const selected = S.selectedRegion &&
        S.selectedRegion.countryCode === c.code &&
        (S.selectedRegion.cityCode === ci.code || !S.selectedRegion.cityCode);
      return `<button class="city-btn ${selected ? "selected" : ""}" data-country="${esc(c.code)}" data-city="${esc(ci.code)}">
        <span>${esc(cityName)}</span>
        <span class="city-count">${ci.count || 0} ${S.lang === "fa" ? "سرور" : "servers"}</span>
      </button>`;
    }).join("");
    return `<div class="country ${idx === 0 && c.recommended ? "open" : ""}" data-idx="${idx}">
      <button class="country-head" data-idx="${idx}">
        ${flagImg(c.code)}
        <span class="name">${esc(localName(c))}${c.recommended ? ` <span class="recommended-badge">${t("recommended")}</span>` : ""}</span>
        <svg class="chev" viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><path fill="currentColor" d="m9 6 6 6-6 6z"/></svg>
      </button>
      <div class="cities">${cities}</div>
    </div>`;
  }).join("");

  list.querySelectorAll(".country-head").forEach((btn) => {
    btn.addEventListener("click", () => {
      const el = btn.closest(".country");
      el.classList.toggle("open");
    });
  });
  list.querySelectorAll(".city-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const country = btn.dataset.country;
      const city = btn.dataset.city;
      try {
        await App.SelectRegion(country, city);
        S.selectedRegion = await App.GetSelectedRegion();
        renderRegions();
        renderRegionCurrent();
        toast(S.lang === "fa" ? "ریجن انتخاب شد" : "Region selected");
      } catch (e) {
        toast(String(e));
      }
    });
  });
}

/* ================= settings ================= */
function opt(value, options) {
  return options.map(([v, label]) =>
    `<option value="${esc(v)}" ${v === value ? "selected" : ""}>${esc(label)}</option>`).join("");
}

function renderSettings() {
  if (!S.settings) return;
  const d = S.settings;
  const c = S.settingsCreds || {};
  const sel = (id, opts) => opt(d[id] !== undefined ? d[id] : "", opts);
  $("settings-body").innerHTML = `
  <div class="settings-group">
    <h3>${t("settingsConn")}</h3>
    <div class="setting-row"><label>${t("proxyOnly")}</label>
      <span class="switch"><input type="checkbox" id="s-proxyOnly" ${d.proxyOnlyMode ? "checked" : ""}/><span class="track"></span></span></div>
    <div class="setting-row"><label>${t("systemProxy")}</label>
      <span class="switch"><input type="checkbox" id="s-systemProxy" ${d.systemProxy !== false ? "checked" : ""}/><span class="track"></span></span></div>
    <div class="setting-row"><label>${t("autoRecovery")}</label>
      <span class="switch"><input type="checkbox" id="s-recovery" ${d.automaticRecovery ? "checked" : ""}/><span class="track"></span></span></div>
    <div class="setting-row"><label>${t("bypassLan")}</label>
      <span class="switch"><input type="checkbox" id="s-bypassLan" ${d.bypassLocalNetwork ? "checked" : ""}/><span class="track"></span></span></div>
    <div class="setting-row"><label>${t("ipMode")}</label>
      <select id="s-ipMode">${sel("ipMode", [["dual_stack", "Dual Stack"], ["prefer_ipv4", "Prefer IPv4"], ["prefer_ipv6", "Prefer IPv6"], ["ipv4_only", "IPv4 only"], ["ipv6_only", "IPv6 only"]])}</select></div>
    <div class="setting-row"><label>${t("mtu")}</label>
      <input type="number" id="s-mtu" min="576" max="9000" value="${d.mtu}"/></div>
    <div class="setting-row"><label>${t("httpVersion")}</label>
      <select id="s-httpVersion">${sel("httpVersion", [["HTTP_1", "HTTP/1.1"], ["HTTP_2", "HTTP/2"], ["HTTP_3", "HTTP/3 (QUIC)"]])}</select></div>
    <div class="setting-row"><label>${t("utls")}</label>
      <select id="s-utls">${sel("utlsFingerprint", [["FIREFOX", "Firefox"], ["CHROME", "Chrome"], ["SAFARI", "Safari"], ["IOS", "iOS"], ["EDGE", "Edge"], ["RANDOMIZED", "Randomized"]])}</select></div>
    <div class="setting-row"><label>${t("tlsFragment")}</label>
      <select id="s-fragment">${sel("tlsFragmentMode", [["OFF", t("fragmentOff")], ["RECORD", t("fragmentRecord")], ["PACKET", t("fragmentPacket")], ["COMBINED", t("fragmentCombined")]])}</select></div>
    <div class="setting-row"><label>${t("customEdge")}</label>
      <input type="text" id="s-edge" dir="ltr" value="${esc(d.customEdgeAddress || "")}" placeholder="auto"/></div>
  </div>
  <div class="settings-group">
    <h3>${t("settingsDns")}</h3>
    <div class="setting-row"><label>${t("dnsProvider")}</label>
      <select id="s-dns">${sel("dnsProvider", [["DIRECT_SYSTEM", "System"], ["GOOGLE", "Google"], ["CLOUDFLARE", "Cloudflare"], ["QUAD9", "Quad9"], ["CUSTOM", "Custom DoH"]])}</select></div>
    <div class="setting-row"><label>${t("customDoh")}</label>
      <input type="text" id="s-customDoh" dir="ltr" value="${esc(d.customDohUrl || "")}" placeholder="https://…/dns-query"/></div>
    <div class="setting-row"><label>${t("bootstrapDns")}</label>
      <select id="s-bootstrap">${sel("bootstrapDnsProvider", [["DIRECT_SYSTEM", "System"], ["GOOGLE", "Google"], ["CLOUDFLARE", "Cloudflare"], ["QUAD9", "Quad9"], ["CUSTOM", "Custom DoH"]])}</select></div>
    <div class="setting-row"><label>${t("customBootstrapDoh")}</label>
      <input type="text" id="s-customBootstrap" dir="ltr" value="${esc(d.customBootstrapDohUrl || "")}"/></div>
  </div>
  <div class="settings-group">
    <h3>${t("settingsConn")}</h3>
    <div class="setting-row"><label>${t("socksPort")}</label>
      <input type="number" id="s-socksPort" min="1" max="65535" value="${d.socksPort}"/></div>
    <div class="setting-row"><label>${t("localProxyAuth")}</label>
      <span class="switch"><input type="checkbox" id="s-localAuth" ${d.localProxyAuthEnabled ? "checked" : ""}/><span class="track"></span></span></div>
    <div class="setting-row"><label>${t("latencyProbe")}</label>
      <input type="text" id="s-probe" dir="ltr" value="${esc(d.latencyProbeUrl || "")}"/></div>
    <div class="setting-row"><label>${t("upstreamProxy")}</label>
      <span class="switch"><input type="checkbox" id="s-upstreamEnabled" ${d.upstreamProxyEnabled ? "checked" : ""}/><span class="track"></span></span></div>
    <div class="setting-row"><label>${t("upstreamHost")}</label>
      <input type="text" id="s-upstreamHost" dir="ltr" value="${esc((c && c.upstreamProxyHost) || "")}" placeholder="host:port"/></div>
  </div>
  <div class="settings-group">
    <h3>${t("settingsSplit")}</h3>
    <div class="setting-row"><label>${t("splitMode")}</label>
      <select id="s-splitMode">${sel("splitTunnelMode", [["EXCLUDE", t("splitExclude")], ["INCLUDE", t("splitInclude")]])}</select></div>
    <div class="setting-row"><label>${t("pickProcesses")}</label>
      <button class="btn ghost small" id="s-pickProcesses">${(d.excludedProcesses || []).length + (d.includedProcesses || []).length}</button></div>
  </div>
  <div class="btn-save-wrap"><button id="btn-save-settings" class="btn primary">${t("save")}</button></div>`;

  $("btn-save-settings").addEventListener("click", saveSettings);
  $("s-pickProcesses").addEventListener("click", pickProcesses);
}

async function saveSettings() {
  const g = (id) => $(id);
  const d = JSON.parse(JSON.stringify(S.settings));
  d.proxyOnlyMode = g("s-proxyOnly").checked;
  d.systemProxy = g("s-systemProxy").checked;
  d.automaticRecovery = g("s-recovery").checked;
  d.bypassLocalNetwork = g("s-bypassLan").checked;
  d.ipMode = g("s-ipMode").value;
  d.mtu = parseInt(g("s-mtu").value, 10) || 1280;
  d.httpVersion = g("s-httpVersion").value;
  d.utlsFingerprint = g("s-utls").value;
  d.tlsFragmentMode = g("s-fragment").value;
  d.customEdgeAddress = g("s-edge").value.trim().toLowerCase();
  d.dnsProvider = g("s-dns").value;
  d.customDohUrl = g("s-customDoh").value.trim();
  d.bootstrapDnsProvider = g("s-bootstrap").value;
  d.customBootstrapDohUrl = g("s-customBootstrap").value.trim();
  d.socksPort = parseInt(g("s-socksPort").value, 10) || 1080;
  d.localProxyAuthEnabled = g("s-localAuth").checked;
  d.latencyProbeUrl = g("s-probe").value.trim();
  d.upstreamProxyEnabled = g("s-upstreamEnabled").checked;
  d.splitTunnelMode = g("s-splitMode").value;

  const c = S.settingsCreds || {};
  const payload = {
    settings: d,
    credentials: {
      localProxyUsername: c.localProxyUsername || "",
      upstreamProxyType: c.upstreamProxyType || "SOCKS5",
      upstreamProxyHost: g("s-upstreamHost").value.trim(),
      upstreamProxyPort: c.upstreamProxyPort || 1080,
      upstreamProxyUsername: c.upstreamProxyUsername || "",
    },
  };
  try {
    await App.SaveSettings(JSON.stringify(payload));
    S.settings = (await App.GetSettings()).settings;
    S.settingsCreds = (await App.GetSettings()).credentials;
    toast(t("saved"));
  } catch (e) {
    toast(String(e));
  }
}

async function pickProcesses() {
  const d = S.settings;
  const current = (d.splitTunnelMode === "INCLUDE" ? d.includedProcesses : d.excludedProcesses) || [];
  const all = (await App.GetRunningProcesses()) || [];
  const win = window.open("", "_blank", "width=420,height=600");
  if (!win) { toast("popup blocked"); return; }
  win.document.write(`<!DOCTYPE html><html dir="${S.lang === "fa" ? "rtl" : "ltr"}"><head><meta charset="utf-8"><title>processes</title>
  <style>body{font-family:system-ui;background:#0F172A;color:#fff;padding:12px}input{width:100%;padding:8px;border-radius:8px;border:1px solid #334155;background:#10192E;color:#fff;margin-bottom:8px}
  .p{display:block;padding:6px 10px;border-radius:8px;cursor:pointer}.p:hover{background:#1E3A5F}
  label{display:flex;gap:8px;align-items:center}button{margin-top:10px;padding:8px 18px;border-radius:10px;border:none;background:#22C55E;color:#04110a;font-weight:700;cursor:pointer}</style></head><body>
  <input id="q" placeholder="filter…"><div id="list" style="max-height:70vh;overflow:auto"></div>
  <button onclick="window.apply()">OK</button>
  <script>
  const ALL = ${JSON.stringify(all)};
  const CUR = ${JSON.stringify(current)};
  const sel = new Set(CUR);
  function draw(f){document.getElementById("list").innerHTML = ALL.filter(p=>!f||p.includes(f)).map(p=>
    '<label class="p"><input type="checkbox" '+(sel.has(p)?"checked":"")+' data-p="'+p+'">'+p+"</label>").join("");
    document.querySelectorAll("input[type=checkbox]").forEach(cb=>cb.addEventListener("change",()=>{cb.checked?sel.add(cb.dataset.p):sel.delete(cb.dataset.p)}));}
  document.getElementById("q").addEventListener("input",e=>draw(e.target.value.toLowerCase()));
  window.apply = function(){window.opener.postMessage({foxyProcesses:[...sel]}, "*");window.close();};
  draw("");
  <\/script></body></html>`);
  win.document.close();
  const handler = (ev) => {
    if (ev.data && ev.data.foxyProcesses) {
      if (d.splitTunnelMode === "INCLUDE") d.includedProcesses = ev.data.foxyProcesses;
      else d.excludedProcesses = ev.data.foxyProcesses;
      window.removeEventListener("message", handler);
      renderSettings();
    }
  };
  window.addEventListener("message", handler);
}

/* ================= logs ================= */
function renderLogs() {
  const list = $("logs-list");
  const entries = S.logs.filter((e) => !S.logsFilter || e.level === S.logsFilter);
  list.innerHTML = entries.map((e) => {
    const time = (e.time || "").replace("T", " ").replace("Z", "").slice(0, 19);
    return `<div class="log-line"><span class="lvl-${esc(e.level)}">[${esc(time)}] ${esc(e.level)}</span> ${esc(e.tag)} — ${esc(e.message)}</div>`;
  }).join("") || `<div class="muted" style="text-align:center;padding:20px">—</div>`;
  list.scrollTop = list.scrollHeight;
}

/* ================= events wiring ================= */
function wire() {
  document.querySelectorAll(".nav-btn").forEach((b) =>
    b.addEventListener("click", () => showView(b.dataset.view)));

  $("btn-login").addEventListener("click", async () => {
    $("login-error").classList.add("hidden");
    $("login-progress").classList.remove("hidden");
    App.StartLogin();
  });
  $("btn-lang").addEventListener("click", () => { S.lang = S.lang === "fa" ? "en" : "fa"; applyLang(); });
  $("btn-lang-login").addEventListener("click", () => { S.lang = S.lang === "fa" ? "en" : "fa"; applyLang(); });
  $("btn-theme").addEventListener("click", () => {
    S.theme = S.theme === "dark" ? "light" : "dark";
    document.body.dataset.theme = S.theme;
  });
  $("mode-tunnel").addEventListener("click", () => setMode("tunnel"));
  $("mode-proxy").addEventListener("click", () => setMode("proxy"));
  $("btn-connect").addEventListener("click", onConnect);
  $("btn-refresh-realip").addEventListener("click", () => App.RefreshRealIP());
  $("region-card").addEventListener("click", () => showView("regions"));
  $("btn-regions-retry").addEventListener("click", () => loadRegions());
  $("btn-refresh-quota").addEventListener("click", async (e) => {
    e.stopPropagation();
    try {
      await App.RefreshAccount();
    } catch (err) {
      toast(String(err));
    }
  });
  $("region-current").addEventListener("click", () => showView("regions"));
  $("region-search").addEventListener("input", (e) => {
    S.search = e.target.value;
    renderRegions();
  });
  $("logs-filter").addEventListener("change", (e) => { S.logsFilter = e.target.value; renderLogs(); });
  $("btn-clear-logs").addEventListener("click", () => App.ClearLogs());
  $("btn-copy-logs").addEventListener("click", async () => {
    const text = S.logs.map((e) => `[${e.time}] ${e.level} ${e.tag}: ${e.message}`).join("\n");
    try { await navigator.clipboard.writeText(text); toast(t("copy") + " ✓"); } catch (e) { /* noop */ }
  });
  $("btn-signout").addEventListener("click", async () => {
    await App.SignOut();
    S.auth = await App.GetAuthStatus();
    renderAuth();
  });

  if (runtime && runtime.EventsOn) {
    runtime.EventsOn("snapshot", (snap) => { S.snapshot = snap; renderHome(); });
    runtime.EventsOn("auth:changed", (st) => { S.auth = st; renderAuth(); });
    runtime.EventsOn("login:success", () => {
      $("login-progress").classList.add("hidden");
      toast(S.lang === "fa" ? "ورود موفق" : "Signed in");
    });
    runtime.EventsOn("login:error", (msg) => {
      $("login-progress").classList.add("hidden");
      const el = $("login-error");
      el.textContent = String(msg);
      el.classList.remove("hidden");
    });
    runtime.EventsOn("login:canceled", () => {
      $("login-progress").classList.add("hidden");
      toast(t("loginCanceled"));
    });
    runtime.EventsOn("region:changed", (r) => { S.selectedRegion = r; renderRegionCurrent(); });
    runtime.EventsOn("account:changed", (acc) => { S.account = acc; renderHome(); });
    runtime.EventsOn("regions:loaded", (regions) => {
      S.regions = regions || [];
      if (!$("view-regions").classList.contains("hidden")) renderRegions();
    });
    runtime.EventsOn("realip:changed", (v) => {
      $("home-realip").textContent = v.ip ? v.ip + (v.country ? " (" + v.country + ")" : "") : "—";
    });
    runtime.EventsOn("logs:cleared", () => { S.logs = []; renderLogs(); });
  }
}

function setMode(mode) {
  S.mode = mode;
  const sw = document.querySelector(".mode-switch");
  sw.classList.toggle("proxy", mode === "proxy");
  $("mode-tunnel").classList.toggle("active", mode === "tunnel");
  $("mode-proxy").classList.toggle("active", mode === "proxy");
}

async function onConnect() {
  const snap = S.snapshot;
  if (snap && (snap.state === "CONNECTED" || snap.state === "CONNECTING")) {
    App.Disconnect();
    return;
  }
  const result = await App.Connect(S.mode);
  if (result === "elevate") {
    toast(t("tunnelElevate"));
  } else if (result && result !== "") {
    toast(t("connectErr") + ": " + result);
  }
}

/* ================= init ================= */
async function init() {
  wire();
  try {
    S.settingsPayload = await App.GetSettings();
    S.settings = S.settingsPayload.settings;
    S.settingsCreds = S.settingsPayload.credentials;
    S.lang = S.settings.language === "en" ? "en" : "fa";
    S.theme = S.settings.themeMode === "light" ? "light" : "dark";
    document.body.dataset.theme = S.theme;
  } catch (e) { /* defaults */ }
  applyLang();
  $("app-version").textContent = "v" + (await App.GetVersion());
  try {
    S.auth = await App.GetAuthStatus();
  } catch (e) { S.auth = { loggedIn: false }; }
  renderAuth();
  if (S.auth.loggedIn) {
    renderHome();
    loadRegions();
    App.RefreshRealIP();
    App.GetRealIP().then((v) => {
      $("home-realip").textContent = v.ip ? v.ip + (v.country ? " (" + v.country + ")" : "") : "—";
    });
  }
  App.GetSnapshot().then((snap) => { S.snapshot = snap; renderHome(); });
  // periodic log refresh while logs view is open
  setInterval(async () => {
    if (!$("view-logs").classList.contains("hidden")) {
      S.logs = (await App.GetLogs()) || [];
      renderLogs();
    }
  }, 1500);
}

init();

// tailscale-underlying.js — v3.6
// 内网穿透（Tailscale）底层出口自动切换
//
// 核心规则：Wi-Fi 无 IPv6（含一切失败情形）→ CELLULAR-ONLY，必有判定、必须对齐；
//          已在目标策略时按 notifyOnNoop 决定是否发通知（默认静默，不刷屏）。
//
// 判定链（不依赖 HTTP 探测，默认路径 0 外部请求）：
//   纯蜂窝            → DIRECT      Tailscale 直接走蜂窝，可打洞
//   SSID 蜂窝名单命中  → CELLULAR-ONLY
//   SSID 直连名单命中  → DIRECT
//   全局 IPv6 有效     → DIRECT      须连续两拍读到（见下方「快照」说明），过滤非全局地址
//   settle 窗口到点仍无 → CELLULAR-ONLY（切蜂窝）
//
// v3.6 变更（均为修 bug，不改动 v3.5 的判定规则）：
//   ① 竞态不再污染状态：旧运行被取代时 giveUp() 不再写 state（v3.5 会把旧判定覆盖到
//      新运行已写好的状态上）；apply 入口、decide 回调、探测回调、每个轮询拍都加 staleRun 检查。
//   ② lastRun 改为单调递增令牌（同一毫秒内连发事件也能分出新旧）。
//   ③ $network 快照事实写进注释：真机验证为普通数据属性、无 getter、身份固定，
//      HTTP API 也无实时网络端点。轮询因此主要是「settle 窗口 + 让位给更新的事件运行」，
//      真正的防陈旧读数靠事件链 + ① 的竞态防护；窗口到点强制收口，杜绝无限轮询。
//   ④ IPv6 只认全局单播 2000::/3（v3.5 仅过滤 fe80::，ULA fc00::/fd00::、::1 会误判）。
//   ⑤ 清错误写空串（不再写空格）；httpGet 完成后清掉多余定时器。
//
// 历史教训（v3.2–v3.5，勿回退）：
//   HTTP 探测不能作为判定依据——$httpClient 走规则栈（经代理测到的是出口 v6），
//   且部分 DoH 对 AAAA-only 域名（6.ipw.cn 等）返回空应答，探测死于 DNS。
//   探测现已降级为纯诊断（probeDetail=true 才运行，结果只写面板）。
//
// 依赖：策略组「内网底层」选项 DIRECT 与 CELLULAR-ONLY；
//   CELLULAR-ONLY 须为 direct, interface=pdp_ip0, dns-follow-interface=true（已实测验证），
//   否则切了也等于没切。名字可用 directPolicy / cellularPolicy 参数覆盖。
//
// 用法：模块（推荐，见同目录 Tailscale-Underlying.sgmodule），面板以 mode=panel 复用本文件；
//   或直接写 [Script]：
//   Tailscale底层切换 = type=event, event-name=network-changed, script-path=tailscale-underlying.js
//   Tailscale底层启动 = type=event, event-name=engine-started, script-path=tailscale-underlying.js
//   远程引用（本文件发布地址）：
//   https://raw.githubusercontent.com/lisongyan7050/sgmodule/main/tailscale-underlying.js
//   https://cdn.jsdelivr.net/gh/lisongyan7050/sgmodule@main/tailscale-underlying.js
//
// argument：JSON（{"directSSID":["家WiFi"]}，配置文件里整段加双引号）或 KV
//   （directSSID=家|另&cellularSSID=公司，& 分对、| 分多值、- 表示不启用）。
//   解析失败 / 未知键写入 ts.underlay.argError，不静默。
//
// 切换后若 Tailscale 会话未重建，开关一次 Wi-Fi 即可。

const DEFAULTS = {
  mode: "",                       // 模块面板调用时传 mode=panel
  group: "内网底层",
  title: "Tailscale 底层",
  cellularSSID: [],               // 命中走蜂窝（屏蔽 UDP 打洞的 Wi-Fi）
  directSSID: [],                 // 命中走直连，跳过判定
  directPolicy: "DIRECT",         // 策略组里「直连」选项的名字（须与组内选项完全一致）
  cellularPolicy: "CELLULAR-ONLY",// 策略组里「蜂窝」选项的名字（须与组内选项完全一致）
  v6RecheckMs: 1200,              // settle 窗口（兼 v6 连续两拍的观察窗口）
  v6RecheckPollMs: 250,           // 窗口内的观察间隔
  probeDetail: false,             // true：附带 HTTP 双探测诊断（只写入面板，不影响判定）
  // 注意：纯 IPv6-only 域名（6.ipw.cn / v6.ident.me）在部分 DoH 下返回空应答，
  // 探测会死于 DNS——又一个不能让判定依赖探测的理由。诊断域名选可解析的：
  probeURL: "http://ipv6.icanhazip.com",   // 以下仅在 probeDetail=true 时使用
  probeURL4: "http://ipv4.icanhazip.com",
  probeCacheSec: 300,
  probeFailCacheSec: 60,
  probeTimeoutMs: 2500,
  debounceMs: 3000,
  notifyOnNoop: false,
  scriptTimeoutMs: 8000          // 模块的 timeout 必须 >= 此值（见 sgmodule 的 timeout=10）
};

const K = {
  state: "ts.underlay.state",
  probe: "ts.underlay.probe",
  lastRun: "ts.underlay.lastRun",
  argError: "ts.underlay.argError",
  error: "ts.underlay.error"
};

// 探测缓存格式版本：记录里的版本号与此不符即视为无缓存（改探测逻辑后自动重探）
const PROBE_VER = 3;

// ---------- 基础设施 ----------

let finished = false;
let failSafe = null;

function finish(payload) {
  if (finished) return;
  finished = true;
  if (failSafe) clearTimeout(failSafe);
  if (payload) $done(payload);
  else $done();
}

function store(key, value) {
  $persistentStore.write(String(value), key);
}

function load(key, fallback) {
  const v = $persistentStore.read(key);
  return v === null || v === undefined || v === "" ? fallback : v;
}

// 状态单键 JSON；写入时白名单重建，旧版本遗留字段自动清除
const STATE_FIELDS = ["target", "current", "reason", "tag", "detail", "ts"];
function readState() {
  const raw = load(K.state, "");
  if (raw) {
    try {
      const v = JSON.parse(raw);
      if (v && typeof v === "object") return v;
    } catch (e) { }
  }
  return null;
}

function saveState(st) {
  const clean = {};
  STATE_FIELDS.forEach(function (k) { if (st[k] !== undefined && st[k] !== "") clean[k] = st[k]; });
  try { store(K.state, JSON.stringify(clean)); } catch (e) { }
}

// 回读当前组选择
function apiGetSelect(cb) {
  $httpAPI("GET", "v1/policy_groups/select?group_name=" + encodeURIComponent(CFG.group),
    null, function (res) { cb((res && res.policy) ? res.policy : ""); });
}

// ---------- 参数解析 ----------

// 优先 JSON，退路 KV（& 分对、| 分多值、布尔/数字自动转型）；纯函数不写 store
function parseArgument(raw) {
  const r = { value: null, err: "" };
  if (raw === null || raw === undefined) return r;
  let s = String(raw).trim();
  if (!s) return r;
  // 剥外层引号，还原 \"（从配置文件连带引号复制过来的情况）
  const q = s[0];
  if ((q === '"' || q === "'") && s[s.length - 1] === q && s.length > 1) {
    s = s.slice(1, -1).trim().replace(/\\"/g, '"');
  }
  try {
    const v = JSON.parse(s);
    if (v && typeof v === "object") return { value: v, err: "" };
    r.err = "内容不是对象";
  } catch (e) {
    r.err = e && e.message ? e.message : String(e);
  }
  const out = {};
  let hit = 0;
  s.split("&").forEach(function (pair) {
    const i = pair.indexOf("=");
    if (i <= 0) return;
    const k = pair.slice(0, i).trim();
    const v = pair.slice(i + 1).trim();
    if (!k) return;
    hit++;
    if (v === "true" || v === "false") out[k] = v === "true";
    else if (/^-?\d+(\.\d+)?$/.test(v)) out[k] = Number(v);
    else if (v.indexOf("|") >= 0) out[k] = v.split("|").map(function (x) { return x.trim(); }).filter(Boolean);
    else out[k] = v;
  });
  if (hit > 0) return { value: out, err: "" };
  return r;
}

let CFG = Object.assign({}, DEFAULTS);
const PARSED = parseArgument(typeof $argument !== "undefined" ? $argument : null);
const isPanel = !!(PARSED.value && String(PARSED.value.mode) === "panel");
if (PARSED.err) {
  // 解析失败时无从判断模式，一律记录（不能让脚本挂掉，按默认值跑）
  store(K.argError, "argument 解析失败：" + PARSED.err);
} else if (PARSED.value) {
  const unknown = [];
  Object.keys(PARSED.value).forEach(function (k) {
    if (k in DEFAULTS) CFG[k] = PARSED.value[k];
    else unknown.push(k);
  });
  // 面板对 store 只读，argError 反映的应是事件脚本参数的问题
  if (!isPanel) store(K.argError, unknown.length ? "未知参数（已忽略）: " + unknown.join(", ") : "");
}

// 归一化：- / 空串视为空数组，| 分隔多值
function toList(v) {
  if (!Array.isArray(v)) v = String(v === null || v === undefined ? "" : v).split("|");
  return v.map(String).map(function (s) { return s.trim(); })
    .filter(function (s) { return s && s !== "-"; });
}

CFG.cellularSSID = toList(CFG.cellularSSID);
CFG.directSSID = toList(CFG.directSSID);
CFG.notifyOnNoop = CFG.notifyOnNoop === true || CFG.notifyOnNoop === "true";
CFG.probeDetail = CFG.probeDetail === true || CFG.probeDetail === "true";
["debounceMs", "probeCacheSec", "probeFailCacheSec", "probeTimeoutMs", "scriptTimeoutMs", "v6RecheckMs", "v6RecheckPollMs"].forEach(function (k) {
  const n = Number(CFG[k]);
  CFG[k] = isFinite(n) && n > 0 ? n : DEFAULTS[k];
});
if (!CFG.group || CFG.group === "-") CFG.group = DEFAULTS.group;
if (!CFG.title) CFG.title = DEFAULTS.title;
if (!CFG.directPolicy || CFG.directPolicy === "-") CFG.directPolicy = DEFAULTS.directPolicy;
if (!CFG.cellularPolicy || CFG.cellularPolicy === "-") CFG.cellularPolicy = DEFAULTS.cellularPolicy;
if (!CFG.probeURL || CFG.probeURL === "-") CFG.probeURL = DEFAULTS.probeURL;
if (!CFG.probeURL4 || CFG.probeURL4 === "-") CFG.probeURL4 = DEFAULTS.probeURL4;

// ---------- 网络判定（事件与面板共用，保证口径一致） ----------

// 只认全局单播 2000::/3：fe80:: 链路本地、fc00::/fd00:: ULA、::1 回环都上不了公网
const GLOBAL_V6_RE = /^[23][0-9a-f]{0,3}:/i;

function netInfo() {
  const net = $network || {};
  const ssid = (net.wifi && net.wifi.ssid) ? net.wifi.ssid : "";
  const primary = net.primaryInterface || "";
  const v4Addr = (net.v4 && net.v4.primaryAddress) ? net.v4.primaryAddress : "";
  const v6Raw = (net.v6 && net.v6.primaryAddress) ? net.v6.primaryAddress : "";
  const v6Addr = GLOBAL_V6_RE.test(v6Raw) ? v6Raw : "";
  // include-all-networks=false 时非主接口的 Wi-Fi 可能读不到 SSID，用主接口名交叉确认
  const onWifi = ssid !== "" || /^en\d+$/.test(primary);
  const fp = ssid ? "w:" + ssid : (onWifi ? "i:" + primary : "cell");
  const cell = net["cellular-data"] || {};
  return {
    ssid: ssid, primary: primary, onWifi: onWifi,
    v4Addr: v4Addr, v6Addr: v6Addr, v6Raw: v6Raw,
    radio: cell.radio || "", carrier: cell.carrier || "", fp: fp
  };
}

// ---------- HTTP 探测（仅诊断，不参与判定；probeDetail=true 时才跑） ----------

// 只认纯 IP 字面量，HTML 错误页 / JSON 报错一律不算数
const IPV6_RE = /^[0-9a-f]{0,4}(:[0-9a-f]{0,4}){2,7}$/i;
const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;

function httpGet(url, cb) {
  let settled = false;
  let timer = null;
  // httpClient 的 timeout 单位是秒，按配置向上取整，不硬编码
  $httpClient.get({ url: url, timeout: Math.max(1, Math.ceil(CFG.probeTimeoutMs / 1000)) },
    function (error, response, data) {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      cb({
        error: error ? String((error && error.message) ? error.message : error).slice(0, 60) : "",
        status: response ? response.status : 0,
        body: typeof data === "string" ? data.trim().slice(0, 40) : ""
      });
    });
  timer = setTimeout(function () {
    if (!settled) { settled = true; cb({ error: "timeout", status: 0, body: "" }); }
  }, CFG.probeTimeoutMs);
}

// v6/v4 双探测并行，返回 (结果, 明细)。明细直接展示在面板，便于排查路由/DNS 问题
function probeIPv6(cb) {
  let r6, r4, done = false;
  function fmt(r, re) {
    if (r.error) return "✗" + r.error;
    if (r.status !== 200) return "✗HTTP" + r.status;
    return re.test(r.body) ? "✓" + r.body : "✗非IP(" + r.body + ")";
  }
  function settle() {
    if (done || r6 === undefined || r4 === undefined) return;
    done = true;
    const detail = "v6 " + fmt(r6, IPV6_RE) + " · v4 " + fmt(r4, IPV4_RE);
    const v6ok = !r6.error && r6.status === 200 && IPV6_RE.test(r6.body);
    const v4ok = !r4.error && r4.status === 200 && IPV4_RE.test(r4.body);
    if (v6ok) return cb("v6", detail);
    if (v4ok) return cb("nov6", detail);
    cb("fail", detail);
  }
  httpGet(CFG.probeURL, function (r) { r6 = r; settle(); });
  httpGet(CFG.probeURL4, function (r) { r4 = r; settle(); });
}

// 缓存「版本|指纹|时间戳|结果」：换网必重探；fail 只挡 probeFailCacheSec
function probeWithCache(fp, cb) {
  const p = load(K.probe, "").split("|");
  if (p.length === 4 && p[0] === String(PROBE_VER) && p[1] === fp) {
    const age = Date.now() - Number(p[2]);
    if (age >= 0) {
      if (p[3] === "fail" && age < CFG.probeFailCacheSec * 1000) {
        return cb("fail", "探测失败（" + Math.round(age / 1000) + "s 前，短缓存）");
      }
      if (p[3] !== "fail" && age < CFG.probeCacheSec * 1000) {
        return cb(p[3], "缓存" + (p[3] === "v6" ? "有" : "无") + " IPv6（" + Math.round(age / 1000) + "s 前）");
      }
    }
  }
  probeIPv6(function (r, detail) {
    store(K.probe, PROBE_VER + "|" + fp + "|" + Date.now() + "|" + r);
    cb(r, detail);
  });
}

// ---------- 决策与执行 ----------

// 本运行是否已被更新的一次运行取代（换网连发事件时的竞态防护）
function staleRun(started) {
  const v = Number(load(K.lastRun, "0").split("|")[0]);
  return isFinite(v) && v > started;
}

// cb(target, reason, tag, detail)；target 恒非空——不存在「静默保持」路径。
// 注意：$network 是脚本启动时的快照（真机验证：普通数据属性、无 getter、身份固定），
// 且 HTTP API 无实时网络端点，所以同一运行内反复读拿到的是同一份数据。
// 这里的窗口主要作用是：给随后到达的 network-changed 事件一次覆盖机会，
// 由 staleRun 让旧判定让位；万一 Surge 将来改为实时值，「连续两拍」自然生效。
function decide(info, cb, started) {
  if (!info.onWifi)
    return cb(CFG.directPolicy, "纯蜂窝：Tailscale 直接走蜂窝，可打洞", "蜂窝直连", "");
  if (info.ssid && CFG.cellularSSID.indexOf(info.ssid) >= 0)
    return cb(CFG.cellularPolicy, "SSID「" + info.ssid + "」在蜂窝名单内", "蜂窝名单", "");
  if (info.ssid && CFG.directSSID.indexOf(info.ssid) >= 0)
    return cb(CFG.directPolicy, "SSID「" + info.ssid + "」在直连名单内", "直连名单", "");

  const deadline = Date.now() + CFG.v6RecheckMs;
  let confirmed = "";
  (function poll() {
    // 已被更新的运行取代：立刻收手，不再耗定时器，也不写任何状态
    if (staleRun(started)) return finish();
    const read = netInfo();
    const v6 = read.v6Addr || "";
    if (v6 && confirmed) {
      return cb(CFG.directPolicy, "Wi-Fi 连续两拍读到 IPv6：" + v6, "IPv6 直连·确认", "");
    }
    confirmed = v6;

    // 到点强制收口：以最后一拍为准，不允许无限轮询
    if (Date.now() >= deadline) {
      if (v6) {
        return cb(CFG.directPolicy, "Wi-Fi 窗口末拍读到 IPv6：" + v6, "IPv6 直连·末拍", "");
      }
      const reason0 = "Wi-Fi「" + (read.ssid || info.ssid || "?") + "」无全局 IPv6（" +
        CFG.v6RecheckMs + "ms 窗口确认），DERP 走蜂窝";
      if (!CFG.probeDetail) {
        return cb(CFG.cellularPolicy, reason0, "Wi-Fi 无 IPv6", "");
      }
      // 探测仅作诊断，不参与判定
      probeWithCache(read.fp, function (res, detail) {
        if (staleRun(started)) return finish();
        let extra = "";
        if (res === "v6") extra = "；探测却返回 v6，疑经代理出口（建议为探测域名配 DIRECT 规则）";
        else if (res === "fail") extra = "；探测亦失败（DNS/网络/规则拦截）";
        else extra = "；探测确认无 IPv6";
        cb(CFG.cellularPolicy, reason0 + extra, "Wi-Fi 无 IPv6", detail);
      });
      return;
    }
    setTimeout(poll, CFG.v6RecheckPollMs);
  })();
}

function apply(target, reason, tag, detail, started) {
  // 入口先让位：v3.5 在这里无条件 saveState，会把旧判定盖到新运行已写好的状态上
  if (staleRun(started)) return finish();

  const st = {
    target: target,
    reason: reason,
    tag: tag,
    detail: detail || "",
    ts: Date.now()
  };
  saveState(st);

  apiGetSelect(function (current) {
    if (staleRun(started)) return finish();
    st.current = current || "?";
    saveState(st);
    if (current === target) {
      if (CFG.notifyOnNoop) $notification.post(CFG.title, "保持 " + target, reason);
      return finish();
    }
    $httpAPI("POST", "v1/policy_groups/select",
      { group_name: CFG.group, policy: target },
      function () {
        if (staleRun(started)) return finish();
        apiGetSelect(function (now) {
          if (staleRun(started)) return finish();
          st.current = now || "?";
          saveState(st);
          const ok = now === target;
          $notification.post(
            ok ? CFG.title : CFG.title + "：切换未生效",
            ok ? (current || "未知") + " → " + target : "目标 " + target + "，当前仍为 " + (now || "未知"),
            ok ? reason : reason + "\n请检查策略组「" + CFG.group + "」里选项名是否恰为 " + target +
              "（可用 directPolicy / cellularPolicy 参数改），或 HTTP API 是否被禁用",
            { sound: true }
          );
          finish();
        });
      });
  });
}

// ---------- 面板 ----------

function relTime(ms) {
  const s = Math.floor((Date.now() - ms) / 1000);
  if (!isFinite(s) || s < 0) return "";
  if (s < 60) return "刚刚";
  if (s < 3600) return Math.floor(s / 60) + " 分钟前";
  if (s < 86400) return Math.floor(s / 3600) + " 小时前";
  return Math.floor(s / 86400) + " 天前";
}

function fmtClock(ms) {
  try {
    const d = new Date(ms);
    return ("0" + d.getHours()).slice(-2) + ":" + ("0" + d.getMinutes()).slice(-2);
  } catch (e) { return ""; }
}

// 网络实况区块
function netLines() {
  try {
    const i = netInfo();
    let head = i.ssid ? "📶 Wi-Fi「" + i.ssid + "」"
      : (i.onWifi ? "📶 Wi-Fi（SSID 未读到 · " + (i.primary || "en?") + "）" : "📶 未连 Wi-Fi");
    if (i.v4Addr) head += " · " + i.v4Addr;
    let cellLine = "📡 蜂窝";
    if (i.radio) cellLine += " " + i.radio;
    if (i.carrier) cellLine += " · " + i.carrier;
    const v6line = i.v6Addr
      ? "IPv6 " + i.v6Addr
      : (i.v6Raw ? "IPv6 " + i.v6Raw + "（非全局地址，不算）" : "无 IPv6" + (i.v4Addr ? " · IPv4 单栈" : ""));
    return [head, "　　" + v6line, cellLine];
  } catch (e) {
    return [];
  }
}

// 实时网络判定：按当前网络即时推一个应有的目标（面板对照用，无轮询/无延迟）
function liveVerdict() {
  try {
    const i = netInfo();
    if (!i.onWifi) return { t: CFG.directPolicy, label: "👁 纯蜂窝 → 直连打洞" };
    if (i.ssid && CFG.cellularSSID.indexOf(i.ssid) >= 0)
      return { t: CFG.cellularPolicy, label: "👁 SSID「" + i.ssid + "」蜂窝名单 → 蜂窝" };
    if (i.ssid && CFG.directSSID.indexOf(i.ssid) >= 0)
      return { t: CFG.directPolicy, label: "👁 SSID「" + i.ssid + "」直连名单 → 直连" };
    if (i.v6Addr) return { t: CFG.directPolicy, label: "👁 Wi-Fi 有 IPv6 → 直连" };
    return { t: CFG.cellularPolicy, label: "👁 Wi-Fi 无 IPv6 → 蜂窝" };
  } catch (e) {
    return null;
  }
}

function runPanel() {
  const st = readState() || {};
  const target = st.target || "";
  const tag = st.tag || "";
  const reason = st.reason || "";
  const detail = st.detail || "";
  const epoch = Number(st.ts || 0);
  const argErr = load(K.argError, "");
  const lastErr = (load(K.error, "") || "").trim();

  let settled = false;
  function render(cur) {
    if (settled) return;
    settled = true;
    if (failSafe) clearTimeout(failSafe);

    const now = cur || st.current || "";
    const v = liveVerdict();
    const L = [];

    // ① 策略组状态
    L.push(now
      ? "组 ▸ " + now + (target ? (now === target ? "  ✓" : "  ⚠️ 应为 " + target) : "  · 目标未记录")
      : (target ? "组读取失败  ⚠️ 应为 " + target : "策略组读取失败"));

    // ② 实时网络判定（与组状态对照）
    if (v) L.push(v.label + (now && v.t !== now ? "（组未跟上，等待事件触发）" : ""));

    // ③ 网络与蜂窝实况
    netLines().forEach(function (l) { L.push(l); });

    // ④ 上次判定详情
    if (!target && !reason) {
      L.push("事件脚本尚未执行过");
    } else {
      L.push("────────────");
      if (tag) L.push("🏷 " + tag);
      if (reason) L.push("📝 " + reason);
      if (epoch) L.push("🕒 " + relTime(epoch) + " · " + fmtClock(epoch));
      if (detail) L.push("🔬 " + detail);
    }

    // ⑤ 错误
    if (argErr) L.push("⚠️ " + argErr);
    if (lastErr) L.push("⚠️ 上次错误: " + lastErr);

    const groupBehind = !!(v && now && v.t !== now);
    const mismatch = !!(now && target && now !== target);
    const warn = mismatch || groupBehind;
    finish({
      title: CFG.title,
      content: L.join("\n"),
      icon: warn ? "exclamationmark.triangle.fill" : (target ? "network" : "clock.badge.questionmark"),
      "icon-color": warn ? "#FF9F0A" : (target ? "#30D158" : "#8E8E93")
    });
  }

  failSafe = setTimeout(function () { render(""); }, 2500);
  apiGetSelect(function (cur) { render(cur); });
}

// ---------- 入口 ----------

(function main() {
  try {
    if (isPanel) return runPanel();

    failSafe = setTimeout(function () {
      store(K.error, "脚本超时（" + CFG.scriptTimeoutMs + "ms）未完成，判定中断");
      finish();
    }, CFG.scriptTimeoutMs);

    // 指纹防抖：只吞同一网络的重复触发（切策略导致的自触发），换网立即执行
    const info = netInfo();
    const p = load(K.lastRun, "").split("|");
    const last = Number(p[0]) || 0;
    if (Date.now() - last < CFG.debounceMs && p[1] === info.fp) return finish();

    // 单调递增令牌：同一毫秒内连发事件也能分出新旧
    const started = Math.max(Date.now(), last + 1);
    store(K.lastRun, started + "|" + info.fp);
    store(K.error, ""); // 新一轮开始，清除旧错误（本轮再失败会重新写入）

    decide(info, function (target, reason, tag, detail) {
      if (staleRun(started)) return finish();
      apply(target, reason, tag, detail, started);
    }, started);
  } catch (e) {
    store(K.error, String(e && e.message ? e.message : e));
    finish();
  }
})();

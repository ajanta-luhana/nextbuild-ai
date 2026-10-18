/* NextBuild AI console. Plain JS, no build step. All dynamic content is inserted with textContent
   (never innerHTML) so model output and user input cannot inject markup. */
"use strict";
const API = "/api/v1";
const $ = (s, el = document) => el.querySelector(s);
let csrf = "", me = null, stream = null, poller = null;

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "text") el.textContent = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return el;
}
// DOM replaceChildren() would render a null child as the text "null"; drop empty children like h() does.
const _rc = Element.prototype.replaceChildren;
Element.prototype.replaceChildren = function (...kids) { return _rc.apply(this, kids.flat().filter((k) => k != null && k !== false)); };
const fmtTime = (s) => (s ? new Date(s).toLocaleTimeString() : "");
const fmtDate = (s) => (s ? new Date(s).toLocaleString() : "");

async function api(method, path, body, headers) {
  const opts = { method, headers: { ...(headers || {}) }, credentials: "same-origin" };
  if (method !== "GET") opts.headers["X-CSRF-Token"] = csrf;
  if (body !== undefined) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
  const res = await fetch(API + path, opts);
  let data = null;
  try { data = await res.json(); } catch (_) { /* empty body */ }
  if (!res.ok) {
    if (res.status === 401 && !path.startsWith("/auth/login") && !path.startsWith("/auth/register") && !path.startsWith("/auth/password")) { me = null; showAuth(); }
    const e = new Error((data && data.error && data.error.message) || res.statusText);
    e.status = res.status; e.details = (data && data.error && data.error.details) || [];
    throw e;
  }
  return data;
}
function toast(msg, bad) {
  const t = h("div", { class: "toast" + (bad ? " bad" : "") }, msg);
  $("#toasts").append(t);
  setTimeout(() => t.remove(), 5000);
}
const guard = (fn) => async (...a) => { try { return await fn(...a); } catch (e) { toast(e.message + (e.details.length ? " — " + e.details.map((d) => `${d.field}: ${d.issue}`).join("; ") : ""), true); } };

function confirmDialog(title, text, okLabel) {
  return new Promise((resolve) => {
    const dlg = $("#dlg");
    dlg.replaceChildren(h("h2", {}, title), h("p", {}, text),
      h("div", { class: "row" },
        h("button", { class: "danger", onclick: () => { dlg.close(); resolve(true); } }, okLabel),
        h("button", { onclick: () => { dlg.close(); resolve(false); } }, "Keep going")));
    dlg.onclose = () => resolve(false);
    dlg.showModal();
  });
}
function promptDialog(title, label) {
  return new Promise((resolve) => {
    const dlg = $("#dlg"); const ta = h("textarea", { id: "pd", "aria-label": label });
    dlg.replaceChildren(h("h2", {}, title), h("label", { for: "pd" }, label), ta,
      h("div", { class: "row mt" },
        h("button", { class: "primary", onclick: () => { dlg.close(); resolve(ta.value.trim()); } }, "Submit"),
        h("button", { onclick: () => { dlg.close(); resolve(null); } }, "Cancel")));
    dlg.onclose = () => resolve(null);
    dlg.showModal(); ta.focus();
  });
}

const STATUS_CLASS = { SUCCEEDED: "ok", FAILED: "bad", POLICY_BLOCKED: "bad", CANCELLED: "warn", AWAITING_PLAN_APPROVAL: "warn", AWAITING_EXPORT_APPROVAL: "warn",
  PLANNING: "run", GENERATING: "run", VERIFYING: "run", REPAIRING: "run", PACKAGING: "run", DRAFT: "" };
const badge = (status) => h("span", { class: "badge " + (STATUS_CLASS[status] ?? "") }, String(status || "").replaceAll("_", " ").toLowerCase());
const checkBadge = (s) => h("span", { class: "badge " + ({ passed: "ok", failed: "bad", timeout: "bad", skipped: "" }[s] ?? "") }, s);
const STAGES = ["PLANNING", "AWAITING_PLAN_APPROVAL", "GENERATING", "VERIFYING", "AWAITING_EXPORT_APPROVAL", "PACKAGING", "SUCCEEDED"];

const STAGE_LABEL = ["Plan", "Plan approval", "Generate", "Verify", "Export approval", "Package", "Done"];
function stageStates(r) {
  const st = r.status, out = STAGES.map(() => "");
  if (st === "SUCCEEDED") return out.map(() => "done");
  const map = { REPAIRING: "VERIFYING", DRAFT: "PLANNING" };
  let idx = STAGES.indexOf(map[st] || st);
  const bad = ["FAILED", "POLICY_BLOCKED", "CANCELLED"].includes(st);
  if (bad) { idx = STAGES.indexOf(map[r.current_stage] || r.current_stage); if (idx < 0) idx = 2; }
  for (let i = 0; i < out.length; i++) out[i] = i < idx ? "done" : "";
  if (idx >= 0) out[idx] = bad ? "fail" : (st === "AWAITING_PLAN_APPROVAL" || st === "AWAITING_EXPORT_APPROVAL") ? "gate" : "now";
  return out;
}
function miniBar(r) { return h("span", { class: "mini", role: "img", "aria-label": "Pipeline progress: " + String(r.status).replaceAll("_", " ").toLowerCase() }, stageStates(r).map((c) => h("i", { class: c }))); }
function threeD() { try { return localStorage.getItem("nb3d") !== "off"; } catch (_) { return true; } }
function stack3d(r, o) {
  const states = (o && o.states) || stageStates(r);
  const cv = h("canvas", { class: "model3d", tabindex: "0", role: "img", "aria-label": "Interactive 3D model of the delivery pipeline. Drag or use arrow keys to rotate. Current status: " + String(r.status).replaceAll("_", " ").toLowerCase() });
  const wrap = h("div", { class: "stage3d" }, cv, h("div", { class: "hint3d" }, "Drag to rotate"));
  requestAnimationFrame(() => window.NB3D && window.NB3D.mount(cv, states, o));
  return wrap;
}
function applyView() { const on = threeD(); document.body.classList.toggle("flat", !on); const b = $("#view3d"); b.textContent = "3D view: " + (on ? "on" : "off"); b.setAttribute("aria-pressed", String(on)); }
function emptyState(t) { return h("div", { class: "empty" }, t); }
function table(cols, rows) {
  return h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, cols.map((c) => h("th", {}, c)))),
    h("tbody", {}, rows.map((r) => h("tr", {}, r.map((c) => h("td", {}, c)))))));
}

/* ------------------------------------------------------------------ auth */
const ICON = {
  lock: "M7 11V8a5 5 0 0110 0v3M6 11h12v9H6z", eye: "M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12zM12 9a3 3 0 100 6 3 3 0 000-6z",
  eyeoff: "M3 3l18 18M10.6 6.2A9.6 9.6 0 0112 6c6 0 10 6 10 6a17 17 0 01-3.2 3.7M6.5 6.8C3.7 8.6 2 12 2 12s4 7 10 7c1.5 0 2.9-.4 4.1-1M9.9 9.9a3 3 0 004.2 4.2",
  alert: "M12 3l10 18H2zM12 10v5M12 18h.01", check: "M5 12l5 5 9-10", shield: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z",
};
function icon(name, cls) {
  const ns = "http://www.w3.org/2000/svg", s = document.createElementNS(ns, "svg"), p = document.createElementNS(ns, "path");
  s.setAttribute("viewBox", "0 0 24 24"); s.setAttribute("fill", "none"); s.setAttribute("stroke", "currentColor"); s.setAttribute("stroke-width", "1.8");
  s.setAttribute("stroke-linecap", "round"); s.setAttribute("stroke-linejoin", "round"); s.setAttribute("aria-hidden", "true"); if (cls) s.setAttribute("class", cls);
  p.setAttribute("d", ICON[name]); s.append(p); return s;
}
function brandBlock() { return h("div", { class: "auth-brand" }, h("span", { class: "mark big", "aria-hidden": "true" }, h("i"), h("i"), h("i")), h("span", { class: "auth-name" }, "NextBuild ", h("b", {}, "AI"))); }
function pwField(id, label, auto, extra) {
  const input = h("input", { id, type: "password", autocomplete: auto, required: true, maxlength: 200, class: "has-addon" });
  const tog = h("button", { type: "button", class: "reveal", "aria-label": "Show password", "aria-pressed": "false" }, icon("eye"));
  tog.onclick = () => { const show = input.type === "password"; input.type = show ? "text" : "password"; tog.setAttribute("aria-pressed", String(show)); tog.setAttribute("aria-label", show ? "Hide password" : "Show password"); tog.replaceChildren(icon(show ? "eyeoff" : "eye")); };
  return { input, node: h("div", { class: "af-field" }, h("div", { class: "af-label" }, h("label", { for: id }, label), extra || null), h("div", { class: "af-input" }, input, tog)) };
}
function textField(id, label, opts) { const input = h("input", { id, required: true, maxlength: 80, autocomplete: "off", ...opts }); return { input, node: h("div", { class: "af-field" }, h("label", { for: id }, label), h("div", { class: "af-input" }, input)) }; }

async function showAuth(notice) {
  closeStream(); $("#top").hidden = true; $("#topbar").hidden = true; document.body.classList.add("guest");
  let st = { setup_required: false };
  try { st = await (await fetch(API + "/auth/status", { credentials: "same-origin" })).json(); } catch (_) { /* offline: login view will report it */ }
  const main = $("#main");
  const post = async (path, body) => {
    const r = await fetch(API + path, { method: "POST", headers: { "Content-Type": "application/json" }, credentials: "same-origin", body: JSON.stringify(body) });
    const d = await r.json().catch(() => ({})); if (!r.ok) { const e = new Error((d.error && ((d.error.details || []).map((x) => x.issue).join(" ") || d.error.message)) || "Request failed"); e.status = r.status; throw e; }
    return d;
  };
  const failText = (x) => (x instanceof TypeError ? "Cannot reach the server. Check that it is running and that you opened the same address (localhost:PORT)." : x.message);
  function shell(title, sub, ...content) {
    const hero = h("div", { class: "auth-hero", "aria-hidden": "true" },
      h("div", { class: "hero-copy" }, h("h2", {}, "From brief to verified software."), h("p", {}, "Two approval gates. A sandbox between every model and your code.")),
      stack3d({ status: "VERIFYING" }, { labels: ["Plan", "Approve", "Generate", "Verify", "Package", "Ship"], states: ["done", "done", "done", "now", "", ""] }),
      h("ol", { class: "hero-steps" }, ["Plan", "Approve", "Generate", "Verify", "Package", "Ship"].map((t, i) => h("li", { class: i < 3 ? "done" : i === 3 ? "now" : "" }, t))));
    main.replaceChildren(h("div", { class: "auth" },
      h("section", { class: "auth-panel" }, h("div", { class: "auth-inner" }, brandBlock(), h("h1", {}, title), sub ? h("p", { class: "auth-sub" }, sub) : null, ...content,
        h("div", { class: "auth-foot" }, icon("lock"), h("span", {}, "Protected workspace · Secure session")))), hero));
  }
  function form(fields, label, busyLabel, onok, extraBelow, notice2) {
    const err = h("div", { class: "af-error", role: "alert", hidden: true });
    const btn = h("button", { class: "primary af-submit", type: "submit" }, h("span", { class: "spin", "aria-hidden": "true" }), h("span", { class: "lbl" }, label));
    const showErr = (m) => { err.replaceChildren(icon("alert"), h("span", {}, m)); err.hidden = false; };
    const f = h("form", { class: "af-form", novalidate: false, onsubmit: async (e) => {
      e.preventDefault(); err.hidden = true; btn.disabled = true; btn.classList.add("busy"); btn.querySelector(".lbl").textContent = busyLabel;
      try { await onok(); } catch (x) { showErr(failText(x)); } finally { btn.disabled = false; btn.classList.remove("busy"); btn.querySelector(".lbl").textContent = label; }
    } }, notice2 ? h("div", { class: "af-ok", role: "status" }, icon("check"), h("span", {}, notice2)) : null, fields, err, btn, extraBelow || null);
    return f;
  }
  const finish = (d) => { csrf = d.csrf_token; me = d.user; boot(); };

  function viewLogin(msg) {
    const name = textField("dn", "Email or user name", { autocomplete: "username", autocapitalize: "none", spellcheck: "false" });
    const forgot = h("a", { href: "#", class: "af-link", onclick: (e) => { e.preventDefault(); viewForgot(); } }, "Forgot password?");
    const pw = pwField("pw", "Password", "current-password", forgot);
    shell("Sign in", "Welcome back. Enter your details to open your workspace.", form([name.node, pw.node], "Sign in", "Signing in…", async () => {
      const d = await post("/auth/login", { display_name: name.input.value, password: pw.input.value });
      if (d.mfa_required) return viewMfa(name.input.value, pw.input.value);
      pw.input.value = ""; finish(d);
    }, null, msg));
    name.input.focus();
  }
  function viewMfa(user, password) {
    const code = textField("otp", "Authentication code", { inputmode: "numeric", autocomplete: "one-time-code", pattern: "[0-9 ]*", maxlength: 8, class: "otp" });
    shell("Two-step verification", "Enter the 6-digit code from your authenticator app.", form([code.node], "Verify and sign in", "Verifying…", async () => { finish(await post("/auth/login", { display_name: user, password, otp: code.input.value })); },
      h("a", { href: "#", class: "af-link center", onclick: (e) => { e.preventDefault(); viewLogin(); } }, "Back to sign in")));
    code.input.focus();
  }
  function viewSetup() {
    const name = textField("dn", "Email or user name", { autocomplete: "username", autocapitalize: "none", spellcheck: "false" });
    const pw = pwField("pw", "Password", "new-password"), pw2 = pwField("pw2", "Confirm password", "new-password");
    shell("Create your workspace", "First-time setup. This account becomes the administrator.", form([name.node, pw.node, pw2.node, h("p", { class: "af-hint" }, "At least 10 characters. Mix letters, numbers or symbols, or use a passphrase of 16+ characters.")], "Create account", "Creating account…", async () => {
      if (pw.input.value !== pw2.input.value) throw new Error("The two passwords do not match.");
      const d = await post("/auth/register", { display_name: name.input.value, password: pw.input.value }); pw.input.value = pw2.input.value = "";
      viewRecovery(d.recovery_code, () => finish(d), "Your account is ready");
    }));
    name.input.focus();
  }
  function viewRecovery(code, next, title) {
    const ack = h("input", { type: "checkbox", id: "ack" }), go = h("button", { class: "primary af-submit", type: "button", disabled: true, onclick: next }, h("span", { class: "lbl" }, "Continue"));
    ack.onchange = () => { go.disabled = !ack.checked; };
    const copy = h("button", { type: "button", class: "af-secondary", onclick: async () => { try { await navigator.clipboard.writeText(code); copy.textContent = "Copied"; } catch (_) { copy.textContent = "Select and copy manually"; } } }, "Copy code");
    shell(title, "Save this recovery code somewhere safe. It is the only way to reset a forgotten password and it is shown just once.",
      h("div", { class: "recovery", "aria-label": "Recovery code" }, code), h("div", { class: "af-row" }, copy), h("label", { class: "af-check", for: "ack" }, ack, h("span", {}, "I have saved my recovery code")), go);
  }
  function viewForgot() {
    const name = textField("dn", "Email or user name", { autocomplete: "username", autocapitalize: "none" });
    const rc = textField("rc", "Recovery code", { placeholder: "XXXX-XXXX-XXXX-XXXX-XXXX", autocapitalize: "characters", maxlength: 40, class: "mono" });
    const pw = pwField("pw", "New password", "new-password");
    shell("Reset your password", "Enter the recovery code you saved when you created the account.", form([name.node, rc.node, pw.node], "Reset password", "Resetting…", async () => {
      const d = await post("/auth/recover", { display_name: name.input.value, recovery_code: rc.input.value, new_password: pw.input.value });
      viewRecovery(d.recovery_code, () => viewLogin("Password changed. Sign in with your new password."), "Password changed");
    }, h("div", { class: "af-help" }, h("a", { href: "#", class: "af-link", onclick: (e) => { e.preventDefault(); viewLogin(); } }, "Back to sign in"),
      h("p", {}, "No recovery code? An administrator with access to the server can run ", h("code", {}, "python -m autoforge.admin reset-password"), "."))));
    name.input.focus();
  }
  if (st.setup_required) viewSetup(); else viewLogin(typeof notice === "string" ? notice : null);
}
const showLogin = showAuth;
async function boot() {
  applyView();
  try { const d = await api("GET", "/auth/me"); me = d.user; csrf = d.csrf_token || csrf; } catch (_) { return showAuth(); }
  if (!me) return showAuth();
  document.body.classList.remove("guest");
  $("#top").hidden = false; $("#topbar").hidden = false; $("#whoami").textContent = me.display_name; $("#avatar").textContent = me.display_name.trim().charAt(0).toUpperCase() || "?";
  $("#role").textContent = me.role; refreshBell(); route(); statusChips();
}
$("#view3d").onclick = () => { try { localStorage.setItem("nb3d", threeD() ? "off" : "on"); } catch (_) { /* ignore */ } applyView(); };
$("#chpw").onclick = guard(async () => {
  const dlg = $("#dlg"), sec = await api("GET", "/auth/security");
  const section = (title, ...kids) => h("section", { class: "sec" }, h("h3", {}, title), ...kids);
  const msg = (el, text, bad) => { el.textContent = text; el.className = "small " + (bad ? "err" : "ok-text"); };
  // password
  const cur = pwField("cpw", "Current password", "current-password"), nw = pwField("npw", "New password", "new-password"), pMsg = h("div", { role: "alert" });
  const pForm = h("form", { class: "af-form", onsubmit: async (e) => { e.preventDefault(); try { await api("POST", "/auth/password", { current_password: cur.input.value, new_password: nw.input.value }); cur.input.value = nw.input.value = ""; msg(pMsg, "Password changed. Other devices were signed out."); } catch (x) { msg(pMsg, (x.details || []).map((d) => d.issue).join(" ") || x.message, true); } } },
    cur.node, nw.node, pMsg, h("button", { class: "primary af-submit", type: "submit" }, h("span", { class: "lbl" }, "Change password")));
  // 2FA
  const tBox = h("div"), tMsg = h("div", { role: "alert" });
  const renderT = (on) => {
    if (on) { const dp = pwField("dpw", "Password to turn off", "current-password"); tBox.replaceChildren(h("p", { class: "ok-text" }, "Two-step verification is on."), dp.node, h("button", { class: "danger af-secondary", type: "button", onclick: guard(async () => { await api("POST", "/auth/totp/disable", { password: dp.input.value }); renderT(false); }) }, "Turn off")); return; }
    tBox.replaceChildren(h("p", { class: "muted small" }, "Protect sign-in with a code from an authenticator app (Google Authenticator, Microsoft Authenticator, 1Password…)."),
      h("button", { class: "af-secondary", type: "button", onclick: guard(async () => {
        const b = await api("POST", "/auth/totp/begin", {}), code = textField("tcode", "6-digit code", { inputmode: "numeric", autocomplete: "one-time-code", maxlength: 8, class: "otp" });
        tBox.replaceChildren(h("p", { class: "small" }, "In your authenticator app choose “Enter a setup key” and type:"), h("div", { class: "recovery small" }, b.secret.replace(/(.{4})/g, "$1 ").trim()),
          h("p", { class: "af-hint" }, "Account: " + me.display_name + " · Type: time-based"), code.node,
          h("button", { class: "primary af-submit", type: "button", onclick: async () => { try { await api("POST", "/auth/totp/enable", { code: code.input.value }); renderT(true); } catch (x) { msg(tMsg, (x.details || []).map((d) => d.issue).join(" ") || x.message, true); } } }, h("span", { class: "lbl" }, "Turn on")));
      }) }, "Set up two-step verification"));
  };
  renderT(sec.totp_enabled);
  // recovery code
  const rp = pwField("rpw", "Password", "current-password"), rBox = h("div");
  const rForm = h("div", {}, h("p", { class: "muted small" }, sec.has_recovery_code ? "Generating a new code makes the old one stop working." : "You do not have a recovery code yet."), rp.node,
    h("button", { class: "af-secondary", type: "button", onclick: guard(async () => { const d = await api("POST", "/auth/recovery-code", { password: rp.input.value }); rp.input.value = ""; rBox.replaceChildren(h("div", { class: "recovery small" }, d.recovery_code), h("p", { class: "af-hint" }, "Save it now. It will not be shown again.")); }) }, "Generate new recovery code"), rBox);
  dlg.classList.add("wide");
  dlg.replaceChildren(h("div", { class: "row spread" }, h("h2", {}, "Account security"), h("span", { class: "chip" }, "Role: " + sec.role)),
    section("Password", pForm), section("Two-step verification", tBox, tMsg), section("Recovery code", rForm), h("div", { class: "row mt" }, h("button", { onclick: () => dlg.close() }, "Close")));
  dlg.onclose = () => dlg.classList.remove("wide");
  dlg.showModal();
});
async function statusChips() {
  try {
    const a = await api("GET", "/about"), iso = a.sandbox && a.sandbox.isolation === "namespaces", chip = $("#chip-sbx");
    chip.classList.toggle("warn", !iso); chip.title = a.sandbox ? a.sandbox.detail : "";
    chip.querySelector("span").textContent = iso ? "Sandbox: isolated" : "Sandbox: not isolated";
    $("#chip-ai").textContent = a.provider_mode === "mock" ? "Mock AI · offline" : "AI: " + a.provider_mode;
  } catch (_) { /* chips stay neutral */ }
}
async function refreshBell() {
  try { const n = (await api("GET", "/notifications")).items.filter((x) => !x.read).length; const b = $("#bell-count"); b.textContent = n; b.hidden = !n; } catch (_) { /* ignore */ }
}
$("#logout").onclick = async () => { try { await api("POST", "/auth/logout", {}); } catch (_) { /* ignore */ } me = null; showAuth(); };
$("#bell").onclick = guard(async () => {
  const items = (await api("GET", "/notifications?mark_read=1")).items;
  const dlg = $("#dlg");
  dlg.replaceChildren(h("h2", {}, "Notifications"),
    items.length ? h("ul", {}, items.map((n) => h("li", {}, h("a", { href: n.run_id ? "#/runs/" + n.run_id : "#/", onclick: () => dlg.close() }, n.message), " ", h("span", { class: "muted small" }, fmtDate(n.created_at))))) : emptyState("Nothing new."),
    h("button", { onclick: () => dlg.close() }, "Close"));
  dlg.showModal(); refreshBell();
});

/* ------------------------------------------------------------------ router */
function closeStream() { if (stream) { stream.close(); stream = null; } if (poller) { clearInterval(poller); poller = null; } }
function route() {
  if (!me) return;
  closeStream();
  const parts = location.hash.replace(/^#\/?/, "").split("/").filter(Boolean);
  document.querySelectorAll("[data-nav]").forEach((a) => a.classList.toggle("on", a.dataset.nav === (parts[0] === "new" ? "new" : parts[0] === "settings" ? "settings" : parts[0] === "audit" ? "audit" : !parts[0] ? "dashboard" : "")));
  $("#crumb").textContent = { new: "New project", settings: "Settings", audit: "Security & audit", projects: "Project", runs: "Run" }[parts[0]] || "Dashboard";
  const main = $("#main"); main.replaceChildren(h("p", { class: "muted" }, "Loading…"));
  const go = guard(async () => {
    if (!parts[0]) await pageDashboard(main);
    else if (parts[0] === "new") pageNew(main);
    else if (parts[0] === "projects" && parts[1]) await pageProject(main, parts[1]);
    else if (parts[0] === "runs" && parts[1]) await pageRun(main, parts[1], parts[2] || "overview");
    else if (parts[0] === "settings") await pageSettings(main);
    else if (parts[0] === "audit") await pageAudit(main);
    else main.replaceChildren(emptyState("Page not found."));
  });
  go().then(() => main.focus({ preventScroll: true }));
}
window.addEventListener("hashchange", route);

/* ------------------------------------------------------------------ dashboard */
async function pageDashboard(main) {
  const [d, pr] = await Promise.all([api("GET", "/dashboard"), api("GET", "/projects?limit=50")]);
  const runRow = (r) => [h("a", { href: "#/runs/" + r.id }, r.project_name), badge(r.status), miniBar(r), fmtDate(r.created_at)];
  const count = (f) => d.recent_runs.filter(f).length;
  const kpi = (label, v) => h("div", { class: "kpi" }, h("div", { class: "kpi-v" }, String(v)), h("div", { class: "muted small" }, label));
  main.replaceChildren(
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Dashboard"), h("p", { class: "muted" }, "Welcome back, " + me.display_name + ".")), h("a", { class: "btn primary", href: "#/new" }, "New project")),
    h("div", { class: "kpis" }, kpi("Projects", pr.items.length), kpi("Awaiting your approval", d.approval_queue.length), kpi("Succeeded (recent)", count((r) => r.status === "SUCCEEDED")), kpi("Failed or blocked (recent)", count((r) => ["FAILED", "POLICY_BLOCKED"].includes(r.status)))),
    d.approval_queue.length ? h("div", { class: "card" }, h("h2", {}, "Needs your approval"), table(["Project", "Status", "Pipeline", "Created"], d.approval_queue.map(runRow))) : null,
    h("div", { class: "grid g2" },
      h("div", { class: "card" }, h("h2", {}, "Projects"),
        pr.items.length ? table(["Name", "Created"], pr.items.map((p) => [h("a", { href: "#/projects/" + p.id }, p.name), fmtDate(p.created_at)])) : emptyState("No projects yet. Create one to get started.")),
      h("div", { class: "card" }, h("h2", {}, "Recent runs"),
        d.recent_runs.length ? table(["Project", "Status", "Pipeline", "Created"], d.recent_runs.map(runRow)) : emptyState("No runs yet."),
        h("p", { class: "muted small" }, `Model calls across recent runs: ${d.model_calls_recent}. Cost is shown only when a provider reports it.`))));
}

/* ------------------------------------------------------------------ new project wizard */
function pageNew(main) {
  const f = {};
  const field = (id, label, hint, tag = "textarea", required = false) => { f[id] = h(tag, { id, required, maxlength: tag === "input" ? 120 : 8000 }); return h("div", {}, h("label", { for: id }, label, " ", h("span", { class: "hint" }, hint || "")), f[id]); };
  const err = h("div", { class: "err", role: "alert" });
  main.replaceChildren(h("h1", {}, "New project"), h("form", { class: "card", onsubmit: guard(async (e) => {
    e.preventDefault(); err.textContent = "";
    const details = {}; for (const k of ["users", "features", "constraints", "sensitivity", "integrations", "acceptance"]) details[k] = f[k].value;
    const brief = [f.brief.value, f.features.value && "Features: " + f.features.value, f.constraints.value && "Constraints: " + f.constraints.value].filter(Boolean).join("\n");
    try { const p = await api("POST", "/projects", { name: f.name.value, description: f.description.value, brief, details, preferred_stack: { backend: "Python (stdlib WSGI)", database: "SQLite" } });
      location.hash = "#/projects/" + p.id; } catch (x) { err.textContent = x.message + " " + x.details.map((d) => d.issue).join(", "); }
  }) },
    field("name", "Project name", "", "input", true), field("description", "Short description", "(optional)", "input"),
    field("brief", "Brief", "What should it do? Naming the main things it manages (e.g. “with job listings, applications and candidates”) shapes the data model.", "textarea", true),
    field("users", "Target users", "", "input"), field("features", "Must-have features"), field("constraints", "Constraints"),
    field("sensitivity", "Data sensitivity", "(public / internal / personal data…)", "input"), field("integrations", "Integrations", "", "input"), field("acceptance", "Acceptance criteria"),
    h("div", { class: "notice mt" }, "Supported template in this edition: ", h("strong", {}, "python-service"), " (dependency-free JSON API with SQLite and unit tests)."),
    err, h("div", { class: "row mt" }, h("button", { class: "primary", type: "submit" }, "Create project"), h("a", { class: "btn", href: "#/" }, "Cancel"))));
  f.name.focus();
}

/* ------------------------------------------------------------------ project */
async function pageProject(main, id) {
  const [p, prov, pol] = await Promise.all([api("GET", "/projects/" + id), api("GET", "/settings/providers"), api("GET", "/settings/policies")]);
  const sel = h("select", { id: "prov" }, prov.items.filter((x) => x.is_enabled).map((x) => h("option", { value: x.id }, `${x.display_name} (${x.model_name})`)));
  const num = (id, v) => h("input", { id, type: "number", min: 0, value: v });
  const rep = num("b-rep", pol.max_repair_attempts), calls = num("b-calls", pol.max_model_calls), wall = num("b-wall", pol.max_wall_time_seconds);
  main.replaceChildren(
    h("div", { class: "row spread" }, h("h1", {}, p.name), h("button", { class: "danger", onclick: guard(async () => { if (await confirmDialog("Archive project?", "Archived projects cannot start new runs.", "Archive")) { await api("DELETE", "/projects/" + id); location.hash = "#/"; } }) }, "Archive")),
    h("div", { class: "card" }, h("h2", {}, "Brief"), h("pre", {}, p.brief), p.description ? h("p", { class: "muted" }, p.description) : null),
    h("div", { class: "card" }, h("h2", {}, "Start a run"),
      h("p", { class: "muted small" }, "A run produces a plan first. Nothing is generated until you approve it."),
      h("div", { class: "grid g2" }, h("div", {}, h("label", { for: "prov" }, "Model provider"), sel),
        h("div", {}, h("label", { for: "b-rep" }, "Max repair attempts"), rep), h("div", {}, h("label", { for: "b-calls" }, "Max model calls"), calls), h("div", {}, h("label", { for: "b-wall" }, "Max wall time (s)"), wall)),
      h("p", { class: "hint" }, "Budgets can only be tightened relative to your policy limits (Settings)."),
      h("button", { class: "primary", onclick: guard(async () => {
        const r = await api("POST", `/projects/${id}/runs`, { provider_config_id: sel.value, budget: { max_repair_attempts: +rep.value, max_model_calls: +calls.value, max_wall_time_seconds: +wall.value } });
        location.hash = "#/runs/" + r.id; }) }, "Start planning")),
    h("div", { class: "card" }, h("h2", {}, "Runs"), p.runs.length ? table(["Run", "Status", "Stage", "Created"], p.runs.map((r) => [h("a", { href: "#/runs/" + r.id }, r.id.slice(0, 8)), badge(r.status), r.current_stage, fmtDate(r.created_at)])) : emptyState("No runs yet.")));
}

/* ------------------------------------------------------------------ run workspace */
async function pageRun(main, id, tab) {
  const state = { run: null, tasks: [], events: [], plan: null };
  const body = h("div"); const head = h("div");
  main.replaceChildren(head, body);
  const tabs = ["overview", "plan", "timeline", "code", "verification", "artifacts"];

  async function load() {
    state.run = await api("GET", "/runs/" + id);
    state.tasks = (await api("GET", `/runs/${id}/tasks`)).items;
    renderHead(); renderBody();
  }
  function renderHead() {
    const r = state.run, failed = ["FAILED", "POLICY_BLOCKED", "CANCELLED"].includes(r.status);
    const active = !["SUCCEEDED", "FAILED", "CANCELLED", "POLICY_BLOCKED"].includes(r.status);
    head.replaceChildren(
      h("div", { class: "row spread" },
        h("div", {}, h("p", { class: "muted small" }, h("a", { href: "#/projects/" + r.project_id }, r.project_name || "Project"), " / run ", r.id.slice(0, 8)), h("h1", {}, "Run ", badge(r.status))),
        h("div", { class: "row" },
          active ? h("button", { class: "danger", onclick: guard(async () => { if (await confirmDialog("Cancel this run?", "Future work stops and any active sandbox process is terminated. This cannot be resumed.", "Cancel run")) { await api("POST", `/runs/${id}/cancel`, {}); load(); } }) }, r.cancel_requested ? "Cancelling…" : "Cancel run") : null,
          r.status === "FAILED" && r.error_code !== "BUDGET_EXHAUSTED" ? h("button", { onclick: guard(async () => { await api("POST", `/runs/${id}/retry`, {}, { "Idempotency-Key": "ui-" + crypto.randomUUID() }); toast("Retry queued"); load(); }) }, "Retry failed stage") : null)),
      h("div", { class: "stage-panel" },
        h("div", {}, h("h2", {}, "Delivery pipeline"),
          h("ol", { class: "pipeline", "aria-label": "Run stages" }, stageStates(r).map((c, i) => h("li", { class: c }, STAGE_LABEL[i]))),
          h("div", { class: "legend" }, h("span", {}, h("i", { class: "lg-done" }), "complete"), h("span", {}, h("i", { class: "lg-now" }), "in progress"), h("span", {}, h("i", { class: "lg-gate" }), "needs you"), h("span", {}, h("i", { class: "lg-fail" }), "stopped"))),
        stack3d(r)),
      r.repair_attempts ? h("p", { class: "small muted" }, `Repair attempts used: ${r.repair_attempts} of ${r.budget.max_repair_attempts}`) : null,
      r.error_code ? h("div", { class: "notice bad", role: "alert" }, h("strong", {}, r.error_code), ": ", r.error_summary || "") : null,
      h("div", { class: "tabs", role: "tablist" }, tabs.map((t) => h("button", { role: "tab", "aria-selected": t === tab, onclick: () => { location.hash = `#/runs/${id}/${t}`; } }, t))));
  }
  function renderBody() {
    const r = state.run;
    if (tab === "overview") body.replaceChildren(overview(r));
    else if (tab === "plan") renderPlan();
    else if (tab === "timeline") renderTimeline();
    else if (tab === "code") renderCode();
    else if (tab === "verification") renderVerification();
    else if (tab === "artifacts") renderArtifacts();
  }
  function overview(r) {
    const done = state.tasks.filter((t) => t.status === "succeeded").length;
    const gate = r.status === "AWAITING_PLAN_APPROVAL" ? h("div", { class: "notice" }, "The plan is ready. Review it, then approve, request changes, or reject. ", h("a", { href: `#/runs/${id}/plan` }, "Open plan")) :
      r.status === "AWAITING_EXPORT_APPROVAL" ? h("div", { class: "notice" }, "All checks passed. Review code, findings and test evidence, then approve export. ", h("a", { href: `#/runs/${id}/verification` }, "Open verification")) : null;
    return h("div", {}, gate,
      h("div", { class: "grid g2" },
        h("div", { class: "card" }, h("h2", {}, "Tasks"), state.tasks.length ? table(["Key", "Task", "Role", "Status", "Depends on"], state.tasks.map((t) => [t.key, t.title, t.agent_role, h("span", { class: "badge " + ({ succeeded: "ok", running: "run", failed: "bad", cancelled: "warn" }[t.status] || "") }, t.status), t.depends_on.join(", ") || "—"])) : emptyState("Tasks appear after planning."),
          state.tasks.length ? h("p", { class: "muted small" }, `${done} of ${state.tasks.length} tasks finished`) : null),
        h("div", { class: "card" }, h("h2", {}, "Run details"), h("dl", { class: "kv" },
          h("dt", {}, "Provider"), h("dd", {}, `${r.provider_key} / ${r.model_name}`), h("dt", {}, "Plan version"), h("dd", {}, String(r.plan_version)),
          h("dt", {}, "Model calls"), h("dd", {}, String(r.usage.model_calls ?? 0)),
          h("dt", {}, "Tokens"), h("dd", {}, r.usage.tokens_known ? `${r.usage.input_tokens} in / ${r.usage.output_tokens} out` : "unknown (not reported by provider)"),
          h("dt", {}, "Estimated cost"), h("dd", {}, r.usage.estimated_cost_usd == null ? "unknown" : "$" + r.usage.estimated_cost_usd.toFixed(4)),
          h("dt", {}, "Budget"), h("dd", {}, `${r.budget.max_model_calls} calls, ${r.budget.max_repair_attempts} repairs, ${r.budget.max_wall_time_seconds}s`),
          h("dt", {}, "Started"), h("dd", {}, fmtDate(r.started_at)), h("dt", {}, "Finished"), h("dd", {}, fmtDate(r.finished_at) || "—")))),
      h("div", { class: "card" }, h("h2", {}, "Live activity"), timelineList(state.events.slice(-12))));
  }
  function timelineList(evs) {
    if (!evs.length) return emptyState("No events yet.");
    return h("ul", { class: "timeline", "aria-live": "off" }, evs.map((e) => h("li", { class: "sev-" + e.severity }, h("time", {}, fmtTime(e.created_at)), h("span", {}, h("strong", {}, e.event_type.replaceAll("_", " ")), " — ", e.message))));
  }
  function renderTimeline() { body.replaceChildren(h("div", { class: "card" }, h("h2", {}, "Event timeline"), h("p", { class: "muted small" }, "Durable events; the stream reconnects from the last event id."), timelineList(state.events))); const ul = $(".timeline", body); if (ul) ul.scrollTop = ul.scrollHeight; }

  async function renderPlan() {
    if (!state.plan) state.plan = (await api("GET", `/runs/${id}/plan`)).plan;
    const pl = state.plan, r = state.run;
    if (!pl) return body.replaceChildren(h("div", { class: "card" }, emptyState(r.status === "PLANNING" ? "Planning in progress…" : "No plan available.")));
    const R = pl.requirements, A = pl.architecture;
    const acts = r.status === "AWAITING_PLAN_APPROVAL" ? h("div", { class: "card row" },
      h("button", { class: "primary", onclick: guard(async () => { await api("POST", `/runs/${id}/plan/approve`, {}); state.plan = null; location.hash = `#/runs/${id}/overview`; load(); }) }, `Approve plan v${pl.version} and generate`),
      h("button", { onclick: guard(async () => { const c = await promptDialog("Request changes", "What should change?"); if (c) { await api("POST", `/runs/${id}/plan/change-request`, { comment: c }); state.plan = null; load(); } }) }, "Request changes"),
      h("button", { class: "danger", onclick: guard(async () => { if (await confirmDialog("Reject plan?", "The run is cancelled and nothing is generated.", "Reject plan")) { await api("POST", `/runs/${id}/plan/reject`, {}); load(); } }) }, "Reject")) : null;
    body.replaceChildren(acts,
      h("div", { class: "card" }, h("h2", {}, `Requirements (plan v${pl.version})`),
        table(["ID", "Requirement", "Priority"], [...R.functional, ...R.non_functional].map((q) => [q.id, q.text, q.priority])),
        h("h3", {}, "Acceptance criteria"), h("ul", {}, R.acceptance_criteria.map((x) => h("li", {}, x))),
        h("h3", {}, "Assumptions"), h("ul", {}, R.assumptions.map((x) => h("li", {}, x))),
        h("h3", {}, "Open questions"), h("ul", {}, R.open_questions.map((x) => h("li", {}, x))),
        h("h3", {}, "Risks"), table(["ID", "Risk", "Severity"], R.risks.map((x) => [x.id, x.text, x.severity]))),
      h("div", { class: "card" }, h("h2", {}, "Architecture"),
        table(["Component", "Responsibility"], A.components.map((c) => [c.name, c.responsibility])),
        h("h3", {}, "Diagram (Mermaid source)"), h("pre", {}, A.mermaid), h("p", { class: "hint" }, "Rendering is disabled because the strict content-security policy forbids loading remote scripts; paste the source into any Mermaid viewer."),
        h("h3", {}, "Decisions"), A.adrs.map((a) => h("p", {}, h("strong", {}, `${a.id} ${a.title}: `), a.decision, " ", h("span", { class: "muted" }, a.rationale))),
        h("h3", {}, "Data model"), table(["Entity", "Fields"], A.data_model.map((e) => [e.name, e.fields.map((f) => `${f.name}:${f.type}`).join(", ")])),
        h("h3", {}, "API contract"), table(["Method", "Path", "Summary"], A.api_contract.map((x) => [x.method, h("code", {}, x.path), x.summary])),
        h("h3", {}, "Security boundaries"), h("ul", {}, A.security_boundaries.map((x) => h("li", {}, x))), h("p", {}, h("strong", {}, "Deployment: "), A.deployment_topology)),
      h("div", { class: "card" }, h("h2", {}, "Task graph"), table(["Key", "Task", "Role", "Depends on", "Files", "Risk", "Requirements"], pl.tasks.map((t) => [t.key, t.title, t.agent_role, t.depends_on.join(", ") || "—", t.expected_files.join(", "), t.risk, t.requirement_ids.join(", ")]))));
  }

  async function renderCode() {
    const d = await api("GET", `/runs/${id}/diff`);
    if (!d.available) return body.replaceChildren(h("div", { class: "card" }, emptyState("No workspace yet — code appears after generation starts.")));
    const view = h("div", {}); let current = null;
    const changes = h("div", {});
    const show = guard(async (path, btn) => {
      const f = await api("GET", `/runs/${id}/file?path=${encodeURIComponent(path)}`);
      view.replaceChildren(h("h3", {}, path), h("pre", {}, f.content)); current = path;
      document.querySelectorAll(".tree button").forEach((b) => b.removeAttribute("aria-current")); btn.setAttribute("aria-current", "true");
    });
    changes.replaceChildren(h("h3", {}, "Changes since generation (repairs)"), d.changes_since_generation.length ? d.changes_since_generation.map((c) => h("div", {}, h("strong", {}, `${c.path} (${c.status})`),
      h("pre", { class: "diff" }, c.diff.split("\n").map((l) => h("div", { class: l.startsWith("+") && !l.startsWith("+++") ? "add" : l.startsWith("-") && !l.startsWith("---") ? "del" : "" }, l || " "))))) : h("p", { class: "muted" }, "No repairs were applied."));
    body.replaceChildren(h("div", { class: "grid g2" },
      h("div", { class: "card" }, h("h2", {}, "Files"), h("ul", { class: "tree" }, d.files.map((f) => { const b = h("button", { type: "button" }, `${f.path}  (${f.size} B)`); b.onclick = () => show(f.path, b); return h("li", {}, b); }))),
      h("div", { class: "card" }, h("h2", {}, "File"), view, h("p", { class: "muted" }, "Select a file to view it."))), h("div", { class: "card" }, changes));
  }

  async function renderVerification() {
    const v = await api("GET", `/runs/${id}/verification`), r = state.run;
    const approve = r.status === "AWAITING_EXPORT_APPROVAL" ? h("div", { class: "card" },
      h("div", { class: "notice" }, "Approving packages the files shown in the Code tab. Review the findings below first. Passing automated checks is not a production-readiness claim."),
      h("button", { class: "primary", onclick: guard(async () => { await api("POST", `/runs/${id}/export/approve`, {}); location.hash = `#/runs/${id}/artifacts`; load(); }) }, "Approve export and package")) : null;
    body.replaceChildren(approve,
      h("div", { class: "card" }, h("h2", {}, "Checks"), v.checks.length ? v.checks.map((c) => h("div", {}, h("div", { class: "row" }, checkBadge(c.status), h("strong", {}, `round ${c.round} · ${c.check_name}`), h("span", { class: "muted small" }, `exit ${c.exit_code ?? "—"} · ${c.duration_ms} ms`)), h("pre", {}, "$ " + c.command + "\n" + c.output_summary))) : emptyState("No checks have run yet.")),
      h("div", { class: "card" }, h("h2", {}, "Security findings"), v.security_findings.length ? table(["Severity", "Category", "Where", "Message", "Evidence"], v.security_findings.map((f) => [f.severity, f.category, `${f.file_path || "—"}${f.line ? ":" + f.line : ""}`, f.message, f.evidence ? h("code", {}, f.evidence) : ""])) : h("p", { class: "muted" }, "None reported (built-in scanner only; not a guarantee).")),
      h("div", { class: "card" }, h("h2", {}, "Sandbox"), h("pre", {}, JSON.stringify(v.sandbox, null, 2))));
  }

  async function renderArtifacts() {
    const a = (await api("GET", `/runs/${id}/artifacts`)).items, ap = (await api("GET", `/runs/${id}/approvals`)).items;
    body.replaceChildren(h("div", { class: "card" }, h("h2", {}, "Artifacts"), a.length ? table(["Name", "Type", "Size", "SHA-256", "Created", ""], a.map((x) => [x.display_name, x.artifact_type, x.size_bytes + " B", h("code", {}, x.sha256.slice(0, 16) + "…"), fmtDate(x.created_at), h("a", { class: "btn", href: API + x.download_url.replace("/api/v1", ""), download: x.display_name }, "Download")])) : emptyState("Artifacts are created after export approval.")),
      h("div", { class: "card" }, h("h2", {}, "Approvals"), ap.length ? table(["Type", "Decision", "Plan v", "Requested", "Decided"], ap.map((x) => [x.approval_type, x.decision || "pending", x.plan_version, fmtDate(x.requested_at), fmtDate(x.decided_at) || "—"])) : emptyState("No approvals yet.")));
  }

  state.events = (await api("GET", `/runs/${id}/events`)).items;
  await load();
  // live updates: SSE with automatic Last-Event-ID resume; falls back to polling if SSE fails
  let last = state.events.length ? state.events[state.events.length - 1].id : 0, refreshTimer = null;
  const refresh = () => { clearTimeout(refreshTimer); refreshTimer = setTimeout(() => { state.plan = null; load().then(() => { if (tab === "timeline") renderTimeline(); }); refreshBell(); }, 250); };
  if (!["SUCCEEDED", "FAILED", "CANCELLED", "POLICY_BLOCKED"].includes(state.run.status)) {
    stream = new EventSource(`${API}/runs/${id}/events/stream?after=${last}`);
    stream.onmessage = null;
    const onEv = (m) => { try { const e = JSON.parse(m.data); if (e.id > last) { last = e.id; state.events.push(e); refresh(); } } catch (_) { /* ignore */ } };
    ["state_transition", "agent_call", "agent_invalid_output", "provider_retry", "task_started", "task_finished", "snapshot", "check_started", "check_finished", "security_scan", "repair_applied", "policy_denied", "policy_blocked", "cancel_requested"].forEach((t) => stream.addEventListener(t, onEv));
    stream.addEventListener("stream_end", () => { closeStream(); refresh(); });
  }
}

/* ------------------------------------------------------------------ settings */
async function pageSettings(main) {
  const [prov, pol] = await Promise.all([api("GET", "/settings/providers"), api("GET", "/settings/policies")]);
  const f = {};
  const inp = (id, label, type = "text", ph = "") => { f[id] = h("input", { id, type, placeholder: ph }); return h("div", {}, h("label", { for: id }, label), f[id]); };
  f.type = h("select", { id: "pt" }, ["openai_compatible", "anthropic"].map((t) => h("option", { value: t }, t)));
  const pf = {}; for (const k of ["max_repair_attempts", "max_model_calls", "max_wall_time_seconds", "max_estimated_cost_usd", "retention_days"]) pf[k] = h("input", { id: "p-" + k, type: "number", min: 0, value: pol[k] });
  main.replaceChildren(h("h1", {}, "Settings"),
    h("div", { class: "card" }, h("h2", {}, "Model providers"),
      table(["Name", "Type", "Model", "Endpoint", "Secret reference", ""], prov.items.map((p) => [p.display_name, p.provider_type, p.model_name, p.base_url || "—", p.secret_reference || "—",
        p.builtin ? h("span", { class: "muted small" }, "built in") : h("button", { class: "danger", onclick: guard(async () => { if (await confirmDialog("Delete provider?", p.display_name, "Delete")) { await api("DELETE", "/settings/providers/" + p.id); route(); } }) }, "Delete")])),
      h("h3", {}, "Add provider"),
      h("p", { class: "muted small" }, "Cloud data flow: with a non-mock provider, briefs and generated code context are sent to that endpoint. API keys are never entered here — reference an environment variable on the server (e.g. env:ANTHROPIC_API_KEY)."),
      h("div", { class: "grid g2" }, h("div", {}, h("label", { for: "pt" }, "Type"), f.type), inp("pn", "Display name"), inp("pm", "Model name"), inp("pu", "Base URL", "url", "http://localhost:11434/v1"), inp("ps", "Secret reference (optional)", "text", "env:MY_API_KEY")),
      h("button", { class: "primary mt", onclick: guard(async () => { await api("POST", "/settings/providers", { provider_type: f.type.value, display_name: f.pn.value, model_name: f.pm.value, base_url: f.pu.value || null, secret_reference: f.ps.value || null }); toast("Provider added"); route(); }) }, "Add provider")),
    h("div", { class: "card" }, h("h2", {}, "Execution & budget policy"),
      h("p", { class: "muted small" }, "Execution mode is fixed to sandbox. Per-run budgets can be tightened but never exceed these limits."),
      h("div", { class: "grid g2" }, Object.keys(pf).map((k) => h("div", {}, h("label", { for: "p-" + k }, k.replaceAll("_", " ")), pf[k]))),
      h("button", { class: "primary mt", onclick: guard(async () => { const b = {}; for (const k in pf) b[k] = +pf[k].value; await api("PATCH", "/settings/policies", b); toast("Policy saved"); }) }, "Save policy")));
}

/* ------------------------------------------------------------------ audit & about */
async function pageAudit(main) {
  const [a, about, ready] = await Promise.all([api("GET", "/audit"), api("GET", "/about"), fetch(API + "/health/ready").then((r) => r.json())]);
  main.replaceChildren(h("h1", {}, "Security & audit"),
    h("div", { class: "grid g2" },
      h("div", { class: "card" }, h("h2", {}, "About"), h("dl", { class: "kv" }, h("dt", {}, "Version"), h("dd", {}, about.version), h("dt", {}, "Environment"), h("dd", {}, about.app_env), h("dt", {}, "Default provider"), h("dd", {}, about.provider_mode),
        h("dt", {}, "Sandbox"), h("dd", {}, about.sandbox.isolation === "namespaces" ? "isolated (" + about.sandbox.detail + ")" : "UNAVAILABLE — untrusted execution disabled"))),
      h("div", { class: "card" }, h("h2", {}, "Health"), h("dl", { class: "kv" }, Object.entries(ready.checks).flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)])))),
    h("div", { class: "card" }, h("h2", {}, "Recent audit events"), a.items.length ? table(["When", "Action", "Resource", "Outcome", "Details"], a.items.map((x) => [fmtDate(x.created_at), x.action, x.resource_type, h("span", { class: "badge " + (x.outcome === "denied" ? "bad" : "ok") }, x.outcome), h("code", {}, JSON.stringify(x.details).slice(0, 120))])) : emptyState("No audit events.")));
}

boot();

const SEARCH_LIMIT = 30;
const defaultIcon = "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><rect width='24' height='24' fill='%23272930'/></svg>";
const $ = (id) => document.getElementById(id);
const iconImg = (url, cls) => `<img src="${url || defaultIcon}" class="${cls}" onerror="this.src='${defaultIcon}'"/>`;

// When Caddy proxies us under /updater, index.html sets window.APP_BASE to
// that prefix (read server-side from request.script_root, which ProxyFix
// derives from the X-Forwarded-Prefix header - see app.py). Every
// same-origin URL in this file - /api/..., /instance-icon/... - needs that
// prefix prepended, or it resolves against the wrong path once the browser
// is actually sitting at https://host/updater/. Absolute URLs (Modrinth's
// api.modrinth.com calls) and data: URIs are left untouched. Running
// standalone with nothing in front, APP_BASE is just "" and this is a no-op.
const APP_BASE = (window.APP_BASE || "").replace(/\/$/, "");
function withBase(path) {
  if (!path || !APP_BASE || /^(https?:|data:)/i.test(path)) return path;
  return path.startsWith("/") ? `${APP_BASE}${path}` : path;
}

// ---------------- Fetch helpers ----------------
async function parseResponse(res) {
  const text = await res.text();
  let data;
  try { data = text ? JSON.parse(text) : {}; }
  catch { throw new Error(`Server returned invalid JSON (HTTP ${res.status})`); }
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}
async function api(url) { return parseResponse(await fetch(withBase(url))); }
async function postJSON(url, body) {
  return parseResponse(await fetch(withBase(url), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }));
}

// Consumes a newline-delimited-JSON streaming response, calling onEvent for
// every complete line as it arrives (instead of buffering the whole body -
// this is what lets the mod list fill in one row at a time instead of all
// at once). Falls back to a single onEvent call for plain, non-streamed
// JSON responses (the backend takes this path when there's nothing to
// check, e.g. an empty mods folder).
async function streamNDJSON(url, body, onEvent) {
  const res = await fetch(withBase(url), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  if (!res.ok) { await parseResponse(res); return; }
  if (!res.body) { onEvent(await parseResponse(res)); return; }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let nl;
    while ((nl = buffer.indexOf("\n")) !== -1) {
      const line = buffer.slice(0, nl).trim();
      buffer = buffer.slice(nl + 1);
      if (line) onEvent(JSON.parse(line));
    }
  }
  if (buffer.trim()) onEvent(JSON.parse(buffer.trim()));
}

// ---------------- Instances & per-instance state ----------------
let instances = [];
let currentInstance = null;
let currentMods = [];
let hasChecked = false;
let busyCount = 0;
let excludedIds = new Set();
let pendingUpdates = [];
let currentGreeting = null;
let statusTimeoutId = null;

const instanceStates = {};

function captureInstanceState(id) {
  instanceStates[id] = { mods: currentMods, hasChecked, excludedIds, pendingUpdates, currentGreeting, webhookText: $("webhook-textarea").value };
}

function restoreInstanceState(id) {
  const s = instanceStates[id];
  ({ mods: currentMods, hasChecked, excludedIds, pendingUpdates, currentGreeting } = s);
  $("search-results").innerHTML = "";
  $("search-input").value = "";
  $("webhook-textarea").value = s.webhookText;
  autoExpandTextarea();
  setWebhookStatus("");
  updateWebhookSendButtonState();
  refreshUpdateAllButton();
  refreshSearchUIState();
  renderTable();
}

async function loadInstances() {
  instances = await api("/api/instances");
  if (!instances.length) {
    $("instance-tabs").innerHTML = `<div class="empty-msg">No instances configured. Add one to instances.json.</div>`;
    return;
  }
  const saved = localStorage.getItem("lastInstanceId");
  await selectInstance((instances.find(i => i.id === saved) || instances[0]).id);
}

function renderInstanceTabs() {
  const wrap = $("instance-tabs");
  wrap.innerHTML = "";
  instances.forEach(inst => {
    const tab = document.createElement("div");
    tab.className = `instance-tab${currentInstance && currentInstance.id === inst.id ? " active" : ""}`;

    const iconEl = document.createElement("div");
    iconEl.className = "instance-tab-icon";
    if (inst.icon && /^(data:|https?:|\/)/.test(inst.icon)) {
      const img = document.createElement("img");
      img.src = withBase(inst.icon);
      img.style.cssText = "width:100%;height:100%;object-fit:cover;border-radius:8px;";
      img.onerror = () => { iconEl.textContent = (inst.name[0] || "?").toUpperCase(); };
      iconEl.appendChild(img);
    } else {
      iconEl.textContent = (inst.icon || inst.name[0] || "?").toUpperCase().slice(0, 2);
    }

    const meta = document.createElement("div");
    meta.className = "instance-tab-meta";
    meta.innerHTML = `<div class="instance-tab-name">${escapeHtml(inst.name)}</div>
      <div class="instance-tab-sub">${escapeHtml(inst.loader)}<span class="dot"></span>${escapeHtml(inst.game_version)}</div>`;

    tab.append(iconEl, meta);
    tab.onclick = () => selectInstance(inst.id);
    wrap.appendChild(tab);
  });
}

async function selectInstance(id) {
  const inst = instances.find(i => i.id === id);
  if (!inst) return;

  if (currentInstance) captureInstanceState(currentInstance.id);
  currentInstance = inst;
  localStorage.setItem("lastInstanceId", id);
  renderInstanceTabs();
  $("instance-heading").textContent = inst.name;

  if (instanceStates[id]) {
    restoreInstanceState(id);
    return;
  }

  currentMods = []; hasChecked = false; busyCount = 0; pendingUpdates = []; currentGreeting = null;
  $("search-results").innerHTML = "";
  $("search-input").value = "";
  $("webhook-textarea").value = "";
  setWebhookStatus("");
  updateWebhookSendButtonState();
  refreshUpdateAllButton();
  refreshSearchUIState();
  renderTable();

  await refreshExcludedIds();
  await runModsCheck("diff");
  captureInstanceState(id);
}

async function refreshExcludedIds() {
  if (!currentInstance) return;
  try { excludedIds = new Set(await api(`/api/excluded?instance=${encodeURIComponent(currentInstance.id)}`)); }
  catch (e) { console.error("Failed to load excluded mods list", e); }
}

// ---------------- Discord broadcast message ----------------
function autoExpandTextarea() {
  const ta = $("webhook-textarea");
  ta.style.height = "auto";
  ta.style.height = ta.scrollHeight + "px";
}

function buildWebhookText() {
  if (!pendingUpdates.length) return "";
  const lines = pendingUpdates.map(u => `${u.name}: ${u.from_version} -> ${u.to_version}`);
  return `${currentGreeting}\n\`\`\`\n${lines.join("\n")}\n\`\`\``;
}

function setWebhookStatus(text, autoDismissMs = null) {
  const status = $("webhook-status");
  if (!status) return;
  clearTimeout(statusTimeoutId);
  statusTimeoutId = null;
  status.textContent = text;
  if (autoDismissMs) statusTimeoutId = setTimeout(() => { status.textContent = ""; }, autoDismissMs);
}

function updateWebhookSendButtonState() { $("btn-send-webhook").disabled = pendingUpdates.length === 0; }

function clearWebhookBox() {
  setWebhookStatus("");
  $("webhook-textarea").value = "";
  autoExpandTextarea();
}

async function refreshDiscordMessage() {
  if (!currentInstance) return;
  const trackable = currentMods
    .filter(m => m.on_modrinth && m.project_id && m.current_version)
    .map(m => ({ project_id: m.project_id, name: m.name, filename: m.filename, current_version: m.current_version }));

  let data;
  try { data = await postJSON("/api/discord/pending", { instance: currentInstance.id, mods: trackable }); }
  catch (e) { console.error("Failed to refresh Discord pending updates", e); return; }

  pendingUpdates = data.pending || [];
  const textarea = $("webhook-textarea");

  if (!pendingUpdates.length) {
    currentGreeting = null;
    textarea.value = "";
  } else {
    if (!currentGreeting) {
      try { currentGreeting = (await api("/api/welcome-phrase")).phrase; }
      catch { currentGreeting = "Here are the latest mod updates:"; }
    }
    textarea.value = buildWebhookText();
  }
  autoExpandTextarea();
  updateWebhookSendButtonState();
}

async function sendWebhookMessage() {
  if (!currentInstance) return;
  const textarea = $("webhook-textarea");
  const content = textarea.value.trim();
  if (!content || !pendingUpdates.length) { setWebhookStatus("Nothing pending to send."); return; }

  const btn = $("btn-send-webhook");
  btn.disabled = true;
  setWebhookStatus("Sending...");

  try {
    const data = await postJSON("/api/webhook/send", {
      instance: currentInstance.id, content,
      updates: pendingUpdates.map(u => ({ project_id: u.project_id, name: u.name, filename: u.filename, to_version: u.to_version })),
    });
    if (data.success) {
      setWebhookStatus("Sent!", 5000);
      pendingUpdates = []; currentGreeting = null;
      textarea.value = "";
      autoExpandTextarea();
    } else {
      setWebhookStatus("Failed: " + (data.error || "Unknown error"));
      btn.disabled = false;
    }
  } catch (err) {
    setWebhookStatus("Failed: " + err.message);
    btn.disabled = false;
  }
}

// ---------------- Busy / search UI ----------------
function refreshSearchUIState() {
  const input = $("search-input"), btn = $("btn-search");
  const enabled = hasChecked && busyCount === 0;
  input.disabled = !enabled;
  btn.disabled = !enabled;
  input.placeholder = !hasChecked ? "Check mods first" : (busyCount > 0 ? "Busy, please wait..." : "Search keyword...");
  setSearchResultButtonsLocked(busyCount > 0);
}

function enterBusy() { busyCount++; refreshSearchUIState(); }
function exitBusy() { busyCount = Math.max(0, busyCount - 1); refreshSearchResultsInstalledState(); refreshSearchUIState(); }

function setSearchResultButtonsLocked(locked) {
  document.querySelectorAll("#search-results .mod-action button").forEach((btn) => {
    if (locked) {
      if (btn.dataset.wasDisabled === undefined) btn.dataset.wasDisabled = btn.disabled ? "1" : "0";
      btn.disabled = true;
    } else if (btn.dataset.wasDisabled !== undefined) {
      btn.disabled = btn.dataset.wasDisabled === "1";
      delete btn.dataset.wasDisabled;
    }
  });
}

function refreshSearchResultsInstalledState() {
  document.querySelectorAll("#search-results .mod-row").forEach((row) => {
    const projectId = row.dataset.projectId;
    const btn = row.querySelector(".mod-action button");
    if (!projectId || !btn) return;
    if (currentMods.some((m) => m.project_id === projectId)) {
      btn.disabled = true; btn.dataset.wasDisabled = "1"; btn.textContent = "Installed";
    } else if (row.dataset.hasDownload === "1") {
      btn.disabled = false; delete btn.dataset.wasDisabled; btn.textContent = "Add";
    }
  });
}

function handleSearchInput() {
  if (!$("search-input").value.trim()) $("search-results").innerHTML = "";
}

async function runWithConcurrency(items, limit, fn) {
  let cursor = 0;
  const worker = async () => { while (cursor < items.length) await fn(items[cursor++]); };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
}

function refreshUpdateAllButton() {
  $("btn-update-all").disabled = !currentMods.some(m => !m.disabled && m.update_available);
}

// ---------------- Progress bar ----------------
function showProgress() { $("progress-container")?.classList.remove("hidden"); setProgress(0); }
function setProgress(fraction) { const bar = $("progress-bar"); if (bar) bar.style.width = `${Math.round(fraction * 100)}%`; }
function hideProgressSoon() { setTimeout(() => $("progress-container")?.classList.add("hidden"), 800); }

document.addEventListener("DOMContentLoaded", () => loadInstances());

function sortModsLexically() {
  currentMods.sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: "base", numeric: true }));
}

// The backend already knows this instance's loader/game_version, so version
// lookups go through its proxy instead of re-encoding Modrinth's
// loaders/game_versions query params on the client (used by both search
// results and the version-switch modal).
async function fetchProjectVersions(projectId) {
  return api(`/api/mod/${encodeURIComponent(projectId)}/versions?instance=${encodeURIComponent(currentInstance.id)}`);
}

async function searchModrinth() {
  if (!hasChecked || !currentInstance) return;
  const query = $("search-input").value.trim();
  const container = $("search-results");
  const btn = $("btn-search");
  if (!query) { container.innerHTML = ""; return; }

  btn.disabled = true;
  container.innerHTML = `<div class="empty-msg">Searching Modrinth...</div>`;

  try {
    const facets = [["project_type:mod"], [`versions:${currentInstance.game_version}`], [`categories:${currentInstance.loader}`]];
    const data = await api(`https://api.modrinth.com/v2/search?query=${encodeURIComponent(query)}&limit=${SEARCH_LIMIT}&facets=${encodeURIComponent(JSON.stringify(facets))}`);

    if (!data.hits?.length) { container.innerHTML = `<div class="empty-msg">No mods found.</div>`; return; }

    container.innerHTML = "";
    const rows = await Promise.all(data.hits.map(async (hit) => {
      let latestVer = "N/A", filename = "", downloadUrl = "";
      try {
        const versions = await fetchProjectVersions(hit.project_id);
        if (versions.length) {
          latestVer = versions[0].version_number;
          const file = versions[0].files.find(f => f.primary) || versions[0].files[0];
          if (file) { filename = file.filename; downloadUrl = file.url; }
        }
      } catch {}

      const isInstalled = currentMods.some(m => m.project_id === hit.project_id);
      const row = document.createElement("div");
      row.className = "mod-row";
      row.dataset.projectId = hit.project_id;
      row.dataset.hasDownload = downloadUrl ? "1" : "0";
      row.innerHTML = `
        <div class="mod-identity">
          ${iconImg(hit.icon_url, "mod-icon")}
          <div class="mod-meta"><a href="https://modrinth.com/mod/${hit.project_id}" target="_blank" class="mod-title mod-link">${escapeHtml(hit.title)}</a><div class="mod-author">${escapeHtml(hit.author)}</div></div>
        </div>
        <div class="mod-version-info"><div class="mod-version">${escapeHtml(latestVer)}</div><div class="mod-filename">${escapeHtml(filename)}</div></div>
        <div></div>
        <div class="mod-action">
          <div class="btn-slot"><button class="btn btn-success" ${isInstalled || !downloadUrl ? "disabled" : ""} onclick="addModFromSearch('${escapeAttr(downloadUrl)}', '${escapeAttr(filename)}', '${escapeAttr(hit.project_id)}', this)">${isInstalled ? "Installed" : "Add"}</button></div>
        </div>`;
      return row;
    }));
    rows.forEach((row) => container.appendChild(row));
  } catch (err) {
    container.innerHTML = `<div class="empty-msg">Search failed.</div>`;
  } finally {
    btn.disabled = false;
  }
}

async function addModFromSearch(downloadUrl, filename, projectId, triggerBtn) {
  if (!currentInstance) return;
  if (triggerBtn) triggerBtn.disabled = true;
  enterBusy();

  try {
    const data = await postJSON("/api/mod/add", { instance: currentInstance.id, download_url: downloadUrl, filename });
    if (!data.success || !data.mod) throw new Error(data.error || "Unknown error");

    data.mod.project_id = projectId;
    currentMods.push(data.mod);
    sortModsLexically();
    renderTable();

    const idx = currentMods.findIndex(m => m.filename === data.mod.filename);
    if (idx !== -1) {
      setRowBusy(idx, true);
      try {
        const checkData = await postJSON("/api/mod/check", { instance: currentInstance.id, sha1: currentMods[idx].sha1, filename: currentMods[idx].filename });
        Object.assign(currentMods[idx], checkData);
      } catch (e) { console.error("Check failed for added mod", e); }
      finally { setRowBusy(idx, false); updateRowUI(idx); }
    }

    refreshUpdateAllButton();
    if (triggerBtn) { triggerBtn.textContent = "Installed"; triggerBtn.dataset.wasDisabled = "1"; }
  } catch (err) {
    alert("Error adding mod: " + err.message);
    if (triggerBtn) triggerBtn.disabled = false;
  } finally {
    exitBusy();
  }
}

// ---------------- Checking mods ----------------
// Streams the check instead of awaiting one big response: each "progress"
// event carries one fully-resolved mod, which gets appended/rendered
// immediately, so the list visibly fills in mod-by-mod as the backend
// resolves them (concurrently, out of order) rather than jumping from
// empty to fully populated in one go. The final "done" event carries the
// authoritative, correctly-ordered list, which replaces the streamed-in
// one for the final render.
async function runModsCheck(mode) {
  if (!currentInstance) return;
  const btnCheck = $("btn-check");
  showProgress();
  btnCheck.disabled = true;
  enterBusy();

  const seen = new Map();
  let finished = false;

  try {
    await streamNDJSON("/api/mods/check", { instance: currentInstance.id, mode, stream: true }, (evt) => {
      if (evt.type === "progress") {
        const isNew = !seen.has(evt.mod.filename);
        seen.set(evt.mod.filename, evt.mod);
        currentMods = Array.from(seen.values());
        if (isNew) {
          if (currentMods.length === 1) $("mods-list").innerHTML = "";
          const row = document.createElement("div");
          row.id = `mod-row-${currentMods.length - 1}`;
          $("mods-list").appendChild(row);
        }
        updateRowUI(currentMods.length - 1);
        if (evt.total) setProgress(evt.completed / evt.total);
      } else if (evt.type === "done" || evt.mods !== undefined) {
        currentMods = evt.mods || [];
        sortModsLexically();
        finished = true;
      }
    });
    setProgress(1);
    hasChecked = true;
    renderTable();
  } catch (e) {
    console.error("Mods check failed", e);
    $("mods-list").innerHTML = `<div class="empty-msg">Failed to check mods: ${escapeHtml(e.message)}</div>`;
  } finally {
    btnCheck.disabled = false;
    refreshUpdateAllButton();
    if (finished) await refreshDiscordMessage();
    exitBusy();
    hideProgressSoon();
  }
}

async function startCheckProgress() {
  if (!currentInstance) return;
  await refreshExcludedIds();
  await runModsCheck("full");
  captureInstanceState(currentInstance.id);
}

// ---------------- Rendering ----------------
function renderTable() {
  const container = $("mods-list");
  if (!currentMods.length) {
    container.innerHTML = hasChecked
      ? `<div class="empty-msg">No mods found for this instance.</div>`
      : `<div class="empty-msg">Select an instance and click <strong>Check</strong> to load and scan mods.</div>`;
    return;
  }
  container.innerHTML = "";
  currentMods.forEach((_, idx) => {
    const row = document.createElement("div");
    row.id = `mod-row-${idx}`;
    container.appendChild(row);
    updateRowUI(idx);
  });
}

function updateRowUI(idx) {
  const row = $(`mod-row-${idx}`);
  const mod = currentMods[idx];
  if (!row || !mod) return;

  const isBusy = row.classList.contains("is-busy");
  const isExcluded = mod.project_id && excludedIds.has(mod.project_id);
  row.className = `mod-row ${mod.disabled ? "mod-disabled" : ""} ${isExcluded ? "mod-excluded" : ""} ${isBusy ? "is-busy" : ""}`;

  const titleHtml = mod.on_modrinth && mod.project_id
    ? `<a href="https://modrinth.com/mod/${mod.project_id}" target="_blank" class="mod-title mod-link">${escapeHtml(mod.name)}</a>`
    : `<div class="mod-title">${escapeHtml(mod.name)}</div>`;

  const toggleBtn = `<div class="btn-slot">${
    mod.disabled
      ? `<button class="btn btn-secondary btn-toggle-off" onclick="toggleMod(${idx})">OFF</button>`
      : `<button class="btn btn-success btn-toggle-on" onclick="toggleMod(${idx})">ON</button>`
  }</div>`;

  let actionBtnSlot = `<div class="btn-slot"></div>`;
  if (mod.on_modrinth) {
    actionBtnSlot = mod.update_available
      ? `<div class="btn-slot"><button class="btn btn-success" ${mod.disabled ? "disabled" : ""} onclick="openVersionSelector(${idx}, true)">Update</button></div>`
      : `<div class="btn-slot"><button class="btn btn-primary" ${mod.disabled ? "disabled" : ""} onclick="openVersionSelector(${idx}, false)">Change</button></div>`;
  }

  const col3Html = mod.update_available
    ? `<div class="mod-version-info"><div class="mod-version">${escapeHtml(mod.latest_version)}</div><div class="mod-filename">${escapeHtml(mod.new_filename)}</div></div>`
    : "";

  row.innerHTML = `
    <div class="mod-identity">
      ${iconImg(mod.icon_url, "mod-icon")}
      <div class="mod-meta">${titleHtml}<div class="mod-author">${escapeHtml(mod.author)}</div></div>
    </div>
    <div class="mod-version-info">
      <div class="mod-version">${escapeHtml(mod.current_version)}</div>
      <div class="mod-filename">${escapeHtml(mod.filename)}</div>
    </div>
    <div>${col3Html}</div>
    <div class="mod-action">${toggleBtn}${actionBtnSlot}<div class="btn-slot"><button class="btn btn-danger" onclick="deleteMod(${idx})">Delete</button></div></div>`;
}

// ---------------- Version selector modal ----------------
// Renders one version's detail panel + footer action button. Shared by both
// the "update to latest" (single version) and "switch version" (full list,
// sidebar-driven) flows below - only the button's color/verb differ.
function renderVersionDetail(idx, v, btnClass, verb) {
  const mod = currentMods[idx];
  const primaryFile = v.files.find(f => f.primary) || v.files[0];
  const pubDate = new Date(v.date_published).toLocaleDateString("en-US", { month: "long", day: "numeric", year: "numeric" });
  const isCurrent = v.version_number === mod.current_version;

  $("modal-content-panel").innerHTML = `
    <div class="v-detail-header">
      <div class="v-detail-title">
        <span>${escapeHtml(v.version_number)}</span>
        <span class="v-type-tag ${v.version_type}">${escapeHtml(v.version_type)}</span>
      </div>
      <div class="v-detail-date">${pubDate}</div>
    </div>
    <div class="v-detail-meta">📄 Changelog • ${escapeHtml(currentInstance.loader)} ${escapeHtml(currentInstance.game_version)}</div>
    <div class="changelog-box">${escapeHtml(v.changelog || "No changelog provided.")}</div>`;

  $("modal-footer").innerHTML = `
    <button class="btn btn-secondary" onclick="closeVersionModal()">Cancel</button>
    <button class="btn ${btnClass}" ${isCurrent ? "disabled" : ""} onclick="applyVersionChange(${idx}, '${escapeAttr(primaryFile.url)}', '${escapeAttr(primaryFile.filename)}')">
      ${isCurrent ? "Current Version" : `${verb} ${escapeHtml(v.version_number)}`}
    </button>`;
}

async function openVersionSelector(idx, isUpdateOnly = false) {
  const mod = currentMods[idx];
  if (!mod || !mod.project_id || !currentInstance) return;

  let modal = $("version-modal");
  if (!modal) {
    modal = document.createElement("div");
    modal.id = "version-modal";
    modal.className = "modal-backdrop";
    document.body.appendChild(modal);
  }

  modal.innerHTML = `
    <div class="modal-card">
      <div class="modal-header">
        <div class="modal-header-title">
          ${iconImg(mod.icon_url, "mod-icon")}
          <span>${isUpdateOnly ? "Update version" : "Switch version"} - ${escapeHtml(mod.name)}</span>
        </div>
        <button class="modal-close" onclick="closeVersionModal()">&times;</button>
      </div>
      <div class="modal-body" id="modal-body-content"><div class="empty-msg" style="width:100%;">Loading versions...</div></div>
      <div class="modal-footer" id="modal-footer"><button class="btn btn-secondary" onclick="closeVersionModal()">Cancel</button></div>
    </div>`;
  modal.classList.add("active");

  try {
    const versions = await fetchProjectVersions(mod.project_id);
    if (!versions.length) {
      $("modal-body-content").innerHTML = `<div class="empty-msg" style="width:100%;">No compatible versions found.</div>`;
      return;
    }

    if (isUpdateOnly) {
      $("modal-body-content").innerHTML = `<div class="modal-content-panel" id="modal-content-panel"></div>`;
      renderVersionDetail(idx, versions[0], "btn-success", "Update to");
      return;
    }

    $("modal-body-content").innerHTML = `<div class="modal-sidebar" id="modal-sidebar"></div><div class="modal-content-panel" id="modal-content-panel"></div>`;
    const sidebar = $("modal-sidebar");

    const select = (v) => {
      renderVersionDetail(idx, v, "btn-primary", "Switch to");
      sidebar.querySelectorAll(".v-list-item").forEach((el, i) => el.classList.toggle("selected", versions[i].version_number === v.version_number));
    };

    versions.forEach((v) => {
      const isCurrent = v.version_number === mod.current_version;
      const item = document.createElement("div");
      item.className = `v-list-item ${isCurrent ? "is-current" : ""}`;
      item.innerHTML = `
        <div style="display:flex; align-items:center; gap:8px;">
          <div class="v-badge-circle ${v.version_type}">${(v.version_type || "release")[0].toUpperCase()}</div>
          <span class="v-item-title">${escapeHtml(v.version_number)}</span>
        </div>
        ${isCurrent ? `<span class="tag-current">Current</span>` : ""}`;
      item.onclick = () => select(v);
      sidebar.appendChild(item);
    });

    select(versions.find(v => v.version_number !== mod.current_version) || versions[0]);
  } catch (err) {
    $("modal-body-content").innerHTML = `<div class="empty-msg" style="width:100%;">Failed to load versions.</div>`;
  }
}

function closeVersionModal() { $("version-modal")?.classList.remove("active"); }

async function applyVersionChange(target, downloadUrl, newFilename, skipDiscordRefresh = false) {
  if (!currentInstance) return;
  closeVersionModal();

  const idx = typeof target === "number" ? target : currentMods.findIndex(m => m.filename === target.filename || (m.project_id && m.project_id === target.project_id));
  if (idx === -1 || !currentMods[idx]) return;

  const oldFilename = currentMods[idx].filename;
  setRowBusy(idx, true);
  enterBusy();

  try {
    const data = await postJSON("/api/mod/update", { instance: currentInstance.id, filename: oldFilename, download_url: downloadUrl, new_filename: newFilename });
    if (!data.success || !data.mod) throw new Error(data.error || "Unknown error");

    const curIdx = currentMods.findIndex(m => m.filename === oldFilename);
    if (curIdx !== -1) await refreshSingleMod(curIdx, data.mod);
    if (!skipDiscordRefresh) await refreshDiscordMessage();
  } catch (err) {
    alert("Update failed: " + err.message);
    const curIdx = currentMods.findIndex(m => m.filename === oldFilename);
    if (curIdx !== -1) setRowBusy(curIdx, false);
  } finally {
    exitBusy();
  }
}

async function refreshSingleMod(idx, updatedLocal) {
  try {
    currentMods[idx] = updatedLocal;
    const checkData = await postJSON("/api/mod/check", { instance: currentInstance.id, sha1: updatedLocal.sha1, filename: updatedLocal.filename });
    if (currentMods[idx]) Object.assign(currentMods[idx], checkData);
  } catch (e) {
    console.error("Single mod refresh failed", e);
  } finally {
    setRowBusy(idx, false);
    updateRowUI(idx);
    refreshUpdateAllButton();
  }
}

async function toggleMod(idx) {
  const mod = currentMods[idx];
  if (!currentInstance || !mod) return;
  const targetState = !mod.disabled;
  setRowBusy(idx, true);

  try {
    const data = await postJSON("/api/mod/toggle", { instance: currentInstance.id, filename: mod.filename, disabled: targetState });
    if (data.success) {
      mod.disabled = targetState;
      mod.filename = data.new_filename;
      updateRowUI(idx);
      refreshUpdateAllButton();
    } else {
      alert("Toggle failed: " + data.error);
    }
  } finally {
    setRowBusy(idx, false);
  }
}

async function deleteMod(idx) {
  const mod = currentMods[idx];
  if (!currentInstance || !mod || !confirm(`Delete ${mod.name}?`)) return;
  setRowBusy(idx, true);

  try {
    const data = await postJSON("/api/mod/delete", { instance: currentInstance.id, filename: mod.filename });
    if (data.success) {
      currentMods.splice(idx, 1);
      renderTable();
      refreshUpdateAllButton();
      refreshSearchResultsInstalledState();
    } else {
      alert("Delete failed: " + data.error);
      setRowBusy(idx, false);
    }
  } catch (e) {
    setRowBusy(idx, false);
  }
}

async function updateAllMods() {
  const targets = currentMods.filter(mod => !mod.disabled && mod.update_available);
  if (!targets.length) return;

  const btnUpdateAll = $("btn-update-all"), btnCheck = $("btn-check");
  showProgress();
  btnUpdateAll.disabled = true;
  btnCheck.disabled = true;

  let completed = 0;
  await runWithConcurrency(targets, 3, async (mod) => {
    await applyVersionChange(mod, mod.download_url, mod.new_filename, true);
    setProgress(++completed / targets.length);
  });

  await refreshDiscordMessage();
  btnCheck.disabled = false;
  refreshUpdateAllButton();
  hideProgressSoon();
}

function setRowBusy(idx, busy) { $(`mod-row-${idx}`)?.classList.toggle("is-busy", busy); }

function escapeHtml(str) { return str ? String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;") : ""; }
function escapeAttr(str) {
  return str ? String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/'/g, "&#39;").replace(/"/g, "&quot;") : "";
}
import os, json, time, base64, zipfile, hashlib, logging, random, tomllib, threading, secrets
from typing import Optional
from pathlib import Path
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from flask import Flask, jsonify, request, render_template, send_from_directory, Response, stream_with_context, session as flask_session, redirect, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

DATA_DIR = Path(os.environ.get("DATA_DIR", "data"))
INSTANCES_FILE = Path(os.environ.get("INSTANCES_FILE", DATA_DIR / "instances.json"))
WELCOMES_FILE = Path(os.environ.get("WELCOMES_FILE", DATA_DIR / "welcomes.txt"))
PUFFERPANEL_SERVERS_DIR = os.environ.get("SERVERS_DIR", "")
PUFFERPANEL_URL = os.environ.get("PANEL_URL", "").rstrip("/")
PUFFERPANEL_CLIENT_ID = os.environ.get("CLIENT_ID", "")
PUFFERPANEL_CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "")
MODRINTH_API = "https://api.modrinth.com/v2"
# SSRF guard: safe_download_and_replace() only ever fetches attacker-influenced
# URLs, so only these hosts are ever allowed as a download target.
ALLOWED_DOWNLOAD_HOSTS = {"cdn.modrinth.com"}
USER_AGENT = "besternos/mod-updater (contact: karisto)"
EXCLUDE_PREFIX = "$"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("mod_updater")

app = Flask(__name__)
# Caddy's handle_path strips "/updater" before proxying to us and re-adds it
# via X-Forwarded-Prefix instead - x_prefix=1 makes Werkzeug read that header
# and set SCRIPT_NAME, so request.script_root / url_for(...) (including the
# redirect(url_for("login"))/url_for("index") calls below) resolve to
# "/updater" automatically. Purely about the browser<->Caddy<->Flask path;
# has no bearing on verify_edit_files_permission() or is_server_running(),
# which call PUFFERPANEL_URL directly from Python and never touch Caddy.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Required for flask.session to be a real, tamper-proof signed cookie rather
# than falling back to a random per-process key (which would silently log
# everyone out on every restart, and worse, would sign sessions with a key
# an attacker could brute-force-guess was just "whatever Flask defaults to").
# Generate one with: python3 -c "import secrets; print(secrets.token_hex(32))"
# and put it in /etc/pufferpanel.env as FLASK_SECRET_KEY=...
_secret = os.environ.get("FLASK_SECRET_KEY")
if not _secret:
    log.warning("FLASK_SECRET_KEY not set - generating a random one for this "
                "process only. Every restart will invalidate all sessions. "
                "Set FLASK_SECRET_KEY in /etc/pufferpanel.env for real deployments.")
    _secret = secrets.token_hex(32)
app.secret_key = _secret
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # JS can never read this cookie - blocks XSS-based session theft
    SESSION_COOKIE_SAMESITE="Lax",  # blocks the classic cross-site form-POST CSRF pattern
    SESSION_COOKIE_SECURE=True,     # cookie only ever sent over HTTPS (Serveo terminates TLS)
    # Pinned, not left to Flask's default of deriving it from SCRIPT_NAME.
    # ProxyFix sets SCRIPT_NAME dynamically per-request from Caddy's
    # X-Forwarded-Prefix header - if that ever differs between the request
    # that sets this cookie and the request that clears it (a direct hit
    # bypassing Caddy, a config hiccup, testing locally vs. through the
    # proxy), the browser ends up holding two different session cookies
    # under two different paths instead of one. Logout only clears the one
    # matching the path it's called with, so the other looks "still logged
    # in" - a fixed Path="/" means every request, proxied or not, only ever
    # sets/reads/clears the exact same single cookie.
    SESSION_COOKIE_PATH="/",
)

SESSION_TTL_SECONDS = 8 * 3600  # re-verify permission at least once a day

def verify_edit_files_permission(access_token: str, server_id: str) -> tuple[bool, str]:
    """
    Real permission check against PufferPanel's own file API - not a guess.
    Writes a small marker file then immediately deletes it; both must
    succeed for the token to genuinely carry edit-files permission on this
    server, since PufferPanel itself is what's enforcing that, not us.

    Returns (verified: bool, detail: str). `detail` is "ok" on success,
    "denied" on a real 401/403, or a diagnostic string for anything else -
    callers must NOT treat a non-"denied" failure as proof of no permission,
    since it may just mean this probe's endpoint path doesn't match this
    PufferPanel version and needs checking, not that the user lacks access.
    """
    headers = {"Authorization": f"Bearer {access_token}"}
    marker_path = f".mod-updater-permission-check-{secrets.token_hex(4)}"
    # Confirmed from a live browser DevTools capture of PufferPanel 3.0.9's
    # own file manager editing a file: PUT/GET/DELETE all hit
    # "/api/servers/{id}/file/{path}" - singular "file", not "files" (the
    # earlier guess) and not "/daemon/server/..." either (the other guess).
    write_url = f"{PUFFERPANEL_URL}/api/servers/{server_id}/file/mods/{marker_path}"

    try:
        r = session.put(write_url, data=b"permission check\n", headers=headers, timeout=10)
    except Exception as e:
        return False, f"could not reach panel: {e}"

    if r.status_code in (401, 403):
        return False, "denied"
    if r.status_code not in (200, 201, 204):
        log.warning("Permission probe write got unexpected status %s for server %s: %s",
                    r.status_code, server_id, r.text[:300])
        return False, f"unexpected response ({r.status_code}) - check PufferPanel API compatibility"

    try:
        session.delete(write_url, headers=headers, timeout=10)
    except Exception as e:
        log.warning("Permission probe cleanup failed for server %s: %s", server_id, e)

    return True, "ok"

PUBLIC_PATHS = {"/login", "/favicon.ico"}

@app.before_request
def require_login():
    """
    Deliberately a global gate, not a per-route decorator - decorators are
    opt-in and it's easy to add a new route later and forget to protect it.
    This protects every route by default; only /login, static assets, and
    the favicon are reachable without a verified session.
    """
    if request.path in PUBLIC_PATHS or request.path.startswith("/static/"):
        return None
    auth = flask_session.get("auth")
    if not auth or time.time() - auth.get("verified_at", 0) > SESSION_TTL_SECONDS:
        if request.path.startswith("/api/"):
            return jsonify({"error": "Not authenticated"}), 401
        return redirect(url_for("login"))
    return None

@app.after_request
def log_request(response):
    # One line per request in journalctl -f: method, path, status, timing.
    # Skips static asset noise so real activity doesn't get buried.
    if not request.path.startswith("/static/"):
        log.info("%s %s -> %s", request.method, request.path, response.status_code)

    # Deliberately conservative - not shipping a Content-Security-Policy here,
    # since a wrong CSP can silently break legitimate functionality (inline
    # scripts, external Modrinth API calls) in ways that are hard to notice.
    # These two are safe with no plausible downside:
    response.headers["X-Content-Type-Options"] = "nosniff"
    # SAMEORIGIN, not DENY - the PufferPanel integration iframes this app
    # from the same origin (via the Caddy proxy), which SAMEORIGIN still
    # permits; it only blocks a *different* origin from framing this app.
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "same-origin"
    return response
session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})
DATA_DIR.mkdir(parents=True, exist_ok=True)

def log_startup_banner():
    """Logged once at boot so `journalctl -u mod-updater -n 20` after any
    restart immediately shows the effective config - which directory it's
    actually running from, whether PufferPanel env vars came through, etc.
    Directly useful for exactly the kind of CHDIR/env mismatch already hit."""
    log.info("=" * 60)
    log.info("Mod Updater starting")
    log.info("cwd: %s", os.getcwd())
    log.info("script dir: %s", Path(__file__).resolve().parent)
    log.info("DATA_DIR: %s (exists: %s)", DATA_DIR.resolve(), DATA_DIR.is_dir())
    log.info("INSTANCES_FILE: %s", INSTANCES_FILE.resolve())
    log.info("PUFFERPANEL_URL: %s", PUFFERPANEL_URL or "(not set)")
    log.info("PUFFERPANEL_CLIENT_ID: %s", "(set)" if PUFFERPANEL_CLIENT_ID else "(not set)")
    log.info("SERVERS_DIR: %s", PUFFERPANEL_SERVERS_DIR or "(not set - using instances.json only)")
    log.info("=" * 60)

log_startup_banner()

def sha1_of(path: Path) -> str:
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

# ---------------- INSTANCES ----------------
def save_instances(instances: list):
    INSTANCES_FILE.write_text(json.dumps({"instances": instances}, indent=2), encoding="utf-8")

def _pufferpanel_signature() -> tuple:
    """A cheap fingerprint of PufferPanel's server directory state - just
    each server dir's name plus its definition file's mtime. As long as this
    doesn't change between calls, nothing was added, removed, or modified,
    so load_instances() can skip the expensive rescan+merge+rewrite entirely."""
    root = Path(PUFFERPANEL_SERVERS_DIR)
    if not PUFFERPANEL_SERVERS_DIR or not root.is_dir():
        return ()
    sig = []
    for server_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        def_file = root / f"{server_dir.name}.json"
        if def_file.is_file():
            icon_file = server_dir / "world" / "icon.png"
            icon_mtime = icon_file.stat().st_mtime_ns if icon_file.is_file() else None
            sig.append((server_dir.name, def_file.stat().st_mtime_ns, icon_mtime))
    return tuple(sig)

def _pufferpanel_instances() -> list:
    root = Path(PUFFERPANEL_SERVERS_DIR)
    if not PUFFERPANEL_SERVERS_DIR or not root.is_dir():
        return []
    found = []
    for server_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        def_file = root / f"{server_dir.name}.json"
        if not def_file.is_file():
            continue
        try:
            defn = json.loads(def_file.read_text(encoding="utf-8"))
            data = defn.get("data", {})
            loader_raw = (data.get("modlauncher", {}) or {}).get("value", "")
            world_icon = server_dir / "world" / "icon.png"
            found.append({
                "id": server_dir.name,
                "name": defn.get("display") or server_dir.name,
                "mods_dir": str(server_dir / "mods"),
                "loader": loader_raw.lower() if loader_raw else "neoforge",
                "game_version": (data.get("version", {}) or {}).get("value", ""),
                # Only set when the world actually has one - an empty string
                # here must NOT clobber a manually-configured icon during the
                # merge below (see load_instances()).
                "icon": f"/api/instance/{server_dir.name}/icon" if world_icon.is_file() else "",
                "webhook_url": "",
            })
        except Exception as e:
            log.warning("Skipping PufferPanel server %s: %s", server_dir.name, e)
    return found

_instances_cache = {"signature": None, "instances": None}

def load_instances() -> list:
    sig = _pufferpanel_signature()
    if _instances_cache["signature"] == sig and _instances_cache["instances"] is not None:
        return _instances_cache["instances"]

    # Signature changed (or first call this run) - do the full merge+persist pass.
    saved = []
    if INSTANCES_FILE.is_file():
        try:
            saved = json.loads(INSTANCES_FILE.read_text(encoding="utf-8")).get("instances", [])
        except Exception as e:
            log.error("Failed reading instances.json: %s", e)

    puffer = _pufferpanel_instances()
    instances_map = {i["id"]: i for i in saved}

    for p in puffer:
        sid = p["id"]
        if sid in instances_map:
            update = {
                "name": p["name"], "mods_dir": p["mods_dir"],
                "loader": p["loader"], "game_version": p["game_version"],
            }
            # A found world/icon.png always wins (it's the live source of
            # truth for that instance's icon). An absent one is NOT written
            # here - p["icon"] would be "" in that case, and blindly copying
            # it over would erase a manually-configured icon in
            # instances.json on every single refresh.
            # A found world/icon.png always wins (it's the live source of
            # truth for that instance's icon). An absent one only clears the
            # field if what's cached is our own previously-auto-detected URL
            # for this instance - if the icon.png that generated it is gone,
            # the cached URL now 404s on every request (exactly what showed
            # up in the logs). A genuinely manual icon (any other value -
            # emoji, data URI, custom URL) never matches that exact pattern,
            # so it's left untouched either way.
            auto_url = f"/api/instance/{sid}/icon"
            if p["icon"] or instances_map[sid].get("icon") == auto_url:
                update["icon"] = p["icon"]
            instances_map[sid].update(update)
        else:
            instances_map[sid] = p

    merged = list(instances_map.values())
    try:
        save_instances(merged)
    except Exception as e:
        log.warning("Could not sync instances.json: %s", e)

    _instances_cache["signature"] = sig
    _instances_cache["instances"] = merged
    return merged

def get_instance(instance_id: str) -> dict | None:
    return next((i for i in load_instances() if i.get("id") == instance_id), None) if instance_id else None

def get_authorized_instance(instance_id: str) -> dict | None:
    """
    Like get_instance(), but also enforces that the CURRENTLY LOGGED IN
    session was actually verified (via verify_edit_files_permission) to have
    edit-files permission on this specific instance. Every route that takes
    an instance_id must resolve it through this, not get_instance() directly,
    or per-instance access control would be bypassable simply by knowing
    another instance's id while logged in with a client only permitted on one.
    """
    inst = get_instance(instance_id)
    if inst is None:
        return None
    auth = flask_session.get("auth") or {}
    if instance_id not in auth.get("instances", []):
        return None
    return inst

# ---------------- PUFFERPANEL SERVER STATUS ----------------
# Mirrors the get_token()/is_running() logic from the shutdown script: same
# OAuth2 client_credentials flow, same GET /api/servers/{id}/status shape.
# Used to lock out mod changes while a server is actually up, per-instance,
# by matching instance id -> PufferPanel server id (they're the same id -
# see _pufferpanel_instances() above).
_pp_token_cache = {"token": None, "expires_at": 0.0}
_pp_token_lock = threading.Lock()

def _pufferpanel_token() -> str | None:
    if not (PUFFERPANEL_URL and PUFFERPANEL_CLIENT_ID and PUFFERPANEL_CLIENT_SECRET):
        return None
    now = time.time()
    with _pp_token_lock:
        if _pp_token_cache["token"] and now < _pp_token_cache["expires_at"]:
            return _pp_token_cache["token"]
        try:
            r = session.post(f"{PUFFERPANEL_URL}/oauth2/token", data={
                "grant_type": "client_credentials",
                "client_id": PUFFERPANEL_CLIENT_ID,
                "client_secret": PUFFERPANEL_CLIENT_SECRET,
            }, timeout=10)
            r.raise_for_status()
            token = r.json().get("access_token")
            if not token:
                return None
            expires_in = r.json().get("expires_in", 300)
            # Refresh a bit early rather than riding the token right up to expiry.
            _pp_token_cache.update(token=token, expires_at=now + max(int(expires_in) - 30, 30))
            return token
        except Exception as e:
            log.warning("PufferPanel token request failed: %s", e)
            return None

def is_server_running(instance_id: str) -> bool | None:
    """True/False if the panel gave a definite answer, None if it couldn't
    be determined (no panel configured for this deployment, auth failure,
    network error, or an instance that just isn't a PufferPanel server).
    Callers fail open on None - a lock can only ever engage on a confirmed
    True, never on "couldn't check"."""
    if not PUFFERPANEL_URL:
        return None
    token = _pufferpanel_token()
    if not token:
        return None
    try:
        r = session.get(f"{PUFFERPANEL_URL}/api/servers/{instance_id}/status",
                         headers={"Authorization": f"Bearer {token}"}, timeout=10)
        r.raise_for_status()
        return bool(r.json().get("running"))
    except Exception as e:
        log.warning("PufferPanel status check failed for %s: %s", instance_id, e)
        return None

def guard_server_running(inst: dict):
    """Short-circuit helper for routes that touch the mods folder. Returns
    a Flask (jsonify(...), status) tuple to return immediately if the
    instance's server is confirmed running, else None to proceed."""
    if is_server_running(inst["id"]):
        return jsonify({"success": False, "error": "Server is running - stop it before changing mods."}), 423
    return None

def mods_dir_for(inst: dict) -> Path:
    d = Path(inst["mods_dir"])
    d.mkdir(parents=True, exist_ok=True)
    return d

# ---------------- PER-INSTANCE DATA FILE ----------------
def data_file_path(instance_id: str) -> Path:
    safe_id = "".join(c for c in instance_id if c.isalnum() or c in "-_") or "instance"
    return DATA_DIR / f"{safe_id}_data.txt"

def load_instance_data(instance_id: str) -> dict:
    path = data_file_path(instance_id)
    memory = {}
    if not path.is_file():
        return memory
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        excluded = line.startswith(EXCLUDE_PREFIX)
        if excluded:
            line = line[len(EXCLUDE_PREFIX):].strip()

        parts = [p.strip() for p in line.split(" - ")]
        if len(parts) < 3:
            continue

        pid, filename, curr_ver = parts[0], parts[1], parts[2]
        version = parts[3] if len(parts) >= 4 else curr_ver
        if version == "Unknown" or not version:
            version = curr_ver

        memory[pid] = {
            "filename": filename,
            "installed_version": curr_ver,
            "version": version,
            "excluded": excluded,
        }
    return memory

def save_instance_data(instance_id: str, memory: dict, inst: dict | None = None):
    inst = inst or get_instance(instance_id) or {}
    header = [
        f"# instance: {instance_id}", f"# name: {inst.get('name', instance_id)}",
        f"# loader: {inst.get('loader', '')}", f"# game_version: {inst.get('game_version', '')}",
        f"# updated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}", "#",
    ]
    rows = sorted(memory.items(), key=lambda kv: kv[1].get("filename", "").casefold())
    lines = []
    for pid, info in rows:
        inst_v = info.get('installed_version', '') or 'Unknown'
        target_v = info.get('version', '') or ''
        if not target_v or target_v == "Unknown":
            target_v = inst_v
        lines.append(
            f"{EXCLUDE_PREFIX if info.get('excluded') else ''}{pid} - {info.get('filename', '')} - {inst_v} - {target_v}"
        )
    data_file_path(instance_id).write_text("\n".join(header + lines) + "\n", encoding="utf-8")

def upsert_instance_entry(memory: dict, project_id: str, *, filename: str | None = None,
                           installed_version: str | None = None, target_version: str | None = None,
                           create_if_missing: bool = True) -> bool:
    """
    Mutates `memory` in place for one project id. Shared by every route that
    touches a mod's entry (single check, batch check, discord pending/send,
    single update, toggle) so the "load, find-or-create, preserve excluded
    flag, only set the fields actually given, save if changed" logic exists
    in exactly one place instead of six slightly-different copies of it.
    Returns True if `memory` was actually changed (caller decides whether
    that's worth a save_instance_data() call).
    """
    existing = memory.get(project_id)

    if existing is None:
        if not create_if_missing:
            return False
        inst_v = installed_version if installed_version else "Unknown"
        tgt_v = target_version if target_version else inst_v
        memory[project_id] = {
            "filename": filename or "",
            "installed_version": inst_v,
            "version": tgt_v if tgt_v != "Unknown" else inst_v,
            "excluded": False,
        }
        return True

    changed = False
    if filename and existing.get("filename") != filename:
        existing["filename"] = filename
        changed = True
    if installed_version is not None:
        if existing.get("installed_version") != installed_version:
            existing["installed_version"] = installed_version
            changed = True
    if target_version is not None:
        if existing.get("version") != target_version:
            existing["version"] = target_version
            changed = True
    return changed

def entries_with_filename(memory: dict, filename: str) -> list:
    """Both toggle (rename) and delete (remove) need to find every data-file
    entry pointing at a given filename - factored out since duplicating this
    scan in both routes was one of the two remaining copy-pasted patterns."""
    return [pid for pid, info in memory.items() if info.get("filename") == filename]

def safe_mods_path(mods_dir: Path, filename: str) -> Path | None:
    if not filename:
        return None
    candidate = (mods_dir / Path(filename).name).resolve()
    try:
        candidate.relative_to(mods_dir.resolve())
        return candidate
    except ValueError:
        return None

# ---------------- LOCAL JAR PARSING ----------------
def extract_jar_metadata(jar_path: Path) -> dict:
    meta = {
        "filename": jar_path.name, "sha1": sha1_of(jar_path),
        "name": jar_path.name.replace(".jar.disabled", "").replace(".jar", ""),
        "current_version": "Unknown", "author": "Unknown Creator",
        "icon_url": None, "disabled": jar_path.name.endswith(".jar.disabled"),
        "on_modrinth": False, "update_available": False
    }

    if not jar_path.is_file():
        return meta

    try:
        with zipfile.ZipFile(jar_path, 'r') as z:
            zmap = {f.lower(): f for f in z.namelist()}
            logo_path = None

            toml_key = next((k for k in ["meta-inf/neoforge.mods.toml", "meta-inf/mods.toml"] if k in zmap), None)
            if toml_key:
                try:
                    with z.open(zmap[toml_key]) as f:
                        parsed = tomllib.load(f)
                    m = parsed.get("mods", [{}])[0] if isinstance(parsed.get("mods"), list) and parsed.get("mods") else {}
                    meta["name"] = m.get("displayName") or parsed.get("displayName") or meta["name"]
                    ver = m.get("version") or parsed.get("version")
                    if ver and not str(ver).startswith("${"):
                        meta["current_version"] = str(ver)
                    auth = m.get("authors") or m.get("author") or parsed.get("authors")
                    if auth:
                        meta["author"] = ", ".join(str(a) for a in auth) if isinstance(auth, list) else str(auth)
                    logo_path = m.get("logoFile") or parsed.get("logoFile")
                except Exception:
                    pass

            fab_key = next((k for k in ["fabric.mod.json", "quilt.mod.json"] if k in zmap), None)
            if fab_key and (meta["current_version"] == "Unknown" or meta["current_version"].startswith("${")):
                try:
                    with z.open(zmap[fab_key]) as f:
                        data = json.load(f)
                    meta["name"] = data.get("name", meta["name"])
                    if data.get("version"):
                        meta["current_version"] = str(data["version"])
                    auths = data.get("authors", [])
                    if isinstance(auths, list) and auths:
                        meta["author"] = ", ".join(a.get("name", a) if isinstance(a, dict) else str(a) for a in auths)
                    elif isinstance(auths, str):
                        meta["author"] = auths
                    logo_path = logo_path or data.get("icon")
                except Exception:
                    pass

            cands = ([logo_path.strip().lstrip("/")] if logo_path else []) + ["assets/icon.png", "icon.png", "logo.png"]
            for cand in cands:
                if cand.lower() in zmap:
                    real = zmap[cand.lower()]
                    with z.open(real) as f:
                        mime = "image/jpeg" if real.lower().endswith((".jpg", ".jpeg")) else "image/png"
                        meta["icon_url"] = f"data:{mime};base64,{base64.b64encode(f.read()).decode('utf-8')}"
                        break
    except Exception as e:
        log.error("Failed zip extraction for %s: %s", jar_path.name, e)

    return meta

# ---------------- MODRINTH HELPERS ----------------
_project_cache: dict[str, tuple[float, dict]] = {}

def get_project(project_id):
    now = time.time()
    if project_id in _project_cache and now - _project_cache[project_id][0] < 300:
        return _project_cache[project_id][1]
    try:
        r = session.get(f"{MODRINTH_API}/project/{project_id}", timeout=10)
        r.raise_for_status()
        data = r.json()
        _project_cache[project_id] = (now, data)
        return data
    except Exception:
        return {}

def get_project_author(project):
    org_id = project.get("organization")
    if org_id:
        try:
            r = session.get(f"{MODRINTH_API}/organization/{org_id}", timeout=5)
            if r.status_code == 200:
                return r.json().get("name")
        except Exception:
            pass

    team_id = project.get("team")
    if team_id:
        try:
            r = session.get(f"{MODRINTH_API}/team/{team_id}/members", timeout=5)
            if r.status_code == 200:
                members = r.json()
                if isinstance(members, list) and members:
                    owner = next((m for m in members if str(m.get("role", "")).lower() in ["owner", "creator", "leader"]), members[0])
                    u = owner.get("user", {})
                    return u.get("name") or u.get("username")
        except Exception:
            pass
    return None

def get_compatible_versions(project_id, loader, game_version):
    try:
        r = session.get(f"{MODRINTH_API}/project/{project_id}/version", 
                        params={"loaders": json.dumps([loader]), "game_versions": json.dumps([game_version])}, timeout=15)
        r.raise_for_status()
        return r.json()
    except Exception:
        return []

def safe_download_and_replace(mods_dir: Path, old_filename: str | None, download_url: str, new_filename: str) -> bool:
    from urllib.parse import urlparse
    parsed = urlparse(download_url or "")
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_DOWNLOAD_HOSTS:
        # This URL ultimately comes from a client request body. Without this
        # check, an attacker could point it at an internal address (e.g.
        # http://127.0.0.1:8081/...) and have this server fetch it and write
        # the response into the mods folder - an SSRF + arbitrary-write
        # primitive. Only Modrinth's actual CDN is ever a legitimate target.
        raise ValueError(f"Download URL host not allowed: {parsed.hostname!r}")

    old_path = safe_mods_path(mods_dir, old_filename) if old_filename else None
    new_path = safe_mods_path(mods_dir, new_filename)
    if not new_path:
        raise ValueError("Invalid new_filename")
    tmp_path = new_path.with_name(new_path.name + ".tmp")

    with session.get(download_url, stream=True, timeout=60) as r:
        r.raise_for_status()
        with open(tmp_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=65536):
                f.write(chunk)

    if old_path and old_path.exists() and old_path != new_path:
        old_path.unlink()

    if tmp_path.exists():
        if new_path.exists():
            new_path.unlink()
        tmp_path.rename(new_path)
    return True

def resolve_by_sha1(sha1: str) -> dict | None:
    try:
        r = session.get(f"{MODRINTH_API}/version_file/{sha1}", timeout=10)
        return r.json() if r.status_code == 200 else None
    except Exception:
        return None

def resolve_project_status(project_id: str, current_version: Optional[str], loader: str, game_version: str, fallback_icon: Optional[str] = None) -> dict:
    with ThreadPoolExecutor(max_workers=2) as ex:
        p_fut = ex.submit(get_project, project_id)
        v_fut = ex.submit(get_compatible_versions, project_id, loader, game_version)
        project, versions = p_fut.result(), v_fut.result()

    modrinth_author = get_project_author(project)
    latest = versions[0] if versions else None
    
    curr = current_version or None
    latest_num = latest.get("version_number") if latest else None
    update_available = bool(latest_num) and bool(curr) and latest_num != curr

    primary_file = next((f for f in latest["files"] if f.get("primary")), latest["files"][0]) if latest else None

    res = {
        "on_modrinth": True, "project_id": project_id, "name": project.get("title"),
        "icon_url": project.get("icon_url") or fallback_icon, 
        "current_version": curr,
        "latest_version": latest_num,
        "update_available": update_available,
        "download_url": primary_file["url"] if primary_file and update_available else None,
        "new_filename": primary_file["filename"] if primary_file and update_available else None,
    }
    if modrinth_author:
        res["author"] = modrinth_author
    return res

# ---------------- ROUTES ----------------
from datetime import timedelta
app.permanent_session_lifetime = timedelta(seconds=SESSION_TTL_SECONDS)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", panel_url=PUFFERPANEL_URL, error=None)

    client_id = request.form.get("client_id", "").strip()
    client_secret = request.form.get("client_secret", "").strip()
    if not client_id or not client_secret:
        return render_template("login.html", panel_url=PUFFERPANEL_URL, error="Client ID and secret are required.")

    try:
        r = session.post(f"{PUFFERPANEL_URL}/oauth2/token", data={
            "grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret,
        }, timeout=10)
    except Exception as e:
        return render_template("login.html", panel_url=PUFFERPANEL_URL, error=f"Could not reach PufferPanel: {e}")

    if r.status_code != 200:
        log.info("Login failed for client %s: token exchange returned %s", client_id, r.status_code)
        return render_template("login.html", panel_url=PUFFERPANEL_URL, error="Invalid client ID or secret.")

    token = (r.json() or {}).get("access_token")
    if not token:
        return render_template("login.html", panel_url=PUFFERPANEL_URL, error="PufferPanel did not return an access token.")

    granted, diagnostics = [], []
    for inst in load_instances():
        ok, detail = verify_edit_files_permission(token, inst["id"])
        if ok:
            granted.append(inst["id"])
        elif detail != "denied":
            diagnostics.append(f"{inst.get('name', inst['id'])}: {detail}")

    if not granted:
        msg = "This client doesn't have 'Can edit files' permission on any configured instance."
        if diagnostics:
            msg += " Some checks couldn't be completed - " + "; ".join(diagnostics)
        log.warning("Login denied for client %s - no instances granted. %s", client_id, diagnostics)
        return render_template("login.html", panel_url=PUFFERPANEL_URL, error=msg)

    flask_session.clear()
    flask_session.permanent = True
    flask_session["auth"] = {"client_id": client_id, "instances": granted, "verified_at": time.time()}
    log.info("Login granted for client %s on instances: %s", client_id, granted)
    return redirect(url_for("index"))

@app.route("/logout", methods=["POST"])
def logout():
    log.info("Logout for client %s", (flask_session.get("auth") or {}).get("client_id", "?"))
    flask_session.clear()
    resp = redirect(url_for("login"))
    # Belt-and-suspenders: Flask's session interface already deletes the
    # cookie on an emptied session (using SESSION_COOKIE_PATH above), but
    # explicitly overwriting it here guarantees the browser drops it even
    # if a cookie from before that fix is still lingering at Path=/.
    resp.delete_cookie(app.config.get("SESSION_COOKIE_NAME", "session"), path="/")
    return resp

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/instances", methods=["GET"])
def api_get_instances():
    authorized_ids = set((flask_session.get("auth") or {}).get("instances", []))
    return jsonify([{
        "id": i["id"], "name": i.get("name", i["id"]), "loader": i.get("loader", ""),
        "game_version": i.get("game_version", ""), "icon": i.get("icon", ""), "has_webhook": bool(i.get("webhook_url")),
    } for i in load_instances() if i["id"] in authorized_ids])

@app.route("/api/welcome-phrase", methods=["GET"])
def api_get_welcome_phrase():
    if WELCOMES_FILE.is_file():
        try:
            lines = [l.strip() for l in WELCOMES_FILE.read_text(encoding="utf-8").splitlines() if l.strip()]
            if lines:
                return jsonify({"phrase": random.choice(lines)})
        except Exception as e:
            log.warning("Failed to read welcomes.txt: %s", e)
    return jsonify({"phrase": "Fresh updates have just been deployed!"})

@app.route('/favicon.ico')
def favicon():
    return send_from_directory('static', 'favicon.svg', mimetype='image/svg+xml')

@app.route("/api/excluded", methods=["GET"])
def api_get_excluded():
    inst = get_authorized_instance(request.args.get("instance", ""))
    return (jsonify({"error": "Unknown instance"}), 404) if not inst else jsonify(sorted(pid for pid, info in load_instance_data(inst["id"]).items() if info["excluded"]))

@app.route("/api/discord/pending", methods=["POST"])
def api_discord_pending():
    body = request.get_json(silent=True) or {}
    inst = get_authorized_instance(body.get("instance", ""))
    if not inst:
        return jsonify({"error": "Unknown instance"}), 404

    memory, pending, changed = load_instance_data(inst["id"]), [], False
    for m in body.get("mods", []):
        pid, fn = m.get("project_id"), m.get("filename", "")
        curr_ver = m.get("current_version") or ""
        if not pid or not curr_ver or curr_ver == "Unknown":
            continue

        entry = memory.get(pid)
        if entry is None:
            # First time seeing this mod - seed it at its current version so
            # it doesn't show as a false "update" the first time it's checked.
            changed |= upsert_instance_entry(memory, pid, filename=fn, installed_version=curr_ver)
            continue
        if entry.get("excluded"):
            continue

        baseline = entry.get("version") or entry.get("installed_version") or ""
        if baseline == "Unknown":
            baseline = curr_ver

        if baseline != curr_ver:
            pending.append({"project_id": pid, "name": m.get("name") or pid, "from_version": baseline, "to_version": curr_ver})

        changed |= upsert_instance_entry(memory, pid, filename=fn, installed_version=curr_ver, create_if_missing=False)

    if changed:
        save_instance_data(inst["id"], memory, inst)
    return jsonify({"pending": pending})

@app.route("/api/webhook/send", methods=["POST"])
def api_send_webhook():
    data = request.get_json(silent=True) or {}
    inst = get_authorized_instance(data.get("instance", ""))
    if not inst:
        return jsonify({"success": False, "error": "Unknown instance"}), 404

    webhook_url = data.get("webhook_url") or inst.get("webhook_url") or ""
    content = data.get("content", "").strip()
    if not webhook_url or not content:
        return jsonify({"success": False, "error": "Missing parameters"}), 400

    try:
        r = session.post(webhook_url, json={"content": content}, timeout=10)
        r.raise_for_status()
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

    updates = data.get("updates", [])
    if updates:
        memory = load_instance_data(inst["id"])
        for u in updates:
            pid = u.get("project_id")
            if pid:
                to_ver = u.get("to_version") or ""
                upsert_instance_entry(memory, pid, filename=u.get("filename"),
                                       installed_version=to_ver, target_version=to_ver)
        save_instance_data(inst["id"], memory, inst)

    return jsonify({"success": True})

@app.route("/api/instance/<instance_id>/icon")
def api_instance_icon(instance_id):
    inst = get_authorized_instance(instance_id)
    if not inst or not PUFFERPANEL_SERVERS_DIR:
        return ("", 404)

    icon_path = (Path(PUFFERPANEL_SERVERS_DIR) / instance_id / "world" / "icon.png").resolve()
    try:
        icon_path.relative_to(Path(PUFFERPANEL_SERVERS_DIR).resolve())
    except ValueError:
        return ("", 404)
    if not icon_path.is_file():
        return ("", 404)

    # conditional=True lets Flask answer with 304s off If-Modified-Since/ETag,
    # so a refresh that finds nothing new doesn't re-ship the image.
    return send_from_directory(icon_path.parent, icon_path.name, mimetype="image/png", conditional=True)

@app.route("/api/mods/local", methods=["GET"])
def api_get_local_mods():
    inst = get_authorized_instance(request.args.get("instance", ""))
    if not inst:
        return jsonify({"error": "Unknown instance", "mods": []}), 404
    mods_dir = mods_dir_for(inst)
    jar_files = sorted(p for p in mods_dir.iterdir() if p.is_file() and (p.name.endswith(".jar") or p.name.endswith(".jar.disabled")))
    return jsonify({"error": None, "mods": [extract_jar_metadata(p) for p in jar_files]})

@app.route("/api/mod/add", methods=["POST"])
def api_add_mod():
    data = request.get_json(silent=True) or {}
    inst, url, fn = get_authorized_instance(data.get("instance", "")), data.get("download_url"), data.get("filename")
    if not inst or not isinstance(url, str) or not isinstance(fn, str):
        return jsonify({"success": False, "error": "Missing parameters"}), 400
    if (guard := guard_server_running(inst)) is not None:
        return guard
    try:
        mods_dir = mods_dir_for(inst)
        safe_download_and_replace(mods_dir, None, url, fn)
        return jsonify({"success": True, "mod": extract_jar_metadata(mods_dir / fn)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/mod/toggle", methods=["POST"])
def api_toggle_mod():
    data = request.get_json(silent=True) or {}
    inst, fn, target_disabled = get_authorized_instance(data.get("instance", "")), data.get("filename"), data.get("disabled")
    if not inst or not fn or target_disabled is None:
        return jsonify({"success": False, "error": "Missing parameters"}), 400
    if (guard := guard_server_running(inst)) is not None:
        return guard

    mods_dir = mods_dir_for(inst)
    old_path = safe_mods_path(mods_dir, fn)
    if not old_path or not old_path.exists():
        return jsonify({"success": False, "error": "File not found"}), 404

    new_fn = f"{fn}.disabled" if target_disabled and not fn.endswith(".disabled") else (fn[:-9] if not target_disabled and fn.endswith(".disabled") else fn)
    new_path = mods_dir / new_fn

    if old_path != new_path:
        old_path.rename(new_path)
        memory = load_instance_data(inst["id"])
        matched = entries_with_filename(memory, fn)
        for pid in matched:
            memory[pid]["filename"] = new_fn
        if matched:
            save_instance_data(inst["id"], memory, inst)

    return jsonify({"success": True, "new_filename": new_fn})

@app.route("/api/mod/delete", methods=["POST"])
def api_delete_mod():
    data = request.get_json(silent=True) or {}
    inst, fn = get_authorized_instance(data.get("instance", "")), data.get("filename")
    if not inst or not fn:
        return jsonify({"success": False, "error": "Missing parameters"}), 400
    if (guard := guard_server_running(inst)) is not None:
        return guard

    target = safe_mods_path(mods_dir_for(inst), fn)
    if target and target.exists():
        target.unlink()
        memory = load_instance_data(inst["id"])
        matched = entries_with_filename(memory, fn)
        if matched:
            for pid in matched:
                del memory[pid]
            save_instance_data(inst["id"], memory, inst)
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "File not found"}), 404

@app.route("/api/mod/check", methods=["POST"])
def api_check_single_mod():
    body = request.get_json(silent=True) or {}
    inst, sha1, fn = get_authorized_instance(body.get("instance", "")), body.get("sha1"), body.get("filename")
    if not inst or not sha1 or not fn:
        return jsonify({"error": "Missing parameters"}), 400

    vdata = resolve_by_sha1(sha1)
    if not vdata:
        return jsonify({"on_modrinth": False, "debug": f"SHA1 '{sha1}' not found."})

    pid = vdata["project_id"]
    res = resolve_project_status(pid, vdata.get("version_number"), inst["loader"], inst["game_version"])

    memory = load_instance_data(inst["id"])
    # Only installed_version moves here - the broadcast target version is
    # deliberately left untouched (preserved by upsert when not passed),
    # only advancing once a Discord send actually happens.
    upsert_instance_entry(memory, pid, filename=fn, installed_version=res.get("current_version") or "")
    save_instance_data(inst["id"], memory, inst)

    return jsonify(res)

@app.route("/api/mods/check", methods=["POST"])
def api_check_mods_batch():
    body = request.get_json(silent=True) or {}
    inst, mode = get_authorized_instance(body.get("instance", "")), body.get("mode", "full")
    stream_requested = body.get("stream", False) or request.args.get("stream") == "true"
    if not inst:
        return jsonify({"error": "Unknown instance", "mods": []}), 404

    mods_dir = mods_dir_for(inst)
    jar_files = sorted(p for p in mods_dir.iterdir() if p.is_file() and (p.name.endswith(".jar") or p.name.endswith(".jar.disabled"))) if mods_dir.is_dir() else []
    local_mods = [extract_jar_metadata(p) for p in jar_files]

    if not local_mods:
        save_instance_data(inst["id"], {}, inst)
        return jsonify({"error": None, "mods": [], "no_mods": True})

    memory = load_instance_data(inst["id"])
    fn_map = {info["filename"]: (pid, info) for pid, info in memory.items() if info.get("filename")}

    def resolve_one(mod: dict):
        fn = mod["filename"]
        cached = fn_map.get(fn)
        fallback_icon = mod.get("icon_url")

        if cached:
            pid, info = cached
            # Prefer the persisted, already-Modrinth-verified version over
            # the raw jar-embedded one - it's the clean source of truth once
            # a mod has been resolved even once, no guessing needed.
            curr_ver = info.get("installed_version") or info.get("version") or mod.get("current_version") or ""

            if mode == "full":
                res = resolve_project_status(pid, curr_ver, inst["loader"], inst["game_version"], fallback_icon=fallback_icon)
                res["name"] = res.get("name") or mod.get("name") or pid
                res["icon_url"] = res.get("icon_url") or fallback_icon
                mod.update(res)
            else:
                mod.update({
                    "on_modrinth": True, "project_id": pid, "name": mod.get("name") or pid,
                    "current_version": curr_ver, "latest_version": None, "update_available": False,
                    "download_url": None, "new_filename": None, "icon_url": fallback_icon
                })
            return mod

        # Not cached (new/unknown mod) - always try to identify it via
        # Modrinth regardless of mode. Skipping this in diff mode would mean
        # a newly-added jar never surfaces as trackable until someone
        # happens to click the full Check button.
        vdata = resolve_by_sha1(mod["sha1"])
        if vdata:
            pid = vdata["project_id"]
            res = resolve_project_status(pid, vdata.get("version_number") or mod.get("current_version"), inst["loader"], inst["game_version"], fallback_icon=fallback_icon)
            res["name"] = res.get("name") or mod.get("name") or pid
            res["icon_url"] = res.get("icon_url") or fallback_icon
            mod.update(res)
        return mod

    def update_memory_state():
        local_fns = {m["filename"] for m in local_mods}
        # Prune entries for mods no longer physically present (deleted outside
        # the app) before upserting the ones that are still here.
        mem = {pid: info for pid, info in memory.items() if info.get("filename") in local_fns}

        for mod in local_mods:
            if mod.get("on_modrinth") and mod.get("project_id"):
                pid = mod["project_id"]
                curr_ver = mod.get("current_version") or mem.get(pid, {}).get("installed_version") or ""
                upsert_instance_entry(mem, pid, filename=mod["filename"], installed_version=curr_ver)
        save_instance_data(inst["id"], mem, inst)

    if stream_requested:
        def generate():
            total = len(local_mods)
            completed = 0
            with ThreadPoolExecutor(max_workers=3) as ex:
                futures = {ex.submit(resolve_one, mod): mod for mod in local_mods}
                for future in as_completed(futures):
                    mod_res = future.result()
                    completed += 1
                    yield json.dumps({"type": "progress", "completed": completed, "total": total, "mod": mod_res}) + "\n"

            update_memory_state()
            yield json.dumps({"type": "done", "mods": local_mods}) + "\n"

        return Response(stream_with_context(generate()), mimetype="application/x-ndjson")

    with ThreadPoolExecutor(max_workers=3) as ex:
        list(ex.map(resolve_one, local_mods))

    update_memory_state()
    return jsonify({"error": None, "mods": local_mods, "no_mods": False})

@app.route("/api/mod/<project_id>/versions", methods=["GET"])
def api_get_project_versions(project_id):
    inst = get_authorized_instance(request.args.get("instance", ""))
    return (jsonify([]), 404) if not inst else jsonify(get_compatible_versions(project_id, inst["loader"], inst["game_version"]))

@app.route("/api/mod/update", methods=["POST"])
def api_update_single_mod():
    body = request.get_json(silent=True) or {}
    inst, fn, url, new_fn = get_authorized_instance(body.get("instance", "")), body.get("filename"), body.get("download_url"), body.get("new_filename")
    if not inst or not isinstance(url, str) or not isinstance(new_fn, str):
        return jsonify({"success": False, "error": "Missing parameters"}), 400
    if (guard := guard_server_running(inst)) is not None:
        return guard

    try:
        mods_dir = mods_dir_for(inst)
        safe_download_and_replace(mods_dir, fn if isinstance(fn, str) else None, url, new_fn)
        mod_meta = extract_jar_metadata(mods_dir / new_fn)

        memory = load_instance_data(inst["id"])
        new_ver = mod_meta.get("current_version") or ""
        for pid in entries_with_filename(memory, fn):
            current_target = memory[pid].get("version")
            backfill = new_ver if (not current_target or current_target == "Unknown") else None
            upsert_instance_entry(memory, pid, filename=new_fn, installed_version=new_ver, target_version=backfill)
        save_instance_data(inst["id"], memory, inst)

        return jsonify({"success": True, "mod": mod_meta})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5055, debug=False, threaded=True)
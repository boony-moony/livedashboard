#!/usr/bin/env python3
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import socket
import struct
import threading
import time
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone

# ── Config ────────────────────────────────────────────────────────────────────
CONFIG_PATH   = os.environ.get("CONFIG_PATH", "/app/config.json")
SETTINGS_PATH = os.environ.get("SETTINGS_PATH", "/data/settings.json")
API_PORT      = int(os.environ.get("API_PORT", "8081"))

with open(CONFIG_PATH) as f:
    CONFIG = json.load(f)

DATA_DIR        = CONFIG.get("data_dir", "/data")
DB_PATH         = os.path.join(DATA_DIR, "uptime.db")
STATUS_PATH     = os.path.join(DATA_DIR, "status.json")
STATUS_PUB_PATH = os.path.join(DATA_DIR, "status-public.json")
HISTORY_PATH    = os.path.join(DATA_DIR, "history.json")
HISTORY_PUB_PATH= os.path.join(DATA_DIR, "history-public.json")
TOTP_SECRET_PATH= os.path.join(DATA_DIR, "totp-secret.txt")
INTERVAL        = CONFIG.get("check_interval_seconds", 60)
DOCKER_SOCK     = "/var/run/docker.sock"
CHECKER_VERSION = "1.0.0"

EXCLUDED_IMAGES = {"homelab-site", "homelab_site"}

os.makedirs(DATA_DIR, exist_ok=True)

# ── TOTP (RFC 6238) ───────────────────────────────────────────────────────────
def load_or_create_totp_secret():
    if os.path.exists(TOTP_SECRET_PATH):
        with open(TOTP_SECRET_PATH) as f:
            secret = f.read().strip()
        print(f"[totp] Secret loaded from {TOTP_SECRET_PATH}")
        return secret
    # generate new secret
    raw    = secrets.token_bytes(20)
    secret = base64.b32encode(raw).decode().rstrip("=")
    with open(TOTP_SECRET_PATH, "w") as f:
        f.write(secret)
    print(f"[totp] New secret generated and saved to {TOTP_SECRET_PATH}")
    print(f"[totp] Scan the QR code in the admin page to set up 2FA.")
    return secret

def totp_code(secret, ts=None):
    ts      = ts or int(time.time())
    counter = ts // 30
    key     = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    msg     = struct.pack(">Q", counter)
    h       = hmac.new(key, msg, hashlib.sha1).digest()
    offset  = h[-1] & 0x0F
    code    = struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF
    return str(code % 1000000).zfill(6)

def verify_totp(secret, code):
    # allow ±1 window (30s tolerance)
    ts = int(time.time())
    for delta in (-30, 0, 30):
        if totp_code(secret, ts + delta) == str(code).strip():
            return True
    return False

def totp_uri(secret, issuer="linuslinus.com", account="admin"):
    secret_padded = secret + "=" * (-len(secret) % 8)
    return (f"otpauth://totp/{urllib.parse.quote(issuer)}:{urllib.parse.quote(account)}"
            f"?secret={secret}&issuer={urllib.parse.quote(issuer)}&algorithm=SHA1&digits=6&period=30")

TOTP_SECRET  = load_or_create_totp_secret()
SESSIONS     = {}  # token -> expiry timestamp
SESSION_TTL  = 8 * 3600  # 8 hours

def create_session():
    token = secrets.token_hex(32)
    SESSIONS[token] = time.time() + SESSION_TTL
    return token

def valid_session(token):
    exp = SESSIONS.get(token)
    if not exp:
        return False
    if time.time() > exp:
        del SESSIONS[token]
        return False
    return True

# ── Database ──────────────────────────────────────────────────────────────────
def init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS checks (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            ts      INTEGER NOT NULL,
            service TEXT NOT NULL,
            state   TEXT NOT NULL,
            latency REAL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS known_containers (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT UNIQUE NOT NULL,
            image        TEXT,
            first_seen   INTEGER,
            public       INTEGER DEFAULT 1,
            tracking     INTEGER DEFAULT 1,
            resumed_at   INTEGER
        )
    """)
    # migrate existing tables that don't have the new columns
    for col, definition in [
        ("tracking",  "INTEGER DEFAULT 1"),
        ("resumed_at","INTEGER"),
        ("status",    "TEXT DEFAULT 'active'"),
        ("deleted_at","INTEGER"),
    ]:
        try:
            cur.execute(f"ALTER TABLE known_containers ADD COLUMN {col} {definition}")
        except Exception:
            pass
    cur.execute("CREATE INDEX IF NOT EXISTS idx_checks_ts  ON checks(ts)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_checks_svc ON checks(service)")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    # record this startup time
    cur.execute("INSERT OR REPLACE INTO meta (key,value) VALUES ('last_start',?)",
                (str(int(time.time())),))
    # record first ever start — never overwritten
    cur.execute("INSERT OR IGNORE INTO meta (key,value) VALUES ('created_at',?)",
                (str(int(time.time())),))
    con.commit()
    con.close()

# ── Docker socket ─────────────────────────────────────────────────────────────
def docker_request(path):
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect(DOCKER_SOCK)
        sock.sendall(f"GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n".encode())
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk: break
            response += chunk
        sock.close()
        header_end = response.find(b"\r\n\r\n")
        if header_end == -1: return None
        return json.loads(response[header_end + 4:].decode())
    except Exception as e:
        print(f"[docker] Socket error: {e}")
        return None

def get_running_containers():
    containers = docker_request("/containers/json")
    if not containers: return {}
    result = {}
    for c in containers:
        names = c.get("Names", [])
        name  = names[0].lstrip("/") if names else c.get("Id","")[:12]
        result[name] = {
            "state": "up" if c.get("State") == "running" else "down",
            "image": c.get("Image", ""),
        }
    return result

def update_known_containers(con, discovered):
    cur = con.cursor()
    ts  = int(time.time())
    # get current count to assign sequential order to new containers
    cur.execute("SELECT COUNT(*) FROM known_containers")
    existing_count = cur.fetchone()[0]
    new_index = existing_count
    for name, info in discovered.items():
        image_base = info["image"].split(":")[0].replace("-","_")
        if image_base in EXCLUDED_IMAGES or info["image"].startswith("homelab"):
            continue
        # check if already exists
        cur.execute("SELECT id FROM known_containers WHERE name=?", (name,))
        exists = cur.fetchone()
        if not exists:
            # new container — assign sequential order
            cur.execute("""
                INSERT INTO known_containers (name, image, first_seen, public)
                VALUES (?, ?, ?, 0)
            """, (name, info["image"], ts))
            # write default settings with sequential order
            new_index += 1
            settings = load_settings()
            if "containers" not in settings:
                settings["containers"] = {}
            if name not in settings["containers"]:
                settings["containers"][name] = {
                    "label":      name,
                    "desc":       "",
                    "showHome":   False,
                    "showUptime": False,
                    "homeOrder":  new_index,
                    "uptimeOrder": new_index,
                }
                save_settings(settings)
        else:
            cur.execute("UPDATE known_containers SET image=? WHERE name=?",
                       (info["image"], name))
    con.commit()

def get_all_known_containers(con):
    cur = con.cursor()
    cur.execute("SELECT name, image, public, tracking, resumed_at, status FROM known_containers WHERE deleted_at IS NULL ORDER BY first_seen")
    return {row[0]: {
        "image":      row[1],
        "public":     bool(row[2]),
        "tracking":   bool(row[3] if row[3] is not None else 1),
        "resumed_at": row[4],
        "status":     row[5] or "active",
    } for row in cur.fetchall()}

# ── Uptime calculations ───────────────────────────────────────────────────────
def calc_uptime(con, service, days):
    now   = int(time.time())
    since = now - days * 86400
    # if container has a resumed_at, only count from then
    cur2  = con.cursor()
    cur2.execute("SELECT resumed_at, tracking FROM known_containers WHERE name=?", (service,))
    row = cur2.fetchone()
    if row and row[0]:
        since = max(since, row[0])
    cur   = con.cursor()
    cur.execute("SELECT COUNT(*) FROM checks WHERE service=? AND ts>=?", (service, since))
    total = cur.fetchone()[0]
    if total == 0: return None
    cur.execute("SELECT COUNT(*) FROM checks WHERE service=? AND ts>=? AND state='up'", (service, since))
    return round((cur.fetchone()[0] / total) * 100, 2)

def day_history(con, service):
    blocks = []
    now = int(time.time())
    for i in range(89, -1, -1):
        day_start = now - (i + 1) * 86400
        day_end   = now - i * 86400
        cur = con.cursor()
        cur.execute(
            "SELECT COUNT(*), SUM(CASE WHEN state='up' THEN 1 ELSE 0 END) "
            "FROM checks WHERE service=? AND ts>=? AND ts<?",
            (service, day_start, day_end)
        )
        row = cur.fetchone()
        total, up = row[0], row[1] or 0
        if total == 0:          blocks.append("unknown")
        elif up/total >= 0.95:  blocks.append("up")
        elif up/total >= 0.5:   blocks.append("degraded")
        else:                   blocks.append("down")
    return blocks

def nas_session():
    try:
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        cur.execute("SELECT value FROM meta WHERE key='last_start'")
        row = cur.fetchone()
        con.close()
        start = int(row[0]) if row else int(CHECKER_START)
        secs  = time.time() - start
        d = int(secs // 86400)
        h = int((secs % 86400) // 3600)
        m = int((secs % 3600) // 60)
        parts = []
        if d: parts.append(f"{d}d")
        if h: parts.append(f"{h}h")
        parts.append(f"{m}m")
        return "Up for " + " ".join(parts)
    except Exception:
        return "Pending"

def nas_day_history():
    """Build NAS history by detecting gaps — a minute with ANY check = NAS was up."""
    blocks = []
    now = int(time.time())
    try:
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        for i in range(89, -1, -1):
            day_start = now - (i + 1) * 86400
            day_end   = now - i * 86400
            cur.execute(
                "SELECT COUNT(DISTINCT (ts/60)) FROM checks WHERE ts>=? AND ts<?",
                (day_start, day_end)
            )
            active_minutes = cur.fetchone()[0]
            total_minutes  = (day_end - day_start) // 60
            if active_minutes == 0:
                blocks.append("unknown")
            elif active_minutes / total_minutes >= 0.95:
                blocks.append("up")
            elif active_minutes / total_minutes >= 0.3:
                blocks.append("degraded")
            else:
                blocks.append("down")
        con.close()
    except Exception as e:
        print(f"[checker] nas_day_history error: {e}")
        blocks = ["unknown"] * 90
    return blocks


    try:
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        cur.execute("SELECT value FROM meta WHERE key='last_start'")
        row = cur.fetchone()
        con.close()
        start = int(row[0]) if row else int(CHECKER_START)
        secs  = time.time() - start
        d = int(secs // 86400)
        h = int((secs % 86400) // 3600)
        m = int((secs % 3600) // 60)
        parts = []
        if d: parts.append(f"{d}d")
        if h: parts.append(f"{h}h")
        parts.append(f"{m}m")
        return "Up for " + " ".join(parts)
    except Exception:
        return "Pending"

def nas_uptime_pct(days):
    try:
        now = int(time.time())
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        # use created_at as the baseline — captures all gaps including shutdowns
        cur.execute("SELECT value FROM meta WHERE key='created_at'")
        row = cur.fetchone()
        created = int(row[0]) if row else int(CHECKER_START)
        since = max(now - days * 86400, created)
        elapsed_minutes = max(1, (now - since) // 60)
        # count distinct minutes where checks were written
        cur.execute("SELECT COUNT(DISTINCT (ts/60)) FROM checks WHERE ts>=?", (since,))
        active = cur.fetchone()[0]
        con.close()
        if active == 0: return None
        return round(min(100.0, (active / elapsed_minutes) * 100), 2)
    except Exception:
        return None

# ── Write output files ────────────────────────────────────────────────────────
def load_settings():
    try:
        with open(SETTINGS_PATH) as f: return json.load(f)
    except Exception: return {}

def save_settings(data):
    tmp = SETTINGS_PATH + ".tmp"
    with open(tmp, "w") as f: json.dump(data, f, indent=2)
    os.replace(tmp, SETTINGS_PATH)

def write_outputs(results, known, discovered):
    con = sqlite3.connect(DB_PATH)
    settings = load_settings()
    container_cfg = settings.get("containers", {})

    services_full = []
    services_pub  = []

    for name, info in known.items():
        if info.get("image","").startswith("homelab"): continue
        cfg   = container_cfg.get(name, {})
        label = cfg.get("label", name)
        # skip containers not being tracked
        if not info.get("tracking", True) and name not in results:
            continue
        state = results.get(name, {}).get("state", "unknown")
        svc_status = info.get("status", "active")
        svc   = {
            "id":          name,
            "name":        label,
            "docker_name": name,
            "image":       info["image"],
            "public":      info["public"],
            "status":      svc_status,
            "state":       "maintenance" if svc_status == "maintenance" else (state if svc_status != "hidden" else "hidden"),
            "pct30":       calc_uptime(con, name, 30),
            "pct180":      calc_uptime(con, name, 180),
            "pct365":      calc_uptime(con, name, 365),
            "history":     day_history(con, name),
            "showHome":    cfg.get("showHome", False),
            "showUptime":  cfg.get("showUptime", False),
            "homeOrder":   cfg.get("homeOrder", 99),
            "uptimeOrder": cfg.get("uptimeOrder", 99),
            "inUse":       cfg.get("inUse", True),
        }
        services_full.append(svc)
        # hidden containers never appear in public output
        if svc_status == "hidden": continue
        if svc["showUptime"]:
            pub_svc = {k: v for k, v in svc.items() if k not in ("docker_name","image")}
            services_pub.append(pub_svc)

    overall_state = "operational"
    for name, r in results.items():
        # inactive and hidden containers never affect overall status
        svc_status = known.get(name, {}).get("status", "active")
        if svc_status not in ("active",): continue
        if not known.get(name, {}).get("tracking", True): continue
        if r["state"] == "down":     overall_state = "down";     break
        if r["state"] == "degraded": overall_state = "degraded"

    nas_p30  = nas_uptime_pct(30)
    nas_p180 = nas_uptime_pct(180)
    nas_p365 = nas_uptime_pct(365)

    base = {
        "version": CHECKER_VERSION,
        "updated": datetime.now(timezone.utc).isoformat(),
        "overall": {
            "state": overall_state,
            "pct30": nas_p30,
            "label": (
                "No data yet — checker starting up." if nas_p30 is None else
                "All systems operational."           if overall_state == "operational" else
                "Some services degraded."            if overall_state == "degraded" else
                "Outage detected."
            )
        },
        "nas": {
            "state":   "up",
            "session": nas_session(),
            "pct30":   nas_p30,
            "pct180":  nas_p180,
            "pct365":  nas_p365,
            "history": nas_day_history()
        },
    }
    con.close()

    # Full (admin only)
    full = {**base, "services": services_full,
            "discovered": {k: {"state": v["state"], "image": v["image"]}
                           for k, v in discovered.items()
                           if not v["image"].startswith("homelab")}}
    # Public (scrubbed)
    pub  = {**base, "services": services_pub}

    for path, data in [(HISTORY_PATH, full), (HISTORY_PUB_PATH, pub)]:
        tmp = path + ".tmp"
        with open(tmp, "w") as f: json.dump(data, f)
        os.replace(tmp, path)

    # status.json — public (overall only, no container names)
    pub_status = {
        "updated": base["updated"],
        "overall": overall_state,
        "operational": overall_state == "operational",
    }
    full_status = {**pub_status,
        "nodes": results,
        "discovered": {k: {"state": v["state"], "image": v["image"]}
                       for k, v in discovered.items()
                       if not v["image"].startswith("homelab")}}
    for path, data in [(STATUS_PATH, full_status), (STATUS_PUB_PATH, pub_status)]:
        tmp = path + ".tmp"
        with open(tmp, "w") as f: json.dump(data, f)
        os.replace(tmp, path)

# ── API server ────────────────────────────────────────────────────────────────
class APIHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args): pass

    def auth(self):
        token = self.headers.get("X-Session-Token", "")
        return valid_session(token)

    def send_json(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Session-Token")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Session-Token")
        self.end_headers()

    def read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length).decode()) if length else {}

    def do_GET(self):
        if self.path == "/api/settings":
            if not self.auth(): return self.send_json(401, {"error": "unauthorized"})
            self.send_json(200, load_settings())

        elif self.path == "/api/containers":
            if not self.auth(): return self.send_json(401, {"error": "unauthorized"})
            con     = sqlite3.connect(DB_PATH)
            known   = get_all_known_containers(con)
            running = get_running_containers()
            con.close()
            result  = {}
            settings = load_settings()
            cfg_map  = settings.get("containers", {})
            for name, info in known.items():
                if info.get("image","").startswith("homelab"): continue
                cfg = cfg_map.get(name, {})
                result[name] = {
                    "state":      running.get(name, {}).get("state", "down"),
                    "image":      info["image"],
                    "public":     info["public"],
                    "tracking":   info.get("tracking", True),
                    "status":     info.get("status", "active"),
                    "running":    name in running,
                    "label":      cfg.get("label", name),
                    "desc":       cfg.get("desc", ""),
                    "showHome":   cfg.get("showHome", False),
                    "showUptime": cfg.get("showUptime", False),
                    "homeOrder":  cfg.get("homeOrder", 99),
                    "uptimeOrder":cfg.get("uptimeOrder", 99),
                    "inUse":      cfg.get("inUse", True),
                }
            self.send_json(200, result)

        elif self.path == "/api/container/deleted":
            if not self.auth(): return self.send_json(401, {"error": "unauthorized"})
            try:
                con = sqlite3.connect(DB_PATH)
                cur = con.cursor()
                cutoff = int(time.time()) - 30 * 86400
                cur.execute("SELECT name FROM known_containers WHERE deleted_at IS NOT NULL AND deleted_at < ?", (cutoff,))
                to_purge = [row[0] for row in cur.fetchall()]
                for name in to_purge:
                    cur.execute("DELETE FROM checks WHERE service=?", (name,))
                    cur.execute("DELETE FROM known_containers WHERE name=?", (name,))
                    print(f"[tracker] {name}: permanently purged (>30 days)")
                cur.execute("SELECT name, image, deleted_at FROM known_containers WHERE deleted_at IS NOT NULL ORDER BY deleted_at DESC")
                rows = cur.fetchall()
                con.commit(); con.close()
                result = [{"name": r[0], "image": r[1], "deleted_at": r[2],
                           "days_left": max(0, 30 - int((time.time()-r[2])//86400))}
                          for r in rows]
                self.send_json(200, result)
            except Exception as e:
                self.send_json(400, {"error": str(e)})

        elif self.path == "/api/history-full":
            if not self.auth(): return self.send_json(401, {"error": "unauthorized"})
            try:
                with open(HISTORY_PATH) as f: self.send_json(200, json.load(f))
            except Exception: self.send_json(404, {"error": "not ready"})

        elif self.path == "/api/totp-uri":
            # only accessible before first auth — returns URI for QR code
            self.send_json(200, {"uri": totp_uri(TOTP_SECRET), "secret": TOTP_SECRET})

        elif self.path == "/api/totp-setup-needed":
            # check DB — true only if never successfully authenticated before
            try:
                con = sqlite3.connect(DB_PATH)
                cur = con.cursor()
                cur.execute("SELECT value FROM meta WHERE key='totp_setup_complete'")
                row = cur.fetchone()
                con.close()
                self.send_json(200, {"setup": row is None})
            except Exception:
                self.send_json(200, {"setup": True})

        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/api/auth":
            data = self.read_body()
            code = str(data.get("code", "")).strip()
            if verify_totp(TOTP_SECRET, code):
                token = create_session()
                self.send_json(200, {"ok": True, "token": token})
            else:
                self.send_json(401, {"ok": False, "error": "Invalid code"})

        elif self.path == "/api/auth/reset-totp":
            data = self.read_body()
            if not self.auth(): return self.send_json(401, {"error": "unauthorized"})
            try:
                os.remove(TOTP_SECRET_PATH)
                con = sqlite3.connect(DB_PATH)
                con.execute("DELETE FROM meta WHERE key='totp_setup_complete'")
                con.commit(); con.close()
                self.send_json(200, {"ok": True, "message": "TOTP reset. Restart the container to generate a new QR code."})
            except Exception as e:
                self.send_json(500, {"error": str(e)})

        elif self.path == "/api/save":
            if not self.auth(): return self.send_json(401, {"error": "unauthorized"})
            try:
                save_settings(self.read_body())
                self.send_json(200, {"ok": True})
            except Exception as e:
                self.send_json(400, {"error": str(e)})

        elif self.path == "/api/container/toggle-public":
            if not self.auth(): return self.send_json(401, {"error": "unauthorized"})
            try:
                data   = self.read_body()
                name   = data.get("name")
                public = int(data.get("public", 1))
                con    = sqlite3.connect(DB_PATH)
                con.execute("UPDATE known_containers SET public=? WHERE name=?", (public, name))
                con.commit(); con.close()
                self.send_json(200, {"ok": True})
            except Exception as e:
                self.send_json(400, {"error": str(e)})

        elif self.path == "/api/container/set-status":
            if not self.auth(): return self.send_json(401, {"error": "unauthorized"})
            try:
                data   = self.read_body()
                name   = data.get("name")
                status = data.get("status", "active")
                if status not in ("active", "inactive", "hidden", "maintenance"):
                    return self.send_json(400, {"error": "invalid status"})
                con = sqlite3.connect(DB_PATH)
                con.execute("UPDATE known_containers SET status=? WHERE name=?", (status, name))
                con.commit(); con.close()
                print(f"[tracker] {name}: status set to {status}")
                self.send_json(200, {"ok": True})
            except Exception as e:
                self.send_json(400, {"error": str(e)})

        elif self.path == "/api/container/toggle-tracking":
            if not self.auth(): return self.send_json(401, {"error": "unauthorized"})
            try:
                data     = self.read_body()
                name     = data.get("name")
                tracking = int(data.get("tracking", 1))
                con      = sqlite3.connect(DB_PATH)
                if tracking:
                    con.execute(
                        "UPDATE known_containers SET tracking=1, resumed_at=? WHERE name=?",
                        (int(time.time()), name)
                    )
                    print(f"[tracker] {name}: tracking resumed — fresh baseline")
                else:
                    con.execute(
                        "UPDATE known_containers SET tracking=0 WHERE name=?",
                        (name,)
                    )
                    print(f"[tracker] {name}: tracking paused")
                con.commit(); con.close()
                # sync showUptime in settings.json to match tracking state
                s = load_settings()
                if "containers" not in s: s["containers"] = {}
                if name not in s["containers"]: s["containers"][name] = {}
                s["containers"][name]["showUptime"] = bool(tracking)
                if not tracking:
                    s["containers"][name]["showHome"] = False
                save_settings(s)
                self.send_json(200, {"ok": True})
            except Exception as e:
                self.send_json(400, {"error": str(e)})

        elif self.path == "/api/container/delete":
            if not self.auth(): return self.send_json(401, {"error": "unauthorized"})
            try:
                data = self.read_body()
                name = data.get("name")
                con  = sqlite3.connect(DB_PATH)
                con.execute("UPDATE known_containers SET deleted_at=? WHERE name=?",
                           (int(time.time()), name))
                con.commit(); con.close()
                # remove from settings
                s = load_settings()
                if "containers" in s and name in s["containers"]:
                    del s["containers"][name]
                    save_settings(s)
                print(f"[tracker] {name}: soft deleted")
                self.send_json(200, {"ok": True})
            except Exception as e:
                self.send_json(400, {"error": str(e)})

        elif self.path == "/api/container/restore":
            if not self.auth(): return self.send_json(401, {"error": "unauthorized"})
            try:
                data = self.read_body()
                name = data.get("name")
                con  = sqlite3.connect(DB_PATH)
                con.execute("UPDATE known_containers SET deleted_at=NULL WHERE name=?", (name,))
                con.commit(); con.close()
                print(f"[tracker] {name}: restored")
                self.send_json(200, {"ok": True})
            except Exception as e:
                self.send_json(400, {"error": str(e)})

        elif self.path == "/api/refresh":
            if not self.auth(): return self.send_json(401, {"error": "unauthorized"})
            # trigger immediate recalculation of outputs
            try:
                con      = sqlite3.connect(DB_PATH)
                known    = get_all_known_containers(con)
                running  = get_running_containers()
                results  = {}
                for name, info in known.items():
                    if info.get("image","").startswith("homelab"): continue
                    if not info.get("tracking", True): continue
                    state = running.get(name, {}).get("state", "down")
                    results[name] = {"state": state, "latency_ms": None}
                con.close()
                write_outputs(results, known, running)
                self.send_json(200, {"ok": True})
            except Exception as e:
                self.send_json(500, {"error": str(e)})

        else:
            self.send_json(404, {"error": "not found"})

def run_api():
    server = HTTPServer(("0.0.0.0", API_PORT), APIHandler)
    print(f"[api] Listening on port {API_PORT}")
    server.serve_forever()

# ── Main loop ─────────────────────────────────────────────────────────────────
def main():
    print(f"[checker] Starting. DB: {DB_PATH}, interval: {INTERVAL}s")
    init_db()
    threading.Thread(target=run_api, daemon=True).start()
    while True:
        ts         = int(time.time())
        discovered = get_running_containers()
        con        = sqlite3.connect(DB_PATH)
        update_known_containers(con, discovered)
        known = get_all_known_containers(con)
        results = {}
        cur = con.cursor()
        # always write a NAS heartbeat check independent of services
        cur.execute("INSERT INTO checks (ts,service,state,latency) VALUES (?,?,?,?)",
                   (ts, "__nas__", "up", None))

        for name in known:
            info = known[name]
            if info.get("image","").startswith("homelab"): continue
            if not info.get("tracking", True):
                print(f"[checker] {name}: tracking paused — skipping")
                continue
            state = discovered.get(name, {}).get("state", "down")
            cur.execute("INSERT INTO checks (ts,service,state,latency) VALUES (?,?,?,?)",
                       (ts, name, state, None))
            results[name] = {"state": state, "latency_ms": None}
            print(f"[checker] {name}: {state}")
        con.commit(); con.close()
        write_outputs(results, known, discovered)
        print(f"[checker] Cycle done. Sleeping {INTERVAL}s")
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()

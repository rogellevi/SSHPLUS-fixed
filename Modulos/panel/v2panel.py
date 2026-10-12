#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
V2Panel - Panel web para administrar cuentas UUID de V2Ray.
Compatible con el script bash (usa /etc/SSHPlus/RegV2ray y /etc/v2ray/config.json).
Sin dependencias externas: solo Python 3.8+.

Uso:
    python3 v2panel.py setup    # crea/actualiza contraseña y puerto
    python3 v2panel.py          # inicia el servidor
"""
import base64
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
import uuid as uuidlib
from datetime import date, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# ---------------------------------------------------------------- rutas ----
PANEL_CFG = os.environ.get("V2PANEL_CONFIG", "/etc/v2panel/config.json")
REG = os.environ.get("V2PANEL_REGISTRY", "/etc/SSHPlus/RegV2ray")
V2CFG = os.environ.get("V2PANEL_V2RAY_CONFIG", "/etc/v2ray/config.json")
BACKUP_DIR = os.path.join(os.path.dirname(PANEL_CFG), "backups")

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
NICK_RE = re.compile(r"^[A-Za-z0-9._-]{2,32}$")
HOST_RE = re.compile(r"^[A-Za-z0-9.-]{0,253}$")
MAX_DAYS = 360
SESSION_TTL = 12 * 3600

LOCK = threading.RLock()
FAILS = {}  # ip -> (intentos, bloqueado_hasta)


class ApiError(Exception):
    def __init__(self, msg, code=400):
        super().__init__(msg)
        self.msg, self.code = msg, code


# ------------------------------------------------------------- utilidades ---
def write_atomic(path, data, mode=None):
    tmp = "%s.tmp.%d" % (path, os.getpid())
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    if os.path.exists(path):
        st = os.stat(path)
        os.chmod(tmp, st.st_mode & 0o7777)
        try:
            os.chown(tmp, st.st_uid, st.st_gid)
        except OSError:
            pass
    elif mode is not None:
        os.chmod(tmp, mode)
    os.replace(tmp, path)


def backup(path, keep=30):
    if not os.path.exists(path):
        return
    os.makedirs(BACKUP_DIR, exist_ok=True)
    base = os.path.basename(path)
    shutil.copy2(path, os.path.join(BACKUP_DIR, "%s.%s" % (base, time.strftime("%Y%m%d-%H%M%S"))))
    old = sorted(f for f in os.listdir(BACKUP_DIR) if f.startswith(base + "."))
    for f in old[:-keep]:
        try:
            os.remove(os.path.join(BACKUP_DIR, f))
        except OSError:
            pass


def hash_pw(pw, salt=None, iters=200_000):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), iters).hex()
    return "pbkdf2$%d$%s$%s" % (iters, salt, h)


def check_pw(pw, stored):
    try:
        _, iters, salt, h = stored.split("$")
        calc = hash_pw(pw, salt, int(iters)).split("$")[3]
        return hmac.compare_digest(calc, h)
    except Exception:
        return False


def load_panel_cfg():
    with open(PANEL_CFG, encoding="utf-8") as f:
        return json.load(f)


def save_panel_cfg(cfg):
    os.makedirs(os.path.dirname(PANEL_CFG), exist_ok=True)
    os.chmod(os.path.dirname(PANEL_CFG), 0o700)
    write_atomic(PANEL_CFG, json.dumps(cfg, indent=2), mode=0o600)


# --------------------------------------------------------------- registro ---
def read_registry():
    """Formato del bash:  '  UUID | usuario | YYYY-MM-DD '"""
    users = []
    if not os.path.exists(REG):
        return users
    with open(REG, encoding="utf-8", errors="ignore") as f:
        for line in f:
            p = [x.strip() for x in line.split("|")]
            if len(p) >= 3 and UUID_RE.match(p[0]):
                users.append({"uuid": p[0], "nick": p[1], "exp": p[2]})
    return users


def write_registry(users):
    backup(REG)
    body = "".join("  %s | %s | %s \n" % (u["uuid"], u["nick"], u["exp"]) for u in users)
    os.makedirs(os.path.dirname(REG), exist_ok=True)
    write_atomic(REG, body, mode=0o644)


def enrich(u):
    """Misma regla que el bash: vencido si ya pasó la medianoche de la fecha."""
    days, status = None, "sr"
    try:
        d = datetime.strptime(u["exp"], "%Y-%m-%d").date()
        days = (d - date.today()).days
        status = "expired" if days <= 0 else ("soon" if days <= 3 else "ok")
    except ValueError:
        pass
    return dict(u, days=days, status=status)


# ------------------------------------------------------- config de v2ray ----
def find_clients(cfg):
    inbounds = cfg.get("inbounds") or ([cfg["inbound"]] if "inbound" in cfg else [])
    for ib in inbounds:
        cl = (ib.get("settings") or {}).get("clients")
        if isinstance(cl, list):
            return ib, cl
    raise ApiError("No se encontró la lista 'clients' en config.json de V2Ray", 500)


def ids_of(text):
    return sorted(str(c.get("id", "")).lower() for c in find_clients(json.loads(text))[1])


def text_add(text, client):
    """Inserta el cliente justo bajo '"clients": [' (igual que tu bash) sin tocar el resto."""
    lines = text.split("\n")
    for i, l in enumerate(lines):
        if re.search(r'"clients"\s*:\s*\[\s*$', l):
            break
    else:
        return None
    ind = re.match(r"\s*", lines[i]).group(0) + "  "
    j = i + 1
    while j < len(lines) and not lines[j].strip():
        j += 1
    last = j < len(lines) and lines[j].strip().startswith("]")
    block = [
        ind + "{",
        ind + '  "alterId": 0,',
        ind + '  "id": "%s",' % client["id"],
        ind + '  "email": "%s"' % client["email"],
        ind + ("}" if last else "},"),
    ]
    lines[i + 1:i + 1] = block
    return "\n".join(lines)


def text_del(text, uid):
    lines = text.split("\n")
    idx = [i for i, l in enumerate(lines) if re.search(r'"id"\s*:\s*"%s"' % re.escape(uid), l, re.I)]
    if len(idx) != 1:
        return None
    i = idx[0]
    s = i
    while s >= 0 and not lines[s].strip().startswith("{"):
        s -= 1
    e = i
    while e < len(lines) and not lines[e].strip().startswith("}"):
        e += 1
    if s < 0 or e >= len(lines):
        return None
    had_comma = lines[e].strip().endswith(",")
    del lines[s:e + 1]
    if not had_comma:  # era el último: quitar coma del anterior
        k = s - 1
        while k >= 0 and not lines[k].strip():
            k -= 1
        if k >= 0 and lines[k].rstrip().endswith(","):
            lines[k] = lines[k].rstrip()[:-1]
    return "\n".join(lines)


def apply_config(adds=(), removes=()):
    """Agrega/quita clientes. Intenta edición por texto (conserva formato y el bash
    sigue funcionando); si falla la verificación, reescribe el JSON completo."""
    with open(V2CFG, encoding="utf-8") as f:
        original = f.read()
    before = ids_of(original)
    rm = [r.lower() for r in removes if r.lower() in before]
    want = sorted([i for i in before if i not in rm] + [a["id"].lower() for a in adds])
    if not rm and not adds:
        return False

    new = original
    try:
        for r in rm:
            new = text_del(new, r) if new else None
        for a in adds:
            new = text_add(new, a) if new else None
        ok = bool(new) and ids_of(new) == want
    except Exception:
        ok = False

    if not ok:  # plan B: reescritura completa del JSON
        cfg = json.loads(original)
        _, cl = find_clients(cfg)
        cl[:] = [c for c in cl if str(c.get("id", "")).lower() not in rm]
        cl.extend(adds)
        new = json.dumps(cfg, indent=2, ensure_ascii=False) + "\n"
        if ids_of(new) != want:
            raise ApiError("No se pudo editar config.json de forma segura", 500)

    backup(V2CFG)
    write_atomic(V2CFG, new)
    return True


def restart_v2ray():
    for cmd in (["v2ray", "restart"], ["systemctl", "restart", "v2ray"]):
        try:
            r = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, timeout=40)
            if r.returncode == 0:
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return False


def v2ray_status():
    try:
        r = subprocess.run(["systemctl", "is-active", "v2ray"], capture_output=True, text=True, timeout=5)
        if r.stdout.strip() == "active":
            return True
    except Exception:
        pass
    try:
        return subprocess.run(["pgrep", "-x", "v2ray"], capture_output=True, timeout=5).returncode == 0
    except Exception:
        return False


def build_link(u, host_hint):
    try:
        with open(V2CFG, encoding="utf-8") as f:
            ib, _ = find_clients(json.load(f))
    except Exception:
        return None
    if ib.get("protocol") != "vmess":
        return None
    ss = ib.get("streamSettings") or {}
    net = ss.get("network", "tcp")
    tls = ss.get("security") == "tls"
    cfg = load_panel_cfg()
    addr = cfg.get("host") or host_hint
    path = hdr_host = ""
    if net == "ws":
        ws = ss.get("wsSettings") or {}
        path = ws.get("path", "/")
        hdr_host = (ws.get("headers") or {}).get("Host", "")
    elif net == "grpc":
        path = (ss.get("grpcSettings") or {}).get("serviceName", "")
    obj = {
        "v": "2", "ps": u["nick"], "add": addr, "port": str(ib.get("port", "")),
        "id": u["uuid"], "aid": "0", "scy": "auto", "net": net, "type": "none",
        "host": hdr_host or (addr if tls else ""), "path": path,
        "tls": "tls" if tls else "", "sni": (hdr_host or addr) if tls else "",
    }
    return "vmess://" + base64.b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode()


# -------------------------------------------------------------- acciones ----
def add_user(nick, days):
    if not NICK_RE.match(nick or ""):
        raise ApiError("Usuario inválido: 2-32 caracteres (letras, números, punto, guion o guion bajo)")
    if not isinstance(days, int) or days < 1 or days > MAX_DAYS:
        raise ApiError("Duración inválida: entre 1 y %d días" % MAX_DAYS)
    with LOCK:
        users = read_registry()
        if any(u["nick"].lower() == nick.lower() for u in users):
            raise ApiError("El usuario ya existe", 409)
        uid = str(uuidlib.uuid4())
        mail = "".join(secrets.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(10)) + "@gmail.com"
        apply_config(adds=[{"alterId": 0, "id": uid, "email": mail}])
        exp = (date.today() + timedelta(days=days)).isoformat()
        users.append({"uuid": uid, "nick": nick, "exp": exp})
        write_registry(users)
        restarted = restart_v2ray()
    return {"uuid": uid, "nick": nick, "exp": exp, "restarted": restarted}


def renew_user(uid, days, reset=False):
    if not isinstance(days, int) or days < 1 or days > MAX_DAYS:
        raise ApiError("Duración inválida: entre 1 y %d días" % MAX_DAYS)
    with LOCK:
        users = read_registry()
        u = next((x for x in users if x["uuid"].lower() == uid.lower()), None)
        if not u:
            raise ApiError("UUID no encontrado", 404)
        e = enrich(u)
        base = date.today()
        if not reset and e["days"] is not None and e["days"] > 0:
            base = base + timedelta(days=e["days"])
        u["exp"] = (base + timedelta(days=days)).isoformat()
        with open(V2CFG, encoding="utf-8") as f:
            in_config = u["uuid"].lower() in ids_of(f.read())
        changed = False
        if not in_config:  # huérfano: está en el registro pero no en config.json
            changed = apply_config(adds=[{"alterId": 0, "id": u["uuid"],
                                          "email": "re%s@gmail.com" % secrets.token_hex(4)}])
        write_registry(users)
        restarted = restart_v2ray() if changed else True
    return {"exp": u["exp"], "restarted": restarted}


def delete_users(uids):
    with LOCK:
        low = {x.lower() for x in uids}
        users = read_registry()
        keep = [u for u in users if u["uuid"].lower() not in low]
        changed = apply_config(removes=list(low))
        write_registry(keep)
        restarted = restart_v2ray() if changed else True
    return {"deleted": len(users) - len(keep), "restarted": restarted}


def clean_expired():
    expired = [u["uuid"] for u in read_registry() if enrich(u)["status"] == "expired"]
    if not expired:
        return {"deleted": 0, "restarted": True}
    return delete_users(expired)


def auto_clean_loop():
    while True:
        time.sleep(3600)
        try:
            if load_panel_cfg().get("auto_clean"):
                clean_expired()
        except Exception as e:
            print("auto_clean error:", e, file=sys.stderr)


# ------------------------------------------- agente para panel maestro -----
def to_int(v):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def find_by_nick(nick):
    u = next((x for x in read_registry() if x["nick"].lower() == nick.lower()), None)
    if not u:
        raise ApiError("Usuario no encontrado", 404)
    return u


def cpu_percent():
    def rd():
        with open("/proc/stat") as f:
            p = [int(x) for x in f.readline().split()[1:]]
        return sum(p), p[3] + (p[4] if len(p) > 4 else 0)
    try:
        t1, i1 = rd()
        time.sleep(0.25)
        t2, i2 = rd()
        return max(0, min(100, round(100 * (1 - (i2 - i1) / max(t2 - t1, 1)))))
    except Exception:
        return 0


def mem_percent():
    try:
        m = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, _, v = line.partition(":")
                m[k] = int(v.split()[0])
        return round(100 * (1 - m["MemAvailable"] / m["MemTotal"]))
    except Exception:
        return 0


def uptime_str():
    try:
        with open("/proc/uptime") as f:
            sec = int(float(f.read().split()[0]))
        d, r = divmod(sec, 86400)
        h, r = divmod(r, 3600)
        return "%dd %dh %dm" % (d, h, r // 60)
    except Exception:
        return "—"


def online_ips():
    """IPs distintas con conexión establecida al puerto de V2Ray (aprox.; tras CDN cuenta IPs del CDN)."""
    try:
        with open(V2CFG, encoding="utf-8") as f:
            port = str(find_clients(json.load(f))[0].get("port", ""))
        if not port.isdigit():
            return 0
        out = subprocess.run(["ss", "-Htn", "state", "established", "( sport = :%s )" % port],
                             capture_output=True, text=True, timeout=5).stdout
        ips = set()
        for line in out.splitlines():
            p = line.split()
            if len(p) >= 4:
                ips.add(p[3].rsplit(":", 1)[0])
        return len(ips)
    except Exception:
        return 0


def build_info():
    users, act, exp = [], 0, 0
    for u in sorted((enrich(x) for x in read_registry()), key=lambda x: x["nick"].lower()):
        expired = u["status"] == "expired"
        exp += expired
        act += not expired
        users.append({
            "username": u["nick"], "uuid": u["uuid"],
            "status": "expired" if expired else "active",
            "days_left": "∞" if u["days"] is None else u["days"],
            "expiry": u["exp"] if u["days"] is not None else "—",
            "conn_active": 0, "conn_limit": 1,
        })
    try:
        du = shutil.disk_usage("/")
        disk = round(100 * du.used / du.total)
    except Exception:
        disk = 0
    import socket
    return {
        "ok": True, "service": "v2panel", "cpu": cpu_percent(), "mem_used": mem_percent(),
        "disk": disk, "uptime": uptime_str(), "online_now": online_ips(),
        "users_count": len(users), "active_count": act, "expired_count": exp,
        "users": users, "hostname": socket.gethostname(),
    }


def agent_action(action, f, host):
    nick = str(f.get("username", "")).strip()
    if action == "ping":
        return {"ok": True, "msg": "pong", "service": "v2panel"}
    if action == "info":
        return build_info()
    if action == "create":
        r = add_user(nick, to_int(f.get("days")))
        link = build_link(r, host)
        return {"ok": True, "msg": "Usuario V2Ray creado", "username": r["nick"], "password": r["uuid"],
                "uuid": r["uuid"], "expiry": r["exp"], "limit": 1, "ip": host, "link": link}
    if action in ("delete", "change_expiry", "link"):
        u = find_by_nick(nick)
        if action == "delete":
            delete_users([u["uuid"]])
            return {"ok": True, "msg": "Usuario eliminado"}
        if action == "change_expiry":
            r = renew_user(u["uuid"], to_int(f.get("days")), reset=True)  # reemplaza: hoy + días
            return {"ok": True, "msg": "Vence: " + r["exp"], "expiry": r["exp"]}
        link = build_link(u, host)
        if not link:
            raise ApiError("No se pudo generar el enlace (solo protocolo vmess)")
        return {"ok": True, "link": link, "uuid": u["uuid"]}
    if action == "delete_expired":
        r = clean_expired()
        return {"ok": True, "msg": "%d expirado(s) eliminado(s)" % r["deleted"], "deleted": r["deleted"]}
    if action in ("change_pass", "change_limit"):
        return {"ok": True, "msg": "V2Ray no usa contraseña ni límite por usuario (sin cambios)"}
    if action == "check_online":
        return {"ok": True, "online": False, "connections": 0, "unsupported": True,
                "msg": "V2Ray no permite ver conexiones por UUID"}
    if action in ("create_token", "token_info"):
        return {"ok": False, "msg": "Acción no soportada en V2Ray"}
    return {"ok": False, "msg": "Acción desconocida"}


# ----------------------------------------------------------------- sesión ---
def make_token(secret):
    exp = str(int(time.time()) + SESSION_TTL)
    sig = hmac.new(secret.encode(), exp.encode(), hashlib.sha256).hexdigest()
    return exp + "." + sig


def valid_token(tok, secret):
    try:
        exp, sig = tok.split(".")
        good = hmac.new(secret.encode(), exp.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, good) and int(exp) > time.time()
    except Exception:
        return False


# -------------------------------------------------------------------- HTTP ---
class Handler(BaseHTTPRequestHandler):
    server_version = "v2panel"

    def log_message(self, *a):
        pass

    # helpers
    def send(self, code, body, ctype="application/json; charset=utf-8", cookie=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False)
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
                         "connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(data)

    def cookie_flags(self):
        sec = "; Secure" if self.headers.get("X-Forwarded-Proto") == "https" else ""
        return "; HttpOnly; SameSite=Strict; Path=/" + sec

    def authed(self, cfg):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "v2p" and valid_token(v, cfg["secret"]):
                return True
        return False

    def read_json(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 10_000:
            raise ApiError("Petición demasiado grande", 413)
        if n == 0:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except Exception:
            raise ApiError("JSON inválido")

    # routing
    def read_form(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 10_000:
            raise ApiError("Petición demasiado grande", 413)
        raw = self.rfile.read(n).decode("utf-8", "ignore") if n else ""
        return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}

    def agent(self, cfg, action):
        ip = self.client_address[0]
        key = "tok:" + ip
        tries, until = FAILS.get(key, (0, 0))
        if until > time.time():
            return self.send(200, {"ok": False, "msg": "Demasiados intentos"})
        allow = cfg.get("api_allow") or []
        if allow and ip not in allow:
            return self.send(200, {"ok": False, "msg": "IP no autorizada"})
        tok = self.headers.get("X-Api-Token", "")
        good = cfg.get("api_token", "")
        if not good or not hmac.compare_digest(tok.encode(), good.encode()):
            tries += 1
            FAILS[key] = (tries, time.time() + 300 if tries >= 10 else 0)
            return self.send(200, {"ok": False, "msg": "Token inválido"})
        FAILS.pop(key, None)
        try:
            form = self.read_form()
            host = cfg.get("host") or (self.headers.get("Host") or "").split(":")[0]
            self.send(200, agent_action(action, form, host))
        except ApiError as e:
            self.send(200, {"ok": False, "msg": e.msg})
        except Exception as e:  # noqa
            print("agent error:", repr(e), file=sys.stderr)
            self.send(200, {"ok": False, "msg": "Error interno"})

    def dispatch(self, method):
        parsed = urlparse(self.path)
        path = parsed.path
        action = (parse_qs(parsed.query).get("action") or [""])[0]
        if action and not path.startswith("/api/"):  # agente: cualquier ruta (/, /api.php, /vps.php, ...)
            try:
                return self.agent(load_panel_cfg(), action)
            except FileNotFoundError:
                return self.send(200, {"ok": False, "msg": "Panel sin configurar"})
        if method == "GET" and path in ("/", "/index.html"):
            return self.send(200, INDEX_HTML, "text/html; charset=utf-8")
        if not path.startswith("/api/"):
            return self.send(404, {"error": "No encontrado"})
        try:
            cfg = load_panel_cfg()
            if method != "GET" and self.headers.get("X-Panel") != "1":
                raise ApiError("Solicitud no permitida", 403)

            if method == "POST" and path == "/api/login":
                return self.login(cfg)
            if method == "POST" and path == "/api/logout":
                return self.send(200, {"ok": True}, cookie="v2p=; Max-Age=0" + self.cookie_flags())
            if not self.authed(cfg):
                raise ApiError("No autorizado", 401)

            body = self.read_json() if method in ("POST", "DELETE") else {}
            m = re.match(r"^/api/users/([0-9a-fA-F-]{36})(?:/(\w+))?$", path)

            if method == "GET" and path == "/api/state":
                users = [enrich(u) for u in read_registry()]
                users.sort(key=lambda u: (u["days"] is None, u["days"] if u["days"] is not None else 0))
                return self.send(200, {
                    "users": users, "running": v2ray_status(),
                    "settings": {"host": cfg.get("host", ""), "auto_clean": bool(cfg.get("auto_clean")),
                                 "api_token": cfg.get("api_token", "")},
                    "max_days": MAX_DAYS,
                })
            if method == "POST" and path == "/api/users":
                r = add_user(str(body.get("nick", "")).strip(), body.get("days"))
                r["link"] = build_link(r, (self.headers.get("Host") or "").split(":")[0])
                return self.send(200, r)
            if method == "POST" and m and m.group(2) == "renew":
                return self.send(200, renew_user(m.group(1), body.get("days")))
            if method == "GET" and m and m.group(2) == "link":
                u = next((x for x in read_registry() if x["uuid"].lower() == m.group(1).lower()), None)
                if not u:
                    raise ApiError("UUID no encontrado", 404)
                link = build_link(u, (self.headers.get("Host") or "").split(":")[0])
                if not link:
                    raise ApiError("No se pudo generar el enlace (solo protocolo vmess)")
                return self.send(200, {"link": link})
            if method == "DELETE" and m and not m.group(2):
                return self.send(200, delete_users([m.group(1)]))
            if method == "POST" and path == "/api/clean":
                return self.send(200, clean_expired())
            if method == "POST" and path == "/api/restart":
                return self.send(200, {"restarted": restart_v2ray()})
            if method == "POST" and path == "/api/settings":
                host = str(body.get("host", "")).strip()
                if not HOST_RE.match(host):
                    raise ApiError("Dominio/IP inválido")
                cfg["host"], cfg["auto_clean"] = host, bool(body.get("auto_clean"))
                save_panel_cfg(cfg)
                return self.send(200, {"ok": True})
            raise ApiError("No encontrado", 404)
        except ApiError as e:
            self.send(e.code, {"error": e.msg})
        except FileNotFoundError as e:
            self.send(500, {"error": "Archivo no encontrado: %s" % e.filename})
        except Exception as e:  # noqa
            print("error:", repr(e), file=sys.stderr)
            self.send(500, {"error": "Error interno"})

    def login(self, cfg):
        ip = self.client_address[0]
        tries, until = FAILS.get(ip, (0, 0))
        if until > time.time():
            raise ApiError("Demasiados intentos. Espera unos minutos.", 429)
        body = self.read_json()
        if check_pw(str(body.get("password", "")), cfg["password_hash"]):
            FAILS.pop(ip, None)
            return self.send(200, {"ok": True}, cookie="v2p=%s; Max-Age=%d%s" % (
                make_token(cfg["secret"]), SESSION_TTL, self.cookie_flags()))
        tries += 1
        FAILS[ip] = (tries, time.time() + 300 if tries >= 5 else 0)
        time.sleep(1)
        raise ApiError("Contraseña incorrecta", 401)

    def do_GET(self):
        self.dispatch("GET")

    def do_POST(self):
        self.dispatch("POST")

    def do_DELETE(self):
        self.dispatch("DELETE")


# ------------------------------------------------------------------- setup ---
def setup():
    cfg = {}
    if os.path.exists(PANEL_CFG):
        cfg = load_panel_cfg()
    while True:
        p1 = getpass.getpass("Contraseña del panel (mín. 8 caracteres): ")
        if len(p1) < 8:
            print("Muy corta.")
            continue
        if p1 != getpass.getpass("Repite la contraseña: "):
            print("No coinciden.")
            continue
        break
    default_port = cfg.get("port", 8085)
    raw = input("Puerto del panel [%s]: " % default_port).strip()
    port = int(raw) if raw.isdigit() and 1 <= int(raw) <= 65535 else default_port
    cfg.update({
        "password_hash": hash_pw(p1),
        "secret": cfg.get("secret") or secrets.token_hex(32),
        "port": port, "bind": cfg.get("bind", "0.0.0.0"),
        "host": cfg.get("host", ""), "auto_clean": cfg.get("auto_clean", False),
        "api_token": cfg.get("api_token") or secrets.token_hex(24),
        "api_allow": cfg.get("api_allow", []),
    })
    save_panel_cfg(cfg)
    print("Configuración guardada en", PANEL_CFG)
    print("Token para el panel maestro:", cfg["api_token"])


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("setup", "passwd"):
        return setup()
    if not os.path.exists(PANEL_CFG):
        sys.exit("Falta configuración. Ejecuta: python3 %s setup" % sys.argv[0])
    cfg = load_panel_cfg()
    if not cfg.get("api_token") or (len(sys.argv) > 1 and sys.argv[1] == "token-new"):
        cfg["api_token"] = secrets.token_hex(24)
        cfg.setdefault("api_allow", [])
        save_panel_cfg(cfg)
    if len(sys.argv) > 1 and sys.argv[1] in ("token", "token-new"):
        return print(cfg["api_token"])
    threading.Thread(target=auto_clean_loop, daemon=True).start()
    srv = ThreadingHTTPServer((cfg.get("bind", "0.0.0.0"), int(cfg.get("port", 8085))), Handler)
    print("V2Panel escuchando en %s:%s" % (cfg.get("bind"), cfg.get("port")), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


# ---------------------------------------------------------------- frontend ---
INDEX_HTML = r"""<!doctype html>
<html lang="es"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>V2Panel</title>
<style>
:root{--bg:#0e1319;--card:#171f29;--line:#263241;--tx:#e8eef5;--mut:#8696ab;--acc:#3b82f6;--ok:#22c55e;--warn:#f59e0b;--bad:#ef4444;--r:14px}
@media(prefers-color-scheme:light){:root{--bg:#f3f5f9;--card:#fff;--line:#e1e7ef;--tx:#0f172a;--mut:#64748b}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);font:15px/1.4 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
button,input{font:inherit;color:inherit}
button{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:9px 14px;cursor:pointer}
button:active{transform:scale(.98)}
button.pri{background:var(--acc);border-color:var(--acc);color:#fff;font-weight:600}
button.danger{color:var(--bad)}
input[type=text],input[type=password],input[type=number],input[type=search]{width:100%;background:var(--bg);border:1px solid var(--line);border-radius:10px;padding:11px 12px;outline:none}
input:focus{border-color:var(--acc)}
.wrap{max-width:1000px;margin:0 auto;padding:16px}
.hidden{display:none!important}
header{display:flex;align-items:center;gap:10px;margin-bottom:14px}
header h1{font-size:18px;margin:0;flex:1}
.pill{display:inline-flex;align-items:center;gap:6px;padding:6px 11px;border-radius:99px;border:1px solid var(--line);background:var(--card);font-size:13px}
.dot{width:8px;height:8px;border-radius:50%;background:var(--mut)}
.dot.on{background:var(--ok)}.dot.off{background:var(--bad)}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:14px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:10px 12px}
.stat b{display:block;font-size:22px}.stat span{color:var(--mut);font-size:12px}
.bar{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap}
.bar input{flex:1;min-width:160px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:14px;border-left:4px solid var(--ok)}
.card.soon{border-left-color:var(--warn)}.card.expired{border-left-color:var(--bad)}.card.sr{border-left-color:var(--mut)}
.row{display:flex;justify-content:space-between;align-items:center;gap:8px}
.row b{font-size:16px;word-break:break-all}
.badge{font-size:12px;font-weight:700;padding:3px 9px;border-radius:99px;white-space:nowrap;background:#22c55e22;color:var(--ok)}
.soon .badge{background:#f59e0b22;color:var(--warn)}.expired .badge{background:#ef444422;color:var(--bad)}.sr .badge{background:#8696ab22;color:var(--mut)}
.uuid{display:block;width:100%;text-align:left;margin:10px 0 6px;font:12px ui-monospace,Menlo,Consolas,monospace;background:var(--bg);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;padding:8px 10px}
.mut{color:var(--mut);font-size:13px}
.acts{display:flex;gap:6px;margin-top:12px}.acts button{flex:1;padding:8px 6px;font-size:13px}
.empty{text-align:center;color:var(--mut);padding:40px 10px}
dialog{background:var(--card);color:var(--tx);border:1px solid var(--line);border-radius:18px;padding:20px;width:min(420px,92vw)}
dialog::backdrop{background:#0009}
dialog h2{margin:0 0 14px;font-size:17px}
label{display:block;margin:12px 0 5px;color:var(--mut);font-size:13px}
.chips{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}.chips button{padding:6px 11px;font-size:13px}
.chips button.sel{border-color:var(--acc);color:var(--acc)}
.foot{display:flex;gap:8px;justify-content:flex-end;margin-top:18px}
.chk{display:flex;align-items:center;gap:10px;margin-top:14px;color:var(--tx);font-size:14px}
.chk input{width:18px;height:18px}
.login{max-width:340px;margin:18vh auto 0}
.login .card{padding:22px}.login h1{margin:0 0 4px}
.err{color:var(--bad);font-size:13px;min-height:18px;margin-top:8px}
.res{word-break:break-all;font:12px ui-monospace,Menlo,monospace;background:var(--bg);padding:10px;border-radius:10px;margin:6px 0}
#toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%);background:#111c;color:#fff;padding:10px 16px;border-radius:99px;font-size:14px;opacity:0;pointer-events:none;transition:opacity .2s;backdrop-filter:blur(6px);max-width:90vw;z-index:99}
#toast.show{opacity:1}
@media(max-width:480px){.stats{grid-template-columns:repeat(2,1fr)}}
</style></head>
<body>

<div id="loginView" class="wrap login hidden">
  <div class="card">
    <h1>V2Panel</h1><div class="mut" style="margin-bottom:16px">Administrador de cuentas UUID</div>
    <input type="password" id="pw" placeholder="Contraseña" autocomplete="current-password">
    <div class="err" id="loginErr"></div>
    <button class="pri" id="loginBtn" style="width:100%;margin-top:6px">Entrar</button>
  </div>
</div>

<div id="appView" class="wrap hidden">
  <header>
    <h1>V2Panel</h1>
    <span class="pill" id="statusPill"><i class="dot" id="dot"></i><span id="statusTxt">…</span></span>
    <button id="gear" title="Ajustes">⚙</button>
    <button id="logout" title="Salir">⎋</button>
  </header>
  <div class="stats">
    <div class="stat"><b id="sTotal">0</b><span>Total</span></div>
    <div class="stat"><b id="sOk" style="color:var(--ok)">0</b><span>Activos</span></div>
    <div class="stat"><b id="sSoon" style="color:var(--warn)">0</b><span>Por vencer (≤3d)</span></div>
    <div class="stat"><b id="sExp" style="color:var(--bad)">0</b><span>Vencidos</span></div>
  </div>
  <div class="bar">
    <input type="search" id="q" placeholder="Buscar usuario o UUID…">
    <button class="pri" id="newBtn">+ Nuevo</button>
    <button id="cleanBtn">Limpiar vencidos</button>
    <button id="restartBtn">Reiniciar V2Ray</button>
  </div>
  <div class="grid" id="list"></div>
</div>

<dialog id="dNew">
  <h2>Nuevo usuario UUID</h2>
  <label>Usuario</label><input type="text" id="nNick" maxlength="20" placeholder="ej. juan01" autocomplete="off">
  <label>Duración (días)</label><input type="number" id="nDays" min="1" value="30" inputmode="numeric">
  <div class="chips" data-for="nDays"><button>7</button><button>15</button><button>30</button><button>60</button><button>90</button></div>
  <div class="err" id="nErr"></div>
  <div class="foot"><button data-close>Cancelar</button><button class="pri" id="nOk">Crear</button></div>
</dialog>

<dialog id="dRenew">
  <h2>Renovar <span id="rNick"></span></h2>
  <div class="mut" id="rInfo"></div>
  <label>Sumar días</label><input type="number" id="rDays" min="1" value="30" inputmode="numeric">
  <div class="chips" data-for="rDays"><button>7</button><button>15</button><button>30</button><button>60</button><button>90</button></div>
  <div class="err" id="rErr"></div>
  <div class="foot"><button data-close>Cancelar</button><button class="pri" id="rOk">Renovar</button></div>
</dialog>

<dialog id="dDone">
  <h2>✅ Usuario creado</h2>
  <div class="mut">Usuario</div><div id="dNick" style="font-weight:600"></div>
  <div class="mut" style="margin-top:10px">UUID</div><div class="res" id="dUuid"></div>
  <div class="mut">Expira</div><div id="dExp"></div>
  <div class="foot"><button id="dCopyUuid">Copiar UUID</button><button class="pri" id="dCopyLink">Copiar enlace</button></div>
  <div class="foot" style="margin-top:8px"><button data-close>Cerrar</button></div>
</dialog>

<dialog id="dManual">
  <h2>Copiar manualmente</h2>
  <div class="mut">Tu navegador bloqueó la copia automática (el panel usa HTTP). Selecciona el texto y cópialo.</div>
  <textarea id="mcText" readonly rows="5" style="width:100%;margin-top:10px;background:var(--bg);color:var(--tx);border:1px solid var(--line);border-radius:10px;padding:10px;font:12px ui-monospace,Menlo,monospace"></textarea>
  <div class="foot"><button class="pri" data-close>Listo</button></div>
</dialog>

<dialog id="dSet">
  <h2>Ajustes</h2>
  <label>Dominio o IP para los enlaces vmess://</label>
  <input type="text" id="setHost" placeholder="vacío = el que uses para abrir el panel">
  <label>Para tu panel maestro (URL y token)</label>
  <input type="text" id="setUrl" readonly>
  <div style="display:flex;gap:6px;margin-top:6px"><input type="text" id="setTok" readonly><button id="setCopyTok">Copiar</button></div>
  <label class="chk"><input type="checkbox" id="setAuto"> Eliminar vencidos automáticamente (cada hora)</label>
  <div class="err" id="setErr"></div>
  <div class="foot"><button data-close>Cancelar</button><button class="pri" id="setOk">Guardar</button></div>
</dialog>

<div id="toast"></div>

<script>
const $=s=>document.querySelector(s);
let S={users:[],running:false,settings:{}},curRenew=null,lastNew=null;

const esc=s=>String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
function toast(t){const e=$("#toast");e.textContent=t;e.classList.add("show");clearTimeout(toast.t);toast.t=setTimeout(()=>e.classList.remove("show"),2400)}

async function api(path,method="GET",body){
  const r=await fetch(path,{method,credentials:"same-origin",headers:{"Content-Type":"application/json","X-Panel":"1"},body:body?JSON.stringify(body):undefined});
  let d={};try{d=await r.json()}catch(e){}
  if(r.status===401&&path!=="/api/login"){showLogin();throw new Error("Sesión expirada")}
  if(!r.ok)throw new Error(d.error||("Error "+r.status));
  return d;
}

function legacyCopy(text){
  const host=document.querySelector("dialog[open]")||document.body;
  const t=document.createElement("textarea");
  t.value=text;t.setAttribute("readonly","");
  t.style.cssText="position:fixed;top:0;left:0;width:1px;height:1px;opacity:0";
  host.appendChild(t);
  t.focus();t.select();t.setSelectionRange(0,text.length);
  let ok=false;try{ok=document.execCommand("copy")}catch(e){}
  t.remove();return ok;
}
function manualCopy(text){
  $("#mcText").value=text;$("#dManual").showModal();
  const t=$("#mcText");t.focus();t.select();t.setSelectionRange(0,text.length);
}
async function copy(text,msg){
  try{
    if(navigator.clipboard&&window.isSecureContext){await navigator.clipboard.writeText(text);toast(msg||"Copiado");return}
  }catch(e){}
  if(legacyCopy(text)){toast(msg||"Copiado");return}
  manualCopy(text);
}

function showLogin(){$("#appView").classList.add("hidden");$("#loginView").classList.remove("hidden");$("#pw").value="";$("#pw").focus()}
function showApp(){$("#loginView").classList.add("hidden");$("#appView").classList.remove("hidden")}

async function load(){
  S=await api("/api/state");showApp();render();
}

function render(){
  const u=S.users,q=$("#q").value.trim().toLowerCase();
  $("#sTotal").textContent=u.length;
  $("#sOk").textContent=u.filter(x=>x.status==="ok"||x.status==="soon").length;
  $("#sSoon").textContent=u.filter(x=>x.status==="soon").length;
  $("#sExp").textContent=u.filter(x=>x.status==="expired").length;
  $("#dot").className="dot "+(S.running?"on":"off");
  $("#statusTxt").textContent=S.running?"V2Ray activo":"V2Ray detenido";
  const f=u.filter(x=>!q||x.nick.toLowerCase().includes(q)||x.uuid.includes(q));
  $("#list").innerHTML=f.length?f.map(x=>{
    const lab=x.status==="expired"?"VENCIDO":x.status==="sr"?"S/R":(x.days+(x.days===1?" día":" días"));
    return `<div class="card ${x.status}" data-u="${esc(x.uuid)}">
      <div class="row"><b>${esc(x.nick)}</b><span class="badge">${lab}</span></div>
      <button class="uuid" data-a="uuid" title="Copiar UUID">${esc(x.uuid)}</button>
      <div class="mut">Vence: ${esc(x.exp)}</div>
      <div class="acts"><button data-a="link">Enlace</button><button data-a="renew">Renovar</button><button class="danger" data-a="del">Eliminar</button></div>
    </div>`}).join(""):`<div class="empty" style="grid-column:1/-1">${u.length?"Sin resultados":"Aún no hay usuarios. Crea el primero con “+ Nuevo”."}</div>`;
}

$("#list").addEventListener("click",async e=>{
  const b=e.target.closest("button[data-a]");if(!b)return;
  const id=b.closest(".card").dataset.u,u=S.users.find(x=>x.uuid===id),a=b.dataset.a;
  try{
    if(a==="uuid")copy(id,"UUID copiado");
    else if(a==="link"){const r=await api(`/api/users/${id}/link`);copy(r.link,"Enlace copiado")}
    else if(a==="renew"){curRenew=u;$("#rNick").textContent=u.nick;$("#rInfo").textContent="Vence: "+u.exp+(u.status==="expired"?" (vencido: cuenta desde hoy)":"");$("#rErr").textContent="";$("#dRenew").showModal()}
    else if(a==="del"){if(!confirm(`¿Eliminar a “${u.nick}”? Esta acción no se puede deshacer.`))return;
      const r=await api(`/api/users/${id}`,"DELETE");toast(r.restarted?"Eliminado":"Eliminado (revisa V2Ray)");await load()}
  }catch(err){toast(err.message)}
});

// chips
document.querySelectorAll(".chips").forEach(c=>c.addEventListener("click",e=>{
  const b=e.target.closest("button");if(!b)return;
  $("#"+c.dataset.for).value=b.textContent;
  c.querySelectorAll("button").forEach(x=>x.classList.toggle("sel",x===b));
}));
document.querySelectorAll("[data-close]").forEach(b=>b.addEventListener("click",()=>b.closest("dialog").close()));

// login
async function doLogin(){
  $("#loginErr").textContent="";
  try{await api("/api/login","POST",{password:$("#pw").value});await load()}
  catch(e){$("#loginErr").textContent=e.message}
}
$("#loginBtn").onclick=doLogin;
$("#pw").addEventListener("keydown",e=>{if(e.key==="Enter")doLogin()});
$("#logout").onclick=async()=>{await api("/api/logout","POST");showLogin()};
$("#q").addEventListener("input",render);

// nuevo
$("#newBtn").onclick=()=>{$("#nNick").value="";$("#nDays").value=30;$("#nErr").textContent="";$("#dNew").showModal();setTimeout(()=>$("#nNick").focus(),50)};
$("#nOk").onclick=async()=>{
  $("#nErr").textContent="";$("#nOk").disabled=true;
  try{
    const r=await api("/api/users","POST",{nick:$("#nNick").value.trim(),days:parseInt($("#nDays").value,10)});
    lastNew=r;$("#dNew").close();
    $("#dNick").textContent=r.nick;$("#dUuid").textContent=r.uuid;$("#dExp").textContent=r.exp;
    $("#dCopyLink").classList.toggle("hidden",!r.link);
    $("#dDone").showModal();await load();
  }catch(e){$("#nErr").textContent=e.message}
  $("#nOk").disabled=false;
};
$("#nNick").addEventListener("keydown",e=>{if(e.key==="Enter")$("#nOk").click()});
$("#dCopyUuid").onclick=()=>copy(lastNew.uuid,"UUID copiado");
$("#dCopyLink").onclick=()=>copy(lastNew.link,"Enlace copiado");

// renovar
$("#rOk").onclick=async()=>{
  $("#rErr").textContent="";
  try{const r=await api(`/api/users/${curRenew.uuid}/renew`,"POST",{days:parseInt($("#rDays").value,10)});
    $("#dRenew").close();toast("Nueva fecha: "+r.exp);await load()}
  catch(e){$("#rErr").textContent=e.message}
};

// acciones globales
$("#cleanBtn").onclick=async()=>{
  const n=S.users.filter(x=>x.status==="expired").length;
  if(!n)return toast("No hay usuarios vencidos");
  if(!confirm(`¿Eliminar ${n} usuario(s) vencido(s)?`))return;
  try{const r=await api("/api/clean","POST");toast(r.deleted+" eliminado(s)");await load()}catch(e){toast(e.message)}
};
$("#restartBtn").onclick=async()=>{
  if(!confirm("¿Reiniciar V2Ray? Se cortarán las conexiones activas unos segundos."))return;
  toast("Reiniciando…");
  try{const r=await api("/api/restart","POST");toast(r.restarted?"V2Ray reiniciado":"No se pudo reiniciar");await load()}catch(e){toast(e.message)}
};

// ajustes
$("#setCopyTok").onclick=()=>copy($("#setTok").value,"Token copiado");
$("#gear").onclick=()=>{$("#setUrl").value=location.origin+"/";$("#setTok").value=S.settings.api_token||"";$("#setHost").value=S.settings.host||"";$("#setAuto").checked=!!S.settings.auto_clean;$("#setErr").textContent="";$("#dSet").showModal()};
$("#setOk").onclick=async()=>{
  try{await api("/api/settings","POST",{host:$("#setHost").value.trim(),auto_clean:$("#setAuto").checked});$("#dSet").close();toast("Guardado");await load()}
  catch(e){$("#setErr").textContent=e.message}
};

load().catch(()=>showLogin());
</script>
</body></html>
"""

if __name__ == "__main__":
    main()
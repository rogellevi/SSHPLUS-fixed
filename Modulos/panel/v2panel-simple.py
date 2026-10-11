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
import ssl
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
NETDEV = os.environ.get("V2PANEL_NETDEV", "/proc/net/dev")
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


def service_cmd(action):
    """Detiene o inicia V2Ray y confirma el resultado mirando el estado real del servicio."""
    want_running = (action == "start")
    for cmd in (["systemctl", action, "v2ray"], ["v2ray", action]):
        try:
            subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, timeout=40)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        time.sleep(1)
        if v2ray_status() == want_running:
            return True
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
def add_user(nick, days, uid=None):
    if not NICK_RE.match(nick or ""):
        raise ApiError("Usuario inválido: 2-32 caracteres (letras, números, punto, guion o guion bajo)")
    if not isinstance(days, int) or days < 1 or days > MAX_DAYS:
        raise ApiError("Duración inválida: entre 1 y %d días" % MAX_DAYS)
    with LOCK:
        users = read_registry()
        if any(u["nick"].lower() == nick.lower() for u in users):
            raise ApiError("El usuario ya existe", 409)
        if uid:
            uid = uid.lower()
            try:
                with open(V2CFG, encoding="utf-8") as f:
                    taken = uid in ids_of(f.read())
            except FileNotFoundError:
                taken = False
            if taken or any(u["uuid"].lower() == uid for u in users):
                raise ApiError("El UUID ya existe en este VPS", 409)
        else:
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


def _cpu_times():
    with open("/proc/stat") as f:
        p = [int(x) for x in f.readline().split()[1:]]
    return sum(p), p[3] + (p[4] if len(p) > 4 else 0)  # total, inactivo (idle + iowait)


def _cpu_pct(a, b):
    return max(0, min(100, round(100 * (1 - (b[1] - a[1]) / max(b[0] - a[0], 1)))))


def cpu_percent():
    try:
        a = _cpu_times()
        time.sleep(0.25)
        return _cpu_pct(a, _cpu_times())
    except Exception:
        return 0


CPU_LAST = {"v": None}
NET_LAST = {"rx": 0.0, "tx": 0.0}


def net_totals():
    """Bytes recibidos y enviados desde el arranque (suma de interfaces reales, sin lo/docker/veth)."""
    rx = tx = 0
    try:
        with open(NETDEV) as f:
            for line in list(f)[2:]:
                name, _, data = line.partition(":")
                name = name.strip()
                if not data or name == "lo" or name.startswith(("docker", "veth", "br-", "virbr")):
                    continue
                p = data.split()
                rx += int(p[0])
                tx += int(p[8])
    except Exception:
        pass
    return rx, tx


def sys_sampler():
    """Mide CPU y velocidad de red en segundo plano cada 2 s (la respuesta es instantánea)."""
    try:
        prev = _cpu_times()
    except Exception:
        prev = None
    pn, pt = net_totals(), time.monotonic()
    while True:
        time.sleep(2)
        now = time.monotonic()
        dt = max(now - pt, 0.001)
        try:
            if prev is not None:
                cur = _cpu_times()
                CPU_LAST["v"] = _cpu_pct(prev, cur)
                prev = cur
        except Exception:
            pass
        cn = net_totals()
        NET_LAST["rx"] = max(0.0, (cn[0] - pn[0]) / dt)  # si el contador se reinicia, queda en 0
        NET_LAST["tx"] = max(0.0, (cn[1] - pn[1]) / dt)
        pn, pt = cn, now


def uptime_seconds():
    try:
        with open("/proc/uptime") as f:
            return int(float(f.read().split()[0]))
    except Exception:
        return None


def mem_info():
    try:
        m = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, _, v = line.partition(":")
                m[k] = int(v.split()[0]) * 1024
        total = m["MemTotal"]
        used = total - m["MemAvailable"]
        return used, total
    except Exception:
        return 0, 0


def system_stats():
    cpu = CPU_LAST["v"] if CPU_LAST["v"] is not None else cpu_percent()
    mu, mt = mem_info()
    try:
        du = shutil.disk_usage("/")
        dused, dtotal = du.used, du.total
    except Exception:
        dused, dtotal = 0, 0
    pct = lambda a, b: round(100 * a / b) if b else 0
    return {
        "cpu": {"pct": cpu, "cores": os.cpu_count() or 1},
        "mem": {"pct": pct(mu, mt), "used": mu, "total": mt},
        "disk": {"pct": pct(dused, dtotal), "used": dused, "total": dtotal},
        "uptime": uptime_str(),
        "uptime_s": uptime_seconds(),
        "net": {"rx_rate": int(NET_LAST["rx"]), "tx_rate": int(NET_LAST["tx"]),
                "rx_total": net_totals()[0], "tx_total": net_totals()[1]},
    }


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
        want = str(f.get("uuid", "")).strip()
        if want and not UUID_RE.match(want):
            raise ApiError("UUID inválido")
        r = add_user(nick, to_int(f.get("days")), want or None)
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


# --------------------------------------------------------------------- TLS ----
def detect_cert():
    """Busca en config.json de V2Ray el certificado (y llave) que ya usa para TLS."""
    try:
        with open(V2CFG, encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception:
        return None
    inbounds = cfg.get("inbounds") or ([cfg["inbound"]] if "inbound" in cfg else [])
    for ib in inbounds:
        ss = ib.get("streamSettings") or {}
        for key in ("tlsSettings", "xtlsSettings"):
            for c in (ss.get(key) or {}).get("certificates") or []:
                crt, k = c.get("certificateFile"), c.get("keyFile")
                if crt and k and os.path.isfile(crt) and os.path.isfile(k):
                    return crt, k
    return None


def cert_summary(crt):
    try:
        r = subprocess.run(["openssl", "x509", "-in", crt, "-noout", "-subject", "-enddate"],
                           capture_output=True, text=True, timeout=5)
        return r.stdout.strip().replace("\n", " | ") if r.returncode == 0 else ""
    except Exception:
        return ""


def make_ssl_context(crt, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(crt, key)
    return ctx


def cert_reload_loop(ctx, crt, key):
    """Si el certificado se renueva (acme, certbot...), lo recarga sin reiniciar el panel."""
    try:
        last = os.path.getmtime(crt)
    except OSError:
        last = 0
    while True:
        time.sleep(6 * 3600)
        try:
            m = os.path.getmtime(crt)
            if m != last:
                ctx.load_cert_chain(crt, key)
                last = m
                print("Certificado SSL recargado", flush=True)
        except Exception as e:
            print("No se pudo recargar el certificado:", e, file=sys.stderr, flush=True)


def https_cmd(args):
    """python3 v2panel.py https [CERT KEY | off]"""
    if not os.path.exists(PANEL_CFG):
        sys.exit("Primero ejecuta: python3 %s setup" % sys.argv[0])
    cfg = load_panel_cfg()
    if args and args[0] == "off":
        cfg["https"] = False
        save_panel_cfg(cfg)
        return print("HTTPS desactivado. Reinicia el panel: systemctl restart v2panel")
    if len(args) >= 2:
        crt, key = args[0], args[1]
    else:
        found = detect_cert()
        if not found:
            return print("No encontré un certificado en la configuración de V2Ray.\n"
                         "Indícalo a mano: python3 %s https /ruta/cert.crt /ruta/llave.key" % sys.argv[0])
        crt, key = found
    try:
        make_ssl_context(crt, key)
    except Exception as e:
        return print("No se pudo usar ese certificado:", e)
    cfg.update({"https": True, "tls_cert": crt, "tls_key": key})
    save_panel_cfg(cfg)
    print("HTTPS activado con:\n  certificado:", crt, "\n  llave:      ", key)
    info = cert_summary(crt)
    if info:
        print("  ", info)
    print("\nReinicia el panel:  systemctl restart v2panel")
    print("Ábrelo con el DOMINIO del certificado: https://TU_DOMINIO:%s/" % cfg.get("port", 8085))
    print("En tu panel maestro, cambia la URL del VPS a https://...")


# -------------------------------------------------------------------- HTTP ---
class Handler(BaseHTTPRequestHandler):
    server_version = "v2panel"

    def setup(self):
        if isinstance(self.request, ssl.SSLSocket):
            self.request.settimeout(10)
            self.request.do_handshake()
        super().setup()

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
                         "default-src 'none'; style-src 'unsafe-inline' https://fonts.googleapis.com; "
                         "font-src https://fonts.gstatic.com; script-src 'unsafe-inline'; "
                         "connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(data)

    def cookie_flags(self):
        tls = isinstance(self.connection, ssl.SSLSocket)
        sec = "; Secure" if tls or self.headers.get("X-Forwarded-Proto") == "https" else ""
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
                    "users": users, "running": v2ray_status(), "system": system_stats(),
                    "settings": {"host": cfg.get("host", ""), "auto_clean": bool(cfg.get("auto_clean")),
                                 "api_token": cfg.get("api_token", "")},
                    "max_days": MAX_DAYS,
                })
            if method == "GET" and path == "/api/system":
                return self.send(200, system_stats())
            if method == "POST" and path == "/api/users":
                r = add_user(str(body.get("nick", "")).strip(), body.get("days"))
                r["link"] = build_link(r, (self.headers.get("Host") or "").split(":")[0])
                return self.send(200, r)
            if method == "POST" and m and m.group(2) == "renew":
                return self.send(200, renew_user(m.group(1), body.get("days")))
            if method == "POST" and m and m.group(2) == "setdays":
                return self.send(200, renew_user(m.group(1), body.get("days"), reset=True))
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
            if method == "POST" and path in ("/api/stop", "/api/start"):
                ok = service_cmd(path.rsplit("/", 1)[1])
                return self.send(200, {"ok": ok, "running": v2ray_status()})
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


class PanelServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass  # p. ej. alguien abre http:// en un puerto que ahora es https://


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
    found = detect_cert()
    if found and not cfg.get("https"):
        try:
            ans = input("Encontré el certificado SSL de V2Ray (%s).\n¿Usarlo para abrir el panel con HTTPS? [s/N]: " % found[0]).strip().lower()
        except EOFError:
            ans = ""
        if ans in ("s", "si", "sí", "y", "yes"):
            cfg.update({"https": True, "tls_cert": found[0], "tls_key": found[1]})
    save_panel_cfg(cfg)
    print("Configuración guardada en", PANEL_CFG)
    print("Token para el panel maestro:", cfg["api_token"])
    if cfg.get("https"):
        print("HTTPS activado. Ábrelo con el dominio del certificado: https://TU_DOMINIO:%s/" % cfg["port"])


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("setup", "passwd"):
        return setup()
    if len(sys.argv) > 1 and sys.argv[1] == "https":
        return https_cmd(sys.argv[2:])
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
    threading.Thread(target=sys_sampler, daemon=True).start()
    srv = PanelServer((cfg.get("bind", "0.0.0.0"), int(cfg.get("port", 8085))), Handler)
    scheme = "http"
    if cfg.get("https"):
        try:
            ctx = make_ssl_context(cfg["tls_cert"], cfg["tls_key"])
            srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
            threading.Thread(target=cert_reload_loop, args=(ctx, cfg["tls_cert"], cfg["tls_key"]), daemon=True).start()
            scheme = "https"
        except Exception as e:
            print("!! HTTPS no disponible (%s). Sirviendo en HTTP sin cifrar." % e, file=sys.stderr, flush=True)
    print("V2Panel escuchando en %s://%s:%s" % (scheme, cfg.get("bind"), cfg.get("port")), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


# ---------------------------------------------------------------- frontend ---
INDEX_HTML = r"""<!doctype html>
<html lang="es"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#060b14">
<title>Panel V2Ray</title>
<script>
(function(){var t=null;try{t=localStorage.getItem('sshplus_theme')}catch(e){}if(!t||['dark','light','paper','gaming'].indexOf(t)<0)t='dark';document.documentElement.setAttribute('data-theme',t);})();
</script>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Share+Tech+Mono&display=swap" rel="stylesheet">
<style>
/* ───────── Temas (mismos tokens del Panel VPS) ───────── */
:root,[data-theme="dark"]{--bg-body:#060b14;--bg-card:#0d1321;--bg-card-alt:#0a1525;--bg-input:#0a0f1a;--bg-hover:rgba(0,200,255,0.04);--border:#1e3a5f;--border-soft:#0e2a45;--text:#e0f0ff;--text-muted:#3a7ca5;--text-soft:#7eb8ff;--accent:#00c8ff;--accent-2:#00ff9d;--accent-3:#ff4d6d;--accent-4:#ffbe0b;--glow:rgba(0,180,255,0.15);--glow-strong:rgba(0,200,255,0.4);--grid-color:rgba(0,200,255,0.03);--font-main:'Share Tech Mono',monospace;--font-title:'Orbitron',monospace;--radius:14px;--radius-sm:8px;--scanline-opacity:1;--grid-opacity:1;--card-glow:0 0 60px rgba(0,180,255,0.15);--neon-text-shadow:0 0 20px;--bar-glow:0 0 8px;--dropdown-shadow:0 8px 30px rgba(0,0,0,0.5),0 0 20px rgba(0,200,255,0.1);color-scheme:dark}
[data-theme="light"]{--bg-body:#f0f4f8;--bg-card:#fff;--bg-card-alt:#f7fafc;--bg-input:#fff;--bg-hover:rgba(0,100,200,0.06);--border:#d8e0e8;--border-soft:#e8edf2;--text:#1a2332;--text-muted:#6b7a8f;--text-soft:#3a5068;--accent:#0077cc;--accent-2:#00a86b;--accent-3:#d93652;--accent-4:#e89a00;--glow:rgba(0,100,200,0.08);--glow-strong:rgba(0,100,200,0.15);--grid-color:rgba(0,100,200,0.04);--font-main:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;--font-title:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;--radius:12px;--radius-sm:8px;--scanline-opacity:0;--grid-opacity:.5;--card-glow:0 2px 20px rgba(0,0,0,0.06);--neon-text-shadow:none;--bar-glow:none;--dropdown-shadow:0 8px 24px rgba(0,0,0,0.12);color-scheme:light}
[data-theme="paper"]{
  --bg-body:#f4f1ea;--bg-card:#fbfaf5;--bg-card-alt:#f7f3e8;--bg-input:#fdfcf7;--bg-hover:rgba(120,90,50,0.06);
  --border:#d4c9a8;--border-soft:#e6ddc2;--text:#3d3833;--text-muted:#8a7a5c;--text-soft:#6b5d45;
  --accent:#8b5a2b;--accent-2:#5a7a3a;--accent-3:#a84032;--accent-4:#c89030;
  --glow:rgba(120,90,50,0.1);--glow-strong:rgba(120,90,50,0.15);--grid-color:rgba(120,90,50,0.06);
  --font-main:'Inter','Segoe UI',system-ui,sans-serif;--font-title:'Playfair Display','Lora',Georgia,serif;
  --radius:6px;--radius-sm:4px;--scanline-opacity:0;--grid-opacity:.4;
  --card-glow:0 2px 12px rgba(120,90,50,0.08);--neon-text-shadow:none;--bar-glow:none;--dropdown-shadow:0 8px 20px rgba(120,90,50,0.15);color-scheme:light}
[data-theme="gaming"]{--bg-body:#08000f;--bg-card:#110020;--bg-card-alt:#0d001a;--bg-input:#0a0015;--bg-hover:rgba(255,0,255,0.06);--border:#3a0066;--border-soft:#220040;--text:#f0e0ff;--text-muted:#8844bb;--text-soft:#cc77ff;--accent:#ff00ff;--accent-2:#39ff14;--accent-3:#ff003c;--accent-4:#00ffff;--glow:rgba(255,0,255,0.2);--glow-strong:rgba(255,0,255,0.5);--grid-color:rgba(255,0,255,0.04);--font-main:'Rajdhani','Share Tech Mono',sans-serif;--font-title:'Orbitron',monospace;--radius:10px;--radius-sm:6px;--scanline-opacity:1;--grid-opacity:1;--card-glow:0 0 40px rgba(255,0,255,0.15),0 0 80px rgba(0,255,255,0.05);--neon-text-shadow:0 0 20px;--bar-glow:0 0 12px;--dropdown-shadow:0 8px 30px rgba(255,0,255,0.3),0 0 40px rgba(0,255,255,0.1);color-scheme:dark}

/* ───────── Base ───────── */
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg-body);font-family:var(--font-main);color:var(--text);min-height:100vh;display:flex;flex-direction:column;transition:background .4s,color .4s;
  padding:env(safe-area-inset-top) env(safe-area-inset-right) env(safe-area-inset-bottom) env(safe-area-inset-left)}
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.03) 2px,rgba(0,0,0,0.03) 4px);pointer-events:none;z-index:999;opacity:var(--scanline-opacity)}
[data-theme="gaming"] body::before{background:repeating-linear-gradient(0deg,transparent,transparent 1px,rgba(255,0,255,0.015) 1px,rgba(255,0,255,0.015) 3px)}
.grid-bg{position:fixed;inset:0;background-image:linear-gradient(var(--grid-color) 1px,transparent 1px),linear-gradient(90deg,var(--grid-color) 1px,transparent 1px);background-size:40px 40px;pointer-events:none;opacity:var(--grid-opacity);z-index:0}
[data-theme="paper"] .grid-bg{background-image:linear-gradient(var(--grid-color) 1px,transparent 1px);background-size:100% 32px}
[data-theme="gaming"] .grid-bg{background-size:50px 50px}
button,input,textarea{font-family:inherit;color:inherit}
.hidden{display:none!important}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:var(--bg-body)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
svg.i{width:16px;height:16px;stroke:currentColor;fill:none;stroke-width:1.9;stroke-linecap:round;stroke-linejoin:round;flex:none;display:block}

@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
@keyframes rgbText{0%{background-position:0% center}100%{background-position:200% center}}
@keyframes rgbPulse{0%,100%{box-shadow:0 0 15px rgba(255,0,255,0.6)}33%{box-shadow:0 0 15px rgba(0,255,255,0.6)}66%{box-shadow:0 0 15px rgba(57,255,20,0.6)}}
@keyframes heartbeat{0%,100%{transform:scale(1)}50%{transform:scale(1.2)}}

/* ───────── Acceso ───────── */
.login-wrap{display:flex;align-items:center;justify-content:center;min-height:calc(100vh - 70px);flex:1;position:relative;z-index:1;padding:20px}
.login-box{background:var(--bg-card);border:1px solid var(--border);border-radius:16px;padding:48px 40px;width:100%;max-width:400px;text-align:center;box-shadow:var(--card-glow);position:relative;overflow:hidden}
.login-box::before{content:'';position:absolute;top:0;left:0;width:100%;height:2px;background:linear-gradient(90deg,transparent,var(--accent),transparent)}
.login-logo{display:flex;align-items:center;justify-content:center;gap:12px;margin-bottom:24px}
.login-logo-icon{width:48px;height:48px;background:linear-gradient(135deg,var(--accent),var(--text-soft));border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:24px;box-shadow:0 0 25px var(--glow-strong)}
[data-theme="gaming"] .login-logo-icon{background:linear-gradient(135deg,#ff00ff,#00ffff);box-shadow:0 0 25px rgba(255,0,255,0.6);animation:rgbPulse 2s ease-in-out infinite}
.login-title{font-family:var(--font-title);font-size:28px;font-weight:900;letter-spacing:3px;background:linear-gradient(90deg,var(--accent),var(--text-soft));-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:4px}
[data-theme="gaming"] .login-title{background:linear-gradient(90deg,#ff00ff,#00ffff,#39ff14);background-size:200% auto;-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;animation:rgbText 3s linear infinite}
.login-title span{-webkit-text-fill-color:var(--accent-2)}
[data-theme="gaming"] .login-title span{-webkit-text-fill-color:#39ff14}
.login-sub{color:var(--text-muted);font-size:11px;letter-spacing:2px;margin-bottom:32px}
[data-theme="paper"] .login-sub{font-style:italic;font-size:13px;letter-spacing:0}
.login-input{width:100%;background:var(--bg-input);border:1px solid var(--border);border-radius:8px;padding:14px 16px;color:var(--text);font-family:monospace;font-size:14px;outline:none;margin-bottom:16px;transition:border-color .2s}
.login-input:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--glow)}
.login-btn{width:100%;background:transparent;border:1px solid var(--accent-2);color:var(--accent-2);border-radius:8px;padding:14px;cursor:pointer;font-family:var(--font-main);font-size:13px;letter-spacing:1px;transition:all .2s;font-weight:700}
.login-btn:hover{background:var(--accent-2);color:var(--bg-body);box-shadow:0 0 20px var(--glow-strong)}
[data-theme="gaming"] .login-btn{border-color:#39ff14;color:#39ff14}
[data-theme="gaming"] .login-btn:hover{background:#39ff14;color:#08000f;box-shadow:0 0 20px rgba(57,255,20,0.4)}
.login-err{color:var(--accent-3);font-size:12px;margin-top:12px;padding:10px;background:color-mix(in srgb,var(--accent-3) 10%,transparent);border:1px solid color-mix(in srgb,var(--accent-3) 30%,transparent);border-radius:8px}
.login-hint{color:var(--text-muted);font-size:10px;margin-top:20px;letter-spacing:.5px;opacity:.7}

/* ───────── Encabezado ───────── */
.wrap{max-width:1200px;margin:0 auto;padding:0 20px;width:100%;flex:1;position:relative;z-index:1}
.header{padding:28px 0 20px;display:grid;grid-template-columns:1fr auto;align-items:center;border-bottom:1px solid var(--border-soft);gap:12px}
.logo{display:flex;align-items:center;gap:12px}
.logo-icon{width:36px;height:36px;background:linear-gradient(135deg,var(--accent),var(--text-soft));border-radius:var(--radius-sm);display:flex;align-items:center;justify-content:center;font-size:18px;box-shadow:0 0 20px var(--glow-strong)}
[data-theme="paper"] .logo-icon{background:var(--bg-card-alt);border:2px solid var(--accent);box-shadow:none}
[data-theme="gaming"] .logo-icon{background:linear-gradient(135deg,#ff00ff,#00ffff);box-shadow:0 0 20px rgba(255,0,255,0.6);animation:rgbPulse 2s ease-in-out infinite}
.logo-text{font-family:var(--font-title);font-size:20px;font-weight:900;letter-spacing:3px;background:linear-gradient(90deg,var(--accent),var(--text-soft));-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
[data-theme="paper"] .logo-text{font-size:28px;letter-spacing:1px;font-weight:700}
[data-theme="gaming"] .logo-text{background:linear-gradient(90deg,#ff00ff,#00ffff,#39ff14);background-size:200% auto;-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;animation:rgbText 3s linear infinite}
.logo-text span{-webkit-text-fill-color:var(--accent-2)}
[data-theme="gaming"] .logo-text span{-webkit-text-fill-color:#39ff14}
.logo-sub{color:var(--text-muted);font-size:10px;margin-top:3px;letter-spacing:2px}
[data-theme="paper"] .logo-sub{font-style:italic;font-size:12px;letter-spacing:0}
[data-theme="gaming"] .logo-sub{letter-spacing:4px;color:#8844bb}
.header-right{display:flex;gap:10px;align-items:center;flex-wrap:wrap}

/* ───────── Botones (sobrios) ───────── */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;min-height:40px;padding:0 16px;border-radius:var(--radius-sm);border:1px solid var(--border);background:var(--bg-card);color:var(--text);font-family:var(--font-main);font-size:13px;cursor:pointer;white-space:nowrap;transition:border-color .15s,background .15s,color .15s,filter .15s}
.btn:hover:not(:disabled){border-color:var(--accent);color:var(--accent)}
.btn:disabled{opacity:.5;cursor:default}
.btn.pri{background:var(--accent-2);border-color:var(--accent-2);color:var(--bg-body);font-weight:700}
.btn.pri:hover:not(:disabled){filter:brightness(1.1);color:var(--bg-body)}
.btn.warn{color:var(--accent-3)}
.btn.warn:hover:not(:disabled){border-color:var(--accent-3);color:var(--accent-3)}
.btn svg.i{width:18px;height:18px}
.ibtn{width:40px;padding:0;border-color:transparent;background:transparent;color:var(--text-muted)}
.ibtn:hover:not(:disabled){background:var(--bg-hover);color:var(--text);border-color:transparent}
.ibtn.warn:hover:not(:disabled){background:color-mix(in srgb,var(--accent-3) 12%,transparent);color:var(--accent-3)}
.pill{display:inline-flex;align-items:center;gap:8px;height:36px;padding:0 14px;border-radius:99px;border:1px solid var(--border);background:var(--bg-card);font-size:12px;letter-spacing:.5px;white-space:nowrap}
.pill .pd{width:8px;height:8px;border-radius:50%;background:var(--text-muted)}
.pill.online .pd{background:var(--accent-2);box-shadow:0 0 8px var(--accent-2)}
.pill.offline .pd{background:var(--accent-3);box-shadow:0 0 8px var(--accent-3)}
.login-switch{position:fixed;top:calc(14px + env(safe-area-inset-top));right:14px;z-index:5}
.login-switch .btn{background:var(--bg-card);border-color:var(--border);color:var(--text-soft)}
.search{position:relative;flex:1;min-width:190px}
.search svg.i{position:absolute;left:13px;top:50%;transform:translateY(-50%);color:var(--text-muted);pointer-events:none}
.search .search-input{width:100%;min-height:40px;padding:0 14px 0 40px;border-radius:var(--radius-sm)}
.foot{display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap;margin-top:20px}
/* Selector de temas (ventana) */
.themes{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:6px}
.tcard{display:flex;flex-direction:column;gap:3px;text-align:left;padding:13px;border:1.5px solid var(--border);background:var(--bg-card-alt);border-radius:var(--radius-sm);cursor:pointer;color:var(--text);font-family:var(--font-main);transition:border-color .15s}
.tcard:hover{border-color:var(--text-muted)}
.tcard b{font-size:13px;letter-spacing:1px}.tcard small{font-size:11px;color:var(--text-muted)}
.tcard[aria-checked=true]{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent),0 0 14px var(--glow)}
.sw{display:flex;margin-bottom:9px}
.sw i{width:22px;height:22px;border-radius:50%;border:2px solid var(--bg-card-alt);margin-right:-6px}
.sw i:nth-child(1){background:var(--a)}.sw i:nth-child(2){background:var(--b)}.sw i:nth-child(3){background:var(--c)}

/* ───────── Resumen (también filtra) ───────── */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:24px 0}
.stat-card{background:linear-gradient(135deg,var(--bg-card),var(--bg-card-alt));border:1px solid var(--border);border-radius:var(--radius);padding:18px 20px;position:relative;overflow:hidden;transition:all .4s;box-shadow:var(--card-glow);text-align:left;cursor:pointer;color:var(--text);font-family:var(--font-main)}
.stat-card::before{content:'';position:absolute;top:0;left:0;width:100%;height:2px}
.stat-card[data-k=all]::before{background:linear-gradient(90deg,transparent,var(--accent),transparent)}
.stat-card[data-k=active]::before{background:linear-gradient(90deg,transparent,var(--accent-2),transparent)}
.stat-card[data-k=soon]::before{background:linear-gradient(90deg,transparent,var(--accent-4),transparent)}
.stat-card[data-k=expired]::before{background:linear-gradient(90deg,transparent,var(--accent-3),transparent)}
.stat-card:hover{border-color:var(--accent)}
.stat-card[aria-pressed=true]{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent),var(--card-glow)}
.stat-label{color:var(--text-muted);font-size:10px;letter-spacing:2px;margin-bottom:6px}
[data-theme="paper"] .stat-label{font-size:12px;letter-spacing:0;font-style:italic}
.stat-value{font-family:var(--font-title);font-weight:700;font-size:30px}
.stat-card[data-k=all] .stat-value{color:var(--accent);text-shadow:var(--neon-text-shadow) var(--accent)}
.stat-card[data-k=active] .stat-value{color:var(--accent-2);text-shadow:var(--neon-text-shadow) var(--accent-2)}
.stat-card[data-k=soon] .stat-value{color:var(--accent-4);text-shadow:var(--neon-text-shadow) var(--accent-4)}
.stat-card[data-k=expired] .stat-value{color:var(--accent-3);text-shadow:var(--neon-text-shadow) var(--accent-3)}
[data-theme="light"] .stat-value,[data-theme="paper"] .stat-value{text-shadow:none}
.stat-sub{font-size:10px;color:var(--text-muted);margin-top:4px;letter-spacing:.5px}

/* ───────── Herramientas ───────── */
.toolbar{display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
.search-input{background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:10px 14px;color:var(--text);font-family:var(--font-main);font-size:13px;outline:none;flex:1;min-width:180px;transition:border-color .2s,background .4s}
.search-input:focus{border-color:var(--accent)}

/* ───────── Lista de cuentas ───────── */
.table-wrap{margin-bottom:40px}
#list{display:flex;flex-direction:column;gap:12px}
.lhead,.lrow{display:grid;grid-template-columns:minmax(150px,1.2fr) minmax(200px,2.2fr) 110px 90px 112px;grid-template-areas:"name uuid exp days acts";gap:12px;align-items:center;padding:13px 16px}
.lhead{color:var(--text-muted);font-size:10px;letter-spacing:2px;padding-top:0;padding-bottom:10px}
[data-theme="paper"] .lhead{font-size:12px;letter-spacing:0;font-style:italic}
.lrow{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--card-glow);transition:border-color .2s,background .2s}
.lrow:hover{background:var(--bg-hover);border-color:color-mix(in srgb,var(--accent) 45%,var(--border))}
.c-name{grid-area:name;min-width:0}.c-uuid{grid-area:uuid;min-width:0}.c-exp{grid-area:exp}.c-days{grid-area:days}.c-acts{grid-area:acts}
.nm{display:block;font-size:14px;font-weight:700;letter-spacing:.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-bottom:5px}
.badge{display:inline-flex;align-items:center;gap:5px;border-radius:20px;padding:3px 10px;font-size:10px;letter-spacing:1px}
.badge-active{background:color-mix(in srgb,var(--accent-2) 12%,transparent);border:1px solid color-mix(in srgb,var(--accent-2) 35%,transparent);color:var(--accent-2)}
.badge-soon{background:color-mix(in srgb,var(--accent-4) 12%,transparent);border:1px solid color-mix(in srgb,var(--accent-4) 35%,transparent);color:var(--accent-4)}
.badge-expired{background:color-mix(in srgb,var(--accent-3) 12%,transparent);border:1px solid color-mix(in srgb,var(--accent-3) 35%,transparent);color:var(--accent-3)}
.badge-sr{background:color-mix(in srgb,var(--text-muted) 10%,transparent);border:1px solid color-mix(in srgb,var(--text-muted) 25%,transparent);color:var(--text-muted)}
.dot{width:5px;height:5px;border-radius:50%;display:inline-block;background:currentColor}
.badge-active .dot{box-shadow:0 0 5px var(--accent-2);animation:pulse 2s infinite}
.uuid-btn{display:flex;align-items:center;gap:8px;width:100%;min-width:0;background:var(--bg-input);border:1px solid transparent;border-radius:6px;padding:7px 10px;cursor:pointer;color:var(--text-soft);text-align:left;transition:all .2s}
.uuid-btn:hover{border-color:var(--accent);color:var(--accent)}
.uuid-btn code{flex:1;min-width:0;font-family:'Share Tech Mono',ui-monospace,Menlo,Consolas,monospace;font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.c-exp{font-size:12px}
.c-exp .lbl{display:none;color:var(--text-muted);margin-right:6px}
.expiry-ok{color:var(--accent-2)}.expiry-warn{color:var(--accent-4)}.expiry-bad{color:var(--accent-3)}.expiry-na{color:var(--text-muted)}
.c-days b{font-family:var(--font-title);font-size:18px;font-weight:700}
.c-days small{margin-left:4px;font-size:10px;color:var(--text-muted);letter-spacing:.5px}
.c-acts{display:flex;gap:2px;justify-content:flex-end}.c-acts .btn{width:36px;min-height:36px}
.empty-state{text-align:center;padding:60px 20px;color:var(--text-muted);background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--card-glow)}
.empty-state .icon{font-size:48px;margin-bottom:14px;opacity:.5}
.empty-state h3{font-family:var(--font-title);font-size:18px;color:var(--text);margin-bottom:8px;letter-spacing:2px}
[data-theme="paper"] .empty-state h3{font-size:26px;letter-spacing:0}
.empty-state p{margin-bottom:20px;font-size:13px}

/* ───────── Diálogos ───────── */
dialog.modal{background:var(--bg-card);color:var(--text);border:1px solid var(--border);border-radius:var(--radius);padding:28px;width:90%;max-width:500px;box-shadow:var(--card-glow);font-family:var(--font-main);margin:auto;max-height:90vh;overflow-y:auto}
dialog.modal[open]{animation:fadeIn .2s ease}
dialog.modal::backdrop{background:rgba(0,0,0,0.8);backdrop-filter:blur(6px)}
[data-theme="light"] dialog.modal::backdrop{background:rgba(20,30,50,0.5)}
[data-theme="paper"] dialog.modal::backdrop{background:rgba(60,50,30,0.5)}
[data-theme="gaming"] dialog.modal::backdrop{background:rgba(10,0,20,0.9);backdrop-filter:blur(10px)}
.modal-title{color:var(--accent);font-family:var(--font-title);font-size:14px;margin-bottom:20px;display:flex;justify-content:space-between;align-items:center;letter-spacing:2px}
[data-theme="paper"] .modal-title{font-size:22px;letter-spacing:0}
.close-btn{background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:18px}
.close-btn:hover{color:var(--text)}
.sub{color:var(--text-muted);font-size:12px;margin:-8px 0 16px;line-height:1.6}
.field{margin-bottom:14px}
.field label{display:block;color:var(--text-soft);font-size:10px;letter-spacing:1px;margin-bottom:5px}
[data-theme="paper"] .field label{font-size:12px;letter-spacing:0;font-style:italic}
.field input[type=text],.field input[type=number]{width:100%;background:var(--bg-input);border:1px solid var(--border);border-radius:7px;padding:9px 12px;color:var(--text);font-family:var(--font-main);font-size:13px;outline:none;transition:border-color .2s,background .4s}
.field input:focus{border-color:var(--accent)}
.field .hint{font-size:10px;color:var(--text-muted);margin-top:4px;letter-spacing:.3px}
.chips{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
.chip-btn{background:transparent;border:1px solid var(--border);color:var(--text-muted);border-radius:8px;padding:6px 12px;cursor:pointer;font-family:var(--font-main);font-size:11px;letter-spacing:1px;transition:all .2s}
.chip-btn:hover{border-color:var(--accent);color:var(--accent)}
.chip-btn.sel{background:color-mix(in srgb,var(--accent) 15%,transparent);border-color:var(--accent);color:var(--accent)}
.form-err{color:var(--accent-3);font-size:12px;margin-bottom:12px;padding:10px;background:color-mix(in srgb,var(--accent-3) 10%,transparent);border:1px solid color-mix(in srgb,var(--accent-3) 30%,transparent);border-radius:8px}
.kv{color:var(--text-muted);font-size:10px;letter-spacing:1px;margin-top:12px}
.kv-v{font-size:14px;margin-top:3px}
.res{word-break:break-all;font:12px/1.5 'Share Tech Mono',ui-monospace,Menlo,monospace;background:var(--bg-input);border:1px solid var(--border-soft);border-radius:7px;padding:10px 12px;margin-top:4px;color:var(--accent)}
.chk{display:flex;align-items:center;gap:10px;margin:6px 0 14px;font-size:12px;cursor:pointer}
.chk input{width:16px;height:16px;accent-color:var(--accent)}
.row2{display:flex;gap:8px}.row2 input{flex:1;min-width:0}.row2 .btn{flex:none}
.tok-t{margin-top:14px}

/* ───────── Aviso y pie ───────── */
.toast{position:fixed;bottom:28px;right:28px;border-radius:10px;padding:12px 20px;font-size:12px;font-family:var(--font-main);z-index:2000;display:none;animation:fadeIn .3s ease;max-width:400px;background:var(--bg-card)}
.toast.show{display:block}
.toast-ok{border:1px solid var(--accent-2);color:var(--accent-2);box-shadow:0 0 20px color-mix(in srgb,var(--accent-2) 25%,transparent)}
.toast-err{border:1px solid var(--accent-3);color:var(--accent-3);box-shadow:0 0 20px color-mix(in srgb,var(--accent-3) 25%,transparent)}
[data-theme="light"] .toast-ok,[data-theme="light"] .toast-err,[data-theme="paper"] .toast-ok,[data-theme="paper"] .toast-err{box-shadow:0 4px 20px rgba(0,0,0,0.15)}
.footer{background:var(--bg-card);border-top:1px solid var(--border);padding:18px 20px;text-align:center;color:var(--text-muted);font-size:11px;letter-spacing:1px;margin-top:40px;position:relative;z-index:1}
.footer .heart{color:var(--accent-3);display:inline-block;animation:heartbeat 1.5s ease-in-out infinite}
.footer .year{color:var(--text-soft);font-weight:700}
.footer .version{margin-top:4px;font-size:10px;opacity:.7}

/* ───────── Móvil ───────── */
@media(max-width:720px){
  .stats{grid-template-columns:1fr 1fr}
  .header{grid-template-columns:1fr;padding:18px 0 14px}
  .header-right{width:100%;justify-content:flex-start}
  .lhead{display:none}
  .lrow{grid-template-columns:1fr auto;grid-template-areas:"name days" "uuid uuid" "exp acts";row-gap:10px;padding:14px 14px}
  .c-days{text-align:right}
  .c-exp .lbl{display:inline}
  .c-acts .btn{width:42px;min-height:42px}
  .toolbar .lbl-sm span{display:none}
  .toolbar .lbl-sm{width:42px;padding:0}
  .login-box{padding:36px 24px}
  .toast{left:16px;right:16px;bottom:18px;max-width:none}
}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
.svc{margin-top:18px;padding-top:16px;border-top:1px solid var(--border-soft)}
.svc label{margin-bottom:8px}
.svc-st{display:block;font-size:12px;margin-bottom:10px}
.svc-btns{display:flex;gap:8px}.svc-btns .btn{flex:1}
.btn.danger{color:var(--accent-3);border-color:color-mix(in srgb,var(--accent-3) 40%,transparent)}
.btn.danger:hover:not(:disabled){background:color-mix(in srgb,var(--accent-3) 14%,transparent);border-color:var(--accent-3);color:var(--accent-3)}
.btn.start{color:var(--accent-2);border-color:color-mix(in srgb,var(--accent-2) 40%,transparent)}
.btn.start:hover:not(:disabled){background:color-mix(in srgb,var(--accent-2) 14%,transparent);border-color:var(--accent-2);color:var(--accent-2)}
.seg{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-bottom:14px}
.seg .chip-btn{padding:9px 12px;font-size:12px}
.preview{margin:4px 0 14px;padding:10px 12px;border:1px dashed var(--border);border-radius:var(--radius-sm);font-size:12px;line-height:1.6;color:var(--text-soft)}
.preview b{color:var(--accent)}
.sys{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin:22px 0 0;padding:14px 18px;background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--card-glow)}
.gauge{min-width:0}
.g-top{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:8px}
.g-lbl{color:var(--text-muted);font-size:10px;letter-spacing:2px}
[data-theme="paper"] .g-lbl{font-size:12px;letter-spacing:0;font-style:italic}
.g-val{font-family:var(--font-title);font-weight:700;font-size:17px;font-variant-numeric:tabular-nums}
.g-bar{height:6px;border-radius:99px;background:var(--bg-input);border:1px solid var(--border-soft);overflow:hidden}
.g-bar i{display:block;height:100%;width:0;border-radius:99px;background:var(--accent-2);box-shadow:var(--bar-glow) var(--accent-2);transition:width .6s ease,background .3s}
.g-det{margin-top:7px;font-size:10px;color:var(--text-muted);letter-spacing:.3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.gauge.warn .g-val{color:var(--accent-4)}.gauge.warn .g-bar i{background:var(--accent-4);box-shadow:var(--bar-glow) var(--accent-4)}
.gauge.bad .g-val{color:var(--accent-3)}.gauge.bad .g-bar i{background:var(--accent-3);box-shadow:var(--bar-glow) var(--accent-3)}
.sys-foot{grid-column:1/-1;display:flex;flex-wrap:wrap;gap:8px 24px;padding-top:12px;border-top:1px solid var(--border-soft)}
.sf{display:inline-flex;align-items:baseline;gap:7px;white-space:nowrap;font-size:11px;color:var(--text-muted)}
.sf-l{font-style:normal;font-size:10px;letter-spacing:1.5px}
.sf.rx .sf-l{color:var(--accent)}.sf.tx .sf-l{color:var(--accent-2)}
[data-theme="paper"] .sf-l{letter-spacing:0;font-style:italic;font-size:12px}
.sf b{font-family:var(--font-title);font-size:13px;font-weight:700;color:var(--text);font-variant-numeric:tabular-nums}
.sf em{font-style:normal}
@media(max-width:720px){.sys-foot{gap:6px 16px;padding-top:10px}.sys{gap:10px;padding:12px 12px;margin-top:16px}.g-val{font-size:15px}.g-lbl{letter-spacing:1px}}
@media(max-width:380px){.g-det{display:none}}
</style></head>
<body>
<div class="grid-bg"></div>

<!-- ───────── Acceso ───────── -->
<div id="loginView" class="login-wrap hidden">
  <div class="login-switch"><button class="btn ibtn" data-open="dTheme" aria-label="Cambiar apariencia" title="Apariencia"><i data-ic="theme"></i></button></div>
  <div class="login-box">
    <div class="login-logo"><div class="login-logo-icon">🔐</div></div>
    <div class="login-title">PANEL <span>V2RAY</span></div>
    <div class="login-sub">ADMINISTRADOR DE CUENTAS UUID</div>
    <input class="login-input" type="password" id="pw" placeholder="Contraseña" autocomplete="current-password" aria-label="Contraseña">
    <button class="login-btn" id="loginBtn">ENTRAR</button>
    <div class="login-err hidden" id="loginErr" role="alert"></div>
    <div class="login-hint">Acceso restringido al administrador</div>
  </div>
</div>

<!-- ───────── Panel ───────── -->
<div id="appView" class="wrap hidden">
  <div class="header">
    <div class="logo">
      <div class="logo-icon">🛰️</div>
      <div><div class="logo-text">Panel<span>V2Ray</span></div><div class="logo-sub">MANAGER · UUID</div></div>
    </div>
    <div class="header-right">
      <span class="pill offline" id="statusPill"><i class="pd"></i><span id="statusTxt">…</span></span>
      <button class="btn ibtn" data-open="dTheme" aria-label="Cambiar apariencia" title="Apariencia"><i data-ic="theme"></i></button>
      <button class="btn ibtn" id="gear" aria-label="Ajustes" title="Ajustes"><i data-ic="sliders"></i></button>
      <button class="btn ibtn" id="logout" aria-label="Cerrar sesión" title="Cerrar sesión"><i data-ic="logout"></i></button>
    </div>
  </div>

  <section class="sys" aria-label="Uso del servidor">
    <div class="gauge" id="gCpu"><div class="g-top"><span class="g-lbl">CPU</span><span class="g-val" id="gCpuV">–</span></div><div class="g-bar" role="progressbar" aria-label="Uso de CPU" aria-valuemin="0" aria-valuemax="100"><i></i></div><div class="g-det" id="gCpuD">&nbsp;</div></div>
    <div class="gauge" id="gMem"><div class="g-top"><span class="g-lbl">RAM</span><span class="g-val" id="gMemV">–</span></div><div class="g-bar" role="progressbar" aria-label="Uso de memoria RAM" aria-valuemin="0" aria-valuemax="100"><i></i></div><div class="g-det" id="gMemD">&nbsp;</div></div>
    <div class="gauge" id="gDisk"><div class="g-top"><span class="g-lbl">DISCO</span><span class="g-val" id="gDiskV">–</span></div><div class="g-bar" role="progressbar" aria-label="Uso de disco" aria-valuemin="0" aria-valuemax="100"><i></i></div><div class="g-det" id="gDiskD">&nbsp;</div></div>
    <div class="sys-foot">
      <span class="sf" title="Tiempo desde el último arranque del servidor"><i class="sf-l">ENCENDIDO</i><b id="sUp">–</b></span>
      <span class="sf rx" title="Tráfico recibido: velocidad actual y total desde el arranque"><i class="sf-l">↓ RECIBIDO</i><b id="sRx">–</b><em id="sRxT"></em></span>
      <span class="sf tx" title="Tráfico enviado: velocidad actual y total desde el arranque"><i class="sf-l">↑ ENVIADO</i><b id="sTx">–</b><em id="sTxT"></em></span>
    </div>
  </section>

  <div class="stats" aria-label="Resumen y filtros">
    <button class="stat-card" data-k="all" aria-pressed="true"><div class="stat-label">CUENTAS</div><div class="stat-value" id="sTotal">0</div></button>
    <button class="stat-card" data-k="active" aria-pressed="false"><div class="stat-label">ACTIVAS</div><div class="stat-value" id="sOk">0</div></button>
    <button class="stat-card" data-k="soon" aria-pressed="false"><div class="stat-label">POR VENCER</div><div class="stat-value" id="sSoon">0</div></button>
    <button class="stat-card" data-k="expired" aria-pressed="false"><div class="stat-label">VENCIDAS</div><div class="stat-value" id="sExp">0</div></button>
  </div>

  <div class="toolbar">
    <label class="search"><i data-ic="search"></i><input class="search-input" type="search" id="q" placeholder="Buscar por usuario o UUID" aria-label="Buscar"></label>
    <button class="btn pri" id="newBtn"><i data-ic="plus"></i><span>Nuevo usuario</span></button>
    <button class="btn lbl-sm" id="cleanBtn" title="Eliminar cuentas vencidas"><i data-ic="clock"></i><span>Limpiar vencidas</span></button>
  </div>

  <div class="table-wrap" aria-label="Cuentas">
    <div class="lhead" id="thead"><div style="grid-area:name">USUARIO</div><div style="grid-area:uuid">UUID</div><div style="grid-area:exp">VENCE</div><div style="grid-area:days">RESTAN</div></div>
    <div id="list"></div>
  </div>
</div>

<footer class="footer"><div>© <span class="year" id="yr"></span> • Panel V2Ray • <span class="heart">v1.0</span></div><div class="version">Todos los derechos reservados</div></footer>

<!-- ───────── Diálogos ───────── -->
<dialog class="modal" id="dNew">
  <div class="modal-title"><span>👤 NUEVO USUARIO V2RAY</span><button class="close-btn" data-close aria-label="Cerrar">✕</button></div>
  <div class="sub">Se genera un UUID y se agrega a V2Ray al instante.</div>
  <div class="field"><label for="nNick">USUARIO</label><input type="text" id="nNick" maxlength="32" placeholder="ej: cliente01" autocomplete="off" autocapitalize="none" spellcheck="false"><div class="hint">2 a 32 caracteres: letras, números, punto, guion o guion bajo</div></div>
  <div class="field"><label for="nDays">DÍAS</label><input type="number" id="nDays" min="1" value="30" inputmode="numeric">
    <div class="chips" data-for="nDays"><button class="chip-btn">7</button><button class="chip-btn">15</button><button class="chip-btn sel">30</button><button class="chip-btn">60</button><button class="chip-btn">90</button></div></div>
  <div class="form-err hidden" id="nErr" role="alert"></div>
  <div class="foot"><button class="btn" data-close>Cancelar</button><button class="btn pri" id="nOk">Crear usuario</button></div>
</dialog>

<dialog class="modal" id="dRenew">
  <div class="modal-title"><span>✎ EDITAR DÍAS: <span id="rNick"></span></span><button class="close-btn" data-close aria-label="Cerrar">✕</button></div>
  <div class="sub" id="rInfo"></div>
  <div class="seg" role="radiogroup" aria-label="Modo">
    <button class="chip-btn sel" data-mode="set" role="radio" aria-checked="true">Fijar días</button>
    <button class="chip-btn" data-mode="add" role="radio" aria-checked="false">Sumar días</button>
  </div>
  <div class="field"><label for="rDays" id="rLabel">NUEVA DURACIÓN (DÍAS DESDE HOY)</label><input type="number" id="rDays" min="1" value="30" inputmode="numeric">
    <div class="chips" data-for="rDays"><button class="chip-btn">7</button><button class="chip-btn">15</button><button class="chip-btn sel">30</button><button class="chip-btn">60</button><button class="chip-btn">90</button></div></div>
  <div class="preview" id="rPrev"></div>
  <div class="form-err hidden" id="rErr" role="alert"></div>
  <div class="foot"><button class="btn" data-close>Cancelar</button><button class="btn pri" id="rOk">Guardar cambios</button></div>
</dialog>

<dialog class="modal" id="dDone">
  <div class="modal-title"><span style="color:var(--accent-2)">✓ CUENTA CREADA</span><button class="close-btn" data-close aria-label="Cerrar">✕</button></div>
  <div class="kv">USUARIO</div><div class="kv-v" id="dNick"></div>
  <div class="kv">UUID</div><div class="res" id="dUuid"></div>
  <div class="kv">EXPIRA</div><div class="kv-v" id="dExp" style="margin-bottom:18px"></div>
  <div class="foot"><button class="btn" data-close>Cerrar</button><button class="btn" id="dCopyUuid"><i data-ic="copy"></i>Copiar UUID</button><button class="btn pri" id="dCopyLink"><i data-ic="link"></i>Copiar enlace</button></div>
</dialog>

<dialog class="modal" id="dManual">
  <div class="modal-title"><span>COPIA MANUAL</span><button class="close-btn" data-close aria-label="Cerrar">✕</button></div>
  <div class="sub">Tu navegador bloqueó la copia automática porque el panel usa HTTP. Selecciona el texto y cópialo.</div>
  <div class="field"><textarea id="mcText" readonly rows="5" style="width:100%;background:var(--bg-input);color:var(--text);border:1px solid var(--border);border-radius:7px;padding:10px;font:12px/1.5 'Share Tech Mono',ui-monospace,Menlo,monospace"></textarea></div>
  <div class="foot"><button class="btn pri" data-close>Listo</button></div>
</dialog>

<dialog class="modal" id="dSet">
  <div class="modal-title"><span>⚙ AJUSTES</span><button class="close-btn" data-close aria-label="Cerrar">✕</button></div>
  <div class="field"><label for="setHost">DOMINIO O IP DE LOS ENLACES VMESS://</label><input type="text" id="setHost" placeholder="Vacío: usa la dirección con que abres el panel"></div>
  <div class="field"><label for="setUrl">CONEXIÓN CON TU PANEL MAESTRO · URL</label><input type="text" id="setUrl" readonly><div class="hint" id="setSec"></div></div>
  <div class="field"><label for="setTok">TOKEN</label><div class="row2"><input type="text" id="setTok" readonly><button class="btn" id="setCopyTok"><i data-ic="copy"></i>Copiar</button></div></div>
  <label class="chk"><input type="checkbox" id="setAuto"> Eliminar cuentas vencidas cada hora</label>
  <div class="svc"><label>SERVICIO V2RAY</label>
    <span class="svc-st" id="svcState"></span>
    <div class="svc-btns"><button class="btn" id="svcRestart"><i data-ic="power"></i>Reiniciar</button><button class="btn" id="svcToggle"></button></div>
    <div class="hint">Reiniciar o detener corta las conexiones activas.</div></div>
  <div class="form-err hidden" id="setErr" role="alert"></div>
  <div class="foot"><button class="btn" data-close>Cancelar</button><button class="btn pri" id="setOk">Guardar ajustes</button></div>
</dialog>

<dialog class="modal" id="dTheme">
  <div class="modal-title"><span>🎨 APARIENCIA</span><button class="close-btn" data-close aria-label="Cerrar">✕</button></div>
  <div class="sub">Elige el tema del panel. Se guarda en este dispositivo.</div>
  <div class="themes" role="radiogroup" aria-label="Tema">
    <button class="tcard" role="radio" data-t="dark" style="--a:#00c8ff;--b:#0d1321;--c:#e0f0ff"><span class="sw"><i></i><i></i><i></i></span><b>🌙 Oscuro</b><small>Neón azul</small></button>
    <button class="tcard" role="radio" data-t="light" style="--a:#0077cc;--b:#ffffff;--c:#1a2332"><span class="sw"><i></i><i></i><i></i></span><b>☀️ Claro</b><small>Limpio y neutro</small></button>
    <button class="tcard" role="radio" data-t="paper" style="--a:#8b5a2b;--b:#fbfaf5;--c:#3d3833"><span class="sw"><i></i><i></i><i></i></span><b>🎨 Papel</b><small>Tonos cálidos</small></button>
    <button class="tcard" role="radio" data-t="gaming" style="--a:#ff00ff;--b:#110020;--c:#00ffff"><span class="sw"><i></i><i></i><i></i></span><b>🎮 Gaming</b><small>Neón y RGB</small></button>
  </div>
  <div class="foot"><button class="btn pri" data-close>Listo</button></div>
</dialog>

<div id="toast" class="toast" role="status" aria-live="polite"></div>

<script>
const $=s=>document.querySelector(s);
let S={users:[],running:false,settings:{}},filter="all",curRenew=null,lastNew=null;

/* ── Iconos de trazo (heredan el color del tema) ── */
const ICON={
  copy:'<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/>',
  link:'<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
  renew:'<path d="M20 12a8 8 0 1 1-2.3-5.7"/><path d="M20 4v4h-4"/>',
  trash:'<path d="M4 7h16M10 11v6M14 11v6M6 7l1 12a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-12M9 7V4h6v3"/>',
  plus:'<path d="M12 5v14M5 12h14"/>',
  edit:'<path d="M4 20h4L19 9l-4-4L4 16z"/><path d="M13.5 6.5l4 4"/>',
  search:'<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
  sliders:'<path d="M4 7h9M17 7h3M4 17h3M11 17h9"/><circle cx="15" cy="7" r="2"/><circle cx="9" cy="17" r="2"/>',
  logout:'<path d="M9 4H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h3M16 8l4 4-4 4M20 12H9"/>',
  theme:'<circle cx="12" cy="12" r="9"/><path d="M12 3a9 9 0 0 1 0 18z" fill="currentColor"/>',
  power:'<path d="M12 3v8M6.3 6.3a8 8 0 1 0 11.4 0"/>',
  stop:'<rect x="6" y="6" width="12" height="12" rx="2"/>',
  play:'<path d="M8 5v14l11-7z"/>',
  clock:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>'
};
const ic=n=>'<svg class="i" viewBox="0 0 24 24" aria-hidden="true">'+ICON[n]+'</svg>';
document.querySelectorAll("[data-ic]").forEach(e=>{e.outerHTML=ic(e.dataset.ic)});
$("#yr").textContent=new Date().getFullYear();

/* ── Temas (misma clave y valores que el Panel VPS) ── */
const THEME_KEY="sshplus_theme",VALID_THEMES=["dark","light","paper","gaming"];
const THEME_COLOR={dark:"#060b14",light:"#f0f4f8",paper:"#f4f1ea",gaming:"#08000f"};
function applyTheme(t){
  if(!VALID_THEMES.includes(t))t="dark";
  document.documentElement.setAttribute("data-theme",t);
  try{localStorage.setItem(THEME_KEY,t)}catch(e){}
  $('meta[name=theme-color]').setAttribute("content",THEME_COLOR[t]);
  document.querySelectorAll(".tcard").forEach(b=>b.setAttribute("aria-checked",b.dataset.t===t));
}
applyTheme(document.documentElement.getAttribute("data-theme"));
document.querySelectorAll(".tcard").forEach(b=>b.addEventListener("click",()=>applyTheme(b.dataset.t)));
document.querySelectorAll("[data-open]").forEach(b=>b.addEventListener("click",()=>$("#"+b.dataset.open).showModal()));

/* ── Utilidades ── */
const esc=s=>String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
function toast(t,isErr){const e=$("#toast");e.textContent=t;e.className="toast show "+(isErr?"toast-err":"toast-ok");clearTimeout(toast.t);toast.t=setTimeout(()=>e.classList.remove("show"),2600)}
function setErr(sel,msg){const e=$(sel);e.textContent=msg||"";e.classList.toggle("hidden",!msg)}

async function api(path,method="GET",body){
  const r=await fetch(path,{method,credentials:"same-origin",headers:{"Content-Type":"application/json","X-Panel":"1"},body:body?JSON.stringify(body):undefined});
  let d={};try{d=await r.json()}catch(e){}
  if(r.status===401&&path!=="/api/login"){showLogin();throw new Error("Tu sesión expiró. Vuelve a entrar.")}
  if(!r.ok)throw new Error(d.error||("Error "+r.status));
  return d;
}

/* ── Copiar (con respaldo para HTTP) ── */
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

/* ── Vistas ── */
function showLogin(){$("#appView").classList.add("hidden");$("#loginView").classList.remove("hidden");$("#pw").value="";$("#pw").focus()}
function showApp(){$("#loginView").classList.add("hidden");$("#appView").classList.remove("hidden")}
/* Uso del servidor (CPU, RAM y disco) */
function fmtB(n){const g=n/1073741824;if(g>=1024)return (g/1024).toFixed(2)+" TB";return g>=1?g.toFixed(g>=10?0:1)+" GB":Math.round(n/1048576)+" MB"}
function fmtRate(b){if(b>=1048576)return (b/1048576).toFixed(1)+" MB/s";if(b>=1024)return Math.round(b/1024)+" KB/s";return Math.round(b)+" B/s"}
function fmtUp(s){const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return d?d+"d "+h+"h":h?h+"h "+m+"m":m+"m"}
function setGauge(id,pct,det){
  const g=$("#"+id),lvl=pct>=90?"bad":pct>=70?"warn":"";
  g.className="gauge"+(lvl?" "+lvl:"");
  $("#"+id+"V").textContent=pct+"%";
  const bar=g.querySelector(".g-bar");bar.setAttribute("aria-valuenow",pct);bar.firstElementChild.style.width=Math.min(pct,100)+"%";
  $("#"+id+"D").textContent=det||"\u00a0";
}
function renderSys(x){
  if(!x)return;
  setGauge("gCpu",x.cpu.pct,x.cpu.cores+(x.cpu.cores===1?" núcleo":" núcleos"));
  setGauge("gMem",x.mem.pct,x.mem.total?fmtB(x.mem.used)+" de "+fmtB(x.mem.total):"");
  setGauge("gDisk",x.disk.pct,x.disk.total?fmtB(x.disk.used)+" de "+fmtB(x.disk.total):"");
  $("#sUp").textContent=x.uptime_s!=null?fmtUp(x.uptime_s):(x.uptime||"–");
  if(x.net){
    $("#sRx").textContent=fmtRate(x.net.rx_rate);$("#sRxT").textContent="· "+fmtB(x.net.rx_total)+" total";
    $("#sTx").textContent=fmtRate(x.net.tx_rate);$("#sTxT").textContent="· "+fmtB(x.net.tx_total)+" total";
  }
}
async function load(){S=await api("/api/state");showApp();render();renderSys(S.system)}
setInterval(async()=>{
  if(document.hidden||$("#appView").classList.contains("hidden"))return;
  try{renderSys(await api("/api/system"))}catch(e){}
},5000);

const LABEL={ok:"ACTIVA",soon:"POR VENCER",expired:"VENCIDA",sr:"SIN FECHA"};
const BADGE={ok:"badge-active",soon:"badge-soon",expired:"badge-expired",sr:"badge-sr"};
const EXPC={ok:"expiry-ok",soon:"expiry-warn",expired:"expiry-bad",sr:"expiry-na"};
function rowHTML(x){
  const d=x.days,dayTxt=d===null?"∞":(x.status==="expired"?"0":d);
  const unit=d===null?"":(d===1?"DÍA":"DÍAS");
  return '<div class="lrow" data-u="'+esc(x.uuid)+'">'+
    '<div class="c-name"><span class="nm" title="'+esc(x.nick)+'">'+esc(x.nick)+'</span><span class="badge '+BADGE[x.status]+'"><i class="dot"></i>'+LABEL[x.status]+'</span></div>'+
    '<div class="c-uuid"><button class="uuid-btn" data-a="uuid" title="Copiar UUID"><code>'+esc(x.uuid)+'</code>'+ic("copy")+'</button></div>'+
    '<div class="c-exp '+EXPC[x.status]+'"><span class="lbl">Vence</span>'+esc(x.exp)+'</div>'+
    '<div class="c-days '+EXPC[x.status]+'"><b>'+dayTxt+'</b><small>'+unit+'</small></div>'+
    '<div class="c-acts">'+
      '<button class="btn ibtn" data-a="link" title="Copiar enlace vmess" aria-label="Copiar enlace de '+esc(x.nick)+'">'+ic("link")+'</button>'+
      '<button class="btn ibtn" data-a="edit" title="Editar días" aria-label="Editar días de '+esc(x.nick)+'">'+ic("edit")+'</button>'+
      '<button class="btn ibtn warn" data-a="del" title="Eliminar" aria-label="Eliminar a '+esc(x.nick)+'">'+ic("trash")+'</button>'+
    '</div></div>';
}

function render(){
  const u=S.users,q=$("#q").value.trim().toLowerCase();
  const nOk=u.filter(x=>x.status==="ok"||x.status==="soon").length,nSoon=u.filter(x=>x.status==="soon").length,nExp=u.filter(x=>x.status==="expired").length;
  $("#sTotal").textContent=u.length;$("#sOk").textContent=nOk;$("#sSoon").textContent=nSoon;$("#sExp").textContent=nExp;
  document.querySelectorAll(".stat-card").forEach(b=>b.setAttribute("aria-pressed",b.dataset.k===filter));
  $("#statusPill").className="pill "+(S.running?"online":"offline");
  $("#statusTxt").textContent=S.running?"V2Ray activo":"V2Ray detenido";
  const f=u.filter(x=>{
    if(filter==="active"&&!(x.status==="ok"||x.status==="soon"))return false;
    if(filter==="soon"&&x.status!=="soon")return false;
    if(filter==="expired"&&x.status!=="expired")return false;
    return !q||x.nick.toLowerCase().includes(q)||x.uuid.includes(q);
  });
  $("#thead").classList.toggle("hidden",!f.length);
  if(f.length){$("#list").innerHTML=f.map(rowHTML).join("");return}
  $("#list").innerHTML=u.length
    ?'<div class="empty-state"><div class="icon">🔍</div><h3>SIN RESULTADOS</h3><p>Prueba con otro nombre o quita el filtro.</p></div>'
    :'<div class="empty-state"><div class="icon">🛰️</div><h3>AÚN NO HAY CUENTAS</h3><p>Crea la primera para generar su UUID y su enlace de conexión.</p><button class="btn pri" data-a="new">Nuevo usuario</button></div>';
}

/* ── Eventos ── */
document.querySelectorAll(".stat-card").forEach(b=>b.addEventListener("click",()=>{filter=b.dataset.k;render()}));
$("#q").addEventListener("input",render);

$("#list").addEventListener("click",async e=>{
  const b=e.target.closest("[data-a]");if(!b)return;
  if(b.dataset.a==="new")return $("#newBtn").click();
  const row=b.closest(".lrow"),id=row.dataset.u,u=S.users.find(x=>x.uuid===id),a=b.dataset.a;
  try{
    if(a==="uuid")copy(id,"UUID copiado");
    else if(a==="link"){const r=await api("/api/users/"+id+"/link");copy(r.link,"Enlace copiado")}
    else if(a==="edit"){
      curRenew=u;rMode="set";$("#rNick").textContent=u.nick;
      $("#rInfo").textContent="Ahora: "+(u.days===null?"sin fecha":(u.status==="expired"?"vencida el "+u.exp:"vence el "+u.exp+" ("+u.days+(u.days===1?" día":" días")+")"))+".";
      $("#rDays").value=30;setRMode("set");
      document.querySelectorAll("#dRenew .chips button").forEach(x=>x.classList.toggle("sel",x.textContent==="30"));
      setErr("#rErr","");updatePrev();$("#dRenew").showModal();
    }
    else if(a==="del"){
      if(!confirm("¿Eliminar a “"+u.nick+"”? Dejará de conectarse y no se puede deshacer."))return;
      const r=await api("/api/users/"+id,"DELETE");
      r.restarted?toast("Usuario eliminado"):toast("Eliminado, pero V2Ray no reinició: revísalo",true);
      await load();
    }
  }catch(err){toast(err.message,true)}
});

document.querySelectorAll(".chips").forEach(c=>c.addEventListener("click",e=>{
  const b=e.target.closest("button");if(!b)return;
  $("#"+c.dataset.for).value=b.textContent;$("#"+c.dataset.for).dispatchEvent(new Event("input"));
  c.querySelectorAll("button").forEach(x=>x.classList.toggle("sel",x===b));
}));
document.querySelectorAll("[data-close]").forEach(b=>b.addEventListener("click",()=>b.closest("dialog").close()));

async function doLogin(){
  setErr("#loginErr","");
  try{await api("/api/login","POST",{password:$("#pw").value});await load()}
  catch(e){setErr("#loginErr",e.message)}
}
$("#loginBtn").onclick=doLogin;
$("#pw").addEventListener("keydown",e=>{if(e.key==="Enter")doLogin()});
$("#logout").onclick=async()=>{try{await api("/api/logout","POST")}catch(e){}showLogin()};

/* Nuevo */
$("#newBtn").onclick=()=>{$("#nNick").value="";$("#nDays").value=30;setErr("#nErr","");
  document.querySelectorAll("#dNew .chips button").forEach(x=>x.classList.toggle("sel",x.textContent==="30"));
  $("#dNew").showModal();setTimeout(()=>$("#nNick").focus(),50)};
$("#nOk").onclick=async()=>{
  setErr("#nErr","");$("#nOk").disabled=true;
  try{
    const r=await api("/api/users","POST",{nick:$("#nNick").value.trim(),days:parseInt($("#nDays").value,10)});
    lastNew=r;$("#dNew").close();
    $("#dNick").textContent=r.nick;$("#dUuid").textContent=r.uuid;$("#dExp").textContent=r.exp;
    $("#dCopyLink").classList.toggle("hidden",!r.link);
    $("#dDone").showModal();await load();
  }catch(e){setErr("#nErr",e.message)}
  $("#nOk").disabled=false;
};
$("#nNick").addEventListener("keydown",e=>{if(e.key==="Enter")$("#nOk").click()});
$("#dCopyUuid").onclick=()=>copy(lastNew.uuid,"UUID copiado");
$("#dCopyLink").onclick=()=>copy(lastNew.link,"Enlace copiado");

/* Editar días: fijar (reemplaza) o sumar */
let rMode="set";
function setRMode(m){
  rMode=m;
  document.querySelectorAll("#dRenew .seg button").forEach(x=>{const on=x.dataset.mode===m;x.classList.toggle("sel",on);x.setAttribute("aria-checked",on)});
  $("#rLabel").textContent=m==="set"?"NUEVA DURACIÓN (DÍAS DESDE HOY)":"DÍAS A SUMAR";
}
const fmtD=d=>d.getFullYear()+"-"+String(d.getMonth()+1).padStart(2,"0")+"-"+String(d.getDate()).padStart(2,"0");
function updatePrev(){
  const el=$("#rPrev"),u=curRenew,n=parseInt($("#rDays").value,10);
  if(!u||!n||n<1){el.textContent="Escribe cuántos días.";return}
  const MS=86400000;let todayS,expD=null;
  if(u.days!==null&&/^\d{4}-\d{2}-\d{2}$/.test(u.exp)){const p=u.exp.split("-").map(Number);expD=new Date(p[0],p[1]-1,p[2]);todayS=new Date(expD.getTime()-u.days*MS)}
  else{const t=new Date();todayS=new Date(t.getFullYear(),t.getMonth(),t.getDate())}
  const base=(rMode==="add"&&expD&&u.days>0)?expD:todayS;
  const res=new Date(base.getFullYear(),base.getMonth(),base.getDate()+n);
  const total=Math.round((res-todayS)/MS);
  el.innerHTML=(rMode==="set"?"Vencerá en <b>"+n+"</b> "+(n===1?"día":"días"):"Quedarán <b>"+total+"</b> "+(total===1?"día":"días"))+" · <b>"+fmtD(res)+"</b>";
}
document.querySelectorAll("#dRenew .seg button").forEach(b=>b.addEventListener("click",()=>{setRMode(b.dataset.mode);updatePrev()}));
$("#rDays").addEventListener("input",updatePrev);
$("#rOk").onclick=async()=>{
  setErr("#rErr","");
  try{
    const r=await api("/api/users/"+curRenew.uuid+(rMode==="set"?"/setdays":"/renew"),"POST",{days:parseInt($("#rDays").value,10)});
    $("#dRenew").close();toast((rMode==="set"?"Días actualizados · vence el ":"Renovada hasta el ")+r.exp);await load();
  }catch(e){setErr("#rErr",e.message)}
};

/* Acciones globales */
$("#cleanBtn").onclick=async()=>{
  const n=S.users.filter(x=>x.status==="expired").length;
  if(!n)return toast("No hay cuentas vencidas");
  if(!confirm("¿Eliminar "+n+" cuenta(s) vencida(s)?"))return;
  try{const r=await api("/api/clean","POST");toast(r.deleted+" cuenta(s) eliminada(s)");await load()}catch(e){toast(e.message,true)}
};
/* Servicio V2Ray (dentro de Ajustes) */
function updateSvc(){
  const on=!!S.running;
  const st=$("#svcState");st.textContent=on?"● En ejecución":"● Detenido";st.style.color=on?"var(--accent-2)":"var(--accent-3)";
  const t=$("#svcToggle");t.className="btn "+(on?"danger":"start");t.innerHTML=ic(on?"stop":"play")+(on?"Detener":"Iniciar");
}
async function svcRun(kind){
  const ask={restart:"¿Reiniciar V2Ray? Las conexiones activas se cortan unos segundos.",stop:"¿Detener V2Ray? Nadie podrá conectarse hasta que lo inicies de nuevo.",start:null}[kind];
  if(ask&&!confirm(ask))return;
  const btns=[$("#svcRestart"),$("#svcToggle")];btns.forEach(b=>b.disabled=true);
  toast({restart:"Reiniciando V2Ray…",stop:"Deteniendo V2Ray…",start:"Iniciando V2Ray…"}[kind]);
  try{
    const r=await api("/api/"+kind,"POST");
    const ok=kind==="restart"?r.restarted:r.ok;
    ok?toast({restart:"V2Ray reiniciado",stop:"V2Ray detenido",start:"V2Ray iniciado"}[kind]):toast("No se pudo completar la acción. Revisa el servicio en el VPS.",true);
    await load();
  }catch(e){toast(e.message,true)}
  btns.forEach(b=>b.disabled=false);updateSvc();
}
$("#svcRestart").onclick=()=>svcRun("restart");
$("#svcToggle").onclick=()=>svcRun(S.running?"stop":"start");

/* Ajustes */
$("#setCopyTok").onclick=()=>copy($("#setTok").value,"Token copiado");
$("#gear").onclick=()=>{$("#setUrl").value=location.origin+"/";$("#setTok").value=S.settings.api_token||"";
  $("#setHost").value=S.settings.host||"";$("#setAuto").checked=!!S.settings.auto_clean;setErr("#setErr","");updateSvc();
  $("#setSec").textContent=location.protocol==="https:"?"🔒 Conexión cifrada (HTTPS).":"⚠ Conexión sin cifrar (HTTP). Para activar HTTPS con el certificado de V2Ray, ejecuta en el VPS: python3 /opt/v2panel/v2panel.py https";
  $("#dSet").showModal()};
$("#setOk").onclick=async()=>{
  try{await api("/api/settings","POST",{host:$("#setHost").value.trim(),auto_clean:$("#setAuto").checked});$("#dSet").close();toast("Ajustes guardados");await load()}
  catch(e){setErr("#setErr",e.message)}
};

load().catch(()=>showLogin());
</script>
</body></html>
"""

if __name__ == "__main__":
    main()

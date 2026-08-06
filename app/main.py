import datetime
import hashlib
import hmac
import html
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import docker
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from fastapi import FastAPI, Form, HTTPException, Request, Response, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

STACKS_DIR = os.environ.get("STACKS_DIR", "/opt/dockpilot/stacks")
DATA_DIR   = os.environ.get("DATA_DIR",   "/data")
CREDS_FILE = os.path.join(DATA_DIR, "credentials.json")
CERTS_DIR  = os.path.join(DATA_DIR, "certs")
SECRET_FILE = os.path.join(DATA_DIR, "secret_key")
SESSION_TTL = 7 * 24 * 3600
COOKIE = "dockpilot_session"
SAFE_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")
TOKENS_FILE    = os.path.join(DATA_DIR, "tokens.json")
DOCKER_CFG_DIR = os.path.join(DATA_DIR, "docker")
SERVERS_FILE   = os.path.join(DATA_DIR, "servers.json")
MODE_FILE      = os.path.join(DATA_DIR, "mode.json")

_INSECURE_DEFAULTS = {"changeme", "insecure", "insecure-default-secret", ""}

def _get_secret() -> bytes:
    """Return the signing secret — explicit env var wins, otherwise auto-generate once."""
    env = os.environ.get("DASH_SECRET", "")
    if env and env not in _INSECURE_DEFAULTS:
        return env.encode()
    if os.path.isfile(SECRET_FILE):
        with open(SECRET_FILE) as f:
            return f.read().strip().encode()
    os.makedirs(DATA_DIR, exist_ok=True)
    secret = secrets.token_hex(32)
    fd = os.open(SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(secret)
    return secret.encode()

# Credentials — live aus Datei lesen, Fallback auf Env-Vars
def _load_creds():
    secret = _get_secret()
    if os.path.isfile(CREDS_FILE):
        with open(CREDS_FILE) as creds_file:
            creds_data = json.load(creds_file)
        return (
            creds_data.get("user",     os.environ.get("DASH_USER",     "admin")),
            creds_data.get("password", os.environ.get("DASH_PASSWORD", "changeme")),
            creds_data.get("secret",   secret.decode()).encode(),
        )
    return (
        os.environ.get("DASH_USER",     "admin"),
        os.environ.get("DASH_PASSWORD", "changeme"),
        secret,
    )

def _load_mode() -> dict:
    if os.path.isfile(MODE_FILE):
        with open(MODE_FILE) as f:
            return json.load(f)
    return {}


def _save_mode(data: dict):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(MODE_FILE, "w") as f:
        json.dump(data, f, indent=2)


def get_dp_mode() -> str:
    return _load_mode().get("mode", "standalone")


def get_agent_token() -> str | None:
    return _load_mode().get("agent_token")


def needs_setup() -> bool:
    if not os.path.isfile(MODE_FILE):
        return True
    mode_data = _load_mode()
    mode = mode_data.get("mode", "standalone")
    if mode == "agent":
        return not mode_data.get("agent_token")
    return not os.path.isfile(CREDS_FILE)


def _load_tokens() -> dict:
    if os.path.isfile(TOKENS_FILE):
        with open(TOKENS_FILE) as tf:
            return json.load(tf)
    return {}


def _save_tokens(tokens: dict):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(TOKENS_FILE, "w") as tf:
        json.dump(tokens, tf)


def _docker_cfg() -> dict:
    cfg_file = os.path.join(DOCKER_CFG_DIR, "config.json")
    if os.path.isfile(cfg_file):
        with open(cfg_file) as f:
            return json.load(f)
    return {"auths": {}}


def _write_docker_cfg(cfg: dict):
    import base64
    os.makedirs(DOCKER_CFG_DIR, exist_ok=True)
    cfg_file = os.path.join(DOCKER_CFG_DIR, "config.json")
    with open(cfg_file, "w") as f:
        json.dump(cfg, f, indent=2)


def _registry_add(registry: str, username: str, password: str):
    import base64
    cfg = _docker_cfg()
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    cfg.setdefault("auths", {})[registry] = {"auth": token}
    _write_docker_cfg(cfg)


def _registry_remove(registry: str):
    cfg = _docker_cfg()
    cfg.setdefault("auths", {}).pop(registry, None)
    _write_docker_cfg(cfg)


def _registry_list() -> list:
    return list(_docker_cfg().get("auths", {}).keys())


client = docker.DockerClient(base_url="unix://var/run/docker.sock")
app = FastAPI()


# ----------------------------- Auth -----------------------------
def make_token() -> str:
    _, _, secret = _load_creds()
    timestamp = str(int(time.time()))
    sig = hmac.new(secret, timestamp.encode(), hashlib.sha256).hexdigest()
    return f"{timestamp}.{sig}"


def valid_token(token: str | None) -> bool:
    if not token or "." not in token:
        return False
    _, _, secret = _load_creds()
    timestamp, sig = token.split(".", 1)
    expected = hmac.new(secret, timestamp.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return False
    try:
        return (time.time() - int(timestamp)) < SESSION_TTL
    except ValueError:
        return False


def require_auth(request: Request):
    if not valid_token(request.cookies.get(COOKIE)):
        raise HTTPException(status_code=401, detail="not authenticated")


def _valid_bearer(request: Request) -> bool:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return False
    token = auth[7:]
    agent_token = get_agent_token()
    if not agent_token:
        return False
    return hmac.compare_digest(token.encode(), agent_token.encode())


def require_auth_any(request: Request):
    """Accept session cookie (UI) OR bearer token (agent API access from hub)."""
    if valid_token(request.cookies.get(COOKIE)):
        return
    if _valid_bearer(request):
        return
    raise HTTPException(status_code=401, detail="not authenticated")


# ----------------------------- Stats -----------------------------
def container_cpu_mem(c):
    try:
        stream = c.stats(stream=True, decode=True)
        first = next(stream)
        second = next(stream)
        stream.close()
    except Exception:
        return {"cpu": None, "mem": None, "mem_used": None, "mem_limit": None,
                "net_rx": None, "net_tx": None}

    cpu = None
    try:
        cur = second["cpu_stats"]
        pre = first["cpu_stats"]
        cpu_delta = cur["cpu_usage"]["total_usage"] - pre["cpu_usage"]["total_usage"]
        sys_delta = cur["system_cpu_usage"] - pre["system_cpu_usage"]
        online = cur.get("online_cpus") or len(
            cur["cpu_usage"].get("percpu_usage") or [1])
        if sys_delta > 0 and cpu_delta >= 0:
            cpu = round((cpu_delta / sys_delta) * online * 100.0, 1)
    except (KeyError, TypeError, ZeroDivisionError):
        cpu = None

    mem_used = mem_limit = mem_pct = None
    try:
        m = second["memory_stats"]
        detail = m.get("stats", {})
        inactive = detail.get("inactive_file", detail.get("cache", 0))
        mem_used = m["usage"] - inactive
        mem_limit = m["limit"]
        if mem_limit:
            mem_pct = round(mem_used / mem_limit * 100.0, 1)
    except (KeyError, TypeError):
        pass

    rx_bytes = tx_bytes = None
    try:
        nets = second.get("networks", {})
        rx_bytes = sum(n.get("rx_bytes", 0) for n in nets.values())
        tx_bytes = sum(n.get("tx_bytes", 0) for n in nets.values())
    except (KeyError, TypeError, AttributeError):
        pass

    return {"cpu": cpu, "mem": mem_pct, "mem_used": mem_used,
            "mem_limit": mem_limit, "net_rx": rx_bytes, "net_tx": tx_bytes}


def serialize(c):
    running = c.status == "running"
    image = c.attrs["Config"]["Image"]
    compose = c.labels.get("com.docker.compose.project")
    compose_dir = c.labels.get("com.docker.compose.project.working_dir", "")
    data = {
        "id": c.short_id,
        "name": c.name,
        "image": image,
        "status": c.status,
        "running": running,
        "compose": compose,
        "compose_dir": compose_dir,
        "cpu": None, "mem": None, "mem_used": None, "mem_limit": None,
        "net_rx": None, "net_tx": None,
    }
    if running:
        data.update(container_cpu_mem(c))
    return data


# ----------------------------- Update -----------------------------
def recreate_with_new_image(c):
    """Pull a newer image for container c and recreate it with the same configuration."""
    attrs = c.attrs
    cfg = attrs["Config"]
    host_cfg = attrs["HostConfig"]
    name = c.name
    image_ref = cfg["Image"]
    networks = attrs.get("NetworkSettings", {}).get("Networks", {})

    client.images.pull(image_ref)

    net_items = list(networks.items())
    endpoint_config = None
    primary_net = None
    if net_items:
        primary_net, ncfg = net_items[0]
        aliases = [a for a in (ncfg.get("Aliases") or []) if a != c.id[:12]]
        endpoint_config = client.api.create_endpoint_config(aliases=aliases or None)

    networking_config = None
    if primary_net:
        networking_config = client.api.create_networking_config(
            {primary_net: endpoint_config})

    new_host_config = client.api.create_host_config(
        binds=host_cfg.get("Binds"),
        port_bindings=host_cfg.get("PortBindings"),
        restart_policy=host_cfg.get("RestartPolicy"),
        network_mode=host_cfg.get("NetworkMode"),
        privileged=host_cfg.get("Privileged", False),
        cap_add=host_cfg.get("CapAdd"),
        cap_drop=host_cfg.get("CapDrop"),
        devices=_devices(host_cfg.get("Devices")),
        security_opt=host_cfg.get("SecurityOpt"),
        dns=host_cfg.get("Dns"),
        extra_hosts=host_cfg.get("ExtraHosts"),
        mounts=None,
    )

    c.stop()
    c.remove()

    new = client.api.create_container(
        image=image_ref,
        name=name,
        command=cfg.get("Cmd"),
        entrypoint=cfg.get("Entrypoint"),
        environment=cfg.get("Env"),
        labels=cfg.get("Labels"),
        working_dir=cfg.get("WorkingDir") or None,
        user=cfg.get("User") or None,
        hostname=cfg.get("Hostname"),
        tty=cfg.get("Tty", False),
        host_config=new_host_config,
        networking_config=networking_config,
    )
    new_id = new["Id"]

    for net_name, ncfg in net_items[1:]:
        aliases = [a for a in (ncfg.get("Aliases") or []) if a != c.id[:12]]
        client.api.connect_container_to_network(new_id, net_name, aliases=aliases or None)

    client.api.start(new_id)
    return new_id


def _devices(devs):
    if not devs:
        return None
    return [f"{d['PathOnHost']}:{d['PathInContainer']}:{d.get('CgroupPermissions','rwm')}" for d in devs]


# ----------------------------- Self-Update -----------------------------
_UPDATE_STATE: dict = {
    "checking": False,
    "update_available": False,
    "current_digest": None,
    "remote_digest": None,
    "last_check": None,
    "error": None,
    "image_ref": None,
}


def _self_container_id() -> str | None:
    try:
        with open("/proc/self/cgroup") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) < 3:
                    continue
                path = parts[2]
                # cgroup v1: /docker/<64-char-id>
                if "/docker/" in path:
                    cid = path.split("/docker/")[-1].split("/")[0]
                    if re.fullmatch(r"[0-9a-f]{12,64}", cid):
                        return cid[:12]
                # cgroup v2: /system.slice/docker-<64-char-id>.scope
                m = re.search(r"docker-([0-9a-f]{64})(?:\.scope)?", path)
                if m:
                    return m.group(1)[:12]
    except OSError:
        pass
    try:
        with open("/proc/self/mountinfo") as f:
            for line in f:
                if "/docker/containers/" in line:
                    cid = line.split("/docker/containers/")[1].split("/")[0]
                    if re.fullmatch(r"[0-9a-f]{12,64}", cid):
                        return cid[:12]
    except OSError:
        pass
    # hostname fallback — Docker sets container hostname to the short container ID
    hostname = os.environ.get("HOSTNAME", "")
    if re.fullmatch(r"[0-9a-f]{12,64}", hostname):
        return hostname[:12]
    return None


def _do_check_update():
    _UPDATE_STATE["checking"] = True
    _UPDATE_STATE["error"] = None
    try:
        cid = _self_container_id()
        if not cid:
            _UPDATE_STATE["error"] = "Eigener Container nicht erkannt"
            return
        try:
            c = client.containers.get(cid)
        except docker.errors.NotFound:
            _UPDATE_STATE["error"] = "Container nicht gefunden"
            return
        image_ref = c.attrs["Config"]["Image"]
        _UPDATE_STATE["image_ref"] = image_ref
        local_img = client.images.get(image_ref)
        local_digests = {rd.split("@")[-1] for rd in local_img.attrs.get("RepoDigests", [])}
        reg_data = client.images.get_registry_data(image_ref)
        remote_digest = reg_data.id
        _UPDATE_STATE["current_digest"] = next(iter(local_digests), None)
        _UPDATE_STATE["remote_digest"] = remote_digest
        _UPDATE_STATE["update_available"] = bool(remote_digest and remote_digest not in local_digests)
        _UPDATE_STATE["last_check"] = time.time()
    except Exception as exc:
        _UPDATE_STATE["error"] = str(exc)
    finally:
        _UPDATE_STATE["checking"] = False


def _update_scheduler():
    while True:
        try:
            _do_check_update()
        except Exception:
            pass
        time.sleep(8 * 3600)


threading.Thread(target=_update_scheduler, daemon=True).start()


def _agent_register_with_hub():
    """Agent-Modus: Meldet sich beim Hub an, damit Hub die Agent-URL kennt."""
    import urllib.request as ureq
    import urllib.error
    mode_data = _load_mode()
    if mode_data.get("mode") != "agent":
        return
    hub_url = mode_data.get("hub_url", "").rstrip("/")
    token = mode_data.get("agent_token", "")
    agent_name = mode_data.get("agent_name", "")
    own_url = os.environ.get("AGENT_URL", "").rstrip("/")
    if not hub_url or not token:
        return
    body = json.dumps({"name": agent_name, "url": own_url}).encode()
    for attempt in range(5):
        try:
            req = ureq.Request(
                f"{hub_url}/api/agents/register",
                data=body,
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                method="POST",
            )
            with ureq.urlopen(req, timeout=10) as r:
                if r.status == 200:
                    return
        except Exception:
            pass
        time.sleep(30 * (attempt + 1))


if get_dp_mode() == "agent":
    threading.Thread(target=_agent_register_with_hub, daemon=True).start()


# ----------------------------- Host-Statistik -----------------------------
HOST_ROOT = "/host" if os.path.isdir("/host") else "/"


def _cpu_times():
    with open("/proc/stat") as stat_file:
        parts = stat_file.readline().split()[1:]
    vals = [int(x) for x in parts]
    idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
    return sum(vals), idle


def _cpu_percent():
    try:
        total1, idle1 = _cpu_times()
        time.sleep(0.25)
        total2, idle2 = _cpu_times()
        delta_total = total2 - total1
        if delta_total > 0:
            return round((1 - (idle2 - idle1) / delta_total) * 100, 1)
    except Exception:
        pass
    return None


def _mem_stats():
    try:
        info = {}
        with open("/proc/meminfo") as meminfo_file:
            for line in meminfo_file:
                key, val = line.split(":", 1)
                info[key] = int(val.strip().split()[0]) * 1024
        mem_total = info.get("MemTotal")
        mem_avail = info.get("MemAvailable")
        mem_used = (mem_total - mem_avail) if (mem_total and mem_avail is not None) else None
        return mem_total, mem_used
    except Exception:
        return None, None


def _disk_stats():
    disk = None
    try:
        disk_usage = shutil.disk_usage(HOST_ROOT)
        disk = {"total": disk_usage.total, "used": disk_usage.used, "free": disk_usage.free}
    except OSError:
        pass
    docker_disk = None
    try:
        docker_df = client.df()
        images = docker_df.get("Images") or []
        docker_disk = {
            "images": sum(img.get("Size", 0) for img in images),
            "containers": sum(c.get("SizeRw", 0) or 0 for c in (docker_df.get("Containers") or [])),
            "volumes": sum(v.get("UsageData", {}).get("Size", 0) or 0
                           for v in (docker_df.get("Volumes") or [])),
            "build_cache": sum(b.get("Size", 0) for b in (docker_df.get("BuildCache") or [])),
            "images_count": len(images),
        }
    except Exception:
        pass
    return disk, docker_disk


def host_stats():
    cpu = _cpu_percent()
    mem_total, mem_used = _mem_stats()
    load = uptime = None
    try:
        with open("/proc/loadavg") as loadavg_file:
            load = [float(x) for x in loadavg_file.read().split()[:3]]
    except Exception:
        pass
    try:
        with open("/proc/uptime") as uptime_file:
            uptime = float(uptime_file.read().split()[0])
    except Exception:
        pass
    disk, docker_disk = _disk_stats()
    return {
        "cpu": cpu, "cpus": os.cpu_count(),
        "mem_total": mem_total, "mem_used": mem_used,
        "mem_pct": round(mem_used / mem_total * 100, 1) if (mem_used and mem_total) else None,
        "load": load, "uptime": uptime,
        "disk": disk, "docker": docker_disk,
    }


# ----------------------------- Stacks -----------------------------
def _stack_dir(name: str) -> str:
    if not SAFE_NAME.match(name):
        raise HTTPException(status_code=400, detail="Ungültiger Stack-Name (nur a-z, 0-9, - und _)")
    stack_path = os.path.realpath(os.path.join(STACKS_DIR, name))
    stacks_root = os.path.realpath(STACKS_DIR)
    if not stack_path.startswith(stacks_root + os.sep):
        raise HTTPException(status_code=400, detail="Ungültiger Pfad")
    return stack_path


def _run_compose(name: str, *args, timeout: int = 300) -> dict:
    d = _stack_dir(name)
    if not os.path.isdir(d):
        raise HTTPException(status_code=404, detail="Stack nicht gefunden")
    env = {**os.environ, "DOCKER_CONFIG": DOCKER_CFG_DIR}
    try:
        proc = subprocess.run(
            ["docker", "compose", "-p", name, *args],
            cwd=d,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        combined = (proc.stdout + proc.stderr).strip()
        return {"ok": proc.returncode == 0, "out": combined}
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(status_code=504, detail="Timeout — Operation dauerte zu lang") from exc


# ----------------------------- Routes -----------------------------
@app.get("/setup", response_class=HTMLResponse)
def setup_page():
    return SETUP_HTML


@app.post("/api/setup/credentials")
async def setup_credentials(request: Request):
    body = await request.json()
    user = body.get("user", "").strip()
    password = body.get("password", "")
    if not user or len(password) < 8:
        raise HTTPException(status_code=400, detail="Benutzername und Passwort (min. 8 Zeichen) erforderlich")
    os.makedirs(DATA_DIR, exist_ok=True)
    new_secret = secrets.token_hex(32)
    with open(CREDS_FILE, "w") as creds_out:
        json.dump({"user": user, "password": password, "secret": new_secret}, creds_out)
    return {"ok": True}


@app.post("/api/setup/generate-cert")
def setup_generate_cert():
    os.makedirs(CERTS_DIR, exist_ok=True)

    # CA
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dockpilot-ca")])
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    # Client cert
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dockpilot-client")])
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(client_name).issuer_name(ca_name)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    # P12 with random password
    p12_password = secrets.token_urlsafe(16)
    p12_data = pkcs12.serialize_key_and_certificates(
        name=b"dockpilot-client",
        key=client_key,
        cert=client_cert,
        cas=[ca_cert],
        encryption_algorithm=serialization.BestAvailableEncryption(p12_password.encode()),
    )

    with open(os.path.join(CERTS_DIR, "ca.crt"), "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    with open(os.path.join(CERTS_DIR, "client.p12"), "wb") as f:
        f.write(p12_data)
    return {"ok": True, "p12_password": p12_password}


@app.get("/api/setup/download/{filename}")
def setup_download(filename: str):
    if filename not in ("client.p12", "ca.crt", "p12-password.txt"):
        raise HTTPException(status_code=404)
    path = os.path.join(CERTS_DIR, filename)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="Zertifikat noch nicht generiert")
    with open(path, "rb") as f:
        data = f.read()
    media = "application/x-pkcs12" if filename.endswith(".p12") else "text/plain"
    from fastapi.responses import Response as RawResponse
    return RawResponse(content=data, media_type=media,
                       headers={"Content-Disposition": f'attachment; filename="{filename}"'})


def _data_host_path() -> str:
    """Findet den Host-Pfad des /data-Volumes durch Inspektion des eigenen Containers."""
    try:
        own_container = client.containers.get("dockpilot")
        for mount in own_container.attrs.get("Mounts", []):
            if mount.get("Destination") == "/data":
                return mount["Source"]
    except Exception:
        pass
    return DATA_DIR


def _traefik_dynamic_path(container) -> str:
    """Resolve Traefik's dynamic config directory from container args and mounts."""
    file_dir = None
    for arg in container.attrs.get("Args", []):
        if arg.startswith("--providers.file.filename="):
            file_dir = os.path.dirname(arg.split("=", 1)[1])
            break
        if arg.startswith("--providers.file.directory="):
            file_dir = arg.split("=", 1)[1]
            break
    mounts = container.attrs.get("Mounts", [])
    if file_dir:
        for mount in mounts:
            dest = mount.get("Destination", "").rstrip("/")
            if file_dir.startswith(dest + "/") or file_dir == dest:
                rel = file_dir[len(dest):].lstrip("/")
                return os.path.join(mount["Source"], rel) if rel else mount["Source"]
    for mount in mounts:
        src = mount.get("Source", "").lower()
        dst = mount.get("Destination", "").lower()
        if "dynamic" in src or "dynamic" in dst:
            return mount["Source"]
    return None


@app.get("/api/setup/detect-proxy")
def setup_detect_proxy():
    """Detect reverse proxy containers (Traefik, Nginx Proxy Manager)."""
    result = {"traefik": None, "nginx_proxy_manager": None}
    try:
        for container in client.containers.list():
            image = container.attrs["Config"]["Image"].lower()
            img_base = image.split("/")[-1] if "/" in image else image
            if container.name.lower() == "traefik" or img_base.startswith("traefik"):
                result["traefik"] = {
                    "container": container.name,
                    "dynamic_path": _traefik_dynamic_path(container),
                }
            elif "nginx-proxy-manager" in image or "jc21/nginx" in image:
                result["nginx_proxy_manager"] = {"container": container.name}
    except Exception:
        pass
    return JSONResponse(result)


@app.post("/api/setup/place-ca-cert")
async def setup_place_ca_cert(request: Request):
    ca_path = os.path.join(CERTS_DIR, "ca.crt")
    if not os.path.isfile(ca_path):
        raise HTTPException(status_code=400, detail="Zertifikat noch nicht generiert")
    body = await request.json()
    target = body.get("path", "").strip()
    if not target or ".." in target:
        raise HTTPException(status_code=400, detail="Ungültiger Zielpfad")
    certs_host = os.path.join(_data_host_path(), "certs")
    try:
        client.containers.run(
            "alpine:latest",
            command=["cp", "/src/ca.crt", "/dst/dockpilot-ca.crt"],
            volumes={
                certs_host: {"bind": "/src", "mode": "ro"},
                target:     {"bind": "/dst", "mode": "rw"},
            },
            remove=True,
        )
        return {"ok": True, "placed_at": os.path.join(target, "dockpilot-ca.crt")}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/api/setup/mode")
async def setup_save_mode(request: Request):
    body = await request.json()
    mode = body.get("mode", "").strip()
    if mode not in ("standalone", "hub", "agent"):
        raise HTTPException(status_code=400, detail="Ungültiger Modus")
    data: dict = {"mode": mode}
    if mode == "agent":
        hub_url = body.get("hub_url", "").strip().rstrip("/")
        if not hub_url:
            raise HTTPException(status_code=400, detail="Hub-URL erforderlich")
        agent_token = body.get("agent_token", "").strip() or secrets.token_urlsafe(32)
        data["hub_url"] = hub_url
        data["agent_token"] = agent_token
        data["agent_name"] = body.get("agent_name", "").strip() or os.uname().nodename
    _save_mode(data)
    return {"ok": True, "mode": mode, "agent_token": data.get("agent_token")}


@app.get("/api/setup/mode")
def setup_get_mode():
    return JSONResponse(_load_mode())


@app.post("/api/agents/register")
async def api_agent_register(request: Request):
    """Hub-seitig: Agent meldet sich mit URL und Token an."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    token = auth[7:]
    body = await request.json()
    agent_url = body.get("url", "").strip().rstrip("/")
    agent_name = body.get("name", "")
    servers = _load_servers()
    for s in servers:
        if s.get("type") == "agent" and hmac.compare_digest(s.get("token", "").encode(), token.encode()):
            if agent_url:
                s["url"] = agent_url
            if agent_name:
                s["name"] = agent_name
            s["last_seen"] = time.time()
            _save_servers(servers)
            return {"ok": True}
    raise HTTPException(status_code=401, detail="Unbekannter Agent-Token")


@app.post("/api/servers/agent-invite")
async def api_agent_invite(request: Request):
    """Hub generiert einen Einladungs-Token für einen neuen Agent."""
    require_auth(request)
    body = await request.json()
    name = body.get("name", "Neuer Agent").strip()
    token = secrets.token_urlsafe(32)
    server: dict = {
        "id": str(uuid.uuid4()),
        "name": name,
        "type": "agent",
        "token": token,
        "url": "",
        "last_seen": None,
    }
    servers = _load_servers()
    servers.append(server)
    _save_servers(servers)
    return {"ok": True, "id": server["id"], "token": token}


@app.get("/login", response_class=HTMLResponse)
def login_page(error: str = ""):
    """Render login page; redirect to setup wizard if not yet configured."""
    if needs_setup():
        return RedirectResponse(url="/setup", status_code=303)
    if get_dp_mode() == "agent":
        return RedirectResponse(url="/", status_code=303)
    return LOGIN_HTML.replace("{{ERROR}}", html.escape(error))


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    user, pw, _ = _load_creds()
    user_ok = hmac.compare_digest(username, user)
    pass_ok = hmac.compare_digest(password, pw)
    if not (user_ok and pass_ok):
        return RedirectResponse(url="/login?error=Falsche+Zugangsdaten", status_code=303)
    resp = RedirectResponse(url="/", status_code=303)
    resp.set_cookie(COOKIE, make_token(), httponly=True, secure=True,
                    samesite="lax", max_age=SESSION_TTL)
    return resp


@app.post("/logout")
def logout():
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie(COOKIE)
    return resp


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    if needs_setup():
        return RedirectResponse(url="/setup", status_code=303)
    if get_dp_mode() == "agent":
        return HTMLResponse(AGENT_HTML)
    if not valid_token(request.cookies.get(COOKIE)):
        return RedirectResponse(url="/login", status_code=303)
    return INDEX_HTML


@app.get("/api/containers")
def api_containers(request: Request):
    require_auth_any(request)
    containers = client.containers.list(all=True)
    with ThreadPoolExecutor(max_workers=8) as ex:
        data = list(ex.map(serialize, containers))
    data.sort(key=lambda d: (not d["running"], d["name"]))
    return JSONResponse(data)


@app.get("/api/host")
def api_host(request: Request):
    require_auth_any(request)
    return JSONResponse(host_stats())


@app.get("/api/sizes")
def api_sizes(request: Request):
    """Return disk sizes (RW layer + rootfs) for all containers."""
    require_auth_any(request)
    raw = client.api.containers(all=True, size=True)
    out = {}
    for c in raw:
        out[c["Id"][:12]] = {"rw": c.get("SizeRw"), "rootfs": c.get("SizeRootFs")}
    return JSONResponse(out)


@app.post("/api/containers/{cid}/{action}")
def api_action(cid: str, action: str, request: Request):
    require_auth_any(request)
    try:
        c = client.containers.get(cid)
    except docker.errors.NotFound:
        raise HTTPException(status_code=404, detail="Container nicht gefunden")
    try:
        if action == "start":
            c.start()
        elif action == "stop":
            c.stop()
        elif action == "restart":
            c.restart()
        elif action == "update":
            recreate_with_new_image(c)
        else:
            raise HTTPException(status_code=400, detail="Unbekannte Aktion")
    except docker.errors.APIError as docker_err:
        raise HTTPException(status_code=500, detail=str(docker_err.explanation or docker_err)) from docker_err
    return {"ok": True}


@app.get("/api/stacks")
def api_stacks(request: Request):
    """List all stacks (subdirectories with a docker-compose.yaml) in STACKS_DIR."""
    require_auth_any(request)
    os.makedirs(STACKS_DIR, exist_ok=True)
    result = []
    try:
        for name in sorted(os.listdir(STACKS_DIR)):
            stack_dir = os.path.join(STACKS_DIR, name)
            if os.path.isdir(stack_dir) and os.path.isfile(os.path.join(stack_dir, "docker-compose.yaml")):
                result.append({"name": name, "dir": os.path.realpath(stack_dir)})
    except OSError:
        pass
    return JSONResponse(result)


@app.get("/api/stacks/{name}/file")
def api_stack_get(name: str, request: Request):
    """Return the docker-compose.yaml content for the given stack."""
    require_auth(request)
    cf = os.path.join(_stack_dir(name), "docker-compose.yaml")
    if not os.path.isfile(cf):
        raise HTTPException(status_code=404, detail="Compose-Datei nicht gefunden")
    with open(cf) as f:
        return JSONResponse({"content": f.read()})


@app.put("/api/stacks/{name}/file")
async def api_stack_save(name: str, request: Request):
    require_auth(request)
    body = await request.json()
    content = body.get("content", "")
    d = _stack_dir(name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "docker-compose.yaml"), "w") as f:
        f.write(content)
    return {"ok": True}


@app.post("/api/stacks/{name}/up")
def api_stack_up(name: str, request: Request):
    require_auth(request)
    res = _run_compose(name, "up", "-d", timeout=300)
    if not res["ok"]:
        raise HTTPException(status_code=500, detail=res["out"])
    return res


@app.post("/api/stacks/{name}/down")
def api_stack_down(name: str, request: Request):
    require_auth(request)
    res = _run_compose(name, "down", timeout=120)
    if not res["ok"]:
        raise HTTPException(status_code=500, detail=res["out"])
    return res


@app.post("/api/stacks/{name}/pull")
def api_stack_pull(name: str, request: Request):
    require_auth(request)
    res = _run_compose(name, "pull", timeout=300)
    if not res["ok"]:
        raise HTTPException(status_code=500, detail=res["out"])
    return res


@app.post("/api/stacks/{name}/logs")
def api_stack_logs(name: str, request: Request):
    require_auth(request)
    res = _run_compose(name, "logs", "--no-color", "--tail=200", timeout=15)
    return res


@app.delete("/api/stacks/{name}")
def api_stack_delete(name: str, request: Request):
    require_auth(request)
    d = _stack_dir(name)
    if not os.path.isdir(d):
        raise HTTPException(status_code=404)
    shutil.rmtree(d)
    return {"ok": True}


@app.post("/api/stacks/import")
async def api_stack_import(request: Request):
    import urllib.request as ureq
    import urllib.error
    require_auth(request)
    body = await request.json()
    url = body.get("url", "").strip()
    token_name = body.get("token", "").strip()
    stack_name = body.get("name", "").strip()
    if not url or not stack_name:
        raise HTTPException(status_code=400, detail="URL und Stack-Name erforderlich")
    if not SAFE_NAME.match(stack_name):
        raise HTTPException(status_code=400, detail="Ungültiger Stack-Name")
    headers = {"User-Agent": "dockpilot/1.0"}
    if token_name:
        tokens = _load_tokens()
        token_val = tokens.get(token_name)
        if not token_val:
            raise HTTPException(status_code=400, detail=f"Token '{token_name}' nicht gefunden")
        headers["Authorization"] = f"Bearer {token_val}"
    try:
        req = ureq.Request(url, headers=headers)
        with ureq.urlopen(req, timeout=30) as resp:
            content = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        raise HTTPException(status_code=400, detail=f"HTTP {exc.code}: {exc.reason}") from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Download fehlgeschlagen: {exc}") from exc
    d = _stack_dir(stack_name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "docker-compose.yaml"), "w") as f:
        f.write(content)
    return {"ok": True}


# ----------------------------- Token-Verwaltung -----------------------------
@app.get("/api/tokens")
def api_tokens_list(request: Request):
    require_auth(request)
    return JSONResponse(list(_load_tokens().keys()))


@app.put("/api/tokens/{name}")
async def api_token_save(name: str, request: Request):
    require_auth(request)
    if not SAFE_NAME.match(name):
        raise HTTPException(status_code=400, detail="Ungültiger Token-Name")
    body = await request.json()
    value = body.get("value", "").strip()
    if not value:
        raise HTTPException(status_code=400, detail="Token-Wert darf nicht leer sein")
    tokens = _load_tokens()
    tokens[name] = value
    _save_tokens(tokens)
    return {"ok": True}


@app.delete("/api/tokens/{name}")
def api_token_delete(name: str, request: Request):
    require_auth(request)
    tokens = _load_tokens()
    if name not in tokens:
        raise HTTPException(status_code=404, detail="Token nicht gefunden")
    del tokens[name]
    _save_tokens(tokens)
    return {"ok": True}


# ----------------------------- Registry-Zugangsdaten -----------------------------
@app.get("/api/registries")
def api_registries_list(request: Request):
    require_auth(request)
    return JSONResponse(_registry_list())


@app.post("/api/registries")
async def api_registry_add(request: Request):
    require_auth(request)
    body = await request.json()
    registry = body.get("registry", "").strip()
    username = body.get("username", "").strip()
    password = body.get("password", "").strip()
    if not registry or not username or not password:
        raise HTTPException(status_code=400, detail="Registry, Benutzername und Passwort/Token erforderlich")
    _registry_add(registry, username, password)
    return {"ok": True}


@app.delete("/api/registries/{registry:path}")
def api_registry_delete(registry: str, request: Request):
    require_auth(request)
    if registry not in _registry_list():
        raise HTTPException(status_code=404, detail="Registry nicht gefunden")
    _registry_remove(registry)
    return {"ok": True}


@app.get("/api/images")
def api_images(request: Request):
    require_auth(request)
    used_ids = {c.image.id for c in client.containers.list(all=True)}
    images = []
    for img in client.images.list(all=False):
        images.append({
            "id": img.id,
            "short_id": img.id.replace("sha256:", "")[:12],
            "tags": img.tags,
            "size": img.attrs.get("Size", 0),
            "created": img.attrs.get("Created", ""),
            "in_use": img.id in used_ids,
        })
    images.sort(key=lambda i: (not i["in_use"], i["tags"][0] if i["tags"] else "\xff"))
    return JSONResponse(images)


@app.delete("/api/images/{image_id:path}")
def api_image_delete(image_id: str, request: Request):
    require_auth(request)
    try:
        client.images.remove(image_id, force=False)
    except docker.errors.ImageNotFound:
        raise HTTPException(status_code=404, detail="Image nicht gefunden")
    except docker.errors.APIError as e:
        raise HTTPException(status_code=409, detail=str(e.explanation or e))
    return {"ok": True}


@app.post("/api/images/prune")
def api_images_prune(request: Request):
    require_auth(request)
    result = client.images.prune(filters={"dangling": False})
    freed = result.get("SpaceReclaimed", 0)
    deleted = len(result.get("ImagesDeleted") or [])
    return {"deleted": deleted, "freed": freed}


# ----------------------------- Ferne Server -----------------------------
def _load_servers() -> list:
    if os.path.isfile(SERVERS_FILE):
        with open(SERVERS_FILE) as f:
            return json.load(f)
    return []


def _save_servers(servers: list):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(SERVERS_FILE, "w") as f:
        json.dump(servers, f, indent=2)


def _get_server(server_id: str) -> dict | None:
    for s in _load_servers():
        if s.get("id") == server_id:
            return s
    return None


def _ssh_connect(server: dict):
    """Open a paramiko SSH connection to the given server config. Caller must close."""
    import paramiko
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs: dict = {
        "hostname": server["host"],
        "port": int(server.get("port", 22)),
        "username": server["username"],
        "timeout": 10,
        "look_for_keys": False,
        "allow_agent": False,
    }
    if server.get("auth_type") == "password":
        kwargs["password"] = server.get("password", "")
    else:
        key_data = server.get("ssh_key", "")
        if key_data:
            for klass in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey, paramiko.DSSKey):
                try:
                    kwargs["pkey"] = klass.from_private_key(io.StringIO(key_data))
                    break
                except Exception:
                    continue
    ssh.connect(**kwargs)
    return ssh


def _agent_http(server: dict, method: str, path: str, body: dict | None = None):
    """Synchronous HTTP call from hub to an agent, returns parsed JSON."""
    import urllib.request as ureq
    import urllib.error
    url = server.get("url", "").rstrip("/") + path
    token = server.get("token", "")
    payload = json.dumps(body).encode() if body else None
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    try:
        req = ureq.Request(url, data=payload, headers=headers, method=method)
        with ureq.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except ureq.error.HTTPError as e:
        raise HTTPException(status_code=e.code, detail=f"Agent: {e.reason}")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Agent nicht erreichbar: {exc}")


@app.get("/api/servers/{server_id}/containers")
def api_server_containers(server_id: str, request: Request):
    require_auth(request)
    server = _get_server(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server nicht gefunden")
    if server.get("type") != "agent":
        raise HTTPException(status_code=400, detail="Nur für Agent-Server")
    if not server.get("url"):
        raise HTTPException(status_code=503, detail="Agent-URL unbekannt – Agent noch nicht registriert")
    return JSONResponse(_agent_http(server, "GET", "/api/containers"))


@app.get("/api/servers")
def api_servers_list(request: Request):
    require_auth(request)
    safe_keys = {"id", "name", "host", "port", "username", "auth_type", "type", "url", "last_seen"}
    return JSONResponse([{k: v for k, v in s.items() if k in safe_keys} for s in _load_servers()])


@app.post("/api/servers")
async def api_server_add(request: Request):
    require_auth(request)
    body = await request.json()
    srv_type = body.get("type", "ssh")  # "ssh" or "agent"
    name = body.get("name", "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Name ist erforderlich")
    if srv_type == "agent":
        token = body.get("token", "").strip()
        if not token:
            raise HTTPException(status_code=400, detail="Token ist erforderlich")
        server: dict = {
            "id": str(uuid.uuid4()),
            "name": name,
            "type": "agent",
            "token": token,
            "url": body.get("url", "").strip().rstrip("/"),
            "last_seen": None,
        }
    else:
        host = body.get("host", "").strip()
        username = body.get("username", "").strip()
        if not host or not username:
            raise HTTPException(status_code=400, detail="Host und Benutzer sind erforderlich")
        auth_type = body.get("auth_type", "key")
        server = {
            "id": str(uuid.uuid4()),
            "name": name,
            "type": "ssh",
            "host": host,
            "port": int(body.get("port", 22)),
            "username": username,
            "auth_type": auth_type,
        }
        if auth_type == "password":
            server["password"] = body.get("password", "")
        else:
            server["ssh_key"] = body.get("ssh_key", "")
    servers = _load_servers()
    servers.append(server)
    _save_servers(servers)
    return {"ok": True, "id": server["id"]}


@app.put("/api/servers/{server_id}")
async def api_server_update(server_id: str, request: Request):
    require_auth(request)
    body = await request.json()
    servers = _load_servers()
    for s in servers:
        if s.get("id") == server_id:
            for k in ("name", "host", "username"):
                if k in body and body[k]:
                    s[k] = body[k]
            if "port" in body:
                s["port"] = int(body["port"])
            if body.get("ssh_key"):
                s["ssh_key"] = body["ssh_key"]
                s["auth_type"] = "key"
                s.pop("password", None)
            elif body.get("password"):
                s["password"] = body["password"]
                s["auth_type"] = "password"
                s.pop("ssh_key", None)
            _save_servers(servers)
            return {"ok": True}
    raise HTTPException(status_code=404, detail="Server nicht gefunden")


@app.delete("/api/servers/{server_id}")
def api_server_delete(server_id: str, request: Request):
    require_auth(request)
    servers = _load_servers()
    filtered = [s for s in servers if s.get("id") != server_id]
    if len(filtered) == len(servers):
        raise HTTPException(status_code=404, detail="Server nicht gefunden")
    _save_servers(filtered)
    return {"ok": True}


@app.patch("/api/servers/{server_id}")
async def api_server_patch(server_id: str, request: Request):
    require_auth(request)
    body = await request.json()
    servers = _load_servers()
    for s in servers:
        if s.get("id") == server_id:
            if "name" in body:
                s["name"] = str(body["name"])[:128]
            _save_servers(servers)
            return {"ok": True}
    raise HTTPException(status_code=404, detail="Server nicht gefunden")


@app.post("/api/servers/{server_id}/test")
def api_server_test(server_id: str, request: Request):
    require_auth(request)
    server = _get_server(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server nicht gefunden")
    if server.get("type") == "agent":
        if not server.get("url"):
            raise HTTPException(status_code=503, detail="Agent noch nicht registriert (URL unbekannt)")
        try:
            _agent_http(server, "GET", "/api/host")
            return {"ok": True}
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        ssh = _ssh_connect(server)
        ssh.close()
        return {"ok": True}
    except ImportError:
        raise HTTPException(status_code=500, detail="paramiko nicht installiert")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/self/update")
def api_self_update_status(request: Request):
    require_auth(request)
    return JSONResponse(_UPDATE_STATE)


@app.post("/api/self/update/check")
def api_self_update_check(request: Request):
    require_auth(request)
    if not _UPDATE_STATE["checking"]:
        threading.Thread(target=_do_check_update, daemon=True).start()
    return {"ok": True}


# Inline Python script executed by the self-updater helper container.
# Receives the target container ID as sys.argv[1].
# Runs outside DockPilot's process namespace so it survives the container stop.
_RECREATE_SCRIPT = """\
import docker, sys, time
client = docker.DockerClient(base_url="unix://var/run/docker.sock")
time.sleep(3)
cid = sys.argv[1]
c = client.containers.get(cid)
attrs = c.attrs; cfg = attrs["Config"]; hc = attrs["HostConfig"]
name = c.name; image_ref = cfg["Image"]
nets = list((attrs.get("NetworkSettings") or {}).get("Networks", {}).items())
primary_ep = None
if nets:
    pnet, ncfg = nets[0]
    aliases = [a for a in (ncfg.get("Aliases") or []) if a != c.id[:12]]
    ep = client.api.create_endpoint_config(aliases=aliases or None)
    primary_ep = (pnet, ep)
nc = client.api.create_networking_config({primary_ep[0]: primary_ep[1]}) if primary_ep else None
new_hc = client.api.create_host_config(
    binds=hc.get("Binds"), port_bindings=hc.get("PortBindings"),
    restart_policy=hc.get("RestartPolicy"), network_mode=hc.get("NetworkMode"),
    privileged=hc.get("Privileged", False), cap_add=hc.get("CapAdd"),
    cap_drop=hc.get("CapDrop"), security_opt=hc.get("SecurityOpt"),
    dns=hc.get("Dns"), extra_hosts=hc.get("ExtraHosts"),
)
c.stop(); c.remove()
new = client.api.create_container(
    image=image_ref, name=name, command=cfg.get("Cmd"),
    entrypoint=cfg.get("Entrypoint"), environment=cfg.get("Env"),
    labels=cfg.get("Labels"), working_dir=cfg.get("WorkingDir") or None,
    user=cfg.get("User") or None, hostname=cfg.get("Hostname"),
    tty=cfg.get("Tty", False), host_config=new_hc, networking_config=nc,
)
new_id = new["Id"]
for net_name, ncfg in nets[1:]:
    aliases = [a for a in (ncfg.get("Aliases") or []) if a != c.id[:12]]
    client.api.connect_container_to_network(new_id, net_name, aliases=aliases or None)
client.api.start(new_id)
"""


@app.post("/api/self/update/apply")
def api_self_update_apply(request: Request):
    require_auth(request)
    cid = _self_container_id()
    if not cid:
        raise HTTPException(status_code=500, detail="Eigener Container nicht erkannt")
    try:
        c = client.containers.get(cid)
    except docker.errors.NotFound:
        raise HTTPException(status_code=404, detail="Container nicht gefunden")

    labels = c.attrs.get("Labels") or {}
    compose_files = labels.get("com.docker.compose.project.config_files", "")
    compose_service = labels.get("com.docker.compose.service", "")
    image_ref = c.attrs["Config"]["Image"]
    full_cid = c.id

    def _do_apply():
        try:
            client.images.pull(image_ref)
        except Exception as exc:
            _UPDATE_STATE["error"] = f"Pull fehlgeschlagen: {exc}"
            return
        try:
            stale = client.containers.get("dockpilot-self-updater")
            stale.remove(force=True)
        except docker.errors.NotFound:
            pass
        try:
            if compose_files and compose_service:
                # Compose-managed: run docker compose up from helper container
                compose_dir = os.path.dirname(compose_files)
                cmd = (
                    f"sleep 3 && docker compose -f '{compose_files}'"
                    f" up -d --force-recreate '{compose_service}'"
                )
                helper = client.api.create_container(
                    image=image_ref,
                    name="dockpilot-self-updater",
                    entrypoint=["sh", "-c", cmd],
                    host_config=client.api.create_host_config(
                        binds=[
                            "/var/run/docker.sock:/var/run/docker.sock",
                            f"{compose_dir}:{compose_dir}:ro",
                        ],
                        auto_remove=True,
                    ),
                )
            else:
                # Standalone docker run: helper recreates container via Python SDK
                helper = client.api.create_container(
                    image=image_ref,
                    name="dockpilot-self-updater",
                    entrypoint=["python3", "-c", _RECREATE_SCRIPT, full_cid],
                    host_config=client.api.create_host_config(
                        binds=["/var/run/docker.sock:/var/run/docker.sock"],
                        auto_remove=True,
                    ),
                )
            client.api.start(helper["Id"])
        except Exception as exc:
            _UPDATE_STATE["error"] = f"Updater-Start fehlgeschlagen: {exc}"

    threading.Thread(target=_do_apply, daemon=True).start()
    return {"ok": True}


@app.websocket("/ws/console")
async def ws_console(websocket: WebSocket, token: str = ""):
    await websocket.accept()
    cookie_token = websocket.cookies.get(COOKIE)
    bearer_token = get_agent_token()
    cookie_ok = valid_token(cookie_token)
    bearer_ok = bool(bearer_token and token and hmac.compare_digest(token.encode(), bearer_token.encode()))
    if not (cookie_ok or bearer_ok):
        await websocket.close(code=4001)
        return

    shell = "/bin/bash" if os.path.exists("/bin/bash") else "/bin/sh"
    try:
        master_fd, slave_fd = pty.openpty()
        fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        proc = subprocess.Popen(
            [shell, "-l"],
            stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
            close_fds=True, preexec_fn=os.setsid,
            env={**os.environ, "TERM": "xterm-256color", "COLORTERM": "truecolor"},
        )
        os.close(slave_fd)
    except Exception as exc:
        await websocket.send_text(f"\r\n\x1b[31m[Terminal-Fehler: {exc}]\x1b[0m\r\n")
        await websocket.close()
        return

    loop = asyncio.get_running_loop()

    async def pty_to_ws():
        while True:
            try:
                ready, _, _ = await loop.run_in_executor(None, select.select, [master_fd], [], [], 0.05)
            except OSError:
                break
            if ready:
                try:
                    data = os.read(master_fd, 4096)
                except OSError:
                    break
                try:
                    await websocket.send_bytes(data)
                except Exception:
                    break
            if proc.poll() is not None:
                break

    async def ws_to_pty():
        while True:
            try:
                msg = await websocket.receive_text()
            except Exception:
                break
            try:
                payload = json.loads(msg)
                if payload.get("type") == "resize":
                    cols = int(payload.get("cols", 80))
                    rows = int(payload.get("rows", 24))
                    fcntl.ioctl(master_fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
                    continue
            except (json.JSONDecodeError, ValueError):
                pass
            try:
                os.write(master_fd, msg.encode())
            except OSError:
                break

    read_task = asyncio.create_task(pty_to_ws())
    write_task = asyncio.create_task(ws_to_pty())
    try:
        _, pending = await asyncio.wait([read_task, write_task], return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        try:
            os.close(master_fd)
        except OSError:
            pass


@app.websocket("/ws/remote-console/{server_id}")
async def ws_remote_console(websocket: WebSocket, server_id: str):
    await websocket.accept()
    token = websocket.cookies.get(COOKIE)
    if not valid_token(token):
        await websocket.close(code=4001)
        return

    server = _get_server(server_id)
    if not server:
        await websocket.send_text("\r\n\x1b[31m[Server nicht gefunden]\x1b[0m\r\n")
        await websocket.close(code=4004)
        return

    loop = asyncio.get_running_loop()

    # Agent-type: proxy WebSocket to agent's /ws/console endpoint
    if server.get("type") == "agent":
        agent_url = server.get("url", "")
        agent_token = server.get("token", "")
        if not agent_url:
            await websocket.send_text("\r\n\x1b[31m[Agent noch nicht registriert]\x1b[0m\r\n")
            await websocket.close()
            return
        ws_url = agent_url.replace("https://", "wss://").replace("http://", "ws://")
        ws_url = f"{ws_url}/ws/console?token={agent_token}"
        try:
            import websockets as _ws_lib
        except ImportError:
            await websocket.send_text("\r\n\x1b[31m[websockets-Bibliothek nicht installiert]\x1b[0m\r\n")
            await websocket.close()
            return
        try:
            agent_ws = await _ws_lib.connect(ws_url)
        except Exception as exc:
            await websocket.send_text(f"\r\n\x1b[31m[Agent-Verbindungsfehler: {exc}]\x1b[0m\r\n")
            await websocket.close()
            return

        async def agent_to_browser():
            try:
                async for msg in agent_ws:
                    if isinstance(msg, bytes):
                        await websocket.send_bytes(msg)
                    else:
                        await websocket.send_text(msg)
            except Exception:
                pass

        async def browser_to_agent():
            while True:
                try:
                    msg = await websocket.receive()
                    if msg["type"] == "websocket.disconnect":
                        break
                    raw = msg.get("bytes") or (msg.get("text") or "").encode()
                    if raw:
                        await agent_ws.send(raw)
                except Exception:
                    break

        t1 = asyncio.create_task(agent_to_browser())
        t2 = asyncio.create_task(browser_to_agent())
        try:
            _, pending = await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
        finally:
            await agent_ws.close()
        return

    try:
        ssh = await loop.run_in_executor(None, _ssh_connect, server)
    except ImportError:
        await websocket.send_text("\r\n\x1b[31m[SSH-Bibliothek nicht installiert]\x1b[0m\r\n")
        await websocket.close()
        return
    except Exception as exc:
        await websocket.send_text(f"\r\n\x1b[31m[SSH-Fehler: {exc}]\x1b[0m\r\n")
        await websocket.close()
        return

    try:
        channel = await loop.run_in_executor(
            None, lambda: ssh.invoke_shell(term="xterm-256color", width=220, height=50)
        )
        channel.settimeout(0.0)
    except Exception as exc:
        await websocket.send_text(f"\r\n\x1b[31m[Shell-Fehler: {exc}]\x1b[0m\r\n")
        await websocket.close()
        ssh.close()
        return

    q: asyncio.Queue = asyncio.Queue()

    def _ssh_reader():
        while True:
            try:
                if channel.closed or channel.eof_received:
                    break
                data = channel.recv(4096)
                if not data:
                    break
                loop.call_soon_threadsafe(q.put_nowait, data)
            except Exception:
                break
        loop.call_soon_threadsafe(q.put_nowait, None)

    threading.Thread(target=_ssh_reader, daemon=True).start()

    async def ssh_to_ws():
        while True:
            data = await q.get()
            if data is None:
                break
            try:
                await websocket.send_bytes(data)
            except Exception:
                break

    async def ws_to_ssh():
        while True:
            try:
                msg = await websocket.receive()
                if msg["type"] == "websocket.disconnect":
                    break
                raw = msg.get("bytes") or (msg.get("text") or "").encode()
                if not raw:
                    continue
                try:
                    parsed = json.loads(raw)
                    if parsed.get("type") == "resize":
                        cols = int(parsed.get("cols", 80))
                        rows = int(parsed.get("rows", 24))
                        await loop.run_in_executor(None, lambda: channel.resize_pty(width=cols, height=rows))
                    continue
                except (json.JSONDecodeError, TypeError, ValueError):
                    pass
                await loop.run_in_executor(None, channel.send, raw)
            except Exception:
                break

    send_task = asyncio.create_task(ssh_to_ws())
    recv_task = asyncio.create_task(ws_to_ssh())
    try:
        _, pending = await asyncio.wait([send_task, recv_task], return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
    finally:
        try:
            channel.close()
        except Exception:
            pass
        try:
            ssh.close()
        except Exception:
            pass


# ----------------------------- Templates -----------------------------
SETUP_HTML = """<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>dockpilot · Setup</title><style>
*{box-sizing:border-box;user-select:none}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
  background:#070d1a;color:#dce8f8;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:1rem}
.wrap{width:440px;max-width:100%}
.logo{text-align:center;font-size:1.5rem;font-weight:700;margin-bottom:.5rem;letter-spacing:-.02em}
.logo span{color:#3b82f6}
.sub{text-align:center;font-size:.85rem;color:#4a6a8a;margin-bottom:2rem}
.steps{display:flex;justify-content:center;gap:.5rem;margin-bottom:2rem}
.step{width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;
  font-size:.78rem;font-weight:700;border:2px solid #182a45;color:#3a5a7a;transition:all .3s}
.step.active{border-color:#3b82f6;color:#3b82f6;background:rgba(59,130,246,.08)}
.step.done{border-color:#22c55e;color:#22c55e;background:rgba(34,197,94,.08)}
.card{background:linear-gradient(150deg,#0e1a2e,#0c1828);border:1px solid #182a45;
  padding:2rem;border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,.5)}
.card h2{margin:0 0 .4rem;font-size:1.15rem;font-weight:700;color:#f0f6ff}
.card p{margin:0 0 1rem;font-size:.85rem;color:#4a6a8a;line-height:1.6}
label{display:block;font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.07em;
  margin:.9rem 0 .3rem;color:#4a6a8a}
input[type=text],input[type=password]{width:100%;padding:.65rem .9rem;border-radius:9px;
  border:1px solid #182a45;background:#070d1a;color:#dce8f8;font-size:.9rem;
  transition:border-color .2s;user-select:text}
input:focus{outline:none;border-color:#2a5aad;box-shadow:0 0 0 3px rgba(59,130,246,.08)}
.btn{width:100%;margin-top:1.25rem;padding:.75rem;border:0;border-radius:9px;
  background:linear-gradient(135deg,#1d4ed8,#3b82f6);color:#fff;font-weight:600;
  font-size:.95rem;cursor:pointer;transition:filter .15s,transform .1s}
.btn:hover{filter:brightness(1.12)}
.btn:active{transform:scale(.98)}
.btn:disabled{opacity:.4;cursor:not-allowed;filter:none}
.err{color:#f87171;font-size:.82rem;margin-top:.75rem;min-height:1rem}
.cert-box{margin-top:1.25rem;background:#060c18;border:1px solid #182a45;border-radius:10px;padding:1.1rem}
.cert-box .pw{font-family:monospace;font-size:.88rem;background:#0a1220;padding:.4rem .7rem;
  border-radius:6px;color:#60a5fa;display:inline-block;margin:.4rem 0;user-select:text}
.dl{display:flex;gap:.6rem;margin-top:.75rem}
.dl a{flex:1;padding:.55rem;border-radius:8px;text-align:center;font-size:.82rem;font-weight:600;
  text-decoration:none;color:#fff;background:linear-gradient(135deg,#1e3a8a,#3b82f6);transition:filter .15s}
.dl a:hover{filter:brightness(1.12)}
.dl a.green{background:linear-gradient(135deg,#166534,#22c55e)}
.note{font-size:.75rem;color:#3a5a7a;margin-top:.75rem;line-height:1.6}
.note code{background:#0a1220;padding:.1rem .4rem;border-radius:4px;color:#60a5fa;font-size:.8rem}
.skip{text-align:center;margin-top:.85rem}
.skip a{font-size:.82rem;color:#3a5a7a;cursor:pointer;text-decoration:underline}
.skip a:hover{color:#8eafd4}
.done-icon{text-align:center;font-size:3rem;margin-bottom:.75rem}
/* Mode selection */
.mode-cards{display:flex;flex-direction:column;gap:.6rem;margin:.5rem 0 .25rem}
.mode-card{border:2px solid #182a45;border-radius:12px;padding:.85rem 1rem;cursor:pointer;
  transition:border-color .2s,background .2s;display:flex;align-items:flex-start;gap:.75rem}
.mode-card:hover{border-color:#2a4060}
.mode-card.selected{border-color:#3b82f6;background:rgba(59,130,246,.07)}
.mode-icon{font-size:1.4rem;line-height:1;flex-shrink:0;margin-top:.1rem}
.mode-title{font-size:.88rem;font-weight:700;color:#f0f6ff;margin-bottom:.18rem}
.mode-desc{font-size:.76rem;color:#4a6a8a;line-height:1.45}
/* Agent done info box */
.info-box{background:#060c18;border:1px solid #182a45;border-radius:10px;padding:.9rem 1rem;margin-top:.75rem}
.info-box ol{margin:.4rem 0 0;padding-left:1.2rem;font-size:.8rem;color:#4a6a8a;line-height:1.8}
.info-box ol li strong{color:#dce8f8}
</style></head>
<body><div class="wrap">
<div class="logo">🐳 dock<span>pilot</span></div>
<div class="sub">Ersteinrichtung</div>
<div class="steps" id="step-indicators"></div>

<!-- Panel 0: Modus wählen -->
<div class="card" id="panel-mode">
  <h2>Installationsmodus</h2>
  <p>Wie soll dieser dockpilot-Server betrieben werden?</p>
  <div class="mode-cards">
    <div class="mode-card" id="mc-standalone" onclick="selectMode('standalone')">
      <div class="mode-icon">🖥️</div>
      <div>
        <div class="mode-title">Standalone</div>
        <div class="mode-desc">Einzelserver — verwalte nur diesen Host. Die einfachste Installation.</div>
      </div>
    </div>
    <div class="mode-card" id="mc-hub" onclick="selectMode('hub')">
      <div class="mode-icon">🌐</div>
      <div>
        <div class="mode-title">Hub (Hauptserver)</div>
        <div class="mode-desc">Zentrales Dashboard — verwalte diesen und weitere Remote-Server.</div>
      </div>
    </div>
    <div class="mode-card" id="mc-agent" onclick="selectMode('agent')">
      <div class="mode-icon">🔌</div>
      <div>
        <div class="mode-title">Agent (Client)</div>
        <div class="mode-desc">Wird vom Hub gesteuert — kein eigenes Dashboard, verbindet sich automatisch.</div>
      </div>
    </div>
  </div>
  <button class="btn" id="mode-next-btn" onclick="modeNext()" disabled>Weiter →</button>
  <div class="err" id="err-mode"></div>
</div>

<!-- Panel 1a: Zugangsdaten (Standalone / Hub) -->
<div class="card" id="panel-creds" style="display:none">
  <h2>Zugangsdaten festlegen</h2>
  <p>Wähle einen Benutzernamen und ein sicheres Passwort für den Login.</p>
  <label>Benutzername</label>
  <input type="text" id="su-user" value="admin" autocomplete="username">
  <label>Passwort</label>
  <input type="password" id="su-pass" autocomplete="new-password" placeholder="min. 8 Zeichen">
  <label>Passwort wiederholen</label>
  <input type="password" id="su-pass2" autocomplete="new-password">
  <button class="btn" onclick="saveCredentials()">Weiter →</button>
  <div class="err" id="err1"></div>
</div>

<!-- Panel 2a: mTLS-Zertifikat (Standalone / Hub) -->
<div class="card" id="panel-mtls" style="display:none">
  <h2>mTLS-Zertifikat <span style="font-size:.72rem;background:rgba(59,130,246,.12);border:1px solid rgba(59,130,246,.2);padding:.1rem .5rem;border-radius:5px;color:#60a5fa;font-weight:500;vertical-align:middle">optional</span></h2>
  <p>Schütze deinen Zugang mit einem Browser-Zertifikat. Ohne gültiges Zertifikat kommt niemand zur Login-Seite — auch mit gestohlenen Zugangsdaten nicht.</p>
  <button class="btn" id="gen-btn" onclick="generateCert()">Zertifikat generieren</button>
  <div class="cert-box" id="cert-result" style="display:none">
    <div style="font-size:.78rem;color:#4a6a8a;margin-bottom:.3rem">Zertifikat erstellt — alles herunterladen:</div>
    <div>P12-Passwort: <span class="pw" id="p12-pw"></span></div>
    <div class="dl">
      <a href="/api/setup/download/client.p12" download class="green" id="dl-p12" onclick="markDownloaded()">↓ client.p12</a>
      <a href="/api/setup/download/ca.crt" download>↓ ca.crt</a>
    </div>
    <div id="dl-hint" style="font-size:.75rem;color:#f59e0b;margin-top:.5rem">⬆ client.p12 herunterladen um fortzufahren</div>
    <div style="margin-top:1rem;padding-top:1rem;border-top:1px solid #182a45">
      <div style="font-size:.78rem;color:#4a6a8a;margin-bottom:.6rem">ca.crt automatisch ablegen:</div>
      <div id="proxy-status" style="font-size:.82rem;color:#3a5a7a">
        <span id="proxy-scanning">⟳ Erkenne Proxy…</span>
      </div>
      <div id="proxy-actions" style="margin-top:.6rem;display:none">
        <div id="traefik-action"></div>
        <div id="npm-action"></div>
        <div id="no-proxy-msg" style="display:none;font-size:.78rem;color:#3a5a7a">
          Kein bekannter Proxy erkannt — ca.crt bitte manuell ablegen.
        </div>
      </div>
      <div id="place-result" style="margin-top:.6rem;font-size:.8rem;display:none"></div>
    </div>
    <div class="note">
      <strong style="color:#dce8f8">Manuelle Schritte nach dem Ablegen:</strong><br>
      1. <code>client.p12</code> im Browser/OS importieren<br>
      2. mTLS-Block in Traefik Dynamic-Config eintragen (siehe <code>examples/traefik.yml</code>)<br>
      3. <code>tls.options</code>-Label in <code>docker-compose.yaml</code> einkommentieren
    </div>
  </div>
  <button class="btn" id="finish-btn" onclick="advancePanel()" style="margin-top:.85rem" disabled>Abschließen →</button>
  <div class="skip"><a onclick="advancePanel()">Diesen Schritt überspringen</a></div>
</div>

<!-- Panel 3a: Fertig (Standalone / Hub) -->
<div class="card" id="panel-done-normal" style="display:none">
  <div class="done-icon">✓</div>
  <h2 style="text-align:center">Setup abgeschlossen</h2>
  <p style="text-align:center">Zugangsdaten gespeichert. Du kannst dich jetzt einloggen.</p>
  <a href="/login"><button class="btn">Zum Login →</button></a>
</div>

<!-- Panel 1b: Hub-Verbindung (Agent) -->
<div class="card" id="panel-agent" style="display:none">
  <h2>Hub-Verbindung einrichten</h2>
  <p>Gib die URL des Hub-Servers und den dort generierten Token ein.<br>
     Den Token erhältst du auf dem Hub unter <strong style="color:#dce8f8">Server → Agent einladen</strong>.</p>
  <label>Hub-URL</label>
  <input type="text" id="ag-hub-url" placeholder="https://dockpilot.example.com">
  <label>Agent-Token</label>
  <input type="text" id="ag-token" placeholder="Token vom Hub einfügen" style="user-select:text;font-family:monospace;font-size:.82rem">
  <label>Agent-Name <span style="font-weight:400;text-transform:none;letter-spacing:0">(optional)</span></label>
  <input type="text" id="ag-name" placeholder="mein-server-02">
  <button class="btn" onclick="saveAgentMode()">Verbinden →</button>
  <div class="err" id="err-agent"></div>
</div>

<!-- Panel 2b: Fertig (Agent) -->
<div class="card" id="panel-done-agent" style="display:none">
  <div class="done-icon">🔌</div>
  <h2 style="text-align:center">Agent eingerichtet</h2>
  <p style="text-align:center">Dieser Server verbindet sich jetzt mit dem Hub.<br>
    Das vollständige Dashboard ist auf dem Hub-Server verfügbar.</p>
  <div class="info-box">
    <div style="font-size:.78rem;font-weight:700;color:#dce8f8;margin-bottom:.25rem">Nächste Schritte auf dem Hub:</div>
    <ol>
      <li>Hub-Dashboard öffnen → Tab <strong>Server</strong></li>
      <li><strong>Agent einladen</strong> klicken, denselben Token eingeben</li>
      <li>Agent erscheint nach dem ersten Verbindungsversuch (bis zu 30 Sek.)</li>
    </ol>
  </div>
  <a href="/"><button class="btn" style="margin-top:1.25rem">Fertig →</button></a>
</div>

</div>
<script>
let selectedMode=null;
const FLOWS={
  standalone:['panel-mode','panel-creds','panel-mtls','panel-done-normal'],
  hub:       ['panel-mode','panel-creds','panel-mtls','panel-done-normal'],
  agent:     ['panel-mode','panel-agent','panel-done-agent'],
};
let curFlow=FLOWS.standalone, curIdx=0;

function renderIndicators(total,active){
  const el=document.getElementById('step-indicators');
  el.innerHTML='';
  for(let i=0;i<total;i++){
    const d=document.createElement('div');
    d.className='step'+(i<active?' done':i===active?' active':'');
    d.textContent=i+1;
    el.appendChild(d);
  }
}

function showPanel(idx){
  curIdx=idx;
  const all=['panel-mode','panel-creds','panel-mtls','panel-done-normal','panel-agent','panel-done-agent'];
  all.forEach(id=>{const e=document.getElementById(id);if(e)e.style.display='none';});
  if(idx<curFlow.length){
    document.getElementById(curFlow[idx]).style.display='';
    renderIndicators(curFlow.length,idx);
  }
}

function selectMode(m){
  selectedMode=m;
  ['standalone','hub','agent'].forEach(x=>document.getElementById('mc-'+x).classList.toggle('selected',x===m));
  document.getElementById('mode-next-btn').disabled=false;
  renderIndicators(FLOWS[m].length,0);
}

async function modeNext(){
  if(!selectedMode)return;
  curFlow=FLOWS[selectedMode];
  const err=document.getElementById('err-mode');
  err.textContent='';
  if(selectedMode!=='agent'){
    try{
      const r=await fetch('/api/setup/mode',{method:'POST',
        headers:{'Content-Type':'application/json'},body:JSON.stringify({mode:selectedMode})});
      if(!r.ok){const j=await r.json().catch(()=>({}));err.textContent=j.detail||'Fehler';return}
    }catch(e){err.textContent='Netzwerkfehler: '+e.message;return}
  }
  showPanel(1);
}

async function saveCredentials(){
  const user=document.getElementById('su-user').value.trim();
  const pass=document.getElementById('su-pass').value;
  const pass2=document.getElementById('su-pass2').value;
  const err=document.getElementById('err1');
  if(!user){err.textContent='Benutzername darf nicht leer sein.';return}
  if(pass.length<8){err.textContent='Passwort muss mindestens 8 Zeichen haben.';return}
  if(pass!==pass2){err.textContent='Passwörter stimmen nicht überein.';return}
  err.textContent='';
  try{
    const r=await fetch('/api/setup/credentials',{method:'POST',
      headers:{'Content-Type':'application/json'},body:JSON.stringify({user,password:pass})});
    if(r.ok){showPanel(2)}
    else{const j=await r.json().catch(()=>({}));err.textContent=j.detail||'Fehler'}
  }catch(e){err.textContent='Netzwerkfehler: '+e.message}
}

async function saveAgentMode(){
  const hubUrl=document.getElementById('ag-hub-url').value.trim();
  const token=document.getElementById('ag-token').value.trim();
  const name=document.getElementById('ag-name').value.trim();
  const err=document.getElementById('err-agent');
  if(!hubUrl){err.textContent='Hub-URL ist erforderlich.';return}
  if(!token){err.textContent='Agent-Token ist erforderlich.';return}
  err.textContent='';
  try{
    const r=await fetch('/api/setup/mode',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({mode:'agent',hub_url:hubUrl,agent_token:token,agent_name:name})});
    if(r.ok){showPanel(2)}
    else{const j=await r.json().catch(()=>({}));err.textContent=j.detail||'Fehler'}
  }catch(e){err.textContent='Netzwerkfehler: '+e.message}
}

async function generateCert(){
  const btn=document.getElementById('gen-btn');
  btn.disabled=true;btn.textContent='⟳ Generiere…';
  try{
    const r=await fetch('/api/setup/generate-cert',{method:'POST'});
    if(r.ok){
      const j=await r.json();
      document.getElementById('p12-pw').textContent=j.p12_password;
      document.getElementById('cert-result').style.display='';
      btn.style.display='none';
      detectProxy();
    }else{btn.disabled=false;btn.textContent='Erneut versuchen'}
  }catch(e){btn.disabled=false;btn.textContent='Fehler: '+e.message}
}
async function detectProxy(){
  const scanning=document.getElementById('proxy-scanning');
  const actions=document.getElementById('proxy-actions');
  const traefikEl=document.getElementById('traefik-action');
  const npmEl=document.getElementById('npm-action');
  const noProxyEl=document.getElementById('no-proxy-msg');
  scanning.style.display='';
  const r=await fetch('/api/setup/detect-proxy');
  if(!r.ok){scanning.textContent='Proxy-Erkennung fehlgeschlagen';return}
  const j=await r.json();
  scanning.style.display='none';
  actions.style.display='';
  let found=false;
  if(j.traefik){
    found=true;
    const name=j.traefik.container;
    const path=j.traefik.dynamic_path;
    if(path){
      const btn=document.createElement('button');
      btn.textContent='Automatisch ablegen';
      btn.setAttribute('style','padding:.28rem .65rem;border-radius:6px;border:0;background:linear-gradient(135deg,#1d4ed8,#3b82f6);color:#fff;font-size:.75rem;cursor:pointer;font-weight:600');
      btn.addEventListener('click',()=>placeCaCert(path));
      const row=document.createElement('div');
      row.setAttribute('style','display:flex;align-items:center;justify-content:space-between;gap:.5rem;margin-bottom:.35rem');
      const lbl=document.createElement('span');
      lbl.setAttribute('style','font-size:.78rem;color:#60a5fa');
      lbl.textContent='Traefik: '+name;
      row.appendChild(lbl);row.appendChild(btn);
      traefikEl.appendChild(row);
    }else{
      traefikEl.innerHTML=`<div style="display:flex;align-items:center;justify-content:space-between;gap:.5rem;margin-bottom:.35rem"><span style="font-size:.78rem;color:#60a5fa">Traefik: ${name}</span><span style="font-size:.72rem;color:#f87171">Kein dynamic-Pfad gefunden</span></div>`;
    }
  }
  if(j.nginx_proxy_manager){
    found=true;
    npmEl.innerHTML=`<div style="font-size:.78rem;color:#4a6a8a;padding:.25rem 0">NPM erkannt (${j.nginx_proxy_manager.container}) — ca.crt manuell im NPM-Interface importieren</div>`;
  }
  if(!found){noProxyEl.style.display='';}
}
async function placeCaCert(path){
  const result=document.getElementById('place-result');
  result.style.display='';result.style.color='#4a6a8a';result.textContent='⟳ Ablegen…';
  const r=await fetch('/api/setup/place-ca-cert',{method:'POST',
    headers:{'Content-Type':'application/json'},body:JSON.stringify({path})});
  if(r.ok){
    const j=await r.json();
    result.style.color='#4ade80';
    result.textContent='✓ Abgelegt: '+j.placed_at;
  }else{
    const j=await r.json().catch(()=>({}));
    result.style.color='#f87171';
    result.textContent='Fehler: '+(j.detail||'Unbekannt');
  }
}
function markDownloaded(){
  document.getElementById('finish-btn').disabled=false;
  document.getElementById('dl-hint').style.display='none';
}
function advancePanel(){showPanel(curIdx+1)}

// Init — show mode selector
renderIndicators(3,0);
</script></body></html>"""

LOGIN_HTML = """<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>dockpilot · Login</title><style>
*{box-sizing:border-box;user-select:none}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
  background:#070d1a;color:#dce8f8;display:flex;min-height:100vh;align-items:center;justify-content:center}
.wrap{width:340px}
.logo{text-align:center;font-size:1.5rem;font-weight:700;margin-bottom:1.75rem;letter-spacing:-.02em}
.logo span{color:#3b82f6}
.card{background:linear-gradient(150deg,#0e1a2e,#0c1828);border:1px solid #182a45;
  padding:2rem;border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,.5)}
label{display:block;font-size:.75rem;font-weight:600;text-transform:uppercase;letter-spacing:.06em;
  margin:.85rem 0 .3rem;color:#4a6a8a}
input{width:100%;padding:.65rem .9rem;border-radius:9px;border:1px solid #182a45;
  background:#070d1a;color:#dce8f8;font-size:.9rem;transition:border-color .2s;user-select:text}
input:focus{outline:none;border-color:#2a5aad;box-shadow:0 0 0 3px rgba(59,130,246,.08)}
input:first-of-type{margin-top:0}
button{width:100%;margin-top:1.5rem;padding:.75rem;border:0;border-radius:9px;
  background:linear-gradient(135deg,#1d4ed8,#3b82f6);color:#fff;font-weight:600;
  font-size:.95rem;cursor:pointer;transition:filter .15s,transform .1s}
button:hover{filter:brightness(1.12)}
button:active{transform:scale(.98)}
.err{color:#f87171;font-size:.82rem;margin-top:.85rem;min-height:1.1rem;text-align:center}
</style></head>
<body><div class="wrap">
<div class="logo">🐳 dock<span>pilot</span></div>
<form class="card" method="post" action="/login">
<label>Benutzer</label><input name="username" autofocus autocomplete="username">
<label>Passwort</label><input name="password" type="password" autocomplete="current-password">
<button type="submit">Anmelden</button>
<div class="err">{{ERROR}}</div>
</form></div></body></html>"""


INDEX_HTML = """<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>dockpilot</title><style>
*{box-sizing:border-box;user-select:none}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
  background:#070d1a;color:#dce8f8;min-height:100vh}
textarea,.output-box,.img,.name{user-select:text}

header{display:flex;align-items:center;justify-content:space-between;padding:.85rem 1.75rem;
  background:#0c1525;border-bottom:1px solid #182a45}
.logo{font-size:1.2rem;font-weight:700;letter-spacing:-.02em;color:#f0f6ff}
.logo span{color:#3b82f6}
header .right{display:flex;gap:1rem;align-items:center;font-size:.82rem;color:#4a6a8a}
header form{margin:0}
.hbtn{background:#0e1e35;color:#7a9ac0;border:1px solid #1a3050;
  padding:.38rem .9rem;border-radius:7px;cursor:pointer;font-size:.82rem;transition:all .15s}
.hbtn:hover{background:#152842;color:#dce8f8}

.tabs{background:#070d1a;border-bottom:1px solid #182a45;padding:0 1.75rem;display:flex}
.tab{padding:.65rem 1.3rem;border:0;border-bottom:2px solid transparent;background:0;
  color:#3a5a7a;cursor:pointer;font-size:.875rem;font-weight:500;transition:color .2s;letter-spacing:.01em}
.tab:hover{color:#8eafd4}
.tab.active{color:#dce8f8;border-bottom-color:#3b82f6}

main{padding:1.5rem 1.75rem;max-width:1300px;margin:0 auto}

.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(195px,1fr));gap:.875rem;margin-bottom:1.5rem}
.card{background:linear-gradient(150deg,#0d1929,#0b1623);border:1px solid #182a45;
  border-radius:13px;padding:1.05rem 1.2rem;transition:border-color .2s,transform .15s}
.card:hover{border-color:#2a4060;transform:translateY(-1px)}
.card .lbl{font-size:.67rem;text-transform:uppercase;letter-spacing:.08em;color:#3a5a7a;font-weight:700}
.card .val{font-size:1.6rem;font-weight:700;margin:.3rem 0 .05rem;color:#f0f6ff;line-height:1}
.card .sub{font-size:.72rem;color:#3a5a7a;margin-top:.2rem}
.bar2{background:#060c18;border-radius:3px;height:3px;overflow:hidden;margin-top:.65rem}
.bar2>i{display:block;height:100%;border-radius:3px;transition:width .6s}
.dk{display:flex;justify-content:space-between;font-size:.74rem;margin:.2rem 0}
.dk span:first-child{color:#6a8aaa}
.dk span:last-child{color:#3a5a7a}

.dot{display:inline-block;width:8px;height:8px;border-radius:50%;flex-shrink:0}
.up{background:#22c55e;box-shadow:0 0 0 2px rgba(34,197,94,.2);animation:glow 2.5s ease-in-out infinite}
.down{background:#1e3a55}
@keyframes glow{0%,100%{box-shadow:0 0 0 2px rgba(34,197,94,.2)}
  50%{box-shadow:0 0 0 5px rgba(34,197,94,.06)}}
.stxt{font-size:.78rem}.stxt.on{color:#4ade80}.stxt.off{color:#3a5a7a}
.muted{color:#1e3a55}

#container-grid{display:flex;flex-wrap:wrap;gap:1rem;align-items:flex-start}
.group-section{background:linear-gradient(150deg,#070e1b,#060b16);border:1px solid #182a45;
  border-radius:14px;padding:1rem 1.1rem;width:fit-content}
.group-section.stack-dragging{opacity:.35;transform:scale(.98)}
.group-section.stack-drag-over{border-color:#3b82f6;box-shadow:0 0 0 2px rgba(59,130,246,.2)}
.group-hdr{font-size:.72rem;text-transform:uppercase;letter-spacing:.09em;color:#8eafd4;
  font-weight:700;display:flex;align-items:center;gap:.5rem;cursor:grab;
  padding-bottom:.65rem;border-bottom:1px solid #182a45;margin-bottom:.75rem}
.ccard-grid{display:grid;gap:.75rem}
.ccard{background:linear-gradient(150deg,#0d1929,#0b1623);border:1px solid #182a45;
  border-radius:13px;padding:.95rem 1rem;cursor:grab;
  transition:border-color .2s,transform .15s,box-shadow .15s}
.ccard:hover{border-color:#2a4060;transform:translateY(-1px)}
.ccard.dragging{opacity:.3;transform:scale(.96)}
.ccard.drag-over{border-color:#3b82f6;box-shadow:0 0 0 2px rgba(59,130,246,.2)}
.ccard-name{font-weight:600;color:#e8f2ff;font-size:.88rem;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ccard-img{color:#3a5a7a;font-size:.68rem;margin-top:.1rem;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ccard-stat{display:flex;align-items:center;gap:.35rem;margin:.22rem 0;font-size:.7rem}
.ccard-stat .sl{color:#3a5a7a;width:28px;flex-shrink:0}
.sbar{flex:1;background:#060c18;border-radius:3px;height:4px;overflow:hidden}
.sbar>i{display:block;height:100%;border-radius:3px}
.sbar.cpu>i{background:linear-gradient(90deg,#1d4ed8,#60a5fa)}
.sbar.mem>i{background:linear-gradient(90deg,#6d28d9,#c084fc)}
.ccard-stat .sv{color:#4a6a8a;width:36px;text-align:right;flex-shrink:0}
.ccard-acts{display:flex;gap:.3rem;flex-wrap:wrap;margin-top:.65rem;padding-top:.65rem;
  border-top:1px solid #0d1929}
.ccard-acts button,.tbtn{border:0;border-radius:7px;padding:.32rem .6rem;cursor:pointer;
  font-size:.73rem;color:#fff;font-weight:500;transition:filter .15s,transform .1s;letter-spacing:.01em}
.ccard-acts button:hover,.tbtn:hover{filter:brightness(1.2)}
.ccard-acts button:active,.tbtn:active{transform:scale(.94)}
.ccard-acts button:disabled,.tbtn:disabled{opacity:.25;cursor:not-allowed;filter:none;transform:none}
.b-start{background:linear-gradient(135deg,#166534,#22c55e)}
.b-stop{background:linear-gradient(135deg,#991b1b,#f87171)}
.b-restart{background:linear-gradient(135deg,#854d0e,#fbbf24)}
.b-update{background:linear-gradient(135deg,#1e3a8a,#60a5fa)}
.b-deploy{background:linear-gradient(135deg,#166534,#22c55e)}
.b-down{background:linear-gradient(135deg,#991b1b,#f87171)}
.b-pull{background:linear-gradient(135deg,#854d0e,#fbbf24)}
.b-logs{background:linear-gradient(135deg,#3730a3,#818cf8)}
.b-save{background:linear-gradient(135deg,#1e3a8a,#60a5fa)}
.b-del{background:linear-gradient(135deg,#1e293b,#475569)}

#toast{position:fixed;bottom:1.5rem;right:1.5rem;background:#0d1929;
  border:1px solid #182a45;padding:.75rem 1.15rem;border-radius:10px;font-size:.84rem;
  color:#8eafd4;opacity:0;transition:opacity .25s;pointer-events:none;
  box-shadow:0 12px 40px rgba(0,0,0,.6)}
#toast.show{opacity:1}
#toast.err{border-color:rgba(239,68,68,.4);color:#fca5a5}
.spin{animation:sp 1s linear infinite;display:inline-block}
@keyframes sp{to{transform:rotate(360deg)}}

.scard-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:.75rem;margin-bottom:1.25rem}
.scard{background:linear-gradient(150deg,#0d1929,#0b1623);border:1px solid #182a45;
  border-radius:13px;padding:1rem;cursor:pointer;
  transition:border-color .2s,transform .15s,box-shadow .15s}
.scard:hover{border-color:#2a4060;transform:translateY(-1px)}
.scard.active{border-color:#3b82f6;box-shadow:0 0 0 2px rgba(59,130,246,.12)}
.scard-new{border:1px dashed #182a45;color:#3a5a7a;display:flex;align-items:center;
  justify-content:center;gap:.5rem;font-size:.875rem;font-weight:500;min-height:90px}
.scard-new:hover{color:#8eafd4;border-color:#2a4060}
.scard-name{font-weight:600;color:#e8f2ff;font-size:.95rem;margin-bottom:.35rem;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.scard-meta{font-size:.72rem;color:#4a6a8a;display:flex;align-items:center;gap:.4rem;margin-bottom:.7rem}
.scard-acts{display:flex;gap:.35rem;flex-wrap:wrap}
.partial{background:#f59e0b}
.stack-editor-panel{background:linear-gradient(150deg,#0d1929,#0b1623);border:1px solid #3b82f6;
  border-radius:13px;padding:1.1rem;margin-top:.25rem}
.stack-toolbar{display:flex;gap:.4rem;align-items:center;margin-bottom:.8rem;flex-wrap:wrap}
.stack-toolbar strong{flex:1;font-size:.95rem;color:#f0f6ff;font-weight:600}
textarea.editor{width:100%;height:52vh;
  font-family:'JetBrains Mono','Fira Code',ui-monospace,'Courier New',monospace;
  font-size:.81rem;background:#04080f;color:#c8dff5;border:1px solid #182a45;
  border-radius:11px;padding:.95rem 1.1rem;resize:vertical;line-height:1.7;
  transition:border-color .2s,box-shadow .2s}
textarea.editor:focus{outline:none;border-color:#2a5aad;box-shadow:0 0 0 3px rgba(59,130,246,.07)}
.output-box{margin-top:.8rem;background:#04080f;border:1px solid #182a45;border-radius:11px;
  padding:.9rem 1.1rem;font-family:'JetBrains Mono','Fira Code',ui-monospace,monospace;
  font-size:.77rem;color:#6a8aaa;white-space:pre-wrap;max-height:220px;overflow-y:auto;line-height:1.65}
.empty-state{color:#1e3a55;font-size:.875rem;padding:3rem 0;text-align:center}
.modal-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:100;display:flex;align-items:center;justify-content:center}
.modal{background:linear-gradient(150deg,#0e1a2e,#0c1828);border:1px solid #182a45;border-radius:16px;padding:1.75rem;width:420px;max-width:calc(100vw - 2rem);box-shadow:0 24px 64px rgba(0,0,0,.7)}
.modal h3{margin:0 0 1.2rem;font-size:1.05rem;font-weight:700;color:#f0f6ff}
.modal label{display:block;font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.07em;margin:.85rem 0 .3rem;color:#4a6a8a}
.modal input,.modal select{width:100%;padding:.6rem .85rem;border-radius:8px;border:1px solid #182a45;background:#070d1a;color:#dce8f8;font-size:.88rem;transition:border-color .2s;user-select:text}
.modal input:focus,.modal select:focus{outline:none;border-color:#2a5aad;box-shadow:0 0 0 3px rgba(59,130,246,.08)}
.modal select option{background:#0c1828}
.modal-actions{display:flex;gap:.5rem;margin-top:1.4rem;justify-content:flex-end}
.modal-actions button{padding:.5rem 1.1rem;border:0;border-radius:8px;font-size:.85rem;font-weight:600;cursor:pointer}
.modal-err{color:#f87171;font-size:.8rem;margin-top:.6rem;min-height:1rem}
.token-list{margin-top:1rem}
.token-row{display:flex;align-items:center;justify-content:space-between;padding:.5rem .7rem;border:1px solid #182a45;border-radius:8px;margin-bottom:.4rem;font-size:.83rem}
.token-row span{color:#8eafd4}
.token-row button{border:0;background:rgba(239,68,68,.15);color:#f87171;border-radius:5px;padding:.22rem .55rem;font-size:.75rem;cursor:pointer}
.token-row button:hover{background:rgba(239,68,68,.28)}

.img-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:.75rem}
.icard{background:linear-gradient(150deg,#0d1929,#0b1623);border:1px solid #182a45;
  border-radius:13px;padding:.95rem 1rem;transition:border-color .2s}
.icard:hover{border-color:#2a4060}
.icard-tags{font-weight:600;color:#e8f2ff;font-size:.85rem;margin-bottom:.2rem;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.icard-tag-none{color:#3a5a7a;font-style:italic}
.icard-id{color:#3a5a7a;font-size:.68rem;font-family:ui-monospace,monospace;margin-bottom:.55rem}
.icard-meta{display:flex;justify-content:space-between;font-size:.72rem;color:#4a6a8a;margin-bottom:.6rem}
.icard-footer{display:flex;align-items:center;justify-content:space-between;
  padding-top:.6rem;border-top:1px solid #0d1929}
.badge-used{font-size:.67rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;
  background:rgba(34,197,94,.12);color:#4ade80;border-radius:5px;padding:.2rem .45rem}
.badge-unused{font-size:.67rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;
  background:rgba(100,116,139,.1);color:#3a5a7a;border-radius:5px;padding:.2rem .45rem}
.b-img-del{background:linear-gradient(135deg,#7f1d1d,#ef4444);font-size:.72rem;padding:.3rem .6rem}

.subtabs{display:flex;gap:.35rem;margin-bottom:1.25rem;padding-bottom:.85rem;border-bottom:1px solid #182a45}
.subtab{padding:.42rem 1rem;border:1px solid #182a45;border-radius:8px;background:0;
  color:#3a5a7a;cursor:pointer;font-size:.82rem;font-weight:500;transition:all .15s}
.subtab:hover{color:#8eafd4;border-color:#2a4060}
.subtab.active{background:linear-gradient(135deg,#1e3a8a,#3b82f6);color:#fff;border-color:transparent}
.upd-card{background:linear-gradient(150deg,#0d1929,#0b1623);border:1px solid #182a45;
  border-radius:13px;padding:1.2rem 1.35rem;max-width:520px}
.upd-row{display:flex;justify-content:space-between;align-items:center;font-size:.82rem;
  padding:.32rem 0;border-bottom:1px solid #0a1520}
.upd-row:last-child{border-bottom:0}
.upd-row span:first-child{color:#4a6a8a;font-weight:500}
.upd-row span:last-child{color:#8eafd4;text-align:right;max-width:70%;word-break:break-all}

.update-badge{background:linear-gradient(135deg,#166534,#16a34a);color:#fff;border:0;
  border-radius:7px;padding:.35rem .8rem;cursor:pointer;font-size:.78rem;font-weight:600;
  letter-spacing:.01em;animation:pulse-upd 2.5s ease-in-out infinite}
@keyframes pulse-upd{0%,100%{box-shadow:0 0 0 0 rgba(34,197,94,.5)}
  50%{box-shadow:0 0 0 6px rgba(34,197,94,.0)}}
.update-badge:hover{filter:brightness(1.15)}

#view-konsole{margin:-1.5rem -1.75rem;height:calc(100vh - 95px);display:flex;flex-direction:column}
.konsole-bar{display:flex;align-items:center;gap:.5rem;padding:.55rem 1.25rem;
  background:#070d1a;border-bottom:1px solid #182a45;flex-wrap:wrap}
.konsole-bar span{font-size:.72rem;color:#3a5a7a}
#console-term{flex:1;min-height:0}
/* ── Server ────────────────────────────────────────────── */
.srv-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:.75rem}
.srvcard{background:linear-gradient(150deg,#0e1a2e,#0c1828);border:1px solid #182a45;
  border-radius:12px;padding:1rem;display:flex;flex-direction:column;gap:.5rem}
.srvcard-name{font-weight:700;font-size:.97rem;color:#dce8f8}
.srvcard-host{font-size:.75rem;color:#4a6a8a}
.srvcard-status{font-size:.7rem;display:inline-flex;align-items:center;gap:.3rem;
  border-radius:20px;padding:.15rem .5rem;width:fit-content}
.srvcard-status.online{background:rgba(34,197,94,.12);color:#4ade80}
.srvcard-status.offline{background:rgba(239,68,68,.1);color:#f87171}
.srvcard-status.checking{background:rgba(251,191,36,.1);color:#fbbf24}
.srvcard-actions{display:flex;gap:.4rem;margin-top:.2rem;flex-wrap:wrap}
/* Server modal */
.srv-modal-row{display:flex;flex-direction:column;gap:.3rem;margin-bottom:.7rem}
.srv-modal-row label{font-size:.72rem;font-weight:700;text-transform:uppercase;
  letter-spacing:.06em;color:#4a6a8a}
.srv-modal-row input,.srv-modal-row select,.srv-modal-row textarea{
  background:#070d1a;border:1px solid #182a45;border-radius:8px;
  color:#dce8f8;padding:.55rem .7rem;font-size:.85rem;width:100%;
  transition:border-color .2s;resize:vertical}
.srv-modal-row input:focus,.srv-modal-row select:focus,.srv-modal-row textarea:focus{
  outline:none;border-color:#2a5aad}
</style></head><body>

<!-- Token / Registry Modal -->
<div id="token-modal" class="modal-backdrop" style="display:none" onclick="if(event.target===this)closeTokenModal()">
  <div class="modal" style="width:480px">
    <div style="display:flex;gap:.5rem;margin-bottom:1.2rem">
      <button id="mtab-tok" onclick="switchMtab('tok')" style="flex:1;padding:.45rem;border-radius:7px;border:0;font-size:.82rem;font-weight:600;cursor:pointer;background:linear-gradient(135deg,#1d4ed8,#3b82f6);color:#fff">Import-Tokens</button>
      <button id="mtab-reg" onclick="switchMtab('reg')" style="flex:1;padding:.45rem;border-radius:7px;border:0;font-size:.82rem;font-weight:600;cursor:pointer;background:#0e1e35;color:#7a9ac0;border:1px solid #1a3050">Registry-Login</button>
    </div>

    <!-- Tab: Import-Tokens -->
    <div id="mtab-tok-panel">
      <div style="font-size:.78rem;color:#4a6a8a;margin-bottom:.85rem">Bearer-Token für HTTP-Downloads (compose-Datei aus privatem Repo holen)</div>
      <label>Token-Name</label>
      <input type="text" id="tok-name" placeholder="z.B. github oder gitea">
      <label>Token-Wert</label>
      <input type="password" id="tok-value" placeholder="ghp_… oder glpat-…">
      <div class="modal-err" id="tok-err"></div>
      <div class="modal-actions">
        <button style="background:linear-gradient(135deg,#166534,#22c55e);color:#fff" onclick="saveToken()">Token speichern</button>
      </div>
      <div class="token-list" id="token-list"></div>
    </div>

    <!-- Tab: Registry-Login -->
    <div id="mtab-reg-panel" style="display:none">
      <div style="font-size:.78rem;color:#4a6a8a;margin-bottom:.85rem">Docker-Registry-Zugangsdaten für <code style="background:#0a1220;padding:.1rem .4rem;border-radius:4px;color:#60a5fa">docker compose pull</code></div>
      <label>Registry</label>
      <input type="text" id="reg-url" placeholder="ghcr.io  oder  registry.example.com">
      <label>Benutzername</label>
      <input type="text" id="reg-user" placeholder="Benutzername">
      <label>Passwort / Token</label>
      <input type="password" id="reg-pass" placeholder="ghp_… oder Passwort">
      <div class="modal-err" id="reg-err"></div>
      <div class="modal-actions">
        <button style="background:linear-gradient(135deg,#166534,#22c55e);color:#fff" onclick="saveRegistry()">Registry speichern</button>
      </div>
      <div class="token-list" id="registry-list"></div>
    </div>

    <div style="margin-top:1rem;text-align:right">
      <button style="background:#0e1e35;color:#7a9ac0;border:1px solid #1a3050;padding:.45rem 1rem;border-radius:7px;cursor:pointer;font-size:.82rem" onclick="closeTokenModal()">Schließen</button>
    </div>
  </div>
</div>

<!-- Import Modal -->
<div id="import-modal" class="modal-backdrop" style="display:none" onclick="if(event.target===this)closeImportDialog()">
  <div class="modal">
    <h3>⬇ Stack importieren</h3>
    <label>URL zur docker-compose.yaml</label>
    <input type="text" id="imp-url" placeholder="https://raw.githubusercontent.com/…/docker-compose.yaml">
    <label>Stack-Name</label>
    <input type="text" id="imp-name" placeholder="mein-stack">
    <label>Token (optional)</label>
    <select id="imp-token">
      <option value="">— kein Token —</option>
    </select>
    <div class="modal-err" id="imp-err"></div>
    <div class="modal-actions">
      <button style="background:#0e1e35;color:#7a9ac0;border:1px solid #1a3050" onclick="closeImportDialog()">Abbrechen</button>
      <button id="imp-btn" style="background:linear-gradient(135deg,#1d4ed8,#3b82f6);color:#fff" onclick="doImport()">Importieren</button>
    </div>
  </div>
</div>

<header>
  <div class="logo">🐳 dock<span>pilot</span></div>
  <div class="right">
    <span id="meta"></span>
    <button id="update-badge" class="update-badge" style="display:none" onclick="switchTab('wartung');switchWartungTab('update')">↑ Update verfügbar</button>
    <form method="post" action="/logout"><button class="hbtn">Logout</button></form>
  </div>
</header>
<div class="tabs">
  <button class="tab active" onclick="switchTab('containers')" id="tab-containers">Container</button>
  <button class="tab" onclick="switchTab('stacks')" id="tab-stacks">Stacks</button>
  <button class="tab" onclick="switchTab('wartung')" id="tab-wartung">Wartung</button>
  <button class="tab" onclick="switchTab('server')" id="tab-server">Server</button>
  <button class="tab" onclick="switchTab('konsole')" id="tab-konsole">Konsole</button>
</div>
<main>

<div id="view-containers">
  <section class="cards" id="host"></section>
  <div id="container-grid"><div class="muted" style="padding:1.5rem 0">lädt…</div></div>
</div>

<div id="view-stacks" style="display:none">
  <div style="display:flex;gap:.5rem;margin-bottom:1rem;flex-wrap:wrap">
    <button class="tbtn" style="background:linear-gradient(135deg,#1e3a8a,#3b82f6)" onclick="openImportDialog()">⬇ Stack importieren</button>
    <button class="tbtn" style="background:linear-gradient(135deg,#1e293b,#334155)" onclick="openTokenModal('reg')">🔑 Registry-Login</button>
    <button class="tbtn" style="background:linear-gradient(135deg,#1e293b,#334155);opacity:.8" onclick="openTokenModal('tok')">Import-Tokens</button>
  </div>
  <div id="scard-grid" class="scard-grid"><div class="empty-state">lädt…</div></div>
  <div class="stack-editor-panel" id="stack-editor" style="display:none">
    <div class="stack-toolbar">
      <strong id="editor-title"></strong>
      <button class="tbtn b-deploy" onclick="stackAction('up')">▶ Deploy</button>
      <button class="tbtn b-pull" onclick="stackAction('pull')">⬇ Pull</button>
      <button class="tbtn b-logs" onclick="stackAction('logs')">≡ Logs</button>
      <button class="tbtn b-down" onclick="stackAction('down')">■ Down</button>
      <button class="tbtn b-save" onclick="saveStack()">↑ Speichern</button>
      <button class="tbtn b-del" onclick="deleteStack()">✕ Löschen</button>
      <button class="tbtn" style="background:#0e1e35;color:#4a6a8a;border:1px solid #182a45" onclick="closeEditor()">✕</button>
    </div>
    <textarea class="editor" id="compose-editor" spellcheck="false"></textarea>
    <div class="output-box" id="stack-output" style="display:none"></div>
  </div>
</div>

<div id="view-wartung" style="display:none">
  <div class="subtabs">
    <button class="subtab active" id="subtab-images" onclick="switchWartungTab('images')">Images</button>
    <button class="subtab" id="subtab-update" onclick="switchWartungTab('update')">Self-Update</button>
  </div>

  <div id="wartung-images">
    <div style="display:flex;gap:.75rem;align-items:center;margin-bottom:1rem;flex-wrap:wrap">
      <button class="tbtn b-del" onclick="pruneImages()">🗑 Ungenutzte aufräumen</button>
      <span id="img-meta" style="font-size:.78rem;color:#4a6a8a"></span>
    </div>
    <div id="img-grid" class="img-grid"><div class="empty-state">lädt…</div></div>
  </div>

  <div id="wartung-update" style="display:none">
    <div class="upd-card">
      <div style="font-size:.78rem;color:#4a6a8a;margin-bottom:1rem">DockPilot aktualisiert sich selbst durch Neuerstellung des eigenen Containers. Der Dienst ist dabei kurz (~5 Sek.) nicht erreichbar.</div>
      <div class="upd-row"><span>Image</span><span id="upd-image">–</span></div>
      <div class="upd-row"><span>Letzte Prüfung</span><span id="upd-lastcheck">–</span></div>
      <div class="upd-row"><span>Status</span><span id="upd-status">–</span></div>
      <div style="display:flex;gap:.5rem;margin-top:1.1rem;flex-wrap:wrap">
        <button id="check-update-btn" class="tbtn" style="background:linear-gradient(135deg,#1e293b,#334155)" onclick="checkForUpdate()">↻ Update prüfen</button>
        <button id="apply-update-btn" class="tbtn update-badge" style="display:none" onclick="applyUpdate()">↑ Update installieren</button>
      </div>
    </div>
  </div>
</div>

<div id="view-server" style="display:none">
  <div style="display:flex;gap:.5rem;align-items:center;margin-bottom:1rem;flex-wrap:wrap">
    <button class="tbtn" style="background:linear-gradient(135deg,#1e3a8a,#3b82f6)" onclick="openAddServerModal('ssh')">+ SSH-Server</button>
    <button class="tbtn" style="background:linear-gradient(135deg,#6d28d9,#a78bfa)" onclick="openAddServerModal('agent')">+ Agent einladen</button>
  </div>
  <div id="srv-grid" class="srv-grid"><div class="empty-state">lädt…</div></div>
</div>

<div id="view-konsole" style="display:none">
  <div class="konsole-bar">
    <span id="konsole-status">● Nicht verbunden</span>
    <select id="konsole-server-select" style="background:#0e1a2e;border:1px solid #182a45;color:#dce8f8;border-radius:6px;padding:.25rem .5rem;font-size:.75rem;cursor:pointer" onchange="onServerSelectChange()">
      <option value="">Lokal (dieser Server)</option>
    </select>
    <button class="tbtn" id="konsole-reconnect" style="display:none;background:linear-gradient(135deg,#1e3a8a,#3b82f6);font-size:.72rem;padding:.28rem .6rem" onclick="connectConsole()">↺ Neu verbinden</button>
  </div>
  <div id="console-term"></div>
</div>

<!-- Add Server Modal -->
<div id="add-server-modal" class="modal-backdrop" style="display:none" onclick="if(event.target===this)closeAddServerModal()">
  <div class="modal" style="width:480px;max-height:90vh;overflow-y:auto">
    <h3 id="srv-modal-title" style="margin:0 0 1rem;font-size:1.05rem;color:#dce8f8">Server hinzufügen</h3>
    <!-- SSH fields -->
    <div id="srv-ssh-fields">
      <div class="srv-modal-row"><label>Name</label><input id="srv-name" type="text" placeholder="Mein Server"></div>
      <div class="srv-modal-row"><label>Host / IP</label><input id="srv-host" type="text" placeholder="192.168.1.100"></div>
      <div style="display:flex;gap:.5rem">
        <div class="srv-modal-row" style="flex:1"><label>Port</label><input id="srv-port" type="number" value="22"></div>
        <div class="srv-modal-row" style="flex:2"><label>Benutzer</label><input id="srv-user" type="text" placeholder="root"></div>
      </div>
      <div class="srv-modal-row">
        <label>Authentifizierung</label>
        <select id="srv-auth-type" onchange="onAuthTypeChange()">
          <option value="key">SSH-Schlüssel (empfohlen)</option>
          <option value="password">Passwort</option>
        </select>
      </div>
      <div id="srv-key-row" class="srv-modal-row">
        <label>Privater SSH-Schlüssel</label>
        <textarea id="srv-ssh-key" rows="5" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----&#10;..."></textarea>
      </div>
      <div id="srv-pw-row" class="srv-modal-row" style="display:none">
        <label>Passwort</label>
        <input id="srv-password" type="password">
      </div>
    </div>
    <!-- Agent fields -->
    <div id="srv-agent-fields" style="display:none">
      <div class="srv-modal-row"><label>Agent-Name</label><input id="srv-agent-name" type="text" placeholder="mein-server-02"></div>
      <div id="srv-agent-token-box" style="display:none">
        <label>Einladungs-Token</label>
        <div style="background:#060c18;border:1px solid #182a45;border-radius:8px;padding:.6rem .85rem;
          font-family:monospace;font-size:.82rem;color:#60a5fa;word-break:break-all;user-select:text;margin-top:.2rem"
          id="srv-agent-token-val"></div>
        <div style="font-size:.74rem;color:#3a5a7a;margin-top:.4rem;line-height:1.5">
          Diesen Token beim Setup des Agent-Servers eingeben (Agent-Modus → Hub-Verbindung).
        </div>
      </div>
      <div id="srv-agent-token-loading" style="font-size:.82rem;color:#4a6a8a;padding:.5rem 0">⟳ Generiere Token…</div>
    </div>
    <div id="srv-add-err" style="color:#f87171;font-size:.8rem;min-height:1rem;margin:.3rem 0"></div>
    <div style="display:flex;gap:.5rem;margin-top:.5rem">
      <button class="tbtn" id="srv-save-btn" style="flex:1;background:linear-gradient(135deg,#1e3a8a,#3b82f6)" onclick="doAddServer()">Speichern</button>
      <button class="tbtn" id="srv-done-btn" style="flex:1;background:linear-gradient(135deg,#166534,#22c55e);display:none" onclick="closeAddServerModal()">Fertig ✓</button>
      <button class="tbtn" style="background:#0e1e35;color:#4a6a8a;border:1px solid #182a45" onclick="closeAddServerModal()">Abbrechen</button>
    </div>
  </div>
</div>

</main>
<div id="toast"></div>
<script>
const fmtBytes=b=>{if(b==null)return '–';const u=['B','KB','MB','GB','TB'];let i=0;b=+b;
while(b>=1024&&i<u.length-1){b/=1024;i++}return b.toFixed(b<10&&i>0?1:0)+u[i]};
function toast(msg,err){const t=document.getElementById('toast');t.textContent=msg;
t.className=err?'err show':'show';setTimeout(()=>t.className=err?'err':'',2800)}
function bar(pct,cls){const p=pct==null?0:Math.min(100,pct);
return `<span class="bar ${cls}"><i style="width:${p}%"></i></span><span class="pct">${pct==null?'–':pct+'%'}</span>`}
const fmtUp=s=>{if(s==null)return '–';const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);
return d?`${d}d ${h}h`:(h?`${h}h ${m}m`:`${m}m`)};
function gauge(lbl,pct,val,sub){const p=pct==null?0:Math.min(100,pct);
const g=p>90?'linear-gradient(90deg,#991b1b,#f87171)':p>75?'linear-gradient(90deg,#854d0e,#fbbf24)':'linear-gradient(90deg,#1d4ed8,#60a5fa)';
return `<div class="card"><div class="lbl">${lbl}</div><div class="val">${val}</div>
<div class="sub">${sub}</div><div class="bar2"><i style="width:${p}%;background:${g}"></i></div></div>`}

let activeTab='containers',activeWartungTab='images';
function switchTab(tab){
  activeTab=tab;
  ['containers','stacks','wartung','server','konsole'].forEach(t=>{
    document.getElementById('view-'+t).style.display=tab===t?'':'none';
    document.getElementById('tab-'+t).classList.toggle('active',tab===t);
  });
  if(tab==='stacks')loadStacks();
  if(tab==='wartung'){
    if(activeWartungTab==='images')loadImages();
    else loadUpdateStatus();
  }
  if(tab==='server')loadServers();
  if(tab==='konsole')initConsole();
}
function switchWartungTab(sub){
  activeWartungTab=sub;
  document.getElementById('wartung-images').style.display=sub==='images'?'':'none';
  document.getElementById('wartung-update').style.display=sub==='update'?'':'none';
  document.getElementById('subtab-images').classList.toggle('active',sub==='images');
  document.getElementById('subtab-update').classList.toggle('active',sub==='update');
  if(sub==='images')loadImages();
  if(sub==='update')loadUpdateStatus();
}

let busy={},sz={},last=[];
async function loadSizes(){try{const r=await fetch('/api/sizes');if(r.ok){sz=await r.json();render(last)}}catch(e){}}
async function loadHost(){try{const r=await fetch('/api/host');if(!r.ok)return;const h=await r.json();
  const d=h.disk,dk=h.docker;let c='';
  c+=gauge('CPU',h.cpu,h.cpu==null?'–':h.cpu+'%',`${h.cpus} Kerne · Load ${h.load?h.load[0].toFixed(2):'–'}`);
  c+=gauge('RAM',h.mem_pct,h.mem_pct==null?'–':h.mem_pct+'%',`${fmtBytes(h.mem_used)} / ${fmtBytes(h.mem_total)}`);
  if(d){const p=Math.round(d.used/d.total*100);c+=gauge('Festplatte',p,p+'%',`${fmtBytes(d.used)} / ${fmtBytes(d.total)} · frei ${fmtBytes(d.free)}`)}
  c+=`<div class="card"><div class="lbl">System</div><div class="val" style="font-size:1.15rem">${fmtUp(h.uptime)}</div><div class="sub">Uptime</div></div>`;
  if(dk){const tot=(dk.images||0)+(dk.containers||0)+(dk.volumes||0)+(dk.build_cache||0);
    c+=`<div class="card"><div class="lbl">Docker-Speicher</div><div class="val" style="font-size:1.25rem">${fmtBytes(tot)}</div>
    <div class="dk"><span>Images (${dk.images_count})</span><span>${fmtBytes(dk.images)}</span></div>
    <div class="dk"><span>Container</span><span>${fmtBytes(dk.containers)}</span></div>
    <div class="dk"><span>Volumes</span><span>${fmtBytes(dk.volumes)}</span></div>
    <div class="dk"><span>Build-Cache</span><span>${fmtBytes(dk.build_cache)}</span></div></div>`}
  document.getElementById('host').innerHTML=c;
}catch(e){}}
async function act(id,action,name){
  if(action==='update'&&!confirm(`"${name}" updaten?\\nImage wird neu gezogen und Container neu erstellt.`))return;
  busy[id]=true;render(last);
  try{const r=await fetch(`/api/containers/${id}/${action}`,{method:'POST'});
    if(r.status===401){location.href='/login';return}
    const j=await r.json().catch(()=>({}));
    r.ok?toast(`${action} ok: ${name}`):toast('Fehler: '+(j.detail||r.status),true);
  }catch(e){toast('Fehler: '+e,true)}
  busy[id]=false;await load();
}
function getOrder(){try{return JSON.parse(localStorage.getItem('dp_order'))||{}}catch{return {}}}
function saveOrder(){
  const o={};
  document.querySelectorAll('.ccard-grid').forEach(g=>{
    o[g.dataset.group]=[...g.querySelectorAll('.ccard')].map(c=>c.dataset.name);
  });
  localStorage.setItem('dp_order',JSON.stringify(o));
}
function getStackOrder(){try{return JSON.parse(localStorage.getItem('dp_stack_order'))||[]}catch{return[]}}
function saveStackOrder(){
  const o=[...document.querySelectorAll('#container-grid>.group-section')].map(s=>s.dataset.stack);
  localStorage.setItem('dp_stack_order',JSON.stringify(o));
}
let dragSrc=null,dragStack=null;
function initDrag(){
  document.querySelectorAll('.ccard').forEach(card=>{
    card.addEventListener('dragstart',function(e){
      dragSrc=this;e.dataTransfer.effectAllowed='move';
      e.dataTransfer.setData('text/plain',this.dataset.name);
      setTimeout(()=>this.classList.add('dragging'),0);
    });
    card.addEventListener('dragend',function(){
      this.classList.remove('dragging');
      document.querySelectorAll('.ccard').forEach(c=>c.classList.remove('drag-over'));
    });
    card.addEventListener('dragover',function(e){
      e.preventDefault();e.dataTransfer.dropEffect='move';
      this.classList.add('drag-over');
    });
    card.addEventListener('dragleave',function(){this.classList.remove('drag-over')});
    card.addEventListener('drop',function(e){
      e.preventDefault();this.classList.remove('drag-over');
      if(!dragSrc||dragSrc===this)return;
      const tp=this.closest('.ccard-grid'),sp=dragSrc.closest('.ccard-grid');
      const all=[...tp.querySelectorAll('.ccard')];
      const di=all.indexOf(this);
      const si=all.indexOf(dragSrc);
      if(sp===tp){if(si<di)tp.insertBefore(dragSrc,this.nextSibling);else tp.insertBefore(dragSrc,this);}
      else{tp.insertBefore(dragSrc,this);}
      saveOrder();
    });
  });
}
function initStackDrag(){
  document.querySelectorAll('.group-section').forEach(sec=>{
    sec.addEventListener('dragstart',function(e){
      if(e.target.closest('.ccard'))return;
      dragStack=this;e.dataTransfer.effectAllowed='move';
      e.dataTransfer.setData('text/plain','stack');
      setTimeout(()=>this.classList.add('stack-dragging'),0);
    });
    sec.addEventListener('dragend',function(){
      this.classList.remove('stack-dragging');
      document.querySelectorAll('.group-section').forEach(s=>s.classList.remove('stack-drag-over'));
      dragStack=null;
    });
    sec.addEventListener('dragover',function(e){
      if(!dragStack||dragStack===this)return;
      e.preventDefault();e.dataTransfer.dropEffect='move';
      this.classList.add('stack-drag-over');
    });
    sec.addEventListener('dragleave',function(e){
      if(!e.relatedTarget||!this.contains(e.relatedTarget))this.classList.remove('stack-drag-over');
    });
    sec.addEventListener('drop',function(e){
      this.classList.remove('stack-drag-over');
      if(!dragStack||dragStack===this)return;
      e.preventDefault();e.stopPropagation();
      const p=this.parentNode;
      const all=[...p.querySelectorAll(':scope>.group-section')];
      const di=all.indexOf(this),si=all.indexOf(dragStack);
      if(si<di)p.insertBefore(dragStack,this.nextSibling);else p.insertBefore(dragStack,this);
      saveStackOrder();
    });
  });
}
function renderCard(c){
  const b=busy[c.id];const p=v=>v==null?0:Math.min(100,v);
  const stats=c.running
    ?`<div class="ccard-stat"><span class="sl">CPU</span><span class="sbar cpu"><i style="width:${p(c.cpu)}%"></i></span><span class="sv">${c.cpu==null?'–':c.cpu+'%'}</span></div>
      <div class="ccard-stat"><span class="sl">RAM</span><span class="sbar mem"><i style="width:${p(c.mem)}%"></i></span><span class="sv">${c.mem==null?'–':c.mem+'%'}</span></div>`:'';
  const upd=`<button class="b-update" ${b?'disabled':''} onclick="act('${c.id}','update','${c.name}')">${b?'<span class=spin>⟳</span>':'Update'}</button>`;
  const acts=c.running
    ?`<button class="b-stop" ${b?'disabled':''} onclick="act('${c.id}','stop','${c.name}')">Stop</button>
       <button class="b-restart" ${b?'disabled':''} onclick="act('${c.id}','restart','${c.name}')">Restart</button>${upd}`
    :`<button class="b-start" ${b?'disabled':''} onclick="act('${c.id}','start','${c.name}')">Start</button>${upd}`;
  return `<div class="ccard" draggable="true" data-id="${c.id}" data-name="${c.name}">
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:.4rem;margin-bottom:.5rem">
      <div style="min-width:0;flex:1">
        <div style="display:flex;align-items:center;gap:.35rem;margin-bottom:.15rem">
          <span class="dot ${c.running?'up':'down'}"></span>
          <span class="ccard-name">${c.name}</span>
        </div>
        <div class="ccard-img">${c.image}</div>
      </div>
      <span class="stxt ${c.running?'on':'off'}" style="font-size:.68rem;flex-shrink:0;padding-top:.1rem">${c.status}</span>
    </div>
    ${stats}
    <div class="ccard-acts">${acts}</div>
  </div>`;
}
function render(list){
  last=list;
  const grid=document.getElementById('container-grid');
  if(!list.length){grid.innerHTML='<div class="muted" style="padding:1.5rem 0">keine Container</div>';return}
  const order=getOrder();
  const stackOrder=getStackOrder();
  const groups={};
  list.forEach(c=>{const g=c.compose||'__solo__';if(!groups[g])groups[g]=[];groups[g].push(c);});
  const keys=Object.keys(groups).sort((a,b)=>{
    if(a==='__solo__')return 1;if(b==='__solo__')return -1;
    const ia=stackOrder.indexOf(a),ib=stackOrder.indexOf(b);
    if(ia<0&&ib<0)return a.localeCompare(b);if(ia<0)return 1;if(ib<0)return -1;return ia-ib;
  });
  grid.innerHTML=keys.map(g=>{
    const label=g==='__solo__'?'Einzeln':g;
    const grp=groups[g];
    const run=grp.filter(c=>c.running).length,total=grp.length;
    const dot=run===total?'up':run>0?'partial':'down';
    const saved=order[g]||[];
    const sorted=[...grp].sort((a,b)=>{
      const ia=saved.indexOf(a.name),ib=saved.indexOf(b.name);
      if(ia<0&&ib<0)return 0;if(ia<0)return 1;if(ib<0)return -1;return ia-ib;
    });
    return `<div class="group-section" draggable="true" data-stack="${g}">
      <div class="group-hdr"><span class="dot ${dot}"></span><span>${label}</span>` +
      `<span style="margin-left:auto;font-size:.68rem;color:#4a6a8a;font-weight:400;text-transform:none;letter-spacing:0">${run}/${total} aktiv</span></div>
      <div class="ccard-grid" data-group="${g}">${sorted.map(renderCard).join('')}</div></div>`;
  }).join('');
  const CARD_W=230,GAP=12,PAD=35;
  const mainEl=document.querySelector('main');
  const halfW=Math.floor((mainEl?mainEl.clientWidth:900)/2)-PAD;
  const maxCols=Math.max(1,Math.floor((halfW+GAP)/(CARD_W+GAP)));
  [...grid.querySelectorAll('.group-section')].forEach(sec=>{
    const cg=sec.querySelector('.ccard-grid');
    const n=Math.min(cg.querySelectorAll('.ccard').length,maxCols);
    if(n>0)cg.style.gridTemplateColumns=`repeat(${n},${CARD_W}px)`;
  });
  initDrag();
  initStackDrag();
}
async function load(){try{const r=await fetch('/api/containers');
  if(r.status===401){location.href='/login';return}
  const list=await r.json();render(list);
  if(activeTab==='stacks')loadStacks();
  if(activeTab==='wartung'&&activeWartungTab==='images')loadImages();
  const up=list.filter(c=>c.running).length;
  document.getElementById('meta').textContent=`${up} / ${list.length} aktiv`;
}catch(e){document.getElementById('meta').textContent='Verbindungsfehler'}}
load();setInterval(load,5000);
loadSizes();setInterval(loadSizes,30000);
loadHost();setInterval(loadHost,5000);
loadUpdateStatus();setInterval(loadUpdateStatus,60000);
window.addEventListener('resize',()=>render(last));

let currentStack=null;
const TMPL=`services:
  myservice:
    image:
    container_name:
    restart: unless-stopped
    networks:
      - proxy

networks:
  proxy:
    external: true
    name: proxy
`;
async function loadStacks(){
  try{
    const r=await fetch('/api/stacks');
    if(r.status===401){location.href='/login';return}
    const stacks=await r.json();
    const grid=document.getElementById('scard-grid');
    let html='';
    stacks.forEach(s=>{
      const ctrs=last.filter(c=>c.compose===s.name||(s.dir&&c.compose_dir===s.dir));
      const total=ctrs.length,run=ctrs.filter(c=>c.running).length;
      const dot=total===0?'down':run===total?'up':run>0?'partial':'down';
      const meta=total===0?'keine Container':`${run}/${total} laufen`;
      html+=`<div class="scard${currentStack===s.name?' active':''}" onclick="openStack('${s.name}')">
        <div class="scard-name">${s.name}</div>
        <div class="scard-meta"><span class="dot ${dot}"></span><span>${meta}</span></div>
        <div class="scard-acts">
          <button class="tbtn b-deploy" title="Deploy" onclick="event.stopPropagation();quickAction('${s.name}','up')">▶</button>
          <button class="tbtn b-down"   title="Down"   onclick="event.stopPropagation();quickAction('${s.name}','down')">■</button>
          <button class="tbtn b-pull"   title="Pull"   onclick="event.stopPropagation();quickAction('${s.name}','pull')">⬇</button>
          <button class="tbtn b-logs"   title="Logs"   onclick="event.stopPropagation();quickAction('${s.name}','logs')">≡</button>
        </div>
      </div>`;
    });
    html+=`<div class="scard scard-new" onclick="newStack()"><span style="font-size:1.3rem;line-height:1">+</span> Neuer Stack</div>`;
    grid.innerHTML=html;
  }catch(e){}
}
async function quickAction(name,action){
  const prev=currentStack;currentStack=name;
  document.getElementById('stack-editor').style.display='';
  document.getElementById('editor-title').textContent=name;
  document.getElementById('stack-output').style.display='';
  document.getElementById('stack-output').textContent='⟳ Läuft…';
  await stackAction(action);
  currentStack=prev||name;
}
function closeEditor(){
  document.getElementById('stack-editor').style.display='none';
  currentStack=null;loadStacks();
}
async function openStack(name){
  currentStack=name;
  try{
    const r=await fetch(`/api/stacks/${name}/file`);
    if(!r.ok)throw 0;
    const {content}=await r.json();
    document.getElementById('compose-editor').value=content;
    document.getElementById('editor-title').textContent=name;
    document.getElementById('stack-editor').style.display='';
    document.getElementById('stack-output').style.display='none';
    document.getElementById('stack-editor').scrollIntoView({behavior:'smooth',block:'nearest'});
    loadStacks();
  }catch(e){toast('Fehler beim Laden',true)}
}
async function saveStack(){
  const content=document.getElementById('compose-editor').value;
  const r=await fetch(`/api/stacks/${currentStack}/file`,{method:'PUT',
    headers:{'Content-Type':'application/json'},body:JSON.stringify({content})});
  if(r.ok){toast('Gespeichert');loadStacks()}
  else{const j=await r.json().catch(()=>({}));toast('Fehler: '+(j.detail||r.status),true)}
}
let stackBusy=false;
async function stackAction(action){
  if(stackBusy)return;
  if(action==='down'&&!confirm(`Stack "${currentStack}" herunterfahren?`))return;
  stackBusy=true;setStackBtns(true);showOutput('⟳  Läuft…');
  try{const r=await fetch(`/api/stacks/${currentStack}/${action}`,{method:'POST'});
    if(r.status===401){location.href='/login';return}
    const j=await r.json().catch(()=>({}));
    r.ok?(showOutput(j.out||'OK'),toast(action+' abgeschlossen'))
       :(showOutput(j.detail||'Fehler'),toast('Fehler: '+(j.detail||r.status),true));
  }catch(e){showOutput('Fehler: '+e);toast('Fehler',true)}
  stackBusy=false;setStackBtns(false);load();
}
function setStackBtns(d){document.querySelectorAll('.stack-toolbar button').forEach(b=>b.disabled=d)}
function showOutput(t){const el=document.getElementById('stack-output');
  el.textContent=t;el.style.display=t?'':'none';if(t)el.scrollTop=el.scrollHeight}
async function deleteStack(){
  if(!confirm(`Stack "${currentStack}" löschen?\\n(Container werden NICHT gestoppt)`))return;
  const r=await fetch(`/api/stacks/${currentStack}`,{method:'DELETE'});
  if(r.ok){toast(currentStack+' gelöscht');closeEditor();}
  else toast('Fehler beim Löschen',true);
}
function newStack(){
  const name=prompt('Stack-Name\\n(Buchstaben, Ziffern, - und _):');
  if(!name||!/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/.test(name)){if(name)toast('Ungültiger Name',true);return;}
  currentStack=name;
  document.getElementById('compose-editor').value=TMPL;
  document.getElementById('editor-title').textContent=name+' (neu)';
  document.getElementById('stack-editor').style.display='';
  document.getElementById('stack-output').style.display='none';
  document.getElementById('stack-editor').scrollIntoView({behavior:'smooth',block:'nearest'});
  loadStacks();toast('Anpassen und dann Speichern');
}

// ---- Token / Registry Modal ----
function switchMtab(tab){
  const isReg=tab==='reg';
  document.getElementById('mtab-tok-panel').style.display=isReg?'none':'';
  document.getElementById('mtab-reg-panel').style.display=isReg?'':'none';
  const active='background:linear-gradient(135deg,#1d4ed8,#3b82f6);color:#fff;border:0';
  const inactive='background:#0e1e35;color:#7a9ac0;border:1px solid #1a3050';
  document.getElementById('mtab-tok').style.cssText=`flex:1;padding:.45rem;border-radius:7px;font-size:.82rem;font-weight:600;cursor:pointer;${isReg?inactive:active}`;
  document.getElementById('mtab-reg').style.cssText=`flex:1;padding:.45rem;border-radius:7px;font-size:.82rem;font-weight:600;cursor:pointer;${isReg?active:inactive}`;
  if(isReg)refreshRegistryList();else refreshTokenList();
}
async function openTokenModal(tab){
  document.getElementById('tok-name').value='';
  document.getElementById('tok-value').value='';
  document.getElementById('tok-err').textContent='';
  document.getElementById('reg-url').value='';
  document.getElementById('reg-user').value='';
  document.getElementById('reg-pass').value='';
  document.getElementById('reg-err').textContent='';
  document.getElementById('token-modal').style.display='';
  switchMtab(tab||'tok');
}
function closeTokenModal(){document.getElementById('token-modal').style.display='none'}

async function refreshTokenList(){
  const r=await fetch('/api/tokens');
  const names=r.ok?await r.json():[];
  const el=document.getElementById('token-list');
  if(!names.length){el.innerHTML='<div style="font-size:.78rem;color:#3a5a7a;margin-top:.5rem">Noch keine Tokens gespeichert.</div>';return}
  el.innerHTML=names.map(n=>`<div class="token-row"><span>${n}</span><button onclick="deleteToken('${n}')">Löschen</button></div>`).join('');
}
async function saveToken(){
  const name=document.getElementById('tok-name').value.trim();
  const value=document.getElementById('tok-value').value.trim();
  const err=document.getElementById('tok-err');
  if(!name||!value){err.textContent='Name und Wert sind erforderlich.';return}
  if(!/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/.test(name)){err.textContent='Ungültiger Name (Buchstaben, Ziffern, - und _).';return}
  err.textContent='';
  const r=await fetch(`/api/tokens/${encodeURIComponent(name)}`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({value})});
  if(r.ok){document.getElementById('tok-name').value='';document.getElementById('tok-value').value='';toast('Token gespeichert');await refreshTokenList();}
  else{const j=await r.json().catch(()=>({}));err.textContent=j.detail||'Fehler'}
}
async function deleteToken(name){
  if(!confirm(`Token "${name}" löschen?`))return;
  const r=await fetch(`/api/tokens/${encodeURIComponent(name)}`,{method:'DELETE'});
  if(r.ok){toast('Token gelöscht');await refreshTokenList();}
  else toast('Fehler beim Löschen',true);
}

async function refreshRegistryList(){
  const r=await fetch('/api/registries');
  const regs=r.ok?await r.json():[];
  const el=document.getElementById('registry-list');
  if(!regs.length){el.innerHTML='<div style="font-size:.78rem;color:#3a5a7a;margin-top:.5rem">Noch keine Registries gespeichert.</div>';return}
  el.innerHTML=regs.map(reg=>`<div class="token-row"><span>${reg}</span><button onclick="deleteRegistry('${reg}')">Löschen</button></div>`).join('');
}
async function saveRegistry(){
  const registry=document.getElementById('reg-url').value.trim();
  const username=document.getElementById('reg-user').value.trim();
  const password=document.getElementById('reg-pass').value.trim();
  const err=document.getElementById('reg-err');
  if(!registry||!username||!password){err.textContent='Alle Felder sind erforderlich.';return}
  err.textContent='';
  const r=await fetch('/api/registries',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({registry,username,password})});
  if(r.ok){document.getElementById('reg-url').value='';document.getElementById('reg-user').value='';document.getElementById('reg-pass').value='';toast('Registry gespeichert');await refreshRegistryList();}
  else{const j=await r.json().catch(()=>({}));err.textContent=j.detail||'Fehler'}
}
async function deleteRegistry(reg){
  if(!confirm(`Registry "${reg}" entfernen?`))return;
  const r=await fetch(`/api/registries/${encodeURIComponent(reg)}`,{method:'DELETE'});
  if(r.ok){toast('Registry entfernt');await refreshRegistryList();}
  else toast('Fehler beim Löschen',true);
}

// ---- Import Dialog ----
async function openImportDialog(){
  document.getElementById('imp-url').value='';
  document.getElementById('imp-name').value='';
  document.getElementById('imp-err').textContent='';
  const r=await fetch('/api/tokens');
  const names=r.ok?await r.json():[];
  const sel=document.getElementById('imp-token');
  sel.innerHTML='<option value="">— kein Token —</option>'+names.map(n=>`<option value="${n}">${n}</option>`).join('');
  document.getElementById('import-modal').style.display='';
}
function closeImportDialog(){document.getElementById('import-modal').style.display='none'}
async function doImport(){
  const url=document.getElementById('imp-url').value.trim();
  const name=document.getElementById('imp-name').value.trim();
  const token=document.getElementById('imp-token').value;
  const err=document.getElementById('imp-err');
  const btn=document.getElementById('imp-btn');
  if(!url||!name){err.textContent='URL und Stack-Name sind erforderlich.';return}
  err.textContent='';btn.disabled=true;btn.textContent='⟳ Lädt…';
  try{
    const r=await fetch('/api/stacks/import',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({url,name,token})});
    const j=await r.json().catch(()=>({}));
    if(r.ok){closeImportDialog();toast(`"${name}" importiert`);loadStacks();}
    else{err.textContent=j.detail||'Fehler';btn.disabled=false;btn.textContent='Importieren';}
  }catch(e){err.textContent='Netzwerkfehler: '+e.message;btn.disabled=false;btn.textContent='Importieren';}
}

const fmtAgo=s=>{if(!s)return '–';const ms=Date.now()-new Date(s);const h=Math.floor(ms/3600000);if(h<24)return h+'h';const d=Math.floor(ms/86400000);return d+'d'};
async function loadImages(){
  try{
    const r=await fetch('/api/images');
    if(r.status===401){location.href='/login';return}
    const imgs=await r.json();
    const grid=document.getElementById('img-grid');
    const unused=imgs.filter(i=>!i.in_use).length;
    const total=imgs.length;
    document.getElementById('img-meta').textContent=`${total} Images · ${unused} ungenutzt`;
    if(!imgs.length){grid.innerHTML='<div class="empty-state">Keine Images gefunden</div>';return}
    grid.innerHTML=imgs.map(i=>{
      const tag=i.tags.length?i.tags.join(', '):'<span class="icard-tag-none">&lt;none&gt;</span>';
      const badge=i.in_use
        ?'<span class="badge-used">In Verwendung</span>'
        :'<span class="badge-unused">Ungenutzt</span>';
      const delBtn=i.in_use?'':`<button class="tbtn b-img-del" onclick="deleteImage('${i.id}','${i.tags[0]||i.short_id}')">✕</button>`;
      return `<div class="icard">
        <div class="icard-tags">${tag}</div>
        <div class="icard-id">${i.short_id}</div>
        <div class="icard-meta"><span>${fmtBytes(i.size)}</span><span>vor ${fmtAgo(i.created)}</span></div>
        <div class="icard-footer">${badge}${delBtn}</div>
      </div>`;
    }).join('');
  }catch(e){}
}
async function deleteImage(id,label){
  if(!confirm(`Image "${label}" löschen?`))return;
  try{
    const r=await fetch('/api/images/'+encodeURIComponent(id),{method:'DELETE'});
    const j=await r.json().catch(()=>({}));
    r.ok?toast('Image gelöscht'):toast('Fehler: '+(j.detail||r.status),true);
  }catch(e){toast('Fehler: '+e,true)}
  loadImages();
}
async function pruneImages(){
  if(!confirm('Alle ungenutzten Images löschen?'))return;
  try{
    const r=await fetch('/api/images/prune',{method:'POST'});
    const j=await r.json().catch(()=>({}));
    r.ok?toast(`${j.deleted} Images entfernt · ${fmtBytes(j.freed)} freigegeben`):toast('Fehler: '+(j.detail||r.status),true);
  }catch(e){toast('Fehler: '+e,true)}
  loadImages();
}

async function loadUpdateStatus(){
  try{
    const r=await fetch('/api/self/update');
    if(!r.ok)return;
    const s=await r.json();
    // Header badge
    const badge=document.getElementById('update-badge');
    if(badge)badge.style.display=s.update_available?'':'none';
    // Apply button inside panel
    const applyBtn=document.getElementById('apply-update-btn');
    if(applyBtn)applyBtn.style.display=s.update_available?'':'none';
    // Info card
    const img=document.getElementById('upd-image');
    const lc=document.getElementById('upd-lastcheck');
    const st=document.getElementById('upd-status');
    if(img)img.textContent=s.image_ref||'–';
    if(lc)lc.textContent=s.last_check?new Date(s.last_check*1000).toLocaleString():'Noch nicht geprüft';
    if(st){
      if(s.checking)st.textContent='Prüft…';
      else if(s.error)st.textContent='Fehler: '+s.error;
      else if(s.last_check===null)st.textContent='–';
      else if(s.update_available)st.textContent='Update verfügbar';
      else st.textContent='Aktuell';
    }
  }catch(e){}
}
async function checkForUpdate(){
  const btn=document.getElementById('check-update-btn');
  btn.disabled=true;btn.textContent='↻ Prüfe…';
  try{
    await fetch('/api/self/update/check',{method:'POST'});
    // Poll until checking is done (max 20s)
    for(let i=0;i<20;i++){
      await new Promise(r=>setTimeout(r,1000));
      const r=await fetch('/api/self/update');
      if(!r.ok)break;
      const s=await r.json();
      if(!s.checking){
        loadUpdateStatus();
        if(s.error)toast('Update-Check fehlgeschlagen: '+s.error,true);
        else if(s.update_available)toast('Update verfügbar! Klick auf "Update installieren".');
        else toast('Kein Update verfügbar — DockPilot ist aktuell.');
        break;
      }
    }
  }catch(e){toast('Fehler: '+e,true)}
  btn.disabled=false;btn.textContent='↻ Update prüfen';
}
async function applyUpdate(){
  if(!confirm('DockPilot jetzt auf die neueste Version aktualisieren?\\n\\nDer Container wird kurz neu gestartet — die Verbindung trennt sich für ~5 Sekunden.'))return;
  try{
    const r=await fetch('/api/self/update/apply',{method:'POST'});
    const j=await r.json().catch(()=>({}));
    r.ok?toast('Update gestartet — Seite lädt gleich neu…'):toast('Fehler: '+(j.detail||r.status),true);
    if(r.ok)setTimeout(()=>location.reload(),8000);
  }catch(e){toast('Fehler: '+e,true)}
}

/* ── Server-Verwaltung ───────────────────────────────── */
let _servers=[];
async function loadServers(){
  try{
    const r=await fetch('/api/servers');
    if(r.status===401){location.href='/login';return}
    _servers=r.ok?await r.json():[];
    renderServers();
    populateServerSelect();
  }catch(e){}
}
function renderServers(){
  const grid=document.getElementById('srv-grid');
  if(!_servers.length){
    grid.innerHTML='<div class="empty-state">Noch keine Server konfiguriert.<br>Verwende "+ SSH-Server" oder "+ Agent einladen" um zu starten.</div>';
    return;
  }
  grid.innerHTML=_servers.map(s=>{
    const isAgent=s.type==='agent';
    const hostLine=isAgent
      ?`<div class="srvcard-host" style="color:#a78bfa">🔌 DockPilot-Agent</div>`
      :`<div class="srvcard-host">${esc(s.username||'')}@${esc(s.host||'')}:${s.port||22}</div>`;
    const consolBtn=isAgent&&!s.url
      ?`<button class="tbtn" style="font-size:.72rem;padding:.25rem .55rem;background:#0e1e35;color:#3a5a7a;border:1px solid #182a45" disabled title="Agent noch nicht verbunden">▶ Konsole</button>`
      :`<button class="tbtn" style="font-size:.72rem;padding:.25rem .55rem;background:linear-gradient(135deg,#1e3a8a,#3b82f6)"
          onclick="openServerConsole('${s.id}','${esc(s.name)}')">▶ Konsole</button>`;
    return `<div class="srvcard">
      <div class="srvcard-name">${esc(s.name)}</div>
      ${hostLine}
      <div class="srvcard-status checking" id="srv-status-${s.id}">⟳ Prüfe…</div>
      <div class="srvcard-actions">
        ${consolBtn}
        <button class="tbtn" style="font-size:.72rem;padding:.25rem .55rem;background:#0e1e35;color:#4a6a8a;border:1px solid #182a45"
          onclick="testServer('${s.id}')">↻ Test</button>
        <button class="tbtn b-del" style="font-size:.72rem;padding:.25rem .55rem"
          onclick="deleteServer('${s.id}','${esc(s.name)}')">✕</button>
      </div>
    </div>`;
  }).join('');
  _servers.forEach(s=>testServer(s.id,true));
}
function esc(t){return String(t).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
async function testServer(id,silent){
  const el=document.getElementById('srv-status-'+id);
  if(el){el.className='srvcard-status checking';el.textContent='⟳ Prüfe…';}
  try{
    const r=await fetch('/api/servers/'+id+'/test',{method:'POST'});
    if(el){
      if(r.ok){el.className='srvcard-status online';el.textContent='● Online';}
      else{el.className='srvcard-status offline';el.textContent='● Offline';}
    }
    if(!silent&&!r.ok){const j=await r.json().catch(()=>({}));toast('Verbindung fehlgeschlagen: '+(j.detail||r.status),true);}
  }catch(e){if(el){el.className='srvcard-status offline';el.textContent='● Offline';}}
}
async function deleteServer(id,name){
  if(!confirm('Server "'+name+'" entfernen?'))return;
  const r=await fetch('/api/servers/'+id,{method:'DELETE'});
  r.ok?toast('Server entfernt'):toast('Fehler',true);
  loadServers();
}
function openServerConsole(id,name){
  const sel=document.getElementById('konsole-server-select');
  if(sel)sel.value=id;
  switchTab('konsole');
  if(_ws&&(_ws.readyState===WebSocket.OPEN||_ws.readyState===WebSocket.CONNECTING)){
    _ws.close();_ws=null;
  }
  initConsole();
}
let _addSrvType='ssh';
async function openAddServerModal(type){
  _addSrvType=type||'ssh';
  const isAgent=_addSrvType==='agent';
  document.getElementById('srv-modal-title').textContent=isAgent?'Agent einladen':'SSH-Server hinzufügen';
  document.getElementById('srv-ssh-fields').style.display=isAgent?'none':'';
  document.getElementById('srv-agent-fields').style.display=isAgent?'':'none';
  document.getElementById('srv-save-btn').style.display=isAgent?'none':'';
  document.getElementById('srv-done-btn').style.display='none';
  document.getElementById('srv-add-err').textContent='';
  if(!isAgent){
    document.getElementById('srv-name').value='';
    document.getElementById('srv-host').value='';
    document.getElementById('srv-port').value='22';
    document.getElementById('srv-user').value='';
    document.getElementById('srv-ssh-key').value='';
    document.getElementById('srv-password').value='';
    document.getElementById('srv-auth-type').value='key';
    onAuthTypeChange();
  } else {
    document.getElementById('srv-agent-name').value='';
    document.getElementById('srv-agent-token-box').style.display='none';
    document.getElementById('srv-agent-token-loading').style.display='';
    document.getElementById('add-server-modal').style.display='';
    // Generate invite token immediately
    try{
      const r=await fetch('/api/servers/agent-invite',{method:'POST',
        headers:{'Content-Type':'application/json'},body:JSON.stringify({name:'Neuer Agent'})});
      if(r.ok){
        const j=await r.json();
        document.getElementById('srv-agent-token-val').textContent=j.token;
        document.getElementById('srv-agent-token-box').style.display='';
        document.getElementById('srv-agent-token-loading').style.display='none';
        document.getElementById('srv-done-btn').style.display='';
        // Update server name from input if user types it
        document.getElementById('srv-agent-name').oninput=function(){
          if(j.id)fetch('/api/servers/'+j.id,{method:'PATCH',
            headers:{'Content-Type':'application/json'},body:JSON.stringify({name:this.value||'Agent'})}).catch(()=>{});
        };
        loadServers();
      }else{
        document.getElementById('srv-agent-token-loading').textContent='Fehler beim Generieren';
        document.getElementById('srv-done-btn').style.display='';
      }
    }catch(e){
      document.getElementById('srv-agent-token-loading').textContent='Netzwerkfehler';
      document.getElementById('srv-done-btn').style.display='';
    }
    return;
  }
  document.getElementById('add-server-modal').style.display='';
}
function closeAddServerModal(){document.getElementById('add-server-modal').style.display='none';loadServers();}
function onAuthTypeChange(){
  const t=document.getElementById('srv-auth-type').value;
  document.getElementById('srv-key-row').style.display=t==='key'?'':'none';
  document.getElementById('srv-pw-row').style.display=t==='password'?'':'none';
}
async function doAddServer(){
  const name=document.getElementById('srv-name').value.trim();
  const host=document.getElementById('srv-host').value.trim();
  const port=document.getElementById('srv-port').value||'22';
  const username=document.getElementById('srv-user').value.trim();
  const auth_type=document.getElementById('srv-auth-type').value;
  const err=document.getElementById('srv-add-err');
  if(!name||!host||!username){err.textContent='Name, Host und Benutzer erforderlich';return}
  const body={name,host,port:parseInt(port),username,auth_type,type:'ssh'};
  if(auth_type==='key')body.ssh_key=document.getElementById('srv-ssh-key').value.trim();
  else body.password=document.getElementById('srv-password').value;
  const r=await fetch('/api/servers',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const j=await r.json().catch(()=>({}));
  if(r.ok){closeAddServerModal();toast('Server "'+name+'" hinzugefügt');}
  else{err.textContent=j.detail||'Fehler beim Speichern';}
}
function populateServerSelect(){
  const sel=document.getElementById('konsole-server-select');
  if(!sel)return;
  const cur=sel.value;
  sel.innerHTML='<option value="">Lokal (dieser Server)</option>'+
    _servers.map(s=>{
      const isAgent=s.type==='agent';
      const label=isAgent?`${esc(s.name)} [Agent]`:`${esc(s.name)} (${esc(s.host)})`;
      const disabled=isAgent&&!s.url?'disabled title="Agent noch nicht verbunden"':'';
      return `<option value="${s.id}" ${disabled}>${label}</option>`;
    }).join('');
  if(cur)sel.value=cur;
}
function onServerSelectChange(){
  if(_ws&&(_ws.readyState===WebSocket.OPEN||_ws.readyState===WebSocket.CONNECTING)){
    _ws.close();_ws=null;
    if(_term)_term.write('\\r\\n\\x1b[33m[Server gewechselt – verbinde neu…]\\x1b[0m\\r\\n');
  }
  connectConsole();
}

/* ── Konsole ─────────────────────────────────────────── */
let _term=null, _ws=null, _fitAddon=null, _xtermLoaded=false;

function _loadXterm(cb){
  if(_xtermLoaded){cb();return;}
  const css=document.createElement('link');
  css.rel='stylesheet';
  css.href='https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css';
  document.head.appendChild(css);
  function loadScript(src,next,onerr){
    const s=document.createElement('script');
    s.src=src;s.onload=next;
    s.onerror=()=>onerr&&onerr(src);
    document.head.appendChild(s);
  }
  loadScript('https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.js',()=>{
    loadScript('https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.js',()=>{
      _xtermLoaded=true;cb();
    },(src)=>{
      toast('Konsole: xterm-addon-fit konnte nicht geladen werden (CDN erreichbar?)',true);
    });
  },(src)=>{
    toast('Konsole: xterm.js konnte nicht geladen werden (CDN erreichbar?)',true);
  });
}

function initConsole(){
  _loadXterm(()=>{
    if(_term)return;
    _term=new Terminal({
      cursorBlink:true,
      fontSize:14,
      fontFamily:'"Cascadia Code","Fira Mono","Consolas",monospace',
      theme:{background:'#0d1117',foreground:'#e6edf3',cursor:'#58a6ff',
             selectionBackground:'#264f78',
             black:'#0d1117',red:'#ff7b72',green:'#3fb950',yellow:'#d29922',
             blue:'#58a6ff',magenta:'#bc8cff',cyan:'#39c5cf',white:'#b1bac4',
             brightBlack:'#6e7681',brightRed:'#ffa198',brightGreen:'#56d364',
             brightYellow:'#e3b341',brightBlue:'#79c0ff',brightMagenta:'#d2a8ff',
             brightCyan:'#56d4dd',brightWhite:'#f0f6fc'},
      allowProposedApi:true,
    });
    _fitAddon=new FitAddon.FitAddon();
    _term.loadAddon(_fitAddon);
    _term.open(document.getElementById('console-term'));
    _fitAddon.fit();
    window.addEventListener('resize',()=>{if(_fitAddon)_fitAddon.fit();});
    _term.onResize(({cols,rows})=>{
      if(_ws&&_ws.readyState===WebSocket.OPEN)
        _ws.send(JSON.stringify({type:'resize',cols,rows}));
    });
    _term.onData(data=>{
      if(_ws&&_ws.readyState===WebSocket.OPEN)_ws.send(data);
    });
    connectConsole();
  });
}

function connectConsole(){
  if(_ws&&(_ws.readyState===WebSocket.OPEN||_ws.readyState===WebSocket.CONNECTING))return;
  const proto=location.protocol==='https:'?'wss':'ws';
  const sel=document.getElementById('konsole-server-select');
  const serverId=sel?sel.value:'';
  const url=serverId
    ?`${proto}://${location.host}/ws/remote-console/${serverId}`
    :`${proto}://${location.host}/ws/console`;
  _ws=new WebSocket(url);
  _ws.binaryType='arraybuffer';
  const status=document.getElementById('konsole-status');
  const reconnBtn=document.getElementById('konsole-reconnect');
  status.textContent='● Verbinde…';status.style.color='#d29922';
  reconnBtn.style.display='none';
  _ws.onopen=()=>{
    status.textContent='● Verbunden';status.style.color='#3fb950';
    if(_term&&_fitAddon){
      _fitAddon.fit();
      const{cols,rows}=_term;
      _ws.send(JSON.stringify({type:'resize',cols,rows}));
    }
  };
  _ws.onmessage=e=>{
    if(_term){
      if(e.data instanceof ArrayBuffer)_term.write(new Uint8Array(e.data));
      else _term.write(e.data);
    }
  };
  _ws.onclose=()=>{
    status.textContent='● Getrennt';status.style.color='#ff7b72';
    reconnBtn.style.display='';
    if(_term)_term.write('\\r\\n\\x1b[31m[Verbindung getrennt]\\x1b[0m\\r\\n');
  };
  _ws.onerror=()=>{
    status.textContent='● Fehler';status.style.color='#ff7b72';
    if(_term)_term.write('\\r\\n\\x1b[31m[WebSocket-Fehler]\\x1b[0m\\r\\n');
  };
}
</script></body></html>"""

AGENT_HTML = """<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>dockpilot · Agent</title><style>
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
  background:#070d1a;color:#dce8f8;display:flex;min-height:100vh;
  align-items:center;justify-content:center}
.wrap{width:480px;padding:1rem}
.logo{text-align:center;font-size:1.5rem;font-weight:700;margin-bottom:.4rem}
.logo span{color:#3b82f6}
.badge{display:inline-flex;align-items:center;gap:.4rem;background:rgba(59,130,246,.1);
  border:1px solid rgba(59,130,246,.25);border-radius:20px;padding:.3rem .8rem;
  font-size:.78rem;color:#60a5fa;margin-bottom:1.5rem}
.card{background:linear-gradient(150deg,#0e1a2e,#0c1828);border:1px solid #182a45;
  border-radius:16px;padding:1.75rem;box-shadow:0 20px 60px rgba(0,0,0,.5)}
.card h2{margin:0 0 .4rem;font-size:1rem;font-weight:700;color:#f0f6ff}
.row{display:flex;justify-content:space-between;align-items:center;padding:.55rem 0;
  border-bottom:1px solid #0e1a2e;font-size:.85rem}
.row:last-child{border-bottom:0}
.lbl{color:#4a6a8a}
.val{color:#dce8f8;font-family:monospace;font-size:.82rem;word-break:break-all;text-align:right;max-width:60%}
.val.ok{color:#4ade80}
.val.warn{color:#fbbf24}
</style></head>
<body><div class="wrap" style="text-align:center">
<div class="logo">🐳 dock<span>pilot</span></div>
<div style="margin:.4rem 0 1.2rem">
  <span class="badge">● Agent-Modus aktiv</span>
</div>
<div class="card" style="text-align:left">
  <h2>Agent-Status</h2>
  <div class="row"><span class="lbl">Modus</span><span class="val ok">Agent (Client)</span></div>
  <div class="row"><span class="lbl">Hub-Verbindung</span><span class="val" id="hub-status">Prüfe…</span></div>
  <div class="row"><span class="lbl">Hub-URL</span><span class="val" id="hub-url">–</span></div>
  <div class="row"><span class="lbl">Agent-Name</span><span class="val" id="agent-name">–</span></div>
  <div class="row"><span class="lbl">API-Endpunkt</span><span class="val ok">/api/*</span></div>
</div>
<div style="margin-top:1rem;font-size:.78rem;color:#3a5a7a">
  Dieser Server ist als Agent eingerichtet. Das vollständige Dashboard ist auf dem Hub-Server verfügbar.
</div>
</div>
<script>
async function loadStatus(){
  try{
    const r=await fetch('/api/setup/mode');
    if(!r.ok)return;
    const j=await r.json();
    document.getElementById('hub-url').textContent=j.hub_url||'–';
    document.getElementById('agent-name').textContent=j.agent_name||'–';
  }catch(e){}
}
loadStatus();
</script></body></html>"""

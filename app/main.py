import hashlib
import hmac
import os
import shutil
import time
from concurrent.futures import ThreadPoolExecutor

import docker
from fastapi import FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

USER = os.environ.get("DASH_USER", "admin")
PASSWORD = os.environ.get("DASH_PASSWORD", "changeme")
SECRET = os.environ.get("DASH_SECRET", "insecure-default-secret").encode()
SESSION_TTL = 7 * 24 * 3600  # 7 Tage
COOKIE = "dockpilot_session"

client = docker.DockerClient(base_url="unix://var/run/docker.sock")
app = FastAPI()


# ----------------------------- Auth -----------------------------
def make_token() -> str:
    ts = str(int(time.time()))
    sig = hmac.new(SECRET, ts.encode(), hashlib.sha256).hexdigest()
    return f"{ts}.{sig}"


def valid_token(token: str | None) -> bool:
    if not token or "." not in token:
        return False
    ts, sig = token.split(".", 1)
    expected = hmac.new(SECRET, ts.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return False
    try:
        return (time.time() - int(ts)) < SESSION_TTL
    except ValueError:
        return False


def require_auth(request: Request):
    if not valid_token(request.cookies.get(COOKIE)):
        raise HTTPException(status_code=401, detail="not authenticated")


# ----------------------------- Stats -----------------------------
def container_cpu_mem(c):
    """Zwei Stats-Frames lesen für korrekte CPU-Berechnung."""
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

    rx = tx = None
    try:
        nets = second.get("networks", {})
        rx = sum(n.get("rx_bytes", 0) for n in nets.values())
        tx = sum(n.get("tx_bytes", 0) for n in nets.values())
    except Exception:
        pass

    return {"cpu": cpu, "mem": mem_pct, "mem_used": mem_used,
            "mem_limit": mem_limit, "net_rx": rx, "net_tx": tx}


def serialize(c):
    running = c.status == "running"
    image = c.attrs["Config"]["Image"]
    compose = c.labels.get("com.docker.compose.project")
    data = {
        "id": c.short_id,
        "name": c.name,
        "image": image,
        "status": c.status,
        "running": running,
        "compose": compose,
        "cpu": None, "mem": None, "mem_used": None, "mem_limit": None,
        "net_rx": None, "net_tx": None,
    }
    if running:
        data.update(container_cpu_mem(c))
    return data


# ----------------------------- Update -----------------------------
def recreate_with_new_image(c):
    """Watchtower-Stil: Image neu ziehen + Container mit gleicher Config neu erstellen."""
    attrs = c.attrs
    cfg = attrs["Config"]
    host_cfg = attrs["HostConfig"]
    name = c.name
    image_ref = cfg["Image"]
    networks = attrs.get("NetworkSettings", {}).get("Networks", {})

    # Neues Image ziehen
    client.images.pull(image_ref)

    # Erstes Netzwerk + Aliase für create übernehmen, Rest danach connecten
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

    # Alten Container stoppen + entfernen
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

    # Weitere Netzwerke anhängen
    for net_name, ncfg in net_items[1:]:
        aliases = [a for a in (ncfg.get("Aliases") or []) if a != c.id[:12]]
        client.api.connect_container_to_network(new_id, net_name, aliases=aliases or None)

    client.api.start(new_id)
    return new_id


def _devices(devs):
    if not devs:
        return None
    out = []
    for d in devs:
        out.append(f"{d['PathOnHost']}:{d['PathInContainer']}:{d.get('CgroupPermissions', 'rwm')}")
    return out


# ----------------------------- Host-Statistik -----------------------------
HOST_ROOT = "/host" if os.path.isdir("/host") else "/"


def _cpu_times():
    with open("/proc/stat") as f:
        parts = f.readline().split()[1:]
    vals = [int(x) for x in parts]
    idle = vals[3] + (vals[4] if len(vals) > 4 else 0)  # idle + iowait
    return sum(vals), idle


def host_stats():
    # CPU über kurzes Intervall
    cpu = None
    try:
        t1, i1 = _cpu_times()
        time.sleep(0.25)
        t2, i2 = _cpu_times()
        dt, di = t2 - t1, i2 - i1
        if dt > 0:
            cpu = round((1 - di / dt) * 100, 1)
    except Exception:
        pass

    # RAM aus /proc/meminfo (kB)
    mem_total = mem_avail = None
    try:
        info = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, v = line.split(":", 1)
                info[k] = int(v.strip().split()[0]) * 1024
        mem_total = info.get("MemTotal")
        mem_avail = info.get("MemAvailable")
    except Exception:
        pass
    mem_used = (mem_total - mem_avail) if (mem_total and mem_avail is not None) else None

    # Load + Uptime
    load = uptime = None
    try:
        with open("/proc/loadavg") as f:
            load = [float(x) for x in f.read().split()[:3]]
    except Exception:
        pass
    try:
        with open("/proc/uptime") as f:
            uptime = float(f.read().split()[0])
    except Exception:
        pass

    # Host-Disk (Root-Dateisystem)
    disk = None
    try:
        du = shutil.disk_usage(HOST_ROOT)
        disk = {"total": du.total, "used": du.used, "free": du.free}
    except Exception:
        pass

    # Docker-Speicherverbrauch
    docker_disk = None
    try:
        df = client.df()
        images = df.get("Images") or []
        docker_disk = {
            "images": sum(i.get("Size", 0) for i in images),
            "containers": sum(c.get("SizeRw", 0) or 0 for c in (df.get("Containers") or [])),
            "volumes": sum(v.get("UsageData", {}).get("Size", 0) or 0
                           for v in (df.get("Volumes") or [])),
            "build_cache": sum(b.get("Size", 0) for b in (df.get("BuildCache") or [])),
            "images_count": len(images),
        }
    except Exception:
        pass

    nproc = os.cpu_count()
    return {
        "cpu": cpu, "cpus": nproc,
        "mem_total": mem_total, "mem_used": mem_used,
        "mem_pct": round(mem_used / mem_total * 100, 1) if (mem_used and mem_total) else None,
        "load": load, "uptime": uptime,
        "disk": disk, "docker": docker_disk,
    }


# ----------------------------- Routes -----------------------------
@app.get("/login", response_class=HTMLResponse)
def login_page(error: str = ""):
    return LOGIN_HTML.replace("{{ERROR}}", error)


@app.post("/login")
def login(response: Response, username: str = Form(...), password: str = Form(...)):
    user_ok = hmac.compare_digest(username, USER)
    pass_ok = hmac.compare_digest(password, PASSWORD)
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
    if not valid_token(request.cookies.get(COOKIE)):
        return RedirectResponse(url="/login", status_code=303)
    return INDEX_HTML


@app.get("/api/containers")
def api_containers(request: Request):
    require_auth(request)
    containers = client.containers.list(all=True)
    with ThreadPoolExecutor(max_workers=8) as ex:
        data = list(ex.map(serialize, containers))
    data.sort(key=lambda d: (not d["running"], d["name"]))
    return JSONResponse(data)


@app.get("/api/host")
def api_host(request: Request):
    require_auth(request)
    return JSONResponse(host_stats())


@app.get("/api/sizes")
def api_sizes(request: Request):
    require_auth(request)
    # size=True lässt den Daemon die Layer-Größen berechnen (etwas teurer)
    raw = client.api.containers(all=True, size=True)
    out = {}
    for c in raw:
        out[c["Id"][:12]] = {
            "rw": c.get("SizeRw"),
            "rootfs": c.get("SizeRootFs"),
        }
    return JSONResponse(out)


@app.post("/api/containers/{cid}/{action}")
def api_action(cid: str, action: str, request: Request):
    require_auth(request)
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
    except docker.errors.APIError as e:
        raise HTTPException(status_code=500, detail=str(e.explanation or e))
    return {"ok": True}


# ----------------------------- Templates -----------------------------
LOGIN_HTML = """<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>dockpilot · Login</title><style>
*{box-sizing:border-box}body{margin:0;font-family:system-ui,sans-serif;background:#0f172a;
color:#e2e8f0;display:flex;min-height:100vh;align-items:center;justify-content:center}
.card{background:#1e293b;padding:2rem;border-radius:12px;width:320px;box-shadow:0 10px 30px rgba(0,0,0,.4)}
h1{margin:0 0 1.2rem;font-size:1.4rem}label{display:block;font-size:.8rem;margin:.6rem 0 .2rem;color:#94a3b8}
input{width:100%;padding:.6rem;border-radius:8px;border:1px solid #334155;background:#0f172a;color:#e2e8f0}
button{width:100%;margin-top:1.2rem;padding:.7rem;border:0;border-radius:8px;background:#3b82f6;
color:#fff;font-weight:600;cursor:pointer}button:hover{background:#2563eb}
.err{color:#f87171;font-size:.85rem;margin-top:.8rem;min-height:1rem}</style></head>
<body><form class="card" method="post" action="/login">
<h1>🐳 dockpilot</h1>
<label>Benutzer</label><input name="username" autofocus>
<label>Passwort</label><input name="password" type="password">
<button type="submit">Anmelden</button>
<div class="err">{{ERROR}}</div></form></body></html>"""

INDEX_HTML = """<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>dockpilot</title><style>
*{box-sizing:border-box}body{margin:0;font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0}
header{display:flex;align-items:center;justify-content:space-between;padding:1rem 1.5rem;
background:#1e293b;border-bottom:1px solid #334155}
header h1{margin:0;font-size:1.3rem}header .right{display:flex;gap:1rem;align-items:center;font-size:.85rem;color:#94a3b8}
header form{margin:0}header button{background:#334155;color:#e2e8f0;border:0;padding:.4rem .8rem;
border-radius:6px;cursor:pointer}
main{padding:1.5rem;max-width:1100px;margin:0 auto}
table{width:100%;border-collapse:collapse;background:#1e293b;border-radius:10px;overflow:hidden}
th,td{padding:.6rem .8rem;text-align:left;font-size:.88rem;border-bottom:1px solid #273449}
th{color:#94a3b8;font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.03em}
tr:last-child td{border-bottom:0}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:.4rem}
.up{background:#22c55e}.down{background:#64748b}
.name{font-weight:600}.img{color:#94a3b8;font-size:.78rem}
.bar{background:#0f172a;border-radius:5px;height:7px;width:80px;overflow:hidden;display:inline-block;vertical-align:middle}
.bar>i{display:block;height:100%;background:#3b82f6}
.mem>i{background:#a855f7}
.act button{border:0;border-radius:6px;padding:.35rem .6rem;margin-right:.3rem;cursor:pointer;font-size:.78rem;color:#fff}
.b-start{background:#16a34a}.b-stop{background:#dc2626}.b-restart{background:#d97706}.b-update{background:#2563eb}
.act button:disabled{opacity:.35;cursor:not-allowed}
.muted{color:#64748b}.tag{font-size:.68rem;background:#334155;padding:.1rem .4rem;border-radius:4px;color:#cbd5e1}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin-bottom:1.5rem}
.card{background:#1e293b;border:1px solid #273449;border-radius:10px;padding:.9rem 1.1rem}
.card .lbl{font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;color:#94a3b8}
.card .val{font-size:1.5rem;font-weight:700;margin:.25rem 0}
.card .sub{font-size:.78rem;color:#94a3b8}
.card .bar2{background:#0f172a;border-radius:5px;height:8px;margin-top:.5rem;overflow:hidden}
.card .bar2>i{display:block;height:100%;background:#3b82f6}
.dk{display:flex;justify-content:space-between;font-size:.8rem;margin:.15rem 0;color:#cbd5e1}
.dk span:last-child{color:#94a3b8}
#toast{position:fixed;bottom:1.5rem;right:1.5rem;background:#1e293b;border:1px solid #334155;
padding:.8rem 1.2rem;border-radius:8px;opacity:0;transition:.3s;pointer-events:none}
#toast.show{opacity:1}.spin{animation:s 1s linear infinite;display:inline-block}@keyframes s{to{transform:rotate(360deg)}}
</style></head><body>
<header><h1>🐳 dockpilot</h1>
<div class="right"><span id="meta"></span>
<form method="post" action="/logout"><button>Logout</button></form></div></header>
<main>
<section class="cards" id="host"></section>
<table><thead><tr>
<th>Status</th><th>Container</th><th>CPU</th><th>RAM</th><th>Speicher</th><th>Netz I/O</th><th>Aktionen</th>
</tr></thead><tbody id="rows"><tr><td colspan="7" class="muted">lädt…</td></tr></tbody></table></main>
<div id="toast"></div>
<script>
const fmtBytes=b=>{if(b==null)return '–';const u=['B','KB','MB','GB','TB'];let i=0;b=+b;
while(b>=1024&&i<u.length-1){b/=1024;i++}return b.toFixed(b<10&&i>0?1:0)+u[i]};
function toast(msg){const t=document.getElementById('toast');t.textContent=msg;t.classList.add('show');
setTimeout(()=>t.classList.remove('show'),2500)}
function bar(pct,cls){const p=pct==null?0:Math.min(100,pct);
return `<span class="bar ${cls}"><i style="width:${p}%"></i></span> <span class="muted">${pct==null?'–':pct+'%'}</span>`}
let busy={};
let sz={};
async function loadSizes(){try{const r=await fetch('/api/sizes');
  if(r.ok){sz=await r.json();render(last)}}catch(e){}}
const fmtUp=s=>{if(s==null)return '–';const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);
  return d?`${d}d ${h}h`:(h?`${h}h ${m}m`:`${m}m`)};
function gauge(lbl,pct,val,sub){const p=pct==null?0:Math.min(100,pct);
  const col=p>90?'#dc2626':p>75?'#d97706':'#3b82f6';
  return `<div class="card"><div class="lbl">${lbl}</div><div class="val">${val}</div>
    <div class="bar2"><i style="width:${p}%;background:${col}"></i></div>
    <div class="sub">${sub}</div></div>`}
async function loadHost(){try{const r=await fetch('/api/host');if(!r.ok)return;const h=await r.json();
  const d=h.disk,dk=h.docker;
  let cards='';
  cards+=gauge('CPU',h.cpu,(h.cpu==null?'–':h.cpu+'%'),`${h.cpus} Kerne · Load ${h.load?h.load[0].toFixed(2):'–'}`);
  cards+=gauge('RAM',h.mem_pct,(h.mem_pct==null?'–':h.mem_pct+'%'),`${fmtBytes(h.mem_used)} / ${fmtBytes(h.mem_total)}`);
  if(d){const dp=Math.round(d.used/d.total*100);
    cards+=gauge('Festplatte',dp,dp+'%',`${fmtBytes(d.used)} / ${fmtBytes(d.total)} · frei ${fmtBytes(d.free)}`)}
  cards+=`<div class="card"><div class="lbl">System</div><div class="val" style="font-size:1.1rem">⏱ ${fmtUp(h.uptime)}</div>
    <div class="sub">Uptime</div></div>`;
  if(dk){const tot=(dk.images||0)+(dk.containers||0)+(dk.volumes||0)+(dk.build_cache||0);
    cards+=`<div class="card"><div class="lbl">Docker-Speicher</div><div class="val" style="font-size:1.25rem">${fmtBytes(tot)}</div>
      <div class="dk"><span>Images (${dk.images_count})</span><span>${fmtBytes(dk.images)}</span></div>
      <div class="dk"><span>Container</span><span>${fmtBytes(dk.containers)}</span></div>
      <div class="dk"><span>Volumes</span><span>${fmtBytes(dk.volumes)}</span></div>
      <div class="dk"><span>Build-Cache</span><span>${fmtBytes(dk.build_cache)}</span></div></div>`}
  document.getElementById('host').innerHTML=cards;
}catch(e){}}
async function act(id,action,name){
  if(action==='update'&&!confirm(`"${name}" updaten?\\nImage wird neu gezogen und der Container neu erstellt.`))return;
  busy[id]=true;render(last);
  try{const r=await fetch(`/api/containers/${id}/${action}`,{method:'POST'});
    if(r.status===401){location.href='/login';return}
    const j=await r.json().catch(()=>({}));
    if(!r.ok){toast('Fehler: '+(j.detail||r.status))}else{toast(`${action} ok: ${name}`)}
  }catch(e){toast('Fehler: '+e)}
  busy[id]=false;await load();
}
let last=[];
function render(list){last=list;const rows=document.getElementById('rows');
  if(!list.length){rows.innerHTML='<tr><td colspan="7" class="muted">keine Container</td></tr>';return}
  rows.innerHTML=list.map(c=>{const b=busy[c.id];
    const upd=`<button class="b-update" ${b?'disabled':''} onclick="act('${c.id}','update','${c.name}')">${b?'<span class=spin>⟳</span>':'Update'}</button>`;
    const actions=c.running
      ?`<button class="b-stop" ${b?'disabled':''} onclick="act('${c.id}','stop','${c.name}')">Stop</button>
        <button class="b-restart" ${b?'disabled':''} onclick="act('${c.id}','restart','${c.name}')">Restart</button>${upd}`
      :`<button class="b-start" ${b?'disabled':''} onclick="act('${c.id}','start','${c.name}')">Start</button>${upd}`;
    return `<tr>
      <td><span class="dot ${c.running?'up':'down'}"></span>${c.status}</td>
      <td><div class="name">${c.name} ${c.compose?`<span class="tag">${c.compose}</span>`:''}</div>
          <div class="img">${c.image}</div></td>
      <td>${c.running?bar(c.cpu,''):'<span class=muted>–</span>'}</td>
      <td>${c.running?bar(c.mem,'mem')+`<div class="img">${fmtBytes(c.mem_used)} / ${fmtBytes(c.mem_limit)}</div>`:'<span class=muted>–</span>'}</td>
      <td>${sz[c.id]?`${fmtBytes(sz[c.id].rw)}<div class="img">gesamt ${fmtBytes(sz[c.id].rootfs)}</div>`:'<span class=muted>…</span>'}</td>
      <td>${c.running?`↓ ${fmtBytes(c.net_rx)}<br>↑ ${fmtBytes(c.net_tx)}`:'<span class=muted>–</span>'}</td>
      <td class="act">${actions}</td></tr>`}).join('');
}
async function load(){try{const r=await fetch('/api/containers');
  if(r.status===401){location.href='/login';return}
  const list=await r.json();render(list);
  const up=list.filter(c=>c.running).length;
  document.getElementById('meta').textContent=`${up}/${list.length} laufen · auto-refresh 5s`;
}catch(e){document.getElementById('meta').textContent='Fehler beim Laden'}}
load();setInterval(load,5000);
loadSizes();setInterval(loadSizes,30000);
loadHost();setInterval(loadHost,5000);
</script></body></html>"""

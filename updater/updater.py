"""DockPilot Updater Sidecar.

Runs alongside the main dockpilot container. Polls for new images every 8 hours
and performs the actual container recreation when requested, so dockpilot never
has to stop itself.

Environment variables:
  DOCKPILOT_CONTAINER  - Name/ID of the dockpilot container (default: dockpilot)
  CHECK_INTERVAL       - Seconds between checks (default: 28800 = 8 hours)
  UPDATER_API_PORT     - Port for internal API (default: 8081)
"""
import json
import logging
import os
import sys
import time
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import docker

logging.basicConfig(level=logging.INFO, format="%(asctime)s updater %(levelname)s %(message)s")
log = logging.getLogger("updater")

DOCKPILOT_NAME = os.environ.get("DOCKPILOT_CONTAINER", "dockpilot")
CHECK_INTERVAL = int(os.environ.get("CHECK_INTERVAL", "28800"))
API_PORT = int(os.environ.get("UPDATER_API_PORT", "8081"))

client = docker.DockerClient(base_url="unix://var/run/docker.sock")

state = {
    "checking": False,
    "update_available": False,
    "current_digest": None,
    "remote_digest": None,
    "last_check": None,
    "error": None,
    "image_ref": None,
    "applying": False,
}


def _check():
    state["checking"] = True
    state["error"] = None
    try:
        c = client.containers.get(DOCKPILOT_NAME)
        image_ref = c.attrs["Config"]["Image"]
        state["image_ref"] = image_ref
        local_img = client.images.get(image_ref)
        local_digests = {rd.split("@")[-1] for rd in local_img.attrs.get("RepoDigests", [])}
        reg = client.images.get_registry_data(image_ref)
        remote_digest = reg.id
        state["current_digest"] = next(iter(local_digests), None)
        state["remote_digest"] = remote_digest
        state["update_available"] = bool(remote_digest and remote_digest not in local_digests)
        state["last_check"] = time.time()
        log.info("Update check done. available=%s", state["update_available"])
    except Exception as exc:
        state["error"] = str(exc)
        log.warning("Update check failed: %s", exc)
    finally:
        state["checking"] = False


def _apply():
    state["applying"] = True
    state["error"] = None
    try:
        c = client.containers.get(DOCKPILOT_NAME)
        attrs = c.attrs
        cfg = attrs["Config"]
        host_cfg = attrs["HostConfig"]
        name = c.name
        image_ref = cfg["Image"]
        networks = attrs.get("NetworkSettings", {}).get("Networks", {})

        log.info("Pulling new image: %s", image_ref)
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
            networking_config = client.api.create_networking_config({primary_net: endpoint_config})

        new_host_config = client.api.create_host_config(
            binds=host_cfg.get("Binds"),
            port_bindings=host_cfg.get("PortBindings"),
            restart_policy=host_cfg.get("RestartPolicy"),
            network_mode=host_cfg.get("NetworkMode"),
            privileged=host_cfg.get("Privileged", False),
            cap_add=host_cfg.get("CapAdd"),
            cap_drop=host_cfg.get("CapDrop"),
            security_opt=host_cfg.get("SecurityOpt"),
            dns=host_cfg.get("Dns"),
            extra_hosts=host_cfg.get("ExtraHosts"),
        )

        log.info("Stopping and removing: %s", name)
        c.stop(timeout=10)
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
        log.info("Container restarted with new image: %s", new_id[:12])
        state["update_available"] = False
    except Exception as exc:
        state["error"] = str(exc)
        log.error("Apply failed: %s", exc)
    finally:
        state["applying"] = False


def _scheduler():
    time.sleep(30)  # wait for dockpilot to start
    while True:
        try:
            _check()
        except Exception:
            pass
        time.sleep(CHECK_INTERVAL)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # suppress access log

    def _json(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/status":
            self._json(200, state)
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/check":
            if not state["checking"]:
                threading.Thread(target=_check, daemon=True).start()
            self._json(200, {"ok": True})
        elif self.path == "/apply":
            if state["applying"]:
                self._json(409, {"error": "already applying"})
            else:
                threading.Thread(target=_apply, daemon=True).start()
                self._json(200, {"ok": True})
        else:
            self._json(404, {"error": "not found"})


if __name__ == "__main__":
    threading.Thread(target=_scheduler, daemon=True).start()
    log.info("Updater sidecar listening on port %d", API_PORT)
    HTTPServer(("0.0.0.0", API_PORT), Handler).serve_forever()

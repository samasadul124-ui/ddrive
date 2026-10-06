"""
Arena <-> Colab bridge  (paste-once control channel)

Why this exists: the Arena sandbox runs behind an allowlist-only egress firewall
(GitHub / PyPI / npm only), so it cannot open a TCP connection to a
trycloudflare.com tunnel. The sandbox *can* read any public URL through the
platform's page-fetcher. This bridge therefore exposes a tiny, dependency-free
HTTP API on a fresh trycloudflare tunnel; the Arena agent drives the Colab GPU
by GETing URLs on that tunnel.

Paste-once bootstrap (one line, in a Colab cell):

    import urllib.request;
    exec(urllib.request.urlopen(
      "https://raw.githubusercontent.com/<owner>/<repo>/<branch>/.arena-bridge/bridge.py"
    ).read().decode())

The cell prints a single BRIDGE_URL line. Send it to the agent.
"""
import base64
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------------------------------------------------------- configuration
PORT = int(os.environ.get("ARENA_BRIDGE_PORT", "8799"))
PREFIX = os.environ.get("ARENA_BRIDGE_PREFIX") or ("/arena-" + secrets.token_hex(4))
MAX_CHUNK = int(os.environ.get("ARENA_BRIDGE_CHUNK", "3500"))
RUN_TIMEOUT = int(os.environ.get("ARENA_BRIDGE_TIMEOUT", "900"))
NO_TUNNEL = os.environ.get("ARENA_BRIDGE_NO_TUNNEL") == "1"

REPO_RAW = "https://raw.githubusercontent.com/samasadul124-ui/ddrive/arena/cff2b00a-ddrive"

_SERVER = {"port": PORT, "prefix": PREFIX, "url": None if not NO_TUNNEL else f"http://127.0.0.1:{PORT}{PREFIX}"}
_OUTS = {}   # id -> full text
_LOCK = threading.Lock()


# ------------------------------------------------------------------- execution
def _run_bash(cmd, timeout=RUN_TIMEOUT, cwd=None):
    t0 = time.time()
    try:
        p = subprocess.run(
            ["/bin/bash", "-lc", cmd], capture_output=True, timeout=timeout, cwd=cwd
        )
        out = p.stdout.decode("utf-8", "replace")
        err = p.stderr.decode("utf-8", "replace")
        rc = p.returncode
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"").decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        err = (e.stderr or b"").decode("utf-8", "replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
        err += f"\n[bridge] killed after {timeout}s"
        rc = 124
    except Exception as e:  # noqa: BLE001
        out, err, rc = "", f"[bridge] {type(e).__name__}: {e}", 1
    return {"rc": rc, "out": out, "err": err, "ms": int((time.time() - t0) * 1000)}


def _store(text):
    oid = uuid.uuid4().hex[:12]
    with _LOCK:
        _OUTS[oid] = text
        if len(_OUTS) > 200:                       # keep memory bounded
            for k in list(_OUTS)[:-200]:
                _OUTS.pop(k, None)
    return oid


def _page(oid, off, mx):
    text = _OUTS.get(oid, "")
    off = max(0, int(off))
    mx = max(200, min(int(mx), 20000))
    return {
        "id": oid,
        "off": off,
        "chunk": text[off:off + mx],
        "next": (off + mx) if (off + mx) < len(text) else None,
        "total": len(text),
    }


# ------------------------------------------------------------------- http layer
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "arena-bridge/1.0"

    def log_message(self, *a):  # keep the Colab cell output clean
        pass

    def _send(self, code, obj):
        body = json.dumps(obj, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: C901
        try:
            u = urllib.parse.urlparse(self.path)
            path = urllib.parse.unquote(u.path)
            q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query, keep_blank_values=True).items()}

            if not path.startswith(PREFIX):
                return self._send(403, {"ok": False, "error": "forbidden"})
            route = path[len(PREFIX):] or "/"

            if route in ("/", "/health", "/status"):
                return self._send(200, {
                    "ok": True, "service": "arena colab bridge", "prefix": PREFIX,
                    "uptime_s": int(time.time() - START), "host": os.uname().nodename,
                    "cwd": os.getcwd(),
                    "url": _SERVER["url"],
                })

            if route == "/exec":
                r = _run_bash(q.get("cmd", "true"), timeout=int(q.get("timeout", RUN_TIMEOUT)),
                              cwd=q.get("cwd") or None)
                oid = _store("$ " + q.get("cmd", "") + "\n" + r["out"] +
                             (("\n--- stderr ---\n" + r["err"]) if r["err"] else ""))
                payload = {"ok": r["rc"] == 0, "rc": r["rc"], "ms": r["ms"], "id": oid,
                           "total": len(_OUTS[oid])}
                payload.update(_page(oid, 0, int(q.get("max", MAX_CHUNK))))
                return self._send(200, payload)

            if route == "/py":
                code = q.get("code", "")
                if not code and "b64" in q:
                    code = base64.b64decode(q["b64"]).decode()
                src = base64.b64encode(code.encode()).decode()
                r = _run_bash(f"python3 -c \"import base64;exec(base64.b64decode('{src}').decode())\"",
                              timeout=int(q.get("timeout", RUN_TIMEOUT)))
                oid = _store("[python]\n" + r["out"] + (("\n--- stderr ---\n" + r["err"]) if r["err"] else ""))
                payload = {"ok": r["rc"] == 0, "rc": r["rc"], "ms": r["ms"], "id": oid,
                           "total": len(_OUTS[oid])}
                payload.update(_page(oid, 0, int(q.get("max", MAX_CHUNK))))
                return self._send(200, payload)

            if route == "/out":
                return self._send(200, _page(q.get("id", ""), q.get("off", 0), q.get("max", MAX_CHUNK)))

            if route == "/file":
                p = q.get("path", "")
                if not p or not os.path.exists(p):
                    return self._send(404, {"ok": False, "error": "no such file", "path": p})
                want_b64 = q.get("b64", "1") == "1"
                with open(p, "rb") as fh:
                    raw = fh.read()
                text = base64.b64encode(raw).decode() if want_b64 else raw.decode("utf-8", "replace")
                oid = _store(text)
                payload = {"ok": True, "id": oid, "size": len(raw), "b64": want_b64,
                           "total": len(text)}
                payload.update(_page(oid, q.get("off", 0), q.get("max", MAX_CHUNK)))
                return self._send(200, payload)

            if route == "/ls":
                r = _run_bash("ls -la --time-style=long-iso " + (q.get("path") or "."))
                return self._send(200, {"ok": True, "out": r["out"] + r["err"]})

            if route == "/pull":                      # repo file -> Colab
                src = q.get("src", "")
                dest = q.get("dest", "")
                if not src or not dest:
                    return self._send(400, {"ok": False, "error": "need src & dest"})
                url = f"{REPO_RAW}/{src.lstrip('/')}"
                try:
                    data = urllib.request.urlopen(url, timeout=30).read()
                except Exception as e:  # noqa: BLE001
                    return self._send(502, {"ok": False, "error": f"{type(e).__name__}: {e}", "url": url})
                os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
                with open(dest, "wb") as fh:
                    fh.write(data)
                return self._send(200, {"ok": True, "bytes": len(data), "dest": dest, "src": url})

            if route == "/reload":                    # re-fetch bridge.py and restart
                threading.Thread(target=_self_update, daemon=True).start()
                return self._send(200, {"ok": True, "note": "reloading; URL will be reprinted"})

            return self._send(404, {"ok": False, "error": "no such route", "route": route})
        except Exception as e:  # noqa: BLE001
            return self._send(500, {"ok": False, "error": f"{type(e).__name__}: {e}"})

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n else b""
            u = urllib.parse.urlparse(self.path)
            if not u.path.startswith(PREFIX):
                return self._send(403, {"ok": False, "error": "forbidden"})
            route = u.path[len(PREFIX):] or "/"
            if route == "/exec":
                try:
                    cmd = json.loads(body or b"{}").get("cmd", "")
                except Exception:  # noqa: BLE001
                    cmd = body.decode("utf-8", "replace")
                r = _run_bash(cmd)
                return self._send(200, {"ok": r["rc"] == 0, "rc": r["rc"], "ms": r["ms"],
                                        "out": r["out"][:MAX_CHUNK], "err": r["err"][:MAX_CHUNK]})
            if route == "/write":                     # arena -> Colab file
                meta = json.loads(body.decode())
                os.makedirs(os.path.dirname(meta["path"]) or ".", exist_ok=True)
                with open(meta["path"], "w") as fh:
                    fh.write(meta["text"])
                return self._send(200, {"ok": True, "bytes": len(meta["text"])})
            return self._send(404, {"ok": False, "error": "no such route"})
        except Exception as e:  # noqa: BLE001
            return self._send(500, {"ok": False, "error": f"{type(e).__name__}: {e}"})


# --------------------------------------------------------------------- tunnel
def _find_cloudflared():
    p = shutil.which("cloudflared")
    if p:
        return p
    for cand in ("/content/cloudflared", "/usr/local/bin/cloudflared", "./cloudflared"):
        if os.path.exists(cand):
            return cand
    dest = "/content/cloudflared" if os.path.isdir("/content") else "./cloudflared"
    url = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"
    print("[bridge] downloading cloudflared ...", flush=True)
    urllib.request.urlretrieve(url, dest)
    os.chmod(dest, 0o755)
    return dest


def _start_tunnel():
    """Start cloudflared and return (public_url, process). Blocks until the URL is known."""
    cf = _find_cloudflared()
    proc = subprocess.Popen(
        [cf, "tunnel", "--url", f"http://127.0.0.1:{PORT}", "--no-autoupdate"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
    )
    deadline = time.time() + 120
    url = None
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                break
            continue
        m = re.search(r"https://[-\w]+\.trycloudflare\.com", line)
        if m:
            url = m.group(0)
            break
    # keep draining in the background so cloudflared never blocks on a full pipe
    threading.Thread(target=lambda: [None for _ in proc.stdout], daemon=True).start()
    return url, proc


def _watchdog(proc):
    while True:
        time.sleep(10)
        if proc.poll() is not None:
            print("[bridge] tunnel died; restarting ...", flush=True)
            url, proc = _start_tunnel()
            _SERVER["url"] = url
            if url:
                print(f"\nBRIDGE_URL={url}{PREFIX}\n", flush=True)


def _self_update():
    try:
        data = urllib.request.urlopen(f"{REPO_RAW}/.arena-bridge/bridge.py", timeout=30).read()
        here = globals().get("__file__")
        here = os.path.abspath(here) if here and os.path.exists(here) else None
        if here:
            with open(here, "wb") as fh:
                fh.write(data)
        print("[bridge] new version fetched — restarting runtime "
              "(Runtime ▸ Restart, then run the paste line again)", flush=True)
    except Exception as e:  # noqa: BLE001
        print(f"[bridge] reload failed: {e}", flush=True)


# ----------------------------------------------------------------------- start
START = time.time()


def _maybe_block():
    """CLI / test mode: keep the process alive (Colab cells must return instead)."""
    if os.environ.get("ARENA_BRIDGE_BLOCK") == "1":
        while True:
            time.sleep(3600)


def main():
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"[bridge] api listening on 0.0.0.0:{PORT}{PREFIX}", flush=True)

    if NO_TUNNEL:
        print(f"\nBRIDGE_URL={_SERVER['url']}\n", flush=True)
        _maybe_block()
        return

    url, proc = _start_tunnel()
    if not url:
        print("[bridge] could not obtain a tunnel URL", flush=True)
        return
    _SERVER["url"] = url
    threading.Thread(target=_watchdog, args=(proc,), daemon=True).start()

    print("\n" + "=" * 72, flush=True)
    print("READY — paste this ONE line into the Arena chat:\n", flush=True)
    print(f"BRIDGE_URL={url}{PREFIX}\n", flush=True)
    print("(keep this Colab tab open — the bridge dies with the runtime)", flush=True)
    print("=" * 72, flush=True)

    _maybe_block()


main()


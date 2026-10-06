# Arena ⇄ Colab bridge

The Arena sandbox runs behind an allowlist-only egress firewall (GitHub / PyPI / npm
only), so it cannot open a TCP connection to a `trycloudflare.com` tunnel — not even
to one running in your own Colab. The sandbox *can* read any public URL through the
platform's page-fetcher, so the bridge flips the direction of control:

```
Arena agent ──GET https://<random>.trycloudflare.com/<secret>/exec?cmd=... ──> Colab GPU
            <── JSON result (chunked) ────────────────────────────────────────
```

## Paste-once bootstrap

One line, in a Colab cell (runtime must be GPU):

```python
import urllib.request; exec(urllib.request.urlopen("https://raw.githubusercontent.com/samasadul124-ui/ddrive/arena/cff2b00a-ddrive/.arena-bridge/bridge.py").read().decode())
```

It downloads `cloudflared` if needed (reusing the runtime's copy if present), starts a
small stdlib-only HTTP server on `0.0.0.0:8799`, opens a fresh quick tunnel, and prints:

```
BRIDGE_URL=https://<random>.trycloudflare.com/arena-<secret>
```

Send that line to the agent. Keep the Colab tab open; the bridge dies with the runtime.

## API (everything lives under the secret `/<prefix>`; anything else returns 403)

| route | purpose |
|---|---|
| `GET /status` | liveness, host, uptime |
| `GET /exec?cmd=<sh>&timeout=&max=&cwd=` | run a shell command, first chunk of output |
| `GET /py?code=<python>` or `?b64=` | run python in a fresh subprocess |
| `GET /out?id=&off=&max=` | page through a previous result |
| `GET /file?path=&off=&max=&b64=` | read a file out of the runtime (base64 by default) |
| `GET /ls?path=` | short listing |
| `GET /pull?src=<repo path>&dest=<colab path>` | copy a file from this repo into the runtime |
| `GET /reload` | re-fetch `bridge.py` and restart |
| `POST /exec` `{"cmd":...}` | shell (for callers that can send a body) |
| `POST /write` `{"path":...,"text":...}` | write a file |

Security: the `/<prefix>` component is a random 8-hex-char secret generated per run, so
the tunnel URL itself is the credential. Results are served in the clear on that URL —
treat the runtime as semi-public, exactly like the existing worker tunnel.

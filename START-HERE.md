# Start here

## The one command

Paste this into **PowerShell** (or any terminal) and press Enter:

```powershell
git clone -b arena/2ed54c7d-ddrive https://github.com/samasadul124-ui/ddrive.git ddrive; cd ddrive; npm install; npm start
```

Then open **<http://localhost:3000>** in your browser and drop a file on the page.
There is **no login and no password** — nothing else to configure.

Already have the folder from last time? Then use:

```powershell
cd ddrive; git pull; npm install; npm start
```

> `;` is correct for Windows PowerShell 5.1. If you are in a shell that prefers
> `&&` (PowerShell 7, CMD, bash), you can use `&&` instead.

## What you will see

```
[ddrive] storage=local chunk=9.9 MiB data=…/data/chunks db=sqlite auth=none
[ddrive] AUTHENTICATION IS DISABLED: anyone who can reach this port has full access …
[ddrive] Ready. Open http://localhost:3000 in your browser and drop a file on the page.
[ddrive] WebDAV: http://localhost:3000/webdav   S3 API: http://localhost:3000/s3   Stop: Ctrl+C
Server listening at http://0.0.0.0:3000
```

Leave that window open while you use it. `Ctrl+C` stops the server.

## Uploading a file

1. Open <http://localhost:3000>.
2. Pick your files, or drag them onto the page. A progress bar appears and the
   file is listed when it finishes.
3. Click the file to download it again — it must be byte-for-byte identical.

Anything you upload is split into ~10 MB chunks and encrypted with AES-256-GCM
before it is written to disk, so the `data/` folder never contains readable
file contents.

## Want proof it works on your machine?

Start the server, then open a **second** terminal in the same folder and run:

```powershell
npm run check
```

It uploads real bytes through the web panel's own endpoint, WebDAV and the S3 API,
downloads them again, compares them byte for byte, verifies the audit chain and the
key file, and then deletes its test data. You should see `22 checks passed, 0 failed`.
Add credentials if you turned a password on: `$env:DDRIVE_USER='admin'; $env:DDRIVE_PASSWORD='…'; npm run check`.

Requires **Node.js 22.5 or newer** — if yours is older, the server now says so
plainly instead of crashing with a stack trace.

## The other ways in

| Surface | Where | How to use it |
| --- | --- | --- |
| Web console | `http://localhost:3000/` | browse, upload, versions, shares, IAM, audit |
| REST API + SDK | `http://localhost:3000/api` | JSON; no auth needed by default |
| WebDAV | `http://localhost:3000/webdav` | mount it as a drive (Windows: map a network drive), or `davfs2` on Linux |
| S3 API | `http://localhost:3000/s3` | SigV4 — create a key under *Access keys*, then point `aws --endpoint-url http://localhost:3000 s3 ls` at it |
| Health / metrics | `/healthz`, `/readyz`, `/metrics` | monitoring |

## Your data lives in `data/` — keep `data/master.key` with it

On first start DDrive creates `data/master.key` (owner-only, 0600). It encrypts
your objects and the secret material in the database. **Back up `data/` and that
key together**: without the key the objects cannot be decrypted. To use your own
key instead, set `MASTER_KEY`, or point `MASTER_KEY_FILE` at a file.

## If you want a password back

One setting is enough:

```powershell
$env:AUTH_MODE='basic'; $env:BOOTSTRAP_ADMIN_PASSWORD='Some-Good-Passw0rd'; npm start
```

The page, the API, WebDAV and the S3 API then all require credentials. Remove
those two variables to go back to no password. Never leave the port open to the
internet without this: whoever can reach it has full access.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `EADDRINUSE` on start | something already uses port 3000 — close the old window, or start with `$env:PORT='3001'; npm start` |
| Windows asks about the firewall | allow it on private networks, or start with `$env:HOST='127.0.0.1'; npm start` to keep it local only |
| `npm install` fails | you need Node.js 20 or newer (`node --version`) |
| Upload stops on a big file | check free disk space; chunking and encryption happen locally, nothing leaves the machine |
| The page shows an old file list | press `Ctrl+F5` — the browser caches the panel |

## Rotate the Discord webhooks you pasted into chat

Those URLs let anyone who has them post into your channels. Discord → your
channel → **Integrations → Webhooks → Delete**, then create new ones. Discord
storage is **not** needed for the local setup above.

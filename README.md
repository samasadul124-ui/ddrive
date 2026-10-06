<h1 align="center" style="font-size: 60px"> DDRIVE </h1>

> **This branch (`arena/2ed54c7d-ddrive`) is DDrive 2.0 — a complete cloud storage
> platform.** The repository below still documents the original Discord-backed
> layer; everything in this section is the current system, and it runs with
> **no Discord, no Postgres and no Docker** if you want it to.

## 60-second quickstart (SQLite + local disk)

```bash
npm install
npm start
```

That is the whole setup on this branch. **There is no login and no password:**
SQLite database (`data/ddrive.sqlite`), local object store (`data/`), HTTP
server on `http://localhost:3000`, and every request is served as the
administrator. Open <http://localhost:3000> and start uploading.

> ⚠️ **Authentication is disabled by default.** Anyone who can reach the port
> can read, write and delete everything, and change settings. That is fine on
> your own machine or a trusted LAN. If the port is reachable from the internet,
> set up a password (below) or bind `HOST=127.0.0.1` and keep it local. DDrive
> prints a warning at every boot while authentication is off.

### Turning the password back on

```bash
AUTH_MODE=basic BOOTSTRAP_ADMIN_PASSWORD='Some-Good-Passw0rd' npm start
```

The panel, WebDAV and the S3 API then require credentials (browser prompt for
the panel, Basic auth for WebDAV, SigV4 or an access key for S3). On the first
boot with `AUTH_MODE=basic` and no password set, DDrive generates one and prints
it:

```
Created administrator "admin" with generated password: <password>
```

The password policy (same one the API enforces) is at least 8 characters with
lower case, upper case and a digit, and it may not contain the username.
A legacy `AUTH=user:password` line also turns authentication on, because setting
a credential pair is an explicit request to be asked for it.

| Surface | URL | Notes |
| --- | --- | --- |
| Web console | `http://localhost:3000/` | buckets, browse, upload, versions, shares, IAM, audit |
| REST API | `http://localhost:3000/api` | JSON API used by the console and SDK |
| **WebDAV** | `http://localhost:3000/webdav` | mountable Class 1/2/3 server (`DAV: 1, 2, 3`) |
| S3 API | `http://localhost:3000/s3` | SigV4, path + virtual-host style, multipart |
| Health / metrics | `/healthz`, `/readyz`, `/metrics` | liveness, readiness, Prometheus |

Every surface answers without credentials by default; `AUTH_MODE=basic` makes
all of them require a password.

**Encryption is on by default too.** On the first boot DDrive generates a master
key at `DATA_DIR/master.key` (mode 0600) and uses it to encrypt object bytes and
secret material at rest (access keys, replication credentials). The key file is
logged in the boot output - **keep it with your data**: without it those objects
cannot be decrypted. Set `MASTER_KEY` (or `MASTER_KEY_FILE`) to manage the key
yourself, which is required when `NODE_ENV=production`.

Try it: `curl -u admin:<password> http://localhost:3000/api/buckets` — or mount it:

```bash
# macOS Finder: Go > Connect to Server... ; Linux:
sudo mount -t davfs http://localhost:3000/webdav /mnt/ddrive
# Windows: map a network drive to http://localhost:3000/webdav
```

## Using Discord as the storage backend

Discord only stores the object **bytes**; buckets, versions, metadata and the
audit trail live in the database, and the console lists your files from there.
So you must keep the database (or its file) - if it is lost, the bytes are still
on Discord but DDrive has no map to them. This is why the default is local disk
and Discord is opt-in.

```bash
STORAGE_DRIVER=discord WEBHOOKS='https://discord.com/api/webhooks/…/…,https://discord.com/api/webhooks/…/…' MASTER_KEY="$(openssl rand -hex 32)" BOOTSTRAP_ADMIN_PASSWORD='Some-Good-Passw0rd' npm start
```

Or put the same three lines in `config/.env` (`STORAGE_DRIVER=discord`,
`WEBHOOKS=…`, `MASTER_KEY=…`) and run `npm start` - that is what `config/.env_sample`
documents. Create one webhook per text channel (5 is a good number) at
Discord → channel → Integrations → Webhooks.

**Chunk size.** A Discord webhook accepts at most 10 MiB (`10485760` bytes) per
request. DDrive defaults to `10420224` bytes, which leaves 64 KiB for the
multipart envelope and the encryption tag - a chunk of exactly 10 MiB would be
rejected with HTTP 413. If you set `CHUNK_SIZE` higher on a Discord deployment it
is clamped to that value and the server tells you so at boot; the startup line
also prints the storage backend, chunk size and webhook count. Raising or
lowering `CHUNK_SIZE` later never invalidates stored objects: downloads read the
chunk size each version was written with.

Startup on a working Discord deployment looks like:

```
[ddrive] storage=discord chunk=9.9 MiB data=5 webhook(s) db=sqlite
Server listening at http://0.0.0.0:3000
```

## What is implemented

| Category | Must-have (done) | Advanced (done) |
| --- | --- | --- |
| **Durability** | Multi-AZ replication between nodes (`src/core/replication.js`, peers push objects, deletes and metadata with HMAC-signed requests) | Cross-region peers + prefix-scoped links, per-peer backlog/health, `POST /api/admin/replication/:name/test`, S3-compatible peers |
| **Security** | AES-256-GCM envelope encryption per object (per-object DEK wrapped by the master key) + full IAM (users, groups, roles, policies, access keys, bucket policies). Request authentication is off by default (`AUTH_MODE`) - the encryption and the IAM engine are unaffected by that switch | Object Lock + legal hold (retention modes, server-side enforcement), key hierarchy with `MASTER_KEY_FILE` / KMS-style `keyId` + wrapping key rotation hooks |
| **Management** | Versioning (version ids, delete markers, restore) and lifecycle rules (expiry, non-current expiry, abort multipart, tier transitions) | AI/rule-based auto-tagging (`auto_tag_rule`, prefix+regex+sweep) with tag search, intelligent tiering policies (`tiering_policy`, hot/cold backends, migration worker) |
| **Access** | REST API + SDK module, WebDAV, S3 API, shares (presigned-style links), multipart upload, ranged downloads | Event-driven delivery (`event_target`, `event_delivery`, retries, dead letters) + serverless-style webhook triggers |
| **Compliance** | Tamper-evident encryption audit log (hash-chained `audit_event`, `audit.verify()`, compliance queries) | Retention/legal-hold enforcement + auditor role; certification work is deployment-specific (see "Compliance notes") |

Also present: quota enforcement, metrics and structure-aware storage tiers
(`local`, `memory`, `s3`, `discord`) - see "Using Discord as the storage
backend" above, and the original DDrive documentation at the end of this file.

## Two deployment modes

**Single node (default)** — SQLite + local disk. Nothing external required.
Data lives in `DATA_DIR`; the whole database is one file you can copy, and the
admin password is generated on first boot (see above).

**Production** — Postgres + (local disk | S3 | Discord) storage:

```bash
DB_DRIVER=postgres \
DATABASE_URL=postgres://user:pass@host:5432/ddrive \
MASTER_KEY="$(openssl rand -hex 32)" \
BOOTSTRAP_ADMIN_PASSWORD="$(openssl rand -base64 18)" \
STORAGE_DRIVER=s3 S3_BUCKET=my-ddrive S3_REGION=eu-west-1 \
npm start
```

The schema is created/upgraded automatically on boot
(`migrations/20260101000000_2.0.0_baseline.js`, generated from the single
declarative schema in `src/db/schema.js`), so `npm start` is still the only
command. `npm run migration:latest` does the same thing manually.

*Upgrading a pre-2.0 database:* the baseline migration detects the old
`directory`/`block` tables, copies their rows into `legacy_directory` /
`legacy_block`, and only then removes them. Nothing is dropped without a copy.
`CREATE EXTENSION pgcrypto` is attempted but not required (managed Postgres
often forbids it; Postgres 13+ needs no extension).

## Tests

```bash
npm test        # 96 tests, no network, no Docker, no Postgres needed
```

The suite boots the real server in-process. It includes a WebDAV client suite,
SigV4 signing tests, tamper-evidence checks for the audit chain, Discord storage
against a local stub, **multi-AZ replication between two live nodes**, and
**the whole application running on the Postgres driver** (via `pg-mem`, so the
production path is covered in CI without a database server). The Discord tests
use a local double that enforces the real 10 MiB webhook limit, so a chunk size
Discord would refuse fails in the suite instead of only in production.

## Configuration reference (2.0 additions)

```shell
DB_DRIVER=sqlite|postgres      # defaults to postgres when DATABASE_URL is set
SQLITE_FILE=./data/ddrive.sqlite
DATA_DIR=./data
AUTH_MODE=none|basic           # none (default) = no login at all
BOOTSTRAP_ADMIN_USER=admin     # the account used when auth is off
BOOTSTRAP_ADMIN_PASSWORD=      # only with AUTH_MODE=basic
MASTER_KEY=<32-byte hex>       # optional: without it a key is generated on first
                               # boot at DATA_DIR/master.key (0600) and reused.
                               # Back that file up: it decrypts your data.
MASTER_KEY_AUTOGENERATE=true   # set false to require an explicit MASTER_KEY
STORAGE_DRIVER=local|s3|discord|memory
CHUNK_SIZE=10420224            # clamps to 10 MiB minus overhead on Discord
WEBHOOKS=url1,url2             # required when any backend is discord
MASTER_KEY=<32-byte hex>       # envelope encryption; MASTER_KEY_FILE also supported
BOOTSTRAP_ADMIN_USER=admin
BOOTSTRAP_ADMIN_PASSWORD=<set before first boot>
NODE_NAME=az1 NODE_REGION=eu-west-1a   # used by replication/node identity
WEBDAV_PATH=/webdav  S3_PATH=/s3  REST_PATH=/api
```

The server prints the resolved storage configuration on every boot, e.g.
`[ddrive] storage=discord chunk=9.9 MiB data=5 webhook(s) db=sqlite`, so you
can always see which backend and chunk size are in effect.

## Compliance notes

Encryption and its audit trail are implemented (per-object encryption, wrapped
keys, hash-chained audit records, retention/legal hold, auditor role, metrics).
Certification (SOC 2 / ISO 27001 / HIPAA paperwork) is an organisational
process, not code — the technical controls it audits are the ones listed above.

---

### Original DDrive documentation (Discord-backed storage layer)


<p align="center"><strong> Turn Discord into a datastore that can manage and store your files. </strong></p>
<p align="center">
    <a href="https://discord.gg/3TCZRYafhW">
        <img src="https://img.shields.io/discord/1020806104881561754?color=5865F2&logo=discord&logoColor=white" alt="Discord server" /></a>
    <a href="https://github.com/forscht/ddrive/actions/workflows/lint.yml">
        <img src="https://github.com/forscht/ddrive/actions/workflows/lint.yml/badge.svg">
    </a>
    <a href="https://hub.docker.com/r/forscht/ddrive">
        <img src="https://img.shields.io/docker/v/forscht/ddrive?logo=docker">
    </a>
    <a href="https://hub.docker.com/r/forscht/ddrive">
        <img src="https://img.shields.io/docker/pulls/forscht/ddrive.svg?logo=docker">
    </a>
    <a href="https://github.com/forscht/ddrive/actions/workflows/codeql-analysis.yml">
        <img src="https://github.com/forscht/ddrive/actions/workflows/codeql-analysis.yml/badge.svg">
    </a>
    <a href="https://github.com/forscht/ddrive/blob/v2/LICENSE">
        <img src="https://img.shields.io/badge/License-MIT-yellow.svg">
    </a>

</p>
<br>

##### **DDrive** A lightweight cloud storage system using discord as storage device written in nodejs. Supports an unlimited file size and unlimited storage, Implemented using node js streams with multi-part up & download.

https://user-images.githubusercontent.com/59018146/167635903-48cdace0-c383-4e7d-a037-4a32eaa4ab69.mp4

#### Current stable branch `4.x`

### Live demo at [ddrive.forscht.dev](https://ddrive.forscht.dev/)

### Features
- Theoretically unlimited file size, thanks to splitting the file in 24mb chunks using nodejs streams API.
- Simple yet robust HTTP front end 
- Rest API with OpenAPI 3.1 specifications.
- Tested with storing 4000 GB of data on single discord channel (With max file size of 16GB).
- Supports basic auth with read only public access to panel.
- Easily deployable on heroku/replit and use as private cloud storage.

## New Version 4.0


This next major version release 4.0 is ddrive written from scratch. It comes with most requested features and several improvements.

- Now uses `postgres` to store files metadata. Why?
  - Once you have huge amount of data stored on ddrive it makes ddrive significantly slow to start since ddrive have to fetch all the metadata from discord channel (For 3 TB of data it takes me 30+ minutes.)
  - With postgres, deleting file is extremely faster because now ddrive don't have to delete files on discord channel and just need to remove from metadata only.
  - With postgres now it's possible to move or rename files/folders which was impossible with older version.
- Added support for `rename` files/folders.
- Added support to `move` file/folder (Only via API, Not sure how to do it with frontend, PR welcomes.)
- Now uses `webhooks` instead of `bot/user tokens` to bypass the discord rate limit
- DDrive now uploads file chunks in parallel with limit. Which significantly increase the upload speed. I was able to upload file with `5GB of size in just 85 seconds`.
- Public access mode - It is now possible to provide users read-only access with just one config var
- Batch upload files - Now you can upload multiple files at once from panel. (DClone support has been removed from this version)
- Bug fix - `download reset` for few mobile devices
- Added support for optional encryption to files uploaded to discord
- DDrive now has proper rest API with OpenAPI 3.1 standards
- Added support for dark/light mode on panel

I spent several weeks finalizing this new version.  Any support is highly appreciated - [Buy me a coffee](https://www.buymeacoffee.com/forscht)

### Requirements
- NodeJS v16.x or Docker
- Postgres Database, Discord Webhook URLs
- Avg technical knowledge

## Setup Guide
1. Clone this project
2. Create few webhook urls. For better performance and to avoid rate limit at least create 5 with 1 webhook / text channel. ([How to create webhook url](https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks))
3. Setup postgres using docker, if you already don't have it running
   - `cd .devcontainer`
   - `docker-compose up -d`
4. Copy `config/.env_sample` to `config/.env` and make necessary changes
5. Optional - If you have lots of webhookURLs you can put those in `webhook.txt` with `\n` seperated.
6. Run - `npm run migration:up`
7. Run - `node bin/ddrive`
8. Navigate to `http://localhost:3000` in your browser.

### How to keep it running forever
1. Install pm2 with `npm install -g pm2`
2. Run - `pm2 start bin/ddrive`
3. Run - `pm2 list` to check status of ddrive
4. Run - `pm2 logs` to check ddrive logs

### Config variables explanation
```shell
# config/.env

# Required params
DATABASE_URL= # Database URL of postgres with valid postgres uri

WEBHOOKS={url1},{url2} # Webhook urls seperated by ","

# Optional params
PORT=3000 # HTTP Port where ddrive panel will start running

REQUEST_TIMEOUT=60000 # Time in ms after which ddrive will abort request to discord api server. Set it high if you have very slow internet

CHUNK_SIZE=10420224 # ChunkSize in bytes. Max 10MB per Discord webhook request (10 MiB = 10485760 bytes),
                     # so anything larger is rejected with HTTP 413 and clamped by DDrive at boot.

SECRET=someverysecuresecret # If you set this every files on discord will be stored using strong encryption, but it will cause significantly high cpu usage, so don't use it unless you're storing important stuff

AUTH=admin:admin # Username password seperated by ":". If you set this panel will ask for username password before access

PUBLIC_ACCESS=READ_ONLY_FILE # If you want to give read only access to panel or file use this option. Check below for valid options.
                             # READ_ONLY_FILE - User will be only access download links of file and not panel
                             # READ_ONLY_PANEL - User will be able to browse the panel for files/directories but won't be able to upload/delete/rename any file/folder.

UPLOAD_CONCURRENCY=3 # ddrive will upload this many chunks in parallel to discord. If you have fast internet increasing it will significantly increase performance at cost of cpu/disk usage                                              

```

### Run using docker
```shell
docker run -rm -it -p 8080:8080 \
-e PORT=8080 \
-e WEBHOOKS={url1},{url2} \
-e DATABASE_URL={database url} \
--name ddrive forscht/ddrive
```
### One Click Deploy with Railway
[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/new/template/tL53xa)

### Setup tutorials
- Setup under 4 minutes in local/cloud server using `neon.tech` postgres - [Youtube](https://youtu.be/Zvr1BHjrYC0)
## API Usage
`npm install @forscht/ddrive`
```javascript
const { DFs, HttpServer } = require('@forscht/ddrive')

const DFsConfig = {
  chunkSize: 25165824,
  webhooks: 'webhookURL1,webhookURL2',
  secret: 'somerandomsecret',
  maxConcurrency: 3, // UPLOAD_CONCURRENCY
  restOpts: {
    timeout: '60000',
  },
}

const httpConfig = {
  authOpts: {
    auth: { user: 'admin', pass: 'admin' },
    publicAccess: 'READ_ONLY_FILE', // or 'READ_ONLY_PANEL'
  },
  port: 8080,
}

const run = async () => {
  // Create DFs Instance
  const dfs = new DFs(DFsConfig)
  // Create HTTP Server instance
  const httpServer = HttpServer(dfs, httpConfig)

  return httpServer.listen({ host: '0.0.0.0', port: httpConfig.port })
}

run().then()

```

## Migrate from v3 to v4
Migrating ddrive v3 to v4 is one way process once you migrate ddrive to v4 and add new files you can't migrate new files to v3 again but you can still use v3 with old files.

1. Clone this project
2. Create few webhooks (1 webhook/text channel). Do not create webhook on old text channel where you have already stored v3 data.
3. Take pull of latest ddrive v3
4. Start ddrive v3 with option `--metadata=true`. Ex - `ddrive --channelId {id} --token {token} --metadata=true`
5. Open `localhost:{ddrive-port}/metadata` in browser
6. Save JSON as old_data.json in cloned ddrive directory
7. Put valid `DATABASE_URL` in `config/.env`
8. Run `node bin/migrate old_data.json`
9. After few seconds once process is done you should see the message `Migration is done`

Feel free to create [new issue](https://github.com/forscht/ddrive/issues/new) if it's not working for you or need any help.

[Discord Support server](https://discord.gg/3TCZRYafhW)

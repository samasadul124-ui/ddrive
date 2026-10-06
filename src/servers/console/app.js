/* eslint-disable no-alert,no-restricted-syntax,no-await-in-loop */
/**
 * DDrive console: single page admin UI on top of the REST API.
 * No build step, no framework - just fetch() + DOM.
 */
const state = {
    token: localStorage.getItem('ddrive_token') || '',
    user: null,
    tab: localStorage.getItem('ddrive_tab') || 'dashboard',
    bucket: localStorage.getItem('ddrive_bucket') || '',
    prefix: '',
    data: {},
}

const TABS = [
    ['dashboard', 'Dashboard'],
    ['objects', 'Objects'],
    ['buckets', 'Buckets'],
    ['access', 'Access'],
    ['compliance', 'Compliance'],
    ['data', 'Lifecycle & Tiering'],
    ['replication', 'Replication'],
    ['events', 'Events & Tagging'],
    ['settings', 'Settings'],
]

const $ = (id) => document.getElementById(id)
const esc = (value) => String(value === undefined || value === null ? '' : value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')

const bytes = (n) => {
    const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
    let value = Number(n) || 0
    let i = 0
    while (value >= 1024 && i < units.length - 1) { value /= 1024; i += 1; }

    return `${value.toFixed(i === 0 ? 0 : 1)} ${units[i]}`
}

function toast(message, isError = false) {
    const el = $('toast')
    el.textContent = message
    el.className = `toast show${isError ? ' err' : ''}`
    setTimeout(() => { el.className = 'toast' }, 3800)
}

async function api(path, options = {}) {
    const headers = { ...(options.headers || {}) }
    if (state.token) headers.authorization = `Bearer ${state.token}`
    if (options.body && !(options.body instanceof FormData)) headers['content-type'] = 'application/json'
    const res = await fetch(path, {
        ...options,
        headers,
        body: options.body && !(options.body instanceof FormData) ? JSON.stringify(options.body) : options.body,
    })
    const contentType = res.headers.get('content-type') || ''
    const payload = contentType.includes('json') ? await res.json().catch(() => ({})) : await res.text()
    if (!res.ok) {
        const message = (payload && payload.message) || (payload && payload.error) || res.statusText
        throw new Error(`${res.status} ${message}`)
    }

    return payload
}

const get = (path) => api(path)
const post = (path, body) => api(path, { method: 'POST', body })
const put = (path, body) => api(path, { method: 'PUT', body })
const patch = (path, body) => api(path, { method: 'PATCH', body })
const del = (path) => api(path, { method: 'DELETE' })

// ---------------------------------------------------------------------------
// Login / session
// ---------------------------------------------------------------------------
async function bootstrap() {
    $('tabs').innerHTML = TABS.map(([id, label]) => `<button data-tab="${id}" class="${state.tab === id ? 'active' : ''}">${label}</button>`).join('')
    $('tabs').onclick = (e) => {
        const tab = e.target.closest('button')?.dataset.tab
        if (!tab) return
        state.tab = tab
        localStorage.setItem('ddrive_tab', tab)
        render()
    }
    $('theme').onclick = () => {
        document.documentElement.classList.toggle('light')
        localStorage.setItem('ddrive_mode', document.documentElement.classList.contains('light') ? 'light' : 'dark')
    }
    if (localStorage.getItem('ddrive_mode') === 'light') document.documentElement.classList.add('light')

    $('login-form').onsubmit = async (event) => {
        event.preventDefault()
        $('login-error').textContent = ''
        try {
            const res = await post('/api/login', {
                username: $('login-user').value,
                password: $('login-pass').value,
                mfaCode: $('login-mfa').value || undefined,
            })
            state.token = res.token
            localStorage.setItem('ddrive_token', res.token)
            await render()
        } catch (err) {
            $('login-error').textContent = err.message
        }
    }

    try {
        state.user = (await get('/api/me')).user
    } catch {
        state.user = null
    }
    await render()
}

async function guarded(loader) {
    try {
        return await loader()
    } catch (err) {
        if (/^401/.test(err.message)) {
            state.user = null
            state.token = ''
            localStorage.removeItem('ddrive_token')
            render()

            return null
        }
        toast(err.message, true)

        return null
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------
async function render() {
    const loggedIn = !!state.user
    $('login-view').classList.toggle('hidden', loggedIn)
    $('tabs').classList.toggle('hidden', !loggedIn)
    $('identity').textContent = loggedIn ? `${state.user.name}${state.user.isAdmin ? ' (admin)' : ''}` : 'not signed in'
    if (!loggedIn) {
        $('view').innerHTML = ''
        $('view').appendChild($('login-view'))
        $('login-view').classList.remove('hidden')

        return
    }
    const view = $('view')
    view.innerHTML = '<div class="card">Loading…</div>'
    const renderers = {
        dashboard: renderDashboard,
        objects: renderObjects,
        buckets: renderBuckets,
        access: renderAccess,
        compliance: renderCompliance,
        data: renderLifecycleTiering,
        replication: renderReplication,
        events: renderEvents,
        settings: renderSettings,
    }
    const html = await guarded(renderers[state.tab] || renderDashboard)
    if (html === null) return
    view.innerHTML = html
    const after = AFTER[state.tab]
    if (after) after()
}

const AFTER = {}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------
async function renderDashboard() {
    const overview = await get('/api/admin/overview')
    const health = overview.health || {}
    const storage = health.storage || {}
    const cards = [
        ['Objects', overview.totals.objects],
        ['Stored bytes', bytes(overview.totals.bytes)],
        ['Versions', overview.totals.versions],
        ['Buckets', overview.buckets.length],
    ].map(([label, value]) => `<div class="stat"><div class="label">${label}</div><div class="value">${value}</div></div>`).join('')

    const bucketRows = overview.buckets.map((b) => `<tr>
        <td><strong>${esc(b.name)}</strong></td>
        <td>${b.versioning === 'enabled' ? '<span class="badge ok">versioned</span>' : `<span class="badge">${b.versioning}</span>`}</td>
        <td>${b.objectLockEnabled ? '<span class="badge ok">locked</span>' : '<span class="badge">—</span>'}</td>
        <td>${b.objects}</td>
        <td>${bytes(b.bytes)}</td>
        <td>${b.versions}</td>
    </tr>`).join('')

    const tiers = (overview.tiers || []).map((t) => `<tr><td>${esc(t.tier)}</td><td>${t.versions}</td><td>${bytes(t.bytes)}</td></tr>`).join('')
    const storageRows = Object.entries(storage).map(([tier, info]) => `<tr><td>${esc(tier)}</td><td>${info.ok ? '<span class="badge ok">ok</span>' : '<span class="badge err">down</span>'}</td><td class="mono">${esc(info.backend || '')} ${esc(info.root || info.bucket || '')}</td></tr>`).join('')

    return `
    <div class="grid cols-4">${cards}</div>
    <div class="card">
        <h2>Posture</h2>
        <div class="row">
            <span class="badge ${health.database?.ok ? 'ok' : 'err'}">database: ${esc(health.database?.driver)}</span>
            <span class="badge ${overview.encryption.enabled ? 'ok' : 'warn'}">encryption: ${overview.encryption.enabled ? esc(overview.encryption.algorithm) : 'disabled'}</span>
            <span class="badge">key: ${esc(overview.encryption.keyId || '—')}</span>
            <span class="badge">node: ${esc(overview.node.name)} / ${esc(overview.node.region)}</span>
            <span class="badge">version: ${esc(overview.version)}</span>
            <span class="badge">audit events: ${overview.audit?.total ?? 0}</span>
        </div>
    </div>
    <div class="grid cols-2">
        <div class="card"><h2>Buckets</h2><table><thead><tr><th>Name</th><th>Versioning</th><th>Lock</th><th>Objects</th><th>Bytes</th><th>Versions</th></tr></thead><tbody>${bucketRows}</tbody></table></div>
        <div>
            <div class="card"><h2>Tier distribution</h2><table><thead><tr><th>Tier</th><th>Versions</th><th>Bytes</th></tr></thead><tbody>${tiers || '<tr><td colspan="3" class="muted">no data</td></tr>'}</tbody></table></div>
            <div class="card"><h2>Storage backends</h2><table><thead><tr><th>Tier</th><th>Status</th><th>Backend</th></tr></thead><tbody>${storageRows}</tbody></table></div>
        </div>
    </div>
    <div class="card"><h2>Replication backlog</h2><pre class="mono">${esc(JSON.stringify(overview.replication, null, 2))}</pre></div>`
}

// ---------------------------------------------------------------------------
// Objects browser
// ---------------------------------------------------------------------------
async function renderObjects() {
    const { buckets } = await get('/api/buckets')
    if (!state.bucket && buckets.length) state.bucket = buckets[0].name
    const bucket = state.bucket || buckets[0]?.name
    if (!bucket) return '<div class="card">No buckets yet. Create one under <em>Buckets</em>.</div>'
    const prefix = state.prefix || ''
    const listing = await get(`/api/buckets/${encodeURIComponent(bucket)}/objects?prefix=${encodeURIComponent(prefix)}&delimiter=/`)
    const rows = [
        ...listing.prefixes.map((p) => {
            const name = p.slice(prefix.length).replace(/\/$/, '')

            return `<tr><td><a href="#" data-dir="${esc(name)}">📁 ${esc(name)}</a></td><td>—</td><td>—</td><td>—</td><td></td></tr>`
        }),
        ...listing.objects.map((o) => `<tr>
            <td><a href="/api/buckets/${encodeURIComponent(bucket)}/objects/${esc(o.path)}/download">📄 ${esc(o.name)}</a></td>
            <td>${bytes(o.size)}</td>
            <td>${esc(o.storageClass)}</td>
            <td class="mono">${esc(o.etag || '').slice(0, 12)}</td>
            <td class="row">
                <button class="ghost" data-tags="${esc(o.path)}">tags</button>
                <button class="ghost" data-versions="${esc(o.path)}">versions</button>
                <button class="ghost" data-share="${esc(o.path)}">share</button>
                <button class="ghost danger" data-delete="${esc(o.path)}">delete</button>
            </td>
        </tr>`),
    ].join('')

    const breadcrumbs = prefix
        ? `<a href="#" data-dir="..">↑ up</a> / <span class="mono">${esc(prefix)}</span>`
        : '<span class="muted">bucket root</span>'

    return `
    <div class="card">
        <div class="row">
            <select id="bucket-select" style="max-width:220px">${buckets.map((b) => `<option ${b.name === bucket ? 'selected' : ''}>${esc(b.name)}</option>`).join('')}</select>
            <span>${breadcrumbs}</span>
            <div class="spacer"></div>
            <input id="upload-path" placeholder="path (optional)" style="max-width:200px">
            <input id="upload-file" type="file" multiple style="max-width:260px">
            <button class="primary" id="upload-btn">Upload</button>
            <button class="ghost" id="mkdir-btn">New folder</button>
        </div>
    </div>
    <div class="card">
        <h2>Objects in ${esc(bucket)}${prefix ? ` / ${esc(prefix)}` : ''}</h2>
        <table><thead><tr><th>Name</th><th>Size</th><th>Class</th><th>ETag</th><th></th></tr></thead><tbody>${rows || '<tr><td colspan="5" class="muted">empty</td></tr>'}</tbody></table>
        ${listing.isTruncated ? '<p class="hint">Listing truncated — refine the prefix or use the S3 API for full pagination.</p>' : ''}
    </div>
    <div class="card hidden" id="detail-card"><h2 id="detail-title"></h2><div id="detail-body"></div></div>`
}

AFTER.objects = () => {
    const select = $('bucket-select')
    if (select) {
        select.onchange = () => {
            state.bucket = select.value
            state.prefix = ''
            localStorage.setItem('ddrive_bucket', state.bucket)
            render()
        }
    }
    document.querySelectorAll('[data-dir]').forEach((el) => {
        el.onclick = (event) => {
            event.preventDefault()
            const target = el.dataset.dir
            if (target === '..') state.prefix = state.prefix.replace(/[^/]+\/$/, '')
            else state.prefix = `${state.prefix}${target}/`
            render()
        }
    })
    document.querySelectorAll('[data-delete]').forEach((el) => {
        el.onclick = async () => {
            if (!confirm(`Delete ${el.dataset.delete}?`)) return
            try {
                await del(`/api/buckets/${state.bucket}/objects/${el.dataset.delete}?permanent=true`)
                toast('Deleted')
                render()
            } catch (err) { toast(err.message, true) }
        }
    })
    document.querySelectorAll('[data-tags]').forEach((el) => {
        el.onclick = () => showTags(el.dataset.tags)
    })
    document.querySelectorAll('[data-versions]').forEach((el) => {
        el.onclick = () => showVersions(el.dataset.versions)
    })
    document.querySelectorAll('[data-share]').forEach((el) => {
        el.onclick = async () => {
            try {
                const share = await post(`/api/buckets/${state.bucket}/shares`, { path: el.dataset.share })
                const url = `${location.origin}${share.url}`
                await navigator.clipboard?.writeText(url).catch(() => {})
                toast(`Share link copied: ${url}`)
            } catch (err) { toast(err.message, true) }
        }
    })
    const uploadBtn = $('upload-btn')
    if (uploadBtn) {
        uploadBtn.onclick = async () => {
            const files = $('upload-file').files
            if (!files.length) return toast('Pick a file first', true)
            const explicit = $('upload-path').value.trim()
            for (const file of files) {
                const path = explicit && files.length === 1 ? explicit : `${state.prefix}${file.name}`
                const form = new FormData()
                form.append('file', file)
                try {
                    await api(`/api/buckets/${state.bucket}/objects?path=${encodeURIComponent(path)}`, { method: 'POST', body: form })
                    toast(`Uploaded ${path}`)
                } catch (err) { toast(`${path}: ${err.message}`, true) }
            }
            render()
        }
    }
    const mkdir = $('mkdir-btn')
    if (mkdir) {
        mkdir.onclick = async () => {
            const name = prompt('Folder name')
            if (!name) return
            try {
                await put(`/api/buckets/${state.bucket}/objects/${state.prefix}${name}/.keep`, '')
                await del(`/api/buckets/${state.bucket}/objects/${state.prefix}${name}/.keep?permanent=true`)
                toast('Folder created')
                render()
            } catch (err) { toast(err.message, true) }
        }
    }
}

async function showTags(path) {
    const card = $('detail-card')
    card.classList.remove('hidden')
    $('detail-title').textContent = `Tags — ${path}`
    const { tags } = await get(`/api/buckets/${state.bucket}/objects/${path}/tags`)
    $('detail-body').innerHTML = `
        <div class="row"><input id="tag-input" value="${esc(Object.entries(tags).map(([k, v]) => `${k}=${v}`).join(', '))}" placeholder="key=value, key2=value2">
        <button class="primary" id="tag-save">Save tags</button>
        <span class="hint">AI tags are prefixed with ai:</span></div>
        <pre class="mono">${esc(JSON.stringify(tags, null, 2))}</pre>`
    $('tag-save').onclick = async () => {
        const parsed = {}
        $('tag-input').value.split(',').forEach((pair) => {
            const [key, ...rest] = pair.split('=')
            if (key && key.trim()) parsed[key.trim()] = rest.join('=').trim()
        })
        try {
            await put(`/api/buckets/${state.bucket}/objects/${path}/tags`, { tags: parsed })
            toast('Tags saved')
        } catch (err) { toast(err.message, true) }
    }
}

async function showVersions(path) {
    const card = $('detail-card')
    card.classList.remove('hidden')
    $('detail-title').textContent = `Versions — ${path}`
    const { versions } = await get(`/api/buckets/${state.bucket}/objects/${path}/versions`)
    $('detail-body').innerHTML = `<table><thead><tr><th>Version</th><th>Size</th><th>Tier</th><th>Created</th><th>Flags</th><th></th></tr></thead><tbody>
    ${versions.map((v) => `<tr>
        <td class="mono">${esc(v.versionId).slice(0, 8)} (v${v.versionNumber})</td>
        <td>${bytes(v.size)}</td><td>${esc(v.tier)}</td><td>${esc(v.createdAt)}</td>
        <td>${v.isLatest ? '<span class="badge ok">latest</span>' : ''}${v.isDeleteMarker ? '<span class="badge warn">delete marker</span>' : ''}${v.encrypted ? '<span class="badge">encrypted</span>' : ''}${v.legalHold ? '<span class="badge err">legal hold</span>' : ''}${v.retainedUntil ? `<span class="badge">${esc(v.retainedUntil)}</span>` : ''}</td>
        <td class="row">
            <a class="ghost" href="/api/buckets/${state.bucket}/objects/${path}/download?versionId=${v.versionId}">download</a>
            <button class="ghost" data-retain="${v.versionId}">retention</button>
            <button class="ghost danger" data-delete-version="${v.versionId}">delete</button>
        </td></tr>`).join('')}
    </tbody></table>`
    document.querySelectorAll('[data-delete-version]').forEach((el) => {
        el.onclick = async () => {
            try {
                await del(`/api/buckets/${state.bucket}/objects/${path}?versionId=${el.dataset.deleteVersion}`)
                toast('Version deleted')
                showVersions(path)
            } catch (err) { toast(err.message, true) }
        }
    })
    document.querySelectorAll('[data-retain]').forEach((el) => {
        el.onclick = async () => {
            const mode = prompt('Retention mode: GOVERNANCE, COMPLIANCE, or blank to remove', 'GOVERNANCE')
            if (mode === null) return
            const days = Number(prompt('Retain for how many days?', '30') || 0)
            try {
                await put(`/api/buckets/${state.bucket}/objects/${path}/retention?versionId=${el.dataset.retain}`, mode
                    ? { mode, retainUntil: new Date(Date.now() + days * 86400000).toISOString() }
                    : { legalHold: false })
                toast('Retention updated')
            } catch (err) { toast(err.message, true) }
        }
    })
}

// ---------------------------------------------------------------------------
// Buckets
// ---------------------------------------------------------------------------
async function renderBuckets() {
    const { buckets } = await get('/api/buckets')
    const rows = buckets.map((b) => `<tr>
        <td><strong>${esc(b.name)}</strong></td>
        <td>${esc(b.region)}</td>
        <td><span class="badge ${b.versioning === 'enabled' ? 'ok' : ''}">${esc(b.versioning)}</span></td>
        <td>${b.objectLockEnabled ? '<span class="badge ok">enabled</span>' : '<span class="badge">disabled</span>'}</td>
        <td>${b.quotaBytes ? bytes(b.quotaBytes) : 'unlimited'}</td>
        <td>${b.stats.objects} / ${bytes(b.stats.bytes)}</td>
        <td class="row">
            <button class="ghost" data-versioning="${esc(b.name)}" data-current="${esc(b.versioning)}">versioning</button>
            <button class="ghost" data-lock="${esc(b.name)}" data-enabled="${b.objectLockEnabled}">object lock</button>
            <button class="ghost" data-quota="${esc(b.name)}">quota</button>
            <button class="ghost danger" data-drop="${esc(b.name)}">delete</button>
        </td>
    </tr>`).join('')

    return `
    <div class="card">
        <h2>Create bucket</h2>
        <div class="row">
            <input id="new-bucket" placeholder="bucket-name" style="max-width:240px">
            <label class="hint"><input type="checkbox" id="new-bucket-lock" style="width:auto"> object lock (WORM)</label>
            <button class="primary" id="create-bucket">Create</button>
        </div>
        <p class="hint">Versioning is enabled by default for new buckets. Object lock must be enabled at creation time for compliance/WORM use.</p>
    </div>
    <div class="card"><h2>Buckets</h2><table><thead><tr><th>Name</th><th>Region</th><th>Versioning</th><th>Object lock</th><th>Quota</th><th>Usage</th><th></th></tr></thead><tbody>${rows || '<tr><td colspan="7" class="muted">none</td></tr>'}</tbody></table></div>`
}

AFTER.buckets = () => {
    $('create-bucket').onclick = async () => {
        try {
            await post('/api/buckets', { name: $('new-bucket').value, objectLockEnabled: $('new-bucket-lock').checked })
            toast('Bucket created')
            render()
        } catch (err) { toast(err.message, true) }
    }
    document.querySelectorAll('[data-versioning]').forEach((el) => {
        el.onclick = async () => {
            const next = el.dataset.current === 'enabled' ? 'off' : 'enabled'
            try {
                await patch(`/api/buckets/${el.dataset.versioning}`, { versioning: next })
                toast(`Versioning ${next}`)
                render()
            } catch (err) { toast(err.message, true) }
        }
    })
    document.querySelectorAll('[data-lock]').forEach((el) => {
        el.onclick = async () => {
            const enabled = el.dataset.enabled === 'true'
            const mode = enabled ? undefined : prompt('Default retention mode (GOVERNANCE/COMPLIANCE), blank for none', 'GOVERNANCE')
            const days = enabled || !mode ? undefined : Number(prompt('Default retention days', '30') || 0)
            try {
                await api(`/api/buckets/${el.dataset.lock}`, {
                    method: 'PATCH',
                    body: { objectLockEnabled: true, defaultRetentionMode: mode || null, defaultRetentionDays: days || null },
                })
                toast('Object lock updated')
                render()
            } catch (err) { toast(err.message, true) }
        }
    })
    document.querySelectorAll('[data-quota]').forEach((el) => {
        el.onclick = async () => {
            const value = prompt('Quota in bytes (blank = unlimited)', '')
            if (value === null) return
            try {
                await patch(`/api/buckets/${el.dataset.quota}`, { quotaBytes: value === '' ? null : Number(value) })
                toast('Quota updated')
                render()
            } catch (err) { toast(err.message, true) }
        }
    })
    document.querySelectorAll('[data-drop]').forEach((el) => {
        el.onclick = async () => {
            if (!confirm(`Delete bucket ${el.dataset.drop} including all objects?`)) return
            try {
                await del(`/api/buckets/${el.dataset.drop}?force=true`)
                toast('Bucket deleted')
                render()
            } catch (err) { toast(err.message, true) }
        }
    })
}

// ---------------------------------------------------------------------------
// Access (IAM)
// ---------------------------------------------------------------------------
async function renderAccess() {
    const [users, groups, roles, policies, keys] = await Promise.all([
        get('/api/admin/users'), get('/api/admin/groups'), get('/api/admin/roles'), get('/api/admin/policies'), get('/api/admin/access-keys'),
    ])
    const userRows = users.users.map((u) => `<tr>
        <td><strong>${esc(u.username)}</strong><div class="hint">${esc(u.displayName || '')}</div></td>
        <td>${u.isAdmin ? '<span class="badge ok">admin</span>' : '<span class="badge">user</span>'}</td>
        <td>${esc((u.roles || []).join(', '))}</td>
        <td>${u.mfaEnabled ? '<span class="badge ok">mfa</span>' : '<span class="badge">—</span>'}</td>
        <td><span class="badge ${u.status === 'active' ? 'ok' : 'err'}">${esc(u.status)}</span></td>
        <td>${esc(u.lastLoginAt || '')}</td>
        <td class="row">
            <button class="ghost" data-roles="${esc(u.username)}">roles</button>
            <button class="ghost" data-key="${esc(u.username)}">add key</button>
            <button class="ghost" data-pass="${esc(u.username)}">password</button>
            <button class="ghost" data-disable="${esc(u.username)}" data-status="${esc(u.status)}">${u.status === 'active' ? 'disable' : 'enable'}</button>
            <button class="ghost danger" data-del-user="${esc(u.username)}">delete</button>
        </td>
    </tr>`).join('')

    const policyRows = policies.policies.map((p) => `<tr><td><strong>${esc(p.name)}</strong>${p.system ? ' <span class="badge">built-in</span>' : ''}</td><td>${esc(p.description || '')}</td><td class="mono"><pre>${esc(JSON.stringify(p.document, null, 1))}</pre></td></tr>`).join('')
    const keyRows = keys.keys.map((k) => `<tr><td class="mono">${esc(k.accessKeyId)}</td><td>${esc(k.userId)}</td><td><span class="badge ${k.status === 'active' ? 'ok' : 'err'}">${esc(k.status)}</span></td><td>${esc(k.lastUsedAt || '—')}</td><td class="row"><button class="ghost" data-rotate="${esc(k.accessKeyId)}">rotate</button><button class="ghost danger" data-del-key="${esc(k.accessKeyId)}">revoke</button></td></tr>`).join('')

    return `
    <div class="card">
        <h2>Create user</h2>
        <div class="row">
            <input id="user-name" placeholder="username" style="max-width:180px">
            <input id="user-pass" type="password" placeholder="password (min 8, upper+lower+digit)" style="max-width:280px">
            <label class="hint"><input type="checkbox" id="user-admin" style="width:auto"> administrator</label>
            <input id="user-quota" placeholder="quota bytes (optional)" style="max-width:180px">
            <button class="primary" id="create-user">Create</button>
        </div>
    </div>
    <div class="card"><h2>Users</h2><table><thead><tr><th>User</th><th>Type</th><th>Roles</th><th>MFA</th><th>Status</th><th>Last login</th><th></th></tr></thead><tbody>${userRows || '<tr><td colspan="7" class="muted">none</td></tr>'}</tbody></table></div>
    <div class="grid cols-2">
        <div class="card"><h2>Access keys (S3 / SigV4)</h2><table><thead><tr><th>Key id</th><th>User</th><th>Status</th><th>Last used</th><th></th></tr></thead><tbody>${keyRows || '<tr><td colspan="5" class="muted">none</td></tr>'}</tbody></table></div>
        <div class="card"><h2>Roles</h2><table><thead><tr><th>Role</th><th>Policies</th></tr></thead><tbody>${roles.roles.map((r) => `<tr><td>${esc(r.name)}${r.system ? ' <span class="badge">built-in</span>' : ''}<div class="hint">${esc(r.description || '')}</div></td><td class="mono">${esc((r.policies || []).map((p) => p.name || '').join(', '))}</td></tr>`).join('')}</tbody></table>
        <h3>Groups</h3>
        <table><tbody>${groups.groups.map((g) => `<tr><td>${esc(g.name)}</td><td class="hint">${esc(g.description || '')}</td><td><button class="ghost danger" data-del-group="${esc(g.name)}">delete</button></td></tr>`).join('') || '<tr><td class="muted">no groups</td></tr>'}</tbody></table>
        <div class="row"><input id="group-name" placeholder="new group" style="max-width:200px"><button class="ghost" id="create-group">Add group</button></div>
        </div>
    </div>
    <div class="card"><h2>Policies</h2><table><thead><tr><th>Name</th><th>Description</th><th>Document</th></tr></thead><tbody>${policyRows}</tbody></table>
        <h3>Create policy</h3>
        <div class="row"><input id="policy-name" placeholder="policy name" style="max-width:200px"></div>
        <textarea id="policy-doc" rows="6" class="mono" placeholder='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:ddrive:s3:::media/*"]}]}'></textarea>
        <div class="row end"><button class="primary" id="create-policy">Create policy</button></div>
    </div>`
}

AFTER.access = () => {
    $('create-user').onclick = async () => {
        try {
            await post('/api/admin/users', {
                username: $('user-name').value,
                password: $('user-pass').value,
                isAdmin: $('user-admin').checked,
                quotaBytes: $('user-quota').value ? Number($('user-quota').value) : undefined,
            })
            toast('User created')
            render()
        } catch (err) { toast(err.message, true) }
    }
    $('create-group').onclick = async () => {
        try {
            await post('/api/admin/groups', { name: $('group-name').value })
            toast('Group created')
            render()
        } catch (err) { toast(err.message, true) }
    }
    $('create-policy').onclick = async () => {
        try {
            await post('/api/admin/policies', { name: $('policy-name').value, document: JSON.parse($('policy-doc').value) })
            toast('Policy created')
            render()
        } catch (err) { toast(err.message, true) }
    }
    document.querySelectorAll('[data-del-user]').forEach((el) => {
        el.onclick = async () => {
            if (!confirm(`Delete ${el.dataset.delUser}?`)) return
            try {
                await del(`/api/admin/users/${el.dataset.delUser}`)
                toast('User deleted')
                render()
            } catch (err) { toast(err.message, true) }
        }
    })
    document.querySelectorAll('[data-disable]').forEach((el) => {
        el.onclick = async () => {
            try {
                await patch(`/api/admin/users/${el.dataset.disable}`, { status: el.dataset.status === 'active' ? 'disabled' : 'active' })
                render()
            } catch (err) { toast(err.message, true) }
        }
    })
    document.querySelectorAll('[data-pass]').forEach((el) => {
        el.onclick = async () => {
            const password = prompt(`New password for ${el.dataset.pass}`)
            if (!password) return
            try {
                await patch(`/api/admin/users/${el.dataset.pass}`, { password })
                toast('Password changed')
            } catch (err) { toast(err.message, true) }
        }
    })
    document.querySelectorAll('[data-roles]').forEach((el) => {
        el.onclick = async () => {
            const roles = prompt('Comma separated role names (Administrators, StorageUsers, ReadOnly, Auditors)', 'StorageUsers')
            if (roles === null) return
            try {
                await patch(`/api/admin/users/${el.dataset.roles}`, { roles: roles.split(',').map((r) => r.trim()).filter(Boolean) })
                toast('Roles updated')
                render()
            } catch (err) { toast(err.message, true) }
        }
    })
    document.querySelectorAll('[data-key]').forEach((el) => {
        el.onclick = async () => {
            try {
                const key = await post('/api/admin/access-keys', { username: el.dataset.key })
                alert(`Access key created (store the secret now):\n\nAccessKeyId: ${key.accessKeyId}\nSecretAccessKey: ${key.secretAccessKey}`)
                render()
            } catch (err) { toast(err.message, true) }
        }
    })
    document.querySelectorAll('[data-del-key]').forEach((el) => {
        el.onclick = async () => {
            if (!confirm('Revoke this access key?')) return
            try {
                await del(`/api/admin/access-keys/${el.dataset.delKey}`)
                render()
            } catch (err) { toast(err.message, true) }
        }
    })
    document.querySelectorAll('[data-rotate]').forEach((el) => {
        el.onclick = async () => {
            try {
                const key = await post(`/api/admin/access-keys/${el.dataset.rotate}/rotate`)
                alert(`New secret for ${key.accessKeyId}:\n\n${key.secretAccessKey}`)
            } catch (err) { toast(err.message, true) }
        }
    })
    document.querySelectorAll('[data-del-group]').forEach((el) => {
        el.onclick = async () => {
            try {
                await del(`/api/admin/groups/${el.dataset.delGroup}`)
                render()
            } catch (err) { toast(err.message, true) }
        }
    })
}

// ---------------------------------------------------------------------------
// Compliance
// ---------------------------------------------------------------------------
async function renderCompliance() {
    const [auditData, verification] = await Promise.all([
        get('/api/admin/audit?limit=100'),
        get('/api/admin/audit/verify').catch((err) => ({ ok: false, error: err.message })),
    ])
    const rows = auditData.events.map((e) => `<tr>
        <td class="mono">${e.seq}</td>
        <td>${esc(e.ts)}</td>
        <td>${esc(e.actor || 'system')}</td>
        <td><span class="badge ${e.result === 'success' ? 'ok' : e.result === 'denied' ? 'warn' : 'err'}">${esc(e.result)}</span></td>
        <td class="mono">${esc(e.action)}</td>
        <td>${esc(e.bucket || '')}${e.objectKey ? `/${esc(e.objectKey)}` : ''}</td>
        <td>${esc(e.protocol || '')} ${esc(e.ip || '')}</td>
    </tr>`).join('')

    return `
    <div class="card">
        <div class="row">
            <h2 style="margin:0">Audit log</h2>
            <div class="spacer"></div>
            <span class="badge ${verification.ok ? 'ok' : 'err'}">hash chain: ${verification.ok ? `verified (${verification.checked} events)` : 'BROKEN'}</span>
            <a class="ghost" href="/api/admin/audit/export">export CSV</a>
            <button class="ghost" id="refresh-audit">refresh</button>
        </div>
        <p class="hint">Append-only SHA-256 hash chain. Any modification, deletion or reordering of a record breaks verification.</p>
        <table><thead><tr><th>#</th><th>Time</th><th>Actor</th><th>Result</th><th>Action</th><th>Resource</th><th>Source</th></tr></thead><tbody>${rows || '<tr><td colspan="7" class="muted">no events</td></tr>'}</tbody></table>
    </div>
    <div class="card">
        <h2>Object lock &amp; legal hold</h2>
        <p class="hint">Buckets with Object Lock enabled enforce WORM semantics: COMPLIANCE retention cannot be shortened or bypassed by anyone, GOVERNANCE retention requires <code>s3:BypassGovernanceRetention</code>.</p>
        <div id="lock-summary"></div>
    </div>`
}

AFTER.compliance = async () => {
    $('refresh-audit').onclick = () => render()
    const { buckets } = await get('/api/buckets').catch(() => ({ buckets: [] }))
    const locked = buckets.filter((b) => b.objectLockEnabled)
    $('lock-summary').innerHTML = locked.length
        ? `<table><thead><tr><th>Bucket</th><th>Region</th><th>Objects</th><th>Bytes</th></tr></thead><tbody>${locked.map((b) => `<tr><td>${esc(b.name)}</td><td>${esc(b.region)}</td><td>${b.stats.objects}</td><td>${bytes(b.stats.bytes)}</td></tr>`).join('')}</tbody></table>`
        : '<p class="muted">No bucket has Object Lock enabled yet.</p>'
}

// ---------------------------------------------------------------------------
// Lifecycle & tiering
// ---------------------------------------------------------------------------
async function renderLifecycleTiering() {
    const { buckets } = await get('/api/buckets')
    const bucket = state.bucket || buckets[0]?.name
    const [lifecycle, tiering] = await Promise.all([
        get(`/api/admin/lifecycle?bucket=${encodeURIComponent(bucket)}`),
        get(`/api/admin/tiering?bucket=${encodeURIComponent(bucket)}`),
    ])
    const ruleRows = lifecycle.rules.map((r) => `<tr>
        <td><strong>${esc(r.name)}</strong><div class="hint">${esc(r.prefix ? `prefix ${r.prefix}` : 'whole bucket')}</div></td>
        <td><span class="badge ${r.status === 'Enabled' ? 'ok' : ''}">${esc(r.status)}</span></td>
        <td class="mono">${esc(JSON.stringify(r.transitions || []))}</td>
        <td>${r.expirationDays ?? '—'}</td>
        <td>${r.noncurrentVersionExpirationDays ?? '—'}${r.noncurrentVersionsToRetain ? ` (keep ${r.noncurrentVersionsToRetain})` : ''}</td>
        <td>${r.abortIncompleteMultipartDays ?? '—'}</td>
        <td class="row">
            <button class="ghost" data-toggle-rule="${r.id}" data-status="${esc(r.status)}">${r.status === 'Enabled' ? 'disable' : 'enable'}</button>
            <button class="ghost danger" data-del-rule="${r.id}">delete</button>
        </td></tr>`).join('')

    const policyRows = tiering.policies.map((p) => `<tr>
        <td><strong>${esc(p.name)}</strong></td>
        <td><span class="badge ${p.enabled ? 'ok' : ''}">${p.enabled ? 'enabled' : 'disabled'}</span></td>
        <td>${p.hotToCoolDays}d → COOL</td>
        <td>${p.coolToArchiveDays}d → ${esc(p.targetTier || 'ARCHIVE')}</td>
        <td>${p.minAccessCount}</td>
        <td class="row">
            <button class="ghost" data-toggle-policy="${p.id}" data-enabled="${p.enabled}">${p.enabled ? 'disable' : 'enable'}</button>
            <button class="ghost danger" data-del-policy="${p.id}">delete</button>
        </td></tr>`).join('')

    const tierReport = (tiering.report || []).map((t) => `<tr><td>${esc(t.tier)}</td><td>${t.versions}</td><td>${bytes(t.bytes)}</td></tr>`).join('')

    return `
    <div class="card">
        <div class="row"><h2 style="margin:0">Bucket</h2>
        <select id="lt-bucket" style="max-width:220px">${buckets.map((b) => `<option ${b.name === bucket ? 'selected' : ''}>${esc(b.name)}</option>`).join('')}</select>
        <div class="spacer"></div>
        <button class="ghost" id="run-lifecycle">Run lifecycle (dry run)</button>
        <button class="ghost" id="run-tiering">Run tiering (dry run)</button>
        </div>
        <pre id="run-output" class="mono hidden"></pre>
    </div>
    <div class="card"><h2>Lifecycle rules</h2>
        <table><thead><tr><th>Rule</th><th>Status</th><th>Transitions</th><th>Expire (days)</th><th>Noncurrent</th><th>Abort MPU</th><th></th></tr></thead><tbody>${ruleRows || '<tr><td colspan="7" class="muted">no rules</td></tr>'}</tbody></table>
        <h3>Create rule</h3>
        <div class="row">
            <input id="rule-name" placeholder="rule name" style="max-width:180px">
            <input id="rule-prefix" placeholder="prefix (optional)" style="max-width:180px">
            <input id="rule-expire" placeholder="expire after days" style="max-width:150px">
            <input id="rule-transition" placeholder="transition: days:CLASS (e.g. 30:STANDARD_IA)" style="max-width:280px">
            <button class="primary" id="create-rule">Create</button>
        </div>
    </div>
    <div class="card"><h2>Intelligent tiering</h2>
        <table><thead><tr><th>Policy</th><th>Status</th><th>Hot→Cool</th><th>Cool→Archive</th><th>Min accesses</th><th></th></tr></thead><tbody>${policyRows || '<tr><td colspan="6" class="muted">no policies</td></tr>'}</tbody></table>
        <h3>Tier distribution</h3>
        <table><thead><tr><th>Tier</th><th>Versions</th><th>Bytes</th></tr></thead><tbody>${tierReport || '<tr><td colspan="3" class="muted">no data</td></tr>'}</tbody></table>
        <h3>Create policy</h3>
        <div class="row">
            <input id="policy2-name" placeholder="policy name" style="max-width:180px">
            <input id="policy2-hot" placeholder="hot→cool days" style="max-width:140px" value="30">
            <input id="policy2-cold" placeholder="cool→archive days" style="max-width:160px" value="180">
            <input id="policy2-access" placeholder="min accesses" style="max-width:130px" value="2">
            <button class="primary" id="create-tier-policy">Create</button>
        </div>
    </div>`
}

AFTER.data = () => {
    $('lt-bucket').onchange = (e) => {
        state.bucket = e.target.value
        localStorage.setItem('ddrive_bucket', state.bucket)
        render()
    }
    $('run-lifecycle').onclick = async () => {
        const out = await post(`/api/admin/lifecycle/run?bucket=${state.bucket}&dryRun=true`)
        $('run-output').classList.remove('hidden')
        $('run-output').textContent = JSON.stringify(out, null, 2)
    }
    $('run-tiering').onclick = async () => {
        const out = await post(`/api/admin/tiering/run?bucket=${state.bucket}&dryRun=true`)
        $('run-output').classList.remove('hidden')
        $('run-output').textContent = JSON.stringify(out, null, 2)
    }
    $('create-rule').onclick = async () => {
        const transitions = ($('rule-transition').value || '').split(',').map((spec) => {
            const [days, storageClass] = spec.split(':')

            return { days: Number(days), storageClass: (storageClass || 'GLACIER').trim() }
        }).filter((t) => t.days)
        try {
            await post('/api/admin/lifecycle', {
                bucket: state.bucket,
                name: $('rule-name').value,
                prefix: $('rule-prefix').value || null,
                expirationDays: $('rule-expire').value ? Number($('rule-expire').value) : null,
                transitions,
                status: 'Enabled',
                abortIncompleteMultipartDays: 7,
            })
            toast('Rule created')
            render()
        } catch (err) { toast(err.message, true) }
    }
    $('create-tier-policy').onclick = async () => {
        try {
            await post('/api/admin/tiering', {
                bucket: state.bucket,
                name: $('policy2-name').value,
                hotToCoolDays: Number($('policy2-hot').value),
                coolToArchiveDays: Number($('policy2-cold').value),
                minAccessCount: Number($('policy2-access').value),
                enabled: true,
            })
            toast('Policy created')
            render()
        } catch (err) { toast(err.message, true) }
    }
    document.querySelectorAll('[data-toggle-rule]').forEach((el) => {
        el.onclick = async () => {
            await patch(`/api/admin/lifecycle/${el.dataset.toggleRule}`, { status: el.dataset.status === 'Enabled' ? 'Disabled' : 'Enabled' })
            render()
        }
    })
    document.querySelectorAll('[data-del-rule]').forEach((el) => {
        el.onclick = async () => {
            await del(`/api/admin/lifecycle/${el.dataset.delRule}`)
            render()
        }
    })
    document.querySelectorAll('[data-toggle-policy]').forEach((el) => {
        el.onclick = async () => {
            await patch(`/api/admin/tiering/${el.dataset.togglePolicy}`, { enabled: el.dataset.enabled !== 'true' })
            render()
        }
    })
    document.querySelectorAll('[data-del-policy]').forEach((el) => {
        el.onclick = async () => {
            await del(`/api/admin/tiering/${el.dataset.delPolicy}`)
            render()
        }
    })
}

// ---------------------------------------------------------------------------
// Replication
// ---------------------------------------------------------------------------
async function renderReplication() {
    const data = await get('/api/admin/replication')
    const { tasks } = await get('/api/admin/replication/tasks?limit=50')
    const peerRows = data.peers.map((p) => `<tr>
        <td><strong>${esc(p.name)}</strong><div class="hint mono">${esc(p.endpoint)}</div></td>
        <td>${esc(p.region || '')}</td>
        <td><span class="badge">${esc(p.mode || 'ddrive')}</span></td>
        <td><span class="badge ${p.status === 'enabled' ? 'ok' : 'err'}">${esc(p.status)}</span></td>
        <td>${data.stats.peers.find((x) => x.name === p.name)?.backlog ?? 0}</td>
        <td>${esc(p.lastSyncAt || '—')}</td>
        <td class="row">
            <button class="ghost" data-test="${esc(p.name)}">test</button>
            <button class="ghost" data-backfill="${esc(p.name)}">backfill</button>
            <button class="ghost danger" data-del-peer="${esc(p.name)}">delete</button>
        </td></tr>`).join('')
    const taskRows = tasks.map((t) => `<tr><td class="mono">${esc(t.id).slice(0, 8)}</td><td>${esc(t.op)}</td><td><span class="badge ${t.status === 'done' ? 'ok' : t.status === 'failed' ? 'err' : 'warn'}">${esc(t.status)}</span></td><td>${t.attempts}</td><td class="hint">${esc(t.lastError || '')}</td><td><button class="ghost" data-retry="${t.id}">retry</button></td></tr>`).join('')

    return `
    <div class="card">
        <h2>Add replication peer</h2>
        <div class="grid cols-2">
            <div><label class="hint">name</label><input id="peer-name" placeholder="eu-west"></div>
            <div><label class="hint">endpoint (DDrive node or S3 URL)</label><input id="peer-endpoint" placeholder="https://eu-west.example.com"></div>
            <div><label class="hint">mode</label><select id="peer-mode"><option value="ddrive">ddrive (native, versions+metadata)</option><option value="s3">s3 (plain object copy)</option></select></div>
            <div><label class="hint">region</label><input id="peer-region" placeholder="eu-west-1"></div>
            <div><label class="hint">access key id</label><input id="peer-key" placeholder="peer access key (auto generated if empty)"></div>
            <div><label class="hint">secret</label><input id="peer-secret" type="password" placeholder="shared secret"></div>
            <div><label class="hint">bucket filter (optional)</label><input id="peer-bucket" placeholder="media"></div>
            <div><label class="hint">prefix filter (optional)</label><input id="peer-prefix" placeholder="photos/"></div>
        </div>
        <div class="row end" style="margin-top:10px"><button class="primary" id="create-peer">Create peer</button></div>
        <p class="hint">Both directions are supported: create a peer on each node pointing at the other for active/active multi-region writes.</p>
    </div>
    <div class="card"><h2>Peers</h2><table><thead><tr><th>Peer</th><th>Region</th><th>Mode</th><th>Status</th><th>Backlog</th><th>Last sync</th><th></th></tr></thead><tbody>${peerRows || '<tr><td colspan="7" class="muted">no peers configured</td></tr>'}</tbody></table></div>
    <div class="card"><h2>Recent tasks</h2><table><thead><tr><th>Task</th><th>Op</th><th>Status</th><th>Attempts</th><th>Error</th><th></th></tr></thead><tbody>${taskRows || '<tr><td colspan="6" class="muted">no tasks</td></tr>'}</tbody></table></div>`
}

AFTER.replication = () => {
    $('create-peer').onclick = async () => {
        try {
            const generated = !$('peer-key').value
            const key = generated ? `DD${Math.random().toString(16).slice(2, 10).toUpperCase()}` : $('peer-key').value
            const secret = $('peer-secret').value || Array.from(crypto.getRandomValues(new Uint8Array(24))).map((b) => b.toString(16).padStart(2, '0')).join('')
            await post('/api/admin/replication', {
                name: $('peer-name').value,
                endpoint: $('peer-endpoint').value,
                mode: $('peer-mode').value,
                region: $('peer-region').value || undefined,
                accessKeyId: key,
                secret,
                bucket: $('peer-bucket').value || undefined,
                prefix: $('peer-prefix').value || undefined,
            })
            toast(`Peer created. Share these with the remote node: key=${key} secret=${secret}`)
            render()
        } catch (err) { toast(err.message, true) }
    }
    document.querySelectorAll('[data-test]').forEach((el) => {
        el.onclick = async () => {
            const result = await post(`/api/admin/replication/${el.dataset.test}/test`)
            toast(result.ok ? `OK (${result.latencyMs}ms)` : `Failed: ${result.error}`, !result.ok)
        }
    })
    document.querySelectorAll('[data-backfill]').forEach((el) => {
        el.onclick = async () => {
            const result = await post(`/api/admin/replication/${el.dataset.backfill}/backfill`, {})
            toast(`Queued ${result.queued} of ${result.scanned} objects`)
        }
    })
    document.querySelectorAll('[data-del-peer]').forEach((el) => {
        el.onclick = async () => {
            if (!confirm('Delete peer and its pending tasks?')) return
            await del(`/api/admin/replication/${el.dataset.delPeer}`)
            render()
        }
    })
    document.querySelectorAll('[data-retry]').forEach((el) => {
        el.onclick = async () => {
            await post(`/api/admin/replication/tasks/${el.dataset.retry}/retry`)
            render()
        }
    })
}

// ---------------------------------------------------------------------------
// Events & tagging
// ---------------------------------------------------------------------------
async function renderEvents() {
    const [events, deliveries, rules] = await Promise.all([
        get('/api/admin/events'), get('/api/admin/events/deliveries?limit=50'), get('/api/admin/auto-tag-rules'),
    ])
    const targetRows = events.targets.map((t) => `<tr>
        <td><strong>${esc(t.name)}</strong><div class="hint mono">${esc(t.url)}</div></td>
        <td><span class="badge">${esc(t.type)}</span></td>
        <td class="mono">${esc((t.events || []).join(', '))}</td>
        <td><span class="badge ${t.status === 'enabled' ? 'ok' : 'err'}">${esc(t.status)}</span></td>
        <td class="row"><button class="ghost danger" data-del-target="${t.id}">delete</button></td></tr>`).join('')
    const deliveryRows = deliveries.deliveries.map((d) => `<tr><td class="mono">${esc(d.eventType)}</td><td><span class="badge ${d.status === 'delivered' ? 'ok' : d.status === 'dead' ? 'err' : 'warn'}">${esc(d.status)}</span></td><td>${d.attempts}</td><td class="hint">${esc(d.lastError || '')}</td></tr>`).join('')
    const ruleRows = rules.rules.map((r) => `<tr><td>${esc(r.name)}</td><td>${esc(r.applyOn)}</td><td class="mono">${esc(JSON.stringify(r.conditions))}</td><td class="mono">${esc(JSON.stringify(r.tags))}</td><td><button class="ghost danger" data-del-rule2="${r.id}">delete</button></td></tr>`).join('')

    return `
    <div class="card">
        <h2>Event target (webhook / serverless)</h2>
        <div class="grid cols-2">
            <div><label class="hint">name</label><input id="event-name" placeholder="thumbnailer"></div>
            <div><label class="hint">type</label><select id="event-type"><option value="webhook">webhook</option><option value="function">function (lambda style payload)</option></select></div>
            <div><label class="hint">url</label><input id="event-url" placeholder="https://functions.example.com/thumbnail"></div>
            <div><label class="hint">events (comma separated, * for all)</label><input id="event-events" value="s3:ObjectCreated:*"></div>
            <div><label class="hint">secret (HMAC signature)</label><input id="event-secret" type="password"></div>
            <div><label class="hint">prefix filter</label><input id="event-prefix" placeholder="uploads/"></div>
        </div>
        <div class="row end" style="margin-top:10px"><button class="primary" id="create-target">Create target</button></div>
    </div>
    <div class="card"><h2>Targets</h2><table><thead><tr><th>Target</th><th>Type</th><th>Events</th><th>Status</th><th></th></tr></thead><tbody>${targetRows || '<tr><td colspan="5" class="muted">no targets</td></tr>'}</tbody></table>
        <div class="row end"><button class="ghost" id="redrive">Redrive dead letters</button></div></div>
    <div class="card"><h2>Recent deliveries</h2><table><thead><tr><th>Event</th><th>Status</th><th>Attempts</th><th>Last error</th></tr></thead><tbody>${deliveryRows || '<tr><td colspan="4" class="muted">no deliveries</td></tr>'}</tbody></table></div>
    <div class="card"><h2>Auto tagging rules</h2>
        <table><thead><tr><th>Rule</th><th>Apply on</th><th>Conditions</th><th>Tags</th><th></th></tr></thead><tbody>${ruleRows || '<tr><td colspan="5" class="muted">no rules (the built-in classifier still tags uploads)</td></tr>'}</tbody></table>
        <h3>Create rule</h3>
        <div class="row">
            <input id="tag-rule-name" placeholder="rule name" style="max-width:180px">
            <input id="tag-rule-ext" placeholder="extensions: jpg,png" style="max-width:200px">
            <input id="tag-rule-tags" placeholder='tags: {"category":"photo"}' style="max-width:280px">
            <button class="primary" id="create-tag-rule">Create</button>
        </div>
        <div class="row end"><button class="ghost" id="sweep">Run sweep on existing objects</button></div>
    </div>`
}

AFTER.events = () => {
    $('create-target').onclick = async () => {
        try {
            await post('/api/admin/events', {
                name: $('event-name').value,
                type: $('event-type').value,
                url: $('event-url').value,
                events: $('event-events').value.split(',').map((e) => e.trim()).filter(Boolean),
                secret: $('event-secret').value || undefined,
                prefix: $('event-prefix').value || undefined,
            })
            toast('Target created')
            render()
        } catch (err) { toast(err.message, true) }
    }
    $('redrive').onclick = async () => {
        const result = await post('/api/admin/events/redrive', {})
        toast(`Requeued ${result.requeued} deliveries`)
        render()
    }
    $('create-tag-rule').onclick = async () => {
        const extensions = ($('tag-rule-ext').value || '').split(',').map((e) => e.trim()).filter(Boolean)
        try {
            await post('/api/admin/auto-tag-rules', {
                name: $('tag-rule-name').value,
                conditions: { extensions },
                tags: JSON.parse($('tag-rule-tags').value || '{}'),
                applyOn: 'both',
            })
            toast('Rule created')
            render()
        } catch (err) { toast(err.message, true) }
    }
    $('sweep').onclick = async () => {
        const result = await post('/api/admin/auto-tag-rules/sweep')
        toast(`Scanned ${result.scanned}, tagged ${result.tagged}`)
    }
    document.querySelectorAll('[data-del-target]').forEach((el) => {
        el.onclick = async () => {
            await del(`/api/admin/events/${el.dataset.delTarget}`)
            render()
        }
    })
    document.querySelectorAll('[data-del-rule2]').forEach((el) => {
        el.onclick = async () => {
            await del(`/api/admin/auto-tag-rules/${el.dataset.delRule2}`)
            render()
        }
    })
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------
async function renderSettings() {
    const settings = await get('/api/admin/settings')
    return `
    <div class="card">
        <h2>Runtime</h2>
        <div class="grid cols-2">
            <pre class="mono">${esc(JSON.stringify(settings.runtime, null, 2))}</pre>
            <div>
                <h3>Storage drivers / clients</h3>
                <table><tbody>
                    <tr><td>WebDAV</td><td class="mono">${location.origin}/webdav/</td></tr>
                    <tr><td>S3 endpoint</td><td class="mono">${location.origin}/s3</td></tr>
                    <tr><td>REST API</td><td class="mono">${location.origin}/api</td></tr>
                    <tr><td>OpenAPI</td><td class="mono"><a href="/api/openapi.json">/api/openapi.json</a></td></tr>
                    <tr><td>Metrics</td><td class="mono"><a href="/metrics">/metrics</a></td></tr>
                    <tr><td>Health</td><td class="mono"><a href="/healthz">/healthz</a></td></tr>
                </tbody></table>
                <h3>MFA for this account</h3>
                <div class="row"><button class="ghost" id="mfa-setup">Provision TOTP</button><span id="mfa-status" class="hint"></span></div>
            </div>
        </div>
    </div>
    <div class="card">
        <h2>Stored settings</h2>
        <table><thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>${Object.entries(settings.settings).map(([k, v]) => `<tr><td class="mono">${esc(k)}</td><td class="mono">${esc(JSON.stringify(v))}</td></tr>`).join('') || '<tr><td colspan="2" class="muted">none</td></tr>'}</tbody></table>
    </div>`
}

AFTER.settings = () => {
    $('mfa-setup').onclick = async () => {
        const result = await post('/api/me/mfa', {})
        const code = prompt(`Add this secret to your authenticator:\n\n${result.secret}\n\n${result.uri}\n\nEnter the current code to activate:`)
        if (!code) return
        try {
            await post('/api/me/mfa/verify', { code })
            toast('MFA enabled')
        } catch (err) { toast(err.message, true) }
    }
}

bootstrap()

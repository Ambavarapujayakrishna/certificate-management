// Frontend for the single test/signing page; talks only to this app's own /api/* routes.
const $ = (sel) => document.querySelector(sel);

function show(el, data) {
    el.textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
}

async function api(path, options = {}) {
    const res = await fetch(path, options);
    const contentType = res.headers.get('content-type') || '';
    const isJson = contentType.includes('application/json');
    const body = isJson ? await res.json() : await res.text();
    if (!res.ok) throw new Error(typeof body === 'string' ? body : body.error || 'Request failed (' + res.status + ')');
    return body;
}

// Tabs
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        $('#tab-' + btn.dataset.tab).classList.add('active');
    });
});

function formToObject(form) {
    return Object.fromEntries(new FormData(form).entries());
}

// 1. Generate key + CSR
$('#form-generate').addEventListener('submit', async (e) => {
    e.preventDefault();
    const out = $('#generate-result');
    try {
        const result = await api('/api/keys/generate-csr', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(formToObject(e.target)),
        });
        show(out, result);
        loadKeys();
    } catch (err) {
        show(out, 'Error: ' + err.message);
    }
});

// 2. Enroll with EJBCA
$('#form-enroll').addEventListener('submit', async (e) => {
    e.preventDefault();
    const out = $('#enroll-result');
    try {
        const result = await api('/api/keys/enroll', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(formToObject(e.target)),
        });
        show(out, result);
        loadKeys();
    } catch (err) {
        show(out, 'Error: ' + err.message);
    }
});

// Fill the import textarea from a picked file
$('#certFile').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    $('#form-import textarea[name="certPem"]').value = await file.text();
});

// 3. Import certificate
$('#form-import').addEventListener('submit', async (e) => {
    e.preventDefault();
    const out = $('#import-result');
    try {
        const fd = formToObject(e.target);
        const result = await api('/api/certificates/import', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ label: fd.label, certificatePem: fd.certPem }),
        });
        show(out, result);
        loadKeys();
    } catch (err) {
        show(out, 'Error: ' + err.message);
    }
});

// 4. Sign document
$('#form-sign').addEventListener('submit', async (e) => {
    e.preventDefault();
    const out = $('#sign-result');
    try {
        const fd = new FormData(e.target);
        const result = await api('/api/sign', { method: 'POST', body: fd });
        const links = result.files.map(f => '<a class="pill" href="/api/signed/' + encodeURIComponent(f) + '" download>' + f + '</a>').join(' ');
        out.innerHTML = 'Signed document: ' + links;
    } catch (err) {
        show(out, 'Error: ' + err.message);
    }
});

// Keys table
async function loadKeys() {
    const tbody = document.querySelector('#keys-table tbody');
    try {
        const keys = await api('/api/keys');
        tbody.innerHTML = keys
            .map(
                k => `
        <tr>
          <td><code>${k.label}</code></td>
          <td>${k.algorithm || '-'}</td>
          <td>${k.status || '-'}</td>
          <td>${k.certificatePem ? '<span class="badge badge-ok">has cert</span>' : '<span class="badge badge-warn">no cert</span>'}</td>
          <td>${k.serial || '-'}</td>
          <td>${k.createdAt ? new Date(k.createdAt).toLocaleDateString() : '-'}</td>
          <td>
            ${k.csrPem ? `<a class="pill" href="/api/keys/${encodeURIComponent(k.label)}/download/csr" download="${k.label}.csr.pem">CSR</a>` : ''}
            ${k.certificatePem ? `<a class="pill" href="/api/keys/${encodeURIComponent(k.label)}/download/certificate" download="${k.label}.cert.pem">Cert</a>` : ''}
          </td>
        </tr>`)
            .join('');
    } catch (err) {
        tbody.innerHTML = '<tr><td colspan="7" class="error">' + err.message + '</td></tr>';
    }
}

$('#btn-keys-refresh').addEventListener('click', loadKeys);

async function loadHealth() {
    try {
        const health = await api('/api/healthz');
        $('#hsmBadge').textContent = 'HSM: ' + (health.hsmMode || 'unknown');
        $('#ejbcaBadge').textContent = 'EJBCA: connected';
    } catch {
        $('#hsmBadge').textContent = 'HSM: unknown';
        $('#ejbcaBadge').textContent = 'EJBCA: offline';
    }
}

loadHealth();
loadKeys();
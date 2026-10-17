require('dotenv').config();
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const hsmClient = require('./src/hsmClient');
const ejbcaClient = require('./src/ejbcaClient');
const certStore = require('./src/certStore');

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
const SIGNED_DIR = path.join(DATA_DIR, 'signed');
[DATA_DIR, UPLOAD_DIR, SIGNED_DIR].forEach((d) => fs.mkdirSync(d, { recursive: true }));

const upload = multer({ dest: UPLOAD_DIR, limits: { fileSize: 25 * 1024 * 1024 } });

app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Only safe, filename-shaped labels are allowed since labels are used in HSM lookups and file names.
const LABEL_RE = /^[a-zA-Z0-9_\-]{1,64}$/;
function assertValidLabel(label) {
    if (typeof label !== 'string' || !LABEL_RE.test(label)) {
        const err = new Error('Label must be 1-64 chars of letters, digits, dash or underscore');
        err.status = 400;
        throw err;
    }
}

// 1. Generate a key pair in the HSM and the CSR signed by it
app.post('/api/keys/generate-csr', async (req, res) => {
    try {
        const { label, subjectDn, subject, algorithm = 'rsa2048' } = req.body || {};
        assertValidLabel(label);
        const dn = subjectDn || subject;
        if (!dn || typeof dn !== 'string') {
            return res.status(400).json({ error: 'subjectDn is required, e.g. "CN=Signer-001,O=Acme,C=US"' });
        }
        if (certStore.get(label)) {
            return res.status(409).json({ error: `Key label "${label}" already exists` });
        }

        const { csrPem, publicKeyPem } = await hsmClient.generateKeyPairCsr({
            label,
            subjectDN: dn,
            algorithm,
        });

        certStore.put(label, {
            label,
            subjectDn,
            algorithm: algorithm || 'rsa2048',
            publicKeyPem,
            csrPem,
            status: 'CSR_GENERATED',
            createdAt: new Date().toISOString(),
        });

        res.json({ label, csrPem });
    } catch (err) {
        console.error('[generate-csr] failed:', err.stack || err);
        res.status(err.status || 500).json({ error: err.message });
    }
});

app.get('/api/keys', (req, res) => {
    res.json(certStore.list());
});

// Download an artifact (CSR / certificate / chain) generated for a key label
app.get('/api/keys/:label/download/:artifact', (req, res) => {
    const { label, artifact } = req.params;
    const entry = certStore.get(label);
    if (!entry) return res.status(404).json({ error: `Unknown key label "${label}"` });

    const fieldMap = {
        csr: 'csrPem',
        certificate: 'certificatePem',
        chain: 'chainPem',
    };
    const mapping = fieldMap[artifact];
    if (!mapping || !entry[mapping]) {
        return res.status(404).json({ error: `Artifact not available for "${label}"` });
    }

    const safeLabel = label.replace(/[^a-zA-Z0-9_\-]/g, '_');
    res.setHeader('Content-Disposition', `attachment; filename="${safeLabel}.${mapping}.pem"`);
    res.type('application/x-pem-file').send(entry[mapping]);
});

// 2. Submit the CSR to EJBCA and receive the issued certificate
app.post('/api/keys/enroll', async (req, res) => {
    try {
        const {
            label,
            username,
            enrollmentCode,
            password,
            certificateProfileName,
            endEntityProfileName,
            certificateAuthorityName,
        } = req.body || {};

        assertValidLabel(label);
        const entry = certStore.get(label);
        if (!entry) return res.status(404).json({ error: `Unknown key label "${label}"` });
        if (!entry.csrPem) return res.status(400).json({ error: 'No CSR stored for this label' });

        const { certificatePem, chainPem } = await ejbcaClient.enroll({
            csrPem: entry.csrPem,
            username,
            password: password || enrollmentCode,
            certificateProfileName,
            endEntityProfileName,
            certificateAuthorityName,
        });

        certStore.update(label, { certificatePem, chainPem, status: 'ENROLLED' });
        res.json({ label, certificatePem, chainPem });
    } catch (err) {
        console.error('[enroll] failed:', err.stack || err);
        res.status(err.status || 502).json({ error: err.message });
    }
});

// 3. Import the issued certificate back, binding it to the HSM key by label
app.post('/api/certificates/import', async (req, res) => {
    try {
        const { label, certificatePem } = req.body || {};
        assertValidLabel(label);
        const entry = certStore.get(label);
        if (!entry) return res.status(404).json({ error: `Unknown key label "${label}"` });
        if (!certificatePem || typeof certificatePem !== 'string') {
            return res.status(400).json({ error: 'certificatePem (PEM text) is required' });
        }

        const bound = await hsmClient.importCertificate({
            label,
            certificatePem,
            expectedPublicKeyPem: entry.publicKeyPem,
        });

        certStore.update(label, {
            certificatePem,
            serial: bound.serial,
            fingerprint: bound.fingerprint,
            notBefore: bound.notBefore,
            notAfter: bound.notAfter,
            status: 'BOUND',
        });

        res.json({ label, bound });
    } catch (err) {
        console.error('[certificates/import] failed:', err.stack || err);
        res.status(err.status || 400).json({ error: err.message });
    }
});

// 4. Upload a document and sign its digest with the bound HSM key
app.post('/api/sign', upload.single('file'), async (req, res) => {
    const cleanup = () => req.file && fs.unlink(req.file.path, () => { });
    try {
        const { label } = req.body || {};
        assertValidLabel(label);
        const entry = certStore.get(label);
        if (!entry) {
            cleanup();
            return res.status(404).json({ error: `Unknown key label "${label}"` });
        }
        if (!entry.certificatePem) {
            cleanup();
            return res.status(400).json({ error: `Key "${label}" has no certificate bound yet` });
        }
        if (!req.file) {
            return res.status(400).json({ error: 'File is required' });
        }

        const fileBuffer = fs.readFileSync(req.file.path);
        const digestHex = crypto.createHash('sha256').update(fileBuffer).digest('hex');

        const { signature } = await hsmClient.sign({
            label,
            data: fileBuffer,
            digestAlgorithm: 'sha256',
        });

        const signedId = crypto.randomUUID();
        const originalExt = path.extname(req.file.originalname) || '.bin';
        const originalOutPath = path.join(SIGNED_DIR, `${signedId}-original${originalExt}`);
        const sigOutPath = path.join(SIGNED_DIR, `${signedId}.sig`);
        const manifestPath = path.join(SIGNED_DIR, `${signedId}-manifest.json`);

        fs.copyFileSync(req.file.path, originalOutPath);
        fs.writeFileSync(sigOutPath, signature, 'utf8');

        const manifest = {
            signedId,
            originalFilename: req.file.originalname,
            originalExt,
            digestHex,
            digestAlgorithm: 'sha256',
            signatureB64: signature,
            signerAlgorithm: entry.algorithm,
            keyLabel: label,
            certificateSerial: entry.serial,
            signedAt: new Date().toISOString(),
        };
        fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), 'utf8');

        cleanup();
        res.json({
            signedId,
            files: [path.basename(originalOutPath), `${signedId}.sig`, `${signedId}-manifest.json`],
            manifest,
        });
    } catch (err) {
        cleanup();
        console.error('[sign] failed:', err.stack || err);
        res.status(err.status || 500).json({ error: err.message });
    }
});

// Download a file produced by a prior /api/sign call
app.get('/api/signed/:file', (req, res) => {
    const safe = path.basename(req.params.file);
    const filePath = path.join(SIGNED_DIR, safe);
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Not found' });
    res.download(filePath);
});

app.get('/api/healthz', (req, res) => {
    res.json({ ok: true, hsmMode: process.env.HSM_MODE || 'mock' });
});

app.listen(PORT, () => {
    console.log(`Document signing app running: http://localhost:${PORT}`);
    console.log(`HSM mode: ${process.env.HSM_MODE || 'mock'}`);
});
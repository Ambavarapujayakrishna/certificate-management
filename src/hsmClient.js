const forge = require('node-forge');
const fs = require('fs');
const path = require('path');

const HSM_MODE = process.env.HSM_MODE || 'mock';

// Accepts "CN=foo,O=bar,C=US" style subject DN.
const DN_SHORT_NAME_MAP = {
    CN: 'commonName',
    O: 'organizationName',
    OU: 'organizationalUnitName',
    C: 'countryName',
    ST: 'stateOrProvinceName',
    L: 'localityName'
};

function parseRsaBits(algorithm) {
    if (!algorithm) return 2048;
    const clean = String(algorithm).replace(/\s+/g, '').toUpperCase();
    if (clean.includes('4096')) return 4096;
    if (clean.includes('3072')) return 3072;
    return 2048;
}

function parseDnToAttributes(subjectDn) {
    return subjectDn
        .split(',')
        .filter(Boolean)
        .map(part => {
            const [shortName, value] = part.split('=').map(s => s.trim());
            return { name: DN_SHORT_NAME_MAP[shortName.toUpperCase()] || shortName, value };
        });
}

function assertCertMatchesPublicKey(certificatePem, expectedPublicKeyPem) {
    const cert = forge.pki.certificateFromPem(certificatePem);
    const certPublicKeyPem = forge.pki.publicKeyToPem(cert.publicKey);

    if (certPublicKeyPem.trim() !== expectedPublicKeyPem.trim()) {
        const err = new Error('Certificate public key does not match the key generated in the HSM for this label');
        err.status = 400;
        throw err;
    }

    if (new Date(cert.validity.notAfter) < new Date()) {
        const err = new Error('Certificate has already expired');
        err.status = 400;
        throw err;
    }

    const der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
    const fingerprint = forge.md.sha256.create().update(der).digest().toHex();

    return {
        serial: cert.serialNumber,
        validTo: cert.validity.notAfter.toISOString(),
        fingerprint,
        subject: cert.subject.attributes.map(a => `${a.shortName || a.name}=${a.value}`).join(', ')
    };
}

// --------------------------------------------------------------------------------------------------------------------
// MOCK implementation: software keys generated in-process with node-forge.
// For local development/testing only - private keys are stored in plaintext
// on disk and never touch a real HSM. Do not use outside local testing.
// --------------------------------------------------------------------------------------------------------------------
const MOCK_KEYS_FILE = path.join(__dirname, '..', 'data', 'mock-hsm-keys.json');

function loadMockKeys() {
    try {
        return JSON.parse(fs.readFileSync(MOCK_KEYS_FILE, 'utf8'));
    } catch (_) {
        return {};
    }
}

function persistMockKeys(all) {
    fs.mkdirSync(path.dirname(MOCK_KEYS_FILE), { recursive: true });
    fs.writeFileSync(MOCK_KEYS_FILE, JSON.stringify(all, null, 2), 'utf8');
}

const mockHsm = {
    async generateKeyPairCsr({ label, subjectDN, algorithm }) {
        console.warn(`[HSM:mock] Generating "${label}" in a local software store (NOT a real HSM, local testing only!)`);
        const bits = parseRsaBits(algorithm);
        const keypair = forge.pki.rsa.generateKeyPair({ bits, workers: 2 });
        const all = loadMockKeys();

        all[label] = {
            label,
            privateKeyPem: forge.pki.privateKeyToPem(keypair.privateKey),
            publicKeyPem: forge.pki.publicKeyToPem(keypair.publicKey),
            algorithm: algorithm || 'RSA2048'
        };
        persistMockKeys(all);

        const csr = forge.pki.createCertificationRequest();
        csr.publicKey = keypair.publicKey;
        csr.setSubject(parseDnToAttributes(subjectDN));
        csr.sign(keypair.privateKey, forge.md.sha256.create());

        return {
            csrPem: forge.pki.certificationRequestToPem(csr),
            publicKeyPem: forge.pki.publicKeyToPem(keypair.publicKey)
        };
    },

    async importCertificate({ label, certificatePem, expectedPublicKeyPem }) {
        const all = loadMockKeys();
        if (!all[label]) {
            const err = new Error(`No HSM key found for label "${label}"`);
            err.status = 404;
            throw err;
        }
        return assertCertMatchesPublicKey(certificatePem, expectedPublicKeyPem);
    },

    async sign({ label, data }) {
        const all = loadMockKeys();
        const entry = all[label];
        if (!entry) {
            const err = new Error(`No HSM key found for label "${label}"`);
            err.status = 404;
            throw err;
        }

        const privateKey = forge.pki.privateKeyFromPem(entry.privateKeyPem);
        const md = forge.md.sha256.create();
        md.update(Buffer.isBuffer(data) ? data.toString('binary') : data);
        const signature = forge.util.encode64(privateKey.sign(md));

        return { signature, algorithm: 'RSA-SHA256' };
    }
};

// --------------------------------------------------------------------------------------------------------------------
// CLOUDHSM implementation: real keys via PKCS#11. Run when this app runs on
// the EC2 client instance with the CloudHSM Client v5+ installed.
// Structurally correct PKCS#11 construction, but validate end-to-end against
// your HSM cluster before relying on it - this environment has no real HSM to test against.
// --------------------------------------------------------------------------------------------------------------------
let pkcs11Module = null;

function loadPkcs11() {
    if (pkcs11Module) return pkcs11Module;
    try {
        const pkcs11js = require('pkcs11js');
        const pkcs11 = new pkcs11js.PKCS11();
        // Copy all PKCS#11 constants (CKF_*, CKO_*, CKA_*, CKM_*, etc.) onto instance
        Object.assign(pkcs11, pkcs11js);
        const lib = process.env.CLOUDHSM_PKCS11_LIB || '/opt/cloudhsm/lib/libcloudhsm_pkcs11.so';
        pkcs11.load(lib);
        pkcs11.C_Initialize();
        pkcs11Module = pkcs11;
        return pkcs11;
    } catch (e) {
        throw new Error(
            'pkcs11js is not installed/built. Run "npm install" on the EC2 client instance where the CloudHSM client is configured: ' +
            e.message
        );
    }
}

async function withSession(fn) {
    const pkcs11 = loadPkcs11();
    const pin = process.env.CLOUDHSM_PIN;
    if (!pin) throw new Error('CLOUDHSM_PIN env var is required (format: <CU_USERNAME>:<CU_PASSWORD>)');

    let session;
    try {
        const slots = pkcs11.C_GetSlotList(true);
        if (!slots.length) {
            throw new Error('No CloudHSM slots found - check CloudHSM status and network connectivity from this EC2 instance');
        }
        const slot = slots[0];
        // In PKCS#11, CKF_SERIAL_SESSION (0x4) is MANDATORY. Without it, CloudHSM returns CKR_SESSION_PARALLEL_NOT_SUPPORTED.
        const CKF_SERIAL_SESSION = pkcs11.CKF_SERIAL_SESSION ?? 0x00000004;
        const CKF_RW_SESSION = pkcs11.CKF_RW_SESSION ?? 0x00000002;
        const CKU_USER = pkcs11.CKU_USER ?? 1;

        session = pkcs11.C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        pkcs11.C_Login(session, CKU_USER, pin);
        return await fn(session, pkcs11);
    } finally {
        if (session) {
            try { pkcs11.C_Logout(session); } catch (_) { } // catch if already logged out
            try { pkcs11.C_CloseSession(session); } catch (_) { }
        }
    }
}

function findHsmKeyHandle(session, pkcs11, keyClass, label) {
    const labelBuf = Buffer.isBuffer(label) ? label : Buffer.from(label, 'utf8');
    pkcs11.C_FindObjectsInit(session, [
        { type: pkcs11.CKA_CLASS, value: keyClass },
        { type: pkcs11.CKA_LABEL, value: labelBuf }
    ]);
    let handles = pkcs11.C_FindObjects(session, 1);
    pkcs11.C_FindObjectsFinal(session);

    if (!handles || !handles.length) {
        // Fallback: search with string label in case driver matched as string
        pkcs11.C_FindObjectsInit(session, [
            { type: pkcs11.CKA_CLASS, value: keyClass },
            { type: pkcs11.CKA_LABEL, value: String(label) }
        ]);
        handles = pkcs11.C_FindObjects(session, 1);
        pkcs11.C_FindObjectsFinal(session);
    }

    if (!handles || !handles.length) {
        const err = new Error(`No HSM key found for label "${label}"`);
        err.status = 404;
        throw err;
    }
    return handles[0];
}

// CloudHSM can answer CKR_FUNCTION_FAILED to the NULL-buffer length query pkcs11js sends by default,
// so supply a preallocated buffer and trim to the returned length.
function readAttribute(pkcs11, session, handle, type, maxBytes) {
    const [attr] = pkcs11.C_GetAttributeValue(session, handle, [{ type, value: Buffer.alloc(maxBytes) }]);
    return attr.value;
}

function findKeyHandle(pkcs11, session, p11, label, keyClass) {
    return findHsmKeyHandle(session, pkcs11, keyClass, label);
}

const cloudHsm = {
    async generateKeyPairCsr({ label, subjectDN, algorithm }) {
        return withSession(async (session, pkcs11) => {
            const p11 = pkcs11;
            const bits = parseRsaBits(algorithm);
            const labelBuf = Buffer.from(label, 'utf8');

            console.log(`[CloudHSM] Generating RSA key pair: label="${label}", bits=${bits}`);

            // In AWS CloudHSM C_GenerateKeyPair:
            // 1. CKA_CLASS and CKA_KEY_TYPE are omitted (implicit in CKM_RSA_PKCS_KEY_PAIR_GEN).
            // 2. If CKA_ENCRYPT is true on public key, CKA_DECRYPT MUST be true on private key.
            const publicTemplate = [
                { type: pkcs11.CKA_TOKEN, value: true },
                { type: pkcs11.CKA_LABEL, value: labelBuf },
                { type: pkcs11.CKA_MODULUS_BITS, value: bits },
                { type: pkcs11.CKA_PUBLIC_EXPONENT, value: Buffer.from([0x01, 0x00, 0x01]) },
                { type: pkcs11.CKA_VERIFY, value: true },
                { type: pkcs11.CKA_ENCRYPT, value: true }
            ];

            const privateTemplate = [
                { type: pkcs11.CKA_TOKEN, value: true },
                { type: pkcs11.CKA_LABEL, value: labelBuf },
                { type: pkcs11.CKA_PRIVATE, value: true },
                { type: pkcs11.CKA_SIGN, value: true },
                { type: pkcs11.CKA_DECRYPT, value: true },
                { type: pkcs11.CKA_EXTRACTABLE, value: false }
            ];

            let handles;
            try {
                handles = pkcs11.C_GenerateKeyPair(
                    session,
                    { mechanism: pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN },
                    publicTemplate,
                    privateTemplate
                );
            } catch (err) {
                console.error('[CloudHSM] C_GenerateKeyPair failed:', err.message);
                throw err;
            }

            console.log('[CloudHSM] Key pair generated. Reading public key modulus and exponent...');

            let modulus;
            let exponent;
            try {
                // Public key handle is re-resolved by label in case the handle returned by keygen is not readable.
                const pubHandle = findKeyHandle(pkcs11, session, p11, label, p11.CKO_PUBLIC_KEY);
                modulus = readAttribute(pkcs11, session, pubHandle, p11.CKA_MODULUS, bits / 8);
                exponent = readAttribute(pkcs11, session, pubHandle, p11.CKA_PUBLIC_EXPONENT, 8);
            } catch (readErr) {
                // Avoid leaving an orphan key pair under this label, which would block a retry.
                try { pkcs11.C_DestroyObject(session, handles.privateKey); } catch (e) { /* best effort */ }
                try { pkcs11.C_DestroyObject(session, handles.publicKey); } catch (e) { /* best effort */ }
                throw new Error(`Key pair was generated but reading the public key failed (${readErr.message}); key pair was removed from HSM`);
            }

            const n = new forge.jsbn.BigInteger(modulus.toString('hex'), 16);
            const e = new forge.jsbn.BigInteger(exponent.toString('hex'), 16);
            const publicKey = forge.pki.setRsaPublicKey(n, e);

            // Build CertificationRequestInfo and sign inside the HSM
            const cri = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
                forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.INTEGER, forge.util.hexToBytes('00')),
                forge.pki.distinguishedNameToAsn1(parseDnToAttributes(subjectDN)),
                forge.pki.publicKeyToAsn1(publicKey),
                forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, [])
            ]);
            const criBytes = Buffer.from(forge.asn1.toDer(cri).getBytes(), 'binary');

            console.log('[CloudHSM] Signing CSR with private key...');
            let signature;
            try {
                pkcs11.C_SignInit(session, { mechanism: pkcs11.CKM_SHA256_RSA_PKCS }, handles.privateKey);
                // Pre-allocating exact signature buffer (bits / 8) ensures a single-pass hardware sign call
                // without triggering CloudHSM multi-call hash finalization errors.
                const sigBuf = Buffer.alloc(bits / 8);
                signature = pkcs11.C_Sign(session, criBytes, sigBuf);
            } catch (err) {
                console.error('[CloudHSM] C_Sign failed:', err.message);
                throw err;
            }

            const signatureAlgorithm = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
                forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, forge.asn1.oidToDer(forge.pki.oids.sha256WithRSAEncryption).getBytes()),
                forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, '')
            ]);

            const csrAsn1 = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
                cri,
                signatureAlgorithm,
                forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.BITSTRING, forge.util.hexToBytes('00' + signature.toString('hex')))
            ]);

            const csrPem = forge.pem.encode({ type: 'CERTIFICATE REQUEST', body: forge.asn1.toDer(csrAsn1).getBytes() });
            console.log(`[CloudHSM] CSR successfully generated for label="${label}"`);
            return { csrPem, publicKeyPem: forge.pki.publicKeyToPem(publicKey) };
        });
    },

    async importCertificate({ label, certificatePem, expectedPublicKeyPem }) {
        return withSession(async (session, pkcs11) => {
            findHsmKeyHandle(session, pkcs11, pkcs11.CKO_PRIVATE_KEY, label);
            return assertCertMatchesPublicKey(certificatePem, expectedPublicKeyPem);
        });
    },

    async sign({ label, data }) {
        return withSession(async (session, pkcs11) => {
            const privateKeyHandle = findHsmKeyHandle(session, pkcs11, pkcs11.CKO_PRIVATE_KEY, label);
            const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data);
            pkcs11.C_SignInit(session, { mechanism: pkcs11.CKM_SHA256_RSA_PKCS }, privateKeyHandle);
            const sigBuf = Buffer.alloc(512); // up to 4096-bit RSA
            const signature = pkcs11.C_Sign(session, buffer, sigBuf);
            return { signature: signature.toString('base64'), algorithm: 'RSA-SHA256' };
        });
    }
};

const client = HSM_MODE === 'cloudhsm' ? cloudHsm : mockHsm;

module.exports = {
    generateKeyPairCsr: client.generateKeyPairCsr,
    generateKeyAndCsr: client.generateKeyPairCsr,
    importCertificate: client.importCertificate,
    sign: client.sign
};
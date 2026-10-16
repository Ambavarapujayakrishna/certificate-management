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
        const bits = algorithm === 'RSA4096' ? 4096 : 2048;
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

function withSession(fn) {
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
        session = pkcs11.C_OpenSession(slot, pkcs11.CKF_SERIAL_SESSION | pkcs11.CKF_RW_SESSION);
        pkcs11.C_Login(session, pkcs11.CKU_USER, pin);
        return fn(session, pkcs11);
    } finally {
        if (session) {
            try { pkcs11.C_Logout(session); } catch (_) { } // catch if already logged out
            pkcs11.C_CloseSession(session);
        }
    }
}

function findHsmKeyHandle(session, pkcs11, keyClass, label) {
    pkcs11.C_FindObjectsInit(session, [
        { type: pkcs11.CKA_CLASS, value: keyClass },
        { type: pkcs11.CKA_LABEL, value: label }
    ]);
    const handles = pkcs11.C_FindObjects(session, 1);
    pkcs11.C_FindObjectsFinal(session);

    if (!handles || !handles.length) {
        const err = new Error(`No HSM key found for label "${label}"`);
        err.status = 404;
        throw err;
    }
    return handles[0];
}

const cloudHsm = {
    async generateKeyPairCsr({ label, subjectDN, algorithm }) {
        return withSession(async (session, pkcs11) => {
            const bits = algorithm === 'RSA4096' ? 4096 : 2048;

            const publicTemplate = [
                { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_PUBLIC_KEY },
                { type: pkcs11.CKA_KEY_TYPE, value: pkcs11.CKK_RSA },
                { type: pkcs11.CKA_TOKEN, value: true },
                { type: pkcs11.CKA_LABEL, value: label },
                { type: pkcs11.CKA_MODULUS_BITS, value: bits },
                { type: pkcs11.CKA_PUBLIC_EXPONENT, value: Buffer.from([0x01, 0x00, 0x01]) },
                { type: pkcs11.CKA_VERIFY, value: true },
                { type: pkcs11.CKA_ENCRYPT, value: true }
            ];

            const privateTemplate = [
                { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_PRIVATE_KEY },
                { type: pkcs11.CKA_KEY_TYPE, value: pkcs11.CKK_RSA },
                { type: pkcs11.CKA_TOKEN, value: true },
                { type: pkcs11.CKA_LABEL, value: label },
                { type: pkcs11.CKA_PRIVATE, value: true },
                { type: pkcs11.CKA_SIGN, value: true },
                { type: pkcs11.CKA_EXTRACTABLE, value: false } // the private key must never be able to leave the HSM
            ];

            const handles = pkcs11.C_GenerateKeyPair(
                session,
                { mechanism: pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN },
                publicTemplate,
                privateTemplate
            );

            const attrs = pkcs11.C_GetAttributeValue(session, handles.publicKey, [
                { type: pkcs11.CKA_MODULUS },
                { type: pkcs11.CKA_PUBLIC_EXPONENT }
            ]);

            const n = new forge.jsbn.BigInteger(attrs[0].value.toString('hex'), 16);
            const e = new forge.jsbn.BigInteger(attrs[1].value.toString('hex'), 16);
            const publicKey = forge.pki.setRsaPublicKey(n, e);

            // Build CertificationRequestInfo (version, subject, subjectPKInfo, attributes) and sign it:
            // DER encoding inside the HSM, then assemble the final PKCS#10 structure around that signature.
            const cri = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
                forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.INTEGER, forge.util.hexToBytes('00')), // version 0
                forge.pki.distinguishedNameToAsn1(parseDnToAttributes(subjectDN)),
                forge.pki.publicKeyToAsn1(publicKey),
                forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, []) // attributes
            ]);
            const criBytes = Buffer.from(forge.asn1.toDer(cri).getBytes(), 'binary');

            pkcs11.C_SignInit(session, { mechanism: pkcs11.CKM_SHA256_RSA_PKCS }, handles.privateKey);
            const signature = pkcs11.C_Sign(session, criBytes, Buffer.alloc(bits / 8));

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
            return { csrPem, publicKeyPem: forge.pki.publicKeyToPem(publicKey) };
        });
    },

    async importCertificate({ label, certificatePem, expectedPublicKeyPem }) {
        return withSession(async (session, pkcs11) => {
            findHsmKeyHandle(session, pkcs11, pkcs11.CKO_PRIVATE_KEY, label); // confirms the key still exists in the HSM
            return assertCertMatchesPublicKey(certificatePem, expectedPublicKeyPem);
        });
    },

    async sign({ label, data }) {
        return withSession(async (session, pkcs11) => {
            const privateKeyHandle = findHsmKeyHandle(session, pkcs11, pkcs11.CKO_PRIVATE_KEY, label);
            const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data);
            pkcs11.C_SignInit(session, { mechanism: pkcs11.CKM_SHA256_RSA_PKCS }, privateKeyHandle);
            const signature = pkcs11.C_Sign(session, buffer, Buffer.alloc(512)); // 512 bytes covers up to RSA-4096
            return { signature: signature.toString('base64'), algorithm: 'RSA-SHA256' };
        });
    }
};

const client = HSM_MODE === 'cloudhsm' ? cloudHsm : mockHsm;

module.exports = {
    generateKeyPairCsr: client.generateKeyPairCsr,
    importCertificate: client.importCertificate,
    sign: client.sign
};
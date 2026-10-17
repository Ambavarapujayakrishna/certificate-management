/**
 * Standalone test script to verify end-to-end RSA Keygen + CSR Generation on CloudHSM
 */
require('dotenv').config();
const pkcs11js = require('pkcs11js');
const forge = require('node-forge');

const LIB_PATH = process.env.CLOUDHSM_PKCS11_LIB || '/opt/cloudhsm/lib/libcloudhsm_pkcs11.so';
const PIN = process.env.CLOUDHSM_PIN;

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

function readAttribute(pkcs11, session, handle, type, maxBytes) {
    const [attr] = pkcs11.C_GetAttributeValue(session, handle, [{ type, value: Buffer.alloc(maxBytes) }]);
    return attr.value;
}

function findKeyHandle(pkcs11, session, p11, label, keyClass) {
    const labelBuf = Buffer.isBuffer(label) ? label : Buffer.from(label, 'utf8');
    pkcs11.C_FindObjectsInit(session, [
        { type: pkcs11.CKA_CLASS, value: keyClass },
        { type: pkcs11.CKA_LABEL, value: labelBuf }
    ]);
    let handles = pkcs11.C_FindObjects(session, 1);
    pkcs11.C_FindObjectsFinal(session);

    if (!handles || !handles.length) {
        pkcs11.C_FindObjectsInit(session, [
            { type: pkcs11.CKA_CLASS, value: keyClass },
            { type: pkcs11.CKA_LABEL, value: String(label) }
        ]);
        handles = pkcs11.C_FindObjects(session, 1);
        pkcs11.C_FindObjectsFinal(session);
    }

    if (!handles || !handles.length) {
        throw new Error(`No HSM key found for label "${label}"`);
    }
    return handles[0];
}

async function test() {
    console.log('1. Loading PKCS#11 library from:', LIB_PATH);
    const pkcs11 = new pkcs11js.PKCS11();
    Object.assign(pkcs11, pkcs11js);
    const p11 = pkcs11;

    pkcs11.load(LIB_PATH);
    pkcs11.C_Initialize();

    const slots = pkcs11.C_GetSlotList(true);
    const session = pkcs11.C_OpenSession(slots[0], 0x00000004 | 0x00000002);
    pkcs11.C_Login(session, 1, PIN);
    console.log('Session established and logged in.');

    const label = 'test_csr_key';
    const labelBuf = Buffer.from(label, 'utf8');
    const bits = 2048;

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

    console.log('Generating RSA key pair in HSM...');
    const handles = pkcs11.C_GenerateKeyPair(
        session,
        { mechanism: pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN },
        publicTemplate,
        privateTemplate
    );
    console.log('Key pair generated successfully!');

    let modulus;
    let exponent;
    try {
        console.log('Reading public key modulus and exponent...');
        const pubHandle = findKeyHandle(pkcs11, session, p11, label, p11.CKO_PUBLIC_KEY);
        modulus = readAttribute(pkcs11, session, pubHandle, p11.CKA_MODULUS, bits / 8);
        exponent = readAttribute(pkcs11, session, pubHandle, p11.CKA_PUBLIC_EXPONENT, 8);
        console.log('SUCCESS: Modulus read! Length:', modulus.length);
        console.log('SUCCESS: Exponent read! Length:', exponent.length);
    } catch (readErr) {
        try { pkcs11.C_DestroyObject(session, handles.privateKey); } catch (e) { }
        try { pkcs11.C_DestroyObject(session, handles.publicKey); } catch (e) { }
        throw new Error(`Public key read failed: ${readErr.message}`);
    }

    const n = new forge.jsbn.BigInteger(modulus.toString('hex'), 16);
    const e = new forge.jsbn.BigInteger(exponent.toString('hex'), 16);
    const publicKey = forge.pki.setRsaPublicKey(n, e);

    console.log('Assembling CSR with node-forge...');
    const csr = forge.pki.createCertificationRequest();
    csr.publicKey = publicKey;
    csr.setSubject(parseDnToAttributes('CN=xchangelab,O=mac,C=IN'));

    csr.certificationRequestInfo = forge.pki.getCertificationRequestInfo(csr);
    const criBytes = Buffer.from(forge.asn1.toDer(csr.certificationRequestInfo).getBytes(), 'binary');

    console.log('Signing CSR with private key in CloudHSM...');
    pkcs11.C_SignInit(session, { mechanism: pkcs11.CKM_SHA256_RSA_PKCS }, handles.privateKey);
    const sigBuf = Buffer.alloc(bits / 8);
    const signature = pkcs11.C_Sign(session, criBytes, sigBuf);
    console.log('SUCCESS: Signed! Signature length:', signature.length);

    csr.md = forge.md.sha256.create();
    csr.signatureOid = csr.siginfo.algorithmOid = forge.pki.oids.sha256WithRSAEncryption;
    csr.signature = signature.toString('binary');

    const csrPem = forge.pki.certificationRequestToPem(csr);
    console.log('\n--- GENERATED CSR PEM ---');
    console.log(csrPem);
    console.log('--- END CSR PEM ---\n');

    // Cleanup
    try { pkcs11.C_DestroyObject(session, handles.privateKey); } catch (e) { }
    try { pkcs11.C_DestroyObject(session, handles.publicKey); } catch (e) { }
    pkcs11.C_Logout(session);
    pkcs11.C_CloseSession(session);
    pkcs11.C_Finalize();
    console.log('Test completed successfully and keys cleaned up.');
}

test().catch(console.error);

/**
 * Test script to find the exact key attributes and sign mechanism accepted by CloudHSM
 */
require('dotenv').config();
const pkcs11js = require('pkcs11js');
const crypto = require('crypto');

const LIB_PATH = process.env.CLOUDHSM_PKCS11_LIB || '/opt/cloudhsm/lib/libcloudhsm_pkcs11.so';
const PIN = process.env.CLOUDHSM_PIN;

async function test() {
    const pkcs11 = new pkcs11js.PKCS11();
    Object.assign(pkcs11, pkcs11js);

    pkcs11.load(LIB_PATH);
    pkcs11.C_Initialize();

    const slots = pkcs11.C_GetSlotList(true);
    const session = pkcs11.C_OpenSession(slots[0], 0x00000004 | 0x00000002);
    pkcs11.C_Login(session, 1, PIN);

    console.log('Logged in. Generating key with CloudHSM standard attributes...');
    const label = Buffer.from('test_attr_probe', 'utf8');

    // Standard AWS CloudHSM recommended templates from AWS documentation:
    const publicTemplate = [
        { type: pkcs11.CKA_TOKEN, value: true },
        { type: pkcs11.CKA_PRIVATE, value: false },       // Public key is NOT private
        { type: pkcs11.CKA_VERIFY, value: true },
        { type: pkcs11.CKA_ENCRYPT, value: true },
        { type: pkcs11.CKA_MODULUS_BITS, value: 2048 },
        { type: pkcs11.CKA_PUBLIC_EXPONENT, value: Buffer.from([1, 0, 1]) },
        { type: pkcs11.CKA_LABEL, value: label }
    ];

    const privateTemplate = [
        { type: pkcs11.CKA_TOKEN, value: true },
        { type: pkcs11.CKA_PRIVATE, value: true },        // Private key IS private
        { type: pkcs11.CKA_SENSITIVE, value: true },
        { type: pkcs11.CKA_SIGN, value: true },
        { type: pkcs11.CKA_DECRYPT, value: true },
        { type: pkcs11.CKA_EXTRACTABLE, value: false },
        { type: pkcs11.CKA_LABEL, value: label }
    ];

    const keys = pkcs11.C_GenerateKeyPair(
        session,
        { mechanism: pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN },
        publicTemplate,
        privateTemplate
    );
    console.log('Key pair generated successfully!');

    // Test 1: Query CKA_MODULUS now that CKA_PRIVATE: false is explicitly set
    console.log('Testing C_GetAttributeValue for Modulus...');
    try {
        const res = pkcs11.C_GetAttributeValue(session, keys.publicKey, [
            { type: pkcs11.CKA_MODULUS }
        ]);
        console.log('SUCCESS: Modulus retrieved! Length:', res[0].value ? res[0].value.length : 0);
    } catch (e) {
        console.error('FAILED Modulus query:', e.message);
    }

    // Test 2: C_Sign with CKM_RSA_PKCS (DigestInfo formatted hash)
    console.log('Testing C_Sign with CKM_RSA_PKCS...');
    try {
        const rawData = Buffer.from('hello world test data');
        const hash = crypto.createHash('sha256').update(rawData).digest();
        // PKCS#1 v1.5 DigestInfo prefix for SHA-256
        const digestInfoPrefix = Buffer.from('3031300d060960864801650304020105000420', 'hex');
        const digestInfo = Buffer.concat([digestInfoPrefix, hash]);

        pkcs11.C_SignInit(session, { mechanism: pkcs11.CKM_RSA_PKCS }, keys.privateKey);
        const sig = pkcs11.C_Sign(session, digestInfo, Buffer.alloc(256));
        console.log('SUCCESS: CKM_RSA_PKCS signed! Signature length:', sig.length);
    } catch (e) {
        console.error('FAILED CKM_RSA_PKCS:', e.message);
    }

    // Test 3: C_Sign with CKM_SHA256_RSA_PKCS
    console.log('Testing C_Sign with CKM_SHA256_RSA_PKCS...');
    try {
        pkcs11.C_SignInit(session, { mechanism: pkcs11.CKM_SHA256_RSA_PKCS }, keys.privateKey);
        const sig = pkcs11.C_Sign(session, Buffer.from('hello world test data'), Buffer.alloc(256));
        console.log('SUCCESS: CKM_SHA256_RSA_PKCS signed! Signature length:', sig.length);
    } catch (e) {
        console.error('FAILED CKM_SHA256_RSA_PKCS:', e.message);
    }

    // Cleanup
    pkcs11.C_DestroyObject(session, keys.publicKey);
    pkcs11.C_DestroyObject(session, keys.privateKey);
    pkcs11.C_Logout(session);
    pkcs11.C_CloseSession(session);
    pkcs11.C_Finalize();
}

test().catch(console.error);

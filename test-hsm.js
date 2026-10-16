/**
 * Diagnostic test to inspect key handles and test C_GetAttributeValue with exact PKCS#11 attributes
 */
require('dotenv').config();
const pkcs11js = require('pkcs11js');

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

    console.log('Logged in.');
    const label = Buffer.from('test_diag_key', 'utf8');

    // The working template from the previous run:
    const publicTemplate = [
        { type: pkcs11.CKA_TOKEN, value: true },
        { type: pkcs11.CKA_LABEL, value: label },
        { type: pkcs11.CKA_MODULUS_BITS, value: 2048 },
        { type: pkcs11.CKA_PUBLIC_EXPONENT, value: Buffer.from([1, 0, 1]) },
        { type: pkcs11.CKA_VERIFY, value: true },
        { type: pkcs11.CKA_ENCRYPT, value: true }
    ];

    const privateTemplate = [
        { type: pkcs11.CKA_TOKEN, value: true },
        { type: pkcs11.CKA_LABEL, value: label },
        { type: pkcs11.CKA_PRIVATE, value: true },
        { type: pkcs11.CKA_SIGN, value: true },
        { type: pkcs11.CKA_DECRYPT, value: true },
        { type: pkcs11.CKA_EXTRACTABLE, value: false }
    ];

    const keys = pkcs11.C_GenerateKeyPair(
        session,
        { mechanism: pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN },
        publicTemplate,
        privateTemplate
    );

    console.log('Keys object keys:', Object.keys(keys));
    console.log('Public handle:', keys.publicKey);
    console.log('Private handle:', keys.privateKey);

    // Test C_GetAttributeValue for basic attributes first
    console.log('Reading CKA_LABEL and CKA_CLASS...');
    try {
        const basic = pkcs11.C_GetAttributeValue(session, keys.publicKey, [
            { type: pkcs11.CKA_CLASS },
            { type: pkcs11.CKA_KEY_TYPE }
        ]);
        console.log('Class & KeyType:', basic);
    } catch (e) {
        console.error('Basic attr failed:', e.message);
    }

    // Now test CKA_MODULUS
    console.log('Reading CKA_MODULUS...');
    try {
        const mod = pkcs11.C_GetAttributeValue(session, keys.publicKey, [
            { type: pkcs11.CKA_MODULUS }
        ]);
        console.log('Modulus read SUCCESS! Value is Buffer?', Buffer.isBuffer(mod[0].value), 'Length:', mod[0].value ? mod[0].value.length : 0);
    } catch (e) {
        console.error('Modulus read failed:', e.message);
    }

    // Test C_Sign with CKM_RSA_PKCS (with SHA-256 pre-hashed DigestInfo)
    console.log('Testing C_Sign with CKM_RSA_PKCS...');
    try {
        const crypto = require('crypto');
        const hash = crypto.createHash('sha256').update('test').digest();
        const prefix = Buffer.from('3031300d060960864801650304020105000420', 'hex');
        const digestInfo = Buffer.concat([prefix, hash]);

        pkcs11.C_SignInit(session, { mechanism: pkcs11.CKM_RSA_PKCS }, keys.privateKey);
        const sig = pkcs11.C_Sign(session, digestInfo, Buffer.alloc(256));
        console.log('C_Sign CKM_RSA_PKCS SUCCESS! Sig length:', sig.length);
    } catch (e) {
        console.error('C_Sign CKM_RSA_PKCS failed:', e.message);
    }

    // Cleanup
    pkcs11.C_DestroyObject(session, keys.publicKey);
    pkcs11.C_DestroyObject(session, keys.privateKey);
    pkcs11.C_Logout(session);
    pkcs11.C_CloseSession(session);
    pkcs11.C_Finalize();
    console.log('Cleanup complete.');
}

test().catch(console.error);

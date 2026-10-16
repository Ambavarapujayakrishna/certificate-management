/**
 * Standalone test script to test RSA Key Generation AND Attribute Reading on CloudHSM
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

    console.log('Logged in. Generating RSA 2048 key pair...');
    const label = Buffer.from('test_read_attrs_key', 'utf8');

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
    console.log('Key pair generated successfully! Public key handle:', keys.publicKey);

    // Test 1: Query with empty template
    console.log('Testing C_GetAttributeValue approach 1: [ { type: CKA_MODULUS }, { type: CKA_PUBLIC_EXPONENT } ]');
    try {
        const res = pkcs11.C_GetAttributeValue(session, keys.publicKey, [
            { type: pkcs11.CKA_MODULUS },
            { type: pkcs11.CKA_PUBLIC_EXPONENT }
        ]);
        console.log('Approach 1 SUCCESS! Modulus length:', res[0].value ? res[0].value.length : 'null');
    } catch (e1) {
        console.error('Approach 1 FAILED:', e1.message);
    }

    // Test 2: Query single attribute
    console.log('Testing C_GetAttributeValue approach 2: single CKA_MODULUS');
    try {
        const res = pkcs11.C_GetAttributeValue(session, keys.publicKey, [
            { type: pkcs11.CKA_MODULUS }
        ]);
        console.log('Approach 2 SUCCESS! Modulus length:', res[0].value ? res[0].value.length : 'null');
    } catch (e2) {
        console.error('Approach 2 FAILED:', e2.message);
    }

    // Test 3: Sign test
    console.log('Testing C_Sign with CKM_SHA256_RSA_PKCS...');
    try {
        pkcs11.C_SignInit(session, { mechanism: pkcs11.CKM_SHA256_RSA_PKCS }, keys.privateKey);
        const sig = pkcs11.C_Sign(session, Buffer.from('hello world test data'), Buffer.alloc(256));
        console.log('C_Sign SUCCESS! Signature length:', sig.length);
    } catch (e3) {
        console.error('C_Sign FAILED:', e3.message);
    }

    // Cleanup
    pkcs11.C_DestroyObject(session, keys.publicKey);
    pkcs11.C_DestroyObject(session, keys.privateKey);
    pkcs11.C_Logout(session);
    pkcs11.C_CloseSession(session);
    pkcs11.C_Finalize();
    console.log('Done test.');
}

test().catch(console.error);

/**
 * Standalone test script for AWS CloudHSM via PKCS#11 in Node.js
 * Equivalent to the working python test script.
 * 
 * Usage on EC2:
 *   node test-hsm.js
 */
require('dotenv').config();
const pkcs11js = require('pkcs11js');

const LIB_PATH = process.env.CLOUDHSM_PKCS11_LIB || '/opt/cloudhsm/lib/libcloudhsm_pkcs11.so';
const PIN = process.env.CLOUDHSM_PIN;

async function testCloudHsm() {
    console.log('1. Loading PKCS#11 library from:', LIB_PATH);
    const pkcs11 = new pkcs11js.PKCS11();
    Object.assign(pkcs11, pkcs11js);

    try {
        pkcs11.load(LIB_PATH);
        pkcs11.C_Initialize();
    } catch (e) {
        console.error('Failed to load PKCS#11 library:', e.message);
        return;
    }

    console.log('2. Looking for CloudHSM Slot/Token...');
    let slots;
    try {
        slots = pkcs11.C_GetSlotList(true);
        if (!slots.length) {
            console.error('Error: No CloudHSM slots found. Is CloudHSM daemon configured & connected?');
            return;
        }
    } catch (e) {
        console.error('Error getting slot list:', e.message);
        return;
    }

    const slot = slots[0];
    const tokenInfo = pkcs11.C_GetTokenInfo(slot);
    console.log('Token found:', tokenInfo.label.trim());

    if (!PIN) {
        console.error('Error: CLOUDHSM_PIN not set in environment or .env');
        return;
    }

    console.log('3. Opening session and logging in as CU...');
    const CKF_SERIAL_SESSION = 0x00000004;
    const CKF_RW_SESSION = 0x00000002;
    const CKU_USER = 1;

    let session;
    try {
        session = pkcs11.C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        pkcs11.C_Login(session, CKU_USER, PIN);
        console.log('Session established and logged in.');

        console.log('4. Testing RSA 2048 key pair generation...');
        const label = Buffer.from('test_node_hsm_key', 'utf8');

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

        console.log('SUCCESS: RSA Key pair generated inside AWS CloudHSM!');

        console.log('5. Cleaning up test keys...');
        pkcs11.C_DestroyObject(session, keys.publicKey);
        pkcs11.C_DestroyObject(session, keys.privateKey);
        console.log('Test keys destroyed successfully.');

    } catch (err) {
        console.error('FAILED with error:', err.message);
    } finally {
        if (session) {
            try { pkcs11.C_Logout(session); } catch (_) { }
            try { pkcs11.C_CloseSession(session); } catch (_) { }
        }
        try { pkcs11.C_Finalize(); } catch (_) { }
    }
}

testCloudHsm();

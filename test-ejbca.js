require('dotenv').config();
const fs = require('fs');
const https = require('https');
const crypto = require('crypto');
const axios = require('axios');

console.log('=== EJBCA TLS & Certificate Diagnostic ===\n');

// 1. Check environment variables
console.log('1. Configuration:');
console.log('   EJBCA_BASE_URL:', process.env.EJBCA_BASE_URL);
console.log('   EJBCA_CLIENT_CERT_PATH:', process.env.EJBCA_CLIENT_CERT_PATH);
console.log('   EJBCA_CLIENT_KEY_PATH:', process.env.EJBCA_CLIENT_KEY_PATH);
console.log('   EJBCA_CA_CERT_PATH:', process.env.EJBCA_CA_CERT_PATH);
console.log('   EJBCA_TLS_INSECURE:', process.env.EJBCA_TLS_INSECURE);
console.log('   EJBCA_TLS_ALLOW_WEAK_KEYS:', process.env.EJBCA_TLS_ALLOW_WEAK_KEYS);
console.log('');

// 2. Check Client Certificate
const certPath = process.env.EJBCA_CLIENT_CERT_PATH;
const keyPath = process.env.EJBCA_CLIENT_KEY_PATH;

if (!certPath || !fs.existsSync(certPath)) {
    console.error(`❌ Client cert file NOT found at: ${certPath}`);
} else {
    const certContent = fs.readFileSync(certPath, 'utf8');
    console.log(`✅ Client cert file exists (${certContent.length} bytes)`);
    try {
        const x509 = new crypto.X509Certificate(certContent);
        console.log('   Subject:', x509.subject);
        console.log('   Issuer:', x509.issuer);
        console.log('   Key details:', JSON.stringify(x509.publicKey.asymmetricKeyDetails || x509.publicKey.asymmetricKeyType));
        console.log('   Valid to:', x509.validTo);
    } catch (e) {
        console.error('   ❌ Could not parse client cert as X509 PEM:', e.message);
    }
}

if (!keyPath || !fs.existsSync(keyPath)) {
    console.error(`❌ Client key file NOT found at: ${keyPath}`);
} else {
    const keyContent = fs.readFileSync(keyPath, 'utf8');
    console.log(`✅ Client key file exists (${keyContent.length} bytes)`);
}
console.log('');

// 3. Test TLS Secure Context creation
console.log('2. Testing TLS SecureContext initialization:');
try {
    const cert = certPath && fs.existsSync(certPath) ? fs.readFileSync(certPath) : undefined;
    const key = keyPath && fs.existsSync(keyPath) ? fs.readFileSync(keyPath) : undefined;
    const tls = require('tls');
    
    // Attempt standard
    try {
        tls.createSecureContext({ cert, key });
        console.log('   ✅ Standard SecureContext (SECLEVEL=2) created successfully!');
    } catch (err) {
        console.log('   ⚠️  Standard SecureContext failed:', err.message);
        console.log('       (This confirms OpenSSL rejected the key size under SECLEVEL=2)');
    }

    // Attempt with SECLEVEL=0
    try {
        tls.createSecureContext({ cert, key, ciphers: 'DEFAULT@SECLEVEL=0' });
        console.log('   ✅ SECLEVEL=0 SecureContext created successfully!');
    } catch (err) {
        console.log('   ❌ SECLEVEL=0 SecureContext also failed:', err.message);
    }
} catch (e) {
    console.error('   Context error:', e.message);
}
console.log('');

// 4. Test live connection to EJBCA
console.log('3. Testing Live Connection to EJBCA:');
async function testConnection() {
    const cert = certPath && fs.existsSync(certPath) ? fs.readFileSync(certPath) : undefined;
    const key = keyPath && fs.existsSync(keyPath) ? fs.readFileSync(keyPath) : undefined;
    const ca = process.env.EJBCA_CA_CERT_PATH && fs.existsSync(process.env.EJBCA_CA_CERT_PATH)
        ? fs.readFileSync(process.env.EJBCA_CA_CERT_PATH)
        : undefined;

    const agent = new https.Agent({
        cert,
        key,
        ca,
        rejectUnauthorized: process.env.EJBCA_TLS_INSECURE !== 'true',
        ciphers: process.env.EJBCA_CIPHERS || 'DEFAULT@SECLEVEL=0',
        minVersion: 'TLSv1',
    });

    try {
        const client = axios.create({
            baseURL: process.env.EJBCA_BASE_URL || 'https://localhost:8443/ejbca/ejbca-rest-api/v1',
            httpsAgent: agent,
            timeout: 10000,
        });

        const res = await client.get('/certificate/status');
        console.log(`   ✅ Connection succeeded! HTTP status: ${res.status}`);
    } catch (err) {
        console.log(`   ❌ Connection result: ${err.message}`);
        if (err.response) {
            console.log(`      Server responded with HTTP ${err.response.status}:`, err.response.data);
        }
    }
}

testConnection();

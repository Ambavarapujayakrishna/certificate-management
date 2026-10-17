const axios = require('axios');
const https = require('https');
const fs = require('fs');

function readIfExists(p) {
    return p && fs.existsSync(p) ? fs.readFileSync(p) : undefined;
}

function buildHttpsAgent() {
    // When EJBCA server or client certificates use legacy or smaller key lengths (e.g. 1024-bit RSA),
    // OpenSSL 3.0+ (built into Node 18+) rejects the TLS handshake with:
    //   "error:0A00018F:SSL routines::ee key too small" (due to default SECLEVEL=2).
    // Using 'DEFAULT@SECLEVEL=0' explicitly lowers OpenSSL's security level to 0,
    // permitting legacy/shorter EE key lengths and avoiding handshake aborts.
    const crypto = require('crypto');
    const agentOptions = {
        ca: readIfExists(process.env.EJBCA_CA_CERT_PATH),
        // Only set EJBCA_TLS_INSECURE=true for local/trial servers where self-signed TLS certs are used (like Postman SSL verification OFF).
        rejectUnauthorized: process.env.EJBCA_TLS_INSECURE !== 'true',
        ciphers: process.env.EJBCA_CIPHERS || 'DEFAULT@SECLEVEL=0',
        minVersion: 'TLSv1',
    };

    if (process.env.EJBCA_CLIENT_PFX_PATH && fs.existsSync(process.env.EJBCA_CLIENT_PFX_PATH)) {
        agentOptions.pfx = fs.readFileSync(process.env.EJBCA_CLIENT_PFX_PATH);
        if (process.env.EJBCA_CLIENT_PFX_PASSWORD) {
            agentOptions.passphrase = process.env.EJBCA_CLIENT_PFX_PASSWORD;
        }
    } else {
        agentOptions.cert = readIfExists(process.env.EJBCA_CLIENT_CERT_PATH);
        agentOptions.key = readIfExists(process.env.EJBCA_CLIENT_KEY_PATH);
        if (process.env.EJBCA_CLIENT_KEY_PASSWORD) {
            agentOptions.passphrase = process.env.EJBCA_CLIENT_KEY_PASSWORD;
        }
    }

    if (crypto.constants?.SSL_OP_LEGACY_SERVER_CONNECT) {
        agentOptions.secureOptions = (crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT || 0x4) |
            (crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION || 0x00040000);
    }

    return new https.Agent(agentOptions);
}

function client() {
    return axios.create({
        baseURL: process.env.EJBCA_BASE_URL || 'https://localhost:8443/ejbca/ejbca-rest-api/v1',
        httpsAgent: buildHttpsAgent(),
        timeout: 15000,
    });
}

// EJBCA's pkcs10enroll response may return certificates as raw base64 DER; normalize to PEM.
function toPem(value) {
    if (!value) return value;
    if (value.includes('BEGIN CERTIFICATE')) return value;
    return `-----BEGIN CERTIFICATE-----\n${(value.match(/.{1,64}/g) || []).join('\n')}\n-----END CERTIFICATE-----\n`;
}

// Submits a CSR to the real EJBCA V1 REST API.
// Requires an end entity with this username/password already registered in EJBCA
// (created via the EJBCA Admin UI or REST, matching the certificate/end-entity profiles used here.
async function enroll({ csrPem, username, password, certificateProfileName, endEntityProfileName, certificateAuthorityName }) {
    if (!username || !password) {
        const err = new Error('username and enrollmentCode are required to enroll with EJBCA');
        err.status = 400;
        throw err;
    }

    const payload = {
        certificate_request: csrPem,
        certificate_profile_name: certificateProfileName || process.env.EJBCA_DEFAULT_CERT_PROFILE || 'DocSigningProfile',
        end_entity_profile_name: endEntityProfileName || process.env.EJBCA_DEFAULT_EE_PROFILE || 'DocSigningEEProfile',
        certificate_authority_name: certificateAuthorityName || process.env.EJBCA_DEFAULT_CA_NAME || 'DocSigning Issuing CA',
        username,
        password,
        include_chain: true,
    };

    try {
        const { data } = await client().post('/certificate/pkcs10enroll', payload);
        return {
            certificatePem: toPem(data.certificate),
            chainPem: (data.certificate_chain || []).map(toPem).join(''),
        };
    } catch (err) {
        const msg = err.response?.data?.error_message || err.response?.data?.message || err.message;
        const wrapped = new Error(`EJBCA enroll failed: ${msg}`);
        wrapped.status = err.response?.status || 500;
        throw wrapped;
    }
}

async function revoke({ issuerDn, serial, reason }) {
    const { data } = await client().put(
        `/certificate/${encodeURIComponent(issuerDn)}/${encodeURIComponent(serial)}/revoke`,
        {
            reason: reason || 'CESSATION_OF_OPERATION',
        }
    );
    return data;
}

module.exports = { enroll, revoke };
const axios = require('axios');
const https = require('https');
const fs = require('fs');

function readIfExists(p) {
    return p && fs.existsSync(p) ? fs.readFileSync(p) : undefined;
}

function buildHttpsAgent() {
    return new https.Agent({
        cert: readIfExists(process.env.EJBCA_CLIENT_CERT_PATH),
        key: readIfExists(process.env.EJBCA_CLIENT_KEY_PATH),
        ca: readIfExists(process.env.EJBCA_CA_CERT_PATH),
        // Only ever set EJBCA_TLS_INSECURE=true against a local trial server you fully control.
        rejectUnauthorized: process.env.EJBCA_TLS_INSECURE !== 'true',
    });
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
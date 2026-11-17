// ==============================================================================
// Verix Zero-Trust Runtime — Phase 4: TLS 1.3 Mutual TLS (mTLS) & SPIFFE Verifier
// ==============================================================================
// Enforces strict TLS 1.3 mutual authentication, SPIFFE URI Subject Alternative
// Name (SAN) verification, and SHA-256 certificate fingerprint pinning for all
// node-to-node cross-cloud quorum replication calls.
// ==============================================================================

import https from 'node:https';
import { X509Certificate } from 'node:crypto';

export const ALLOWED_SPIFFE_PREFIX = 'spiffe://verix.internal/ns/prod/node/';

/**
 * Builds strict TLS 1.3 server options requiring client X.509 certificates
 * signed by the internal Verix Root CA.
 */
export function buildMtlsServerOptions({ certPem, keyPem, caCertPem }) {
  if (!certPem || !keyPem || !caCertPem) {
    throw new Error('Zero-Trust mTLS requires certPem, keyPem, and caCertPem');
  }
  return {
    cert: certPem,
    key: keyPem,
    ca: [caCertPem],
    minVersion: 'TLSv1.3',
    maxVersion: 'TLSv1.3',
    ciphers: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
    honorCipherOrder: true,
    requestCert: true,
    rejectUnauthorized: true,
  };
}

/**
 * Verifies a peer's presented X.509 client/server certificate against the
 * expected SPIFFE URI SAN and optional SHA-256 fingerprint allowlist.
 */
export function verifyPeerSpiffeIdentity(rawCertBuffer, { allowedNodeIds = [], pinnedFingerprints256 = [] } = {}) {
  const x509 = new X509Certificate(rawCertBuffer);
  const san = x509.subjectAltName ?? '';

  const uriMatch = san
    .split(',')
    .map((entry) => entry.trim())
    .find((entry) => entry.startsWith(`URI:${ALLOWED_SPIFFE_PREFIX}`));

  if (!uriMatch) {
    throw new Error(`mTLS peer certificate rejected: missing SPIFFE URI with prefix ${ALLOWED_SPIFFE_PREFIX}`);
  }

  const spiffeUri = uriMatch.slice(4);
  const nodeId = spiffeUri.slice(ALLOWED_SPIFFE_PREFIX.length);

  if (allowedNodeIds.length > 0 && !allowedNodeIds.includes(nodeId)) {
    throw new Error(`mTLS peer certificate rejected: unauthorized SPIFFE nodeId "${nodeId}"`);
  }

  if (pinnedFingerprints256.length > 0 && !pinnedFingerprints256.includes(x509.fingerprint256)) {
    throw new Error(`mTLS peer certificate rejected: SHA-256 fingerprint ${x509.fingerprint256} is not pinned`);
  }

  return {
    authorized: true,
    nodeId,
    spiffeUri,
    subject: x509.subject,
    fingerprint256: x509.fingerprint256,
    validTo: x509.validTo,
  };
}

/**
 * Creates a hardened HTTPS client agent for cross-cloud AWS <-> GCP peer gossip.
 */
export function createMtlsPeerAgent({ certPem, keyPem, caCertPem, allowedNodeIds = [], pinnedFingerprints256 = [] }) {
  return new https.Agent({
    cert: certPem,
    key: keyPem,
    ca: [caCertPem],
    minVersion: 'TLSv1.3',
    maxVersion: 'TLSv1.3',
    rejectUnauthorized: true,
    keepAlive: true,
    checkServerIdentity: (_host, cert) => {
      try {
        verifyPeerSpiffeIdentity(cert.raw, { allowedNodeIds, pinnedFingerprints256 });
        return undefined;
      } catch (error) {
        return error;
      }
    },
  });
}

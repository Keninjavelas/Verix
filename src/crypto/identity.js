import { canonicalize, digestOf, fromB64u, sha3_256, toB64u } from './hash.js';
import { SIGNING_ALGS, generateSigningKeyPair, sign, verify } from './pqc.js';

const IDENTITY_BODY_FIELDS = ['id', 'alg', 'publicKey', 'subject', 'scopes', 'issuedAt', 'expiresAt', 'kind', 'parent'];

export function fingerprintPublicKey(publicKey) {
  return sha3_256(publicKey);
}

export function identityIdFor(publicKey) {
  return `verix:agent:${toB64u(fingerprintPublicKey(publicKey)).slice(0, 12)}`;
}

function bodyOf(identity) {
  const body = {};
  for (const field of IDENTITY_BODY_FIELDS) {
    if (field === 'parent') {
      /* The issuer signature is attached after the subject has signed, so the
         self binding covers the issuer id only; verifyIssuerLink signs this same body. */
      if (identity.parent?.id !== undefined) body.parent = { id: identity.parent.id };
      continue;
    }
    if (identity[field] !== undefined) body[field] = identity[field];
  }
  return body;
}

export function identityDigest(identity) {
  return digestOf(bodyOf(identity), 'verix:identity:v1');
}

export async function createIdentity({
  keyPair,
  subject,
  scopes = [],
  kind = 'agent',
  ttlSeconds = 60 * 60 * 24 * 30,
  issuedAt = new Date().toISOString(),
  parent = null,
} = {}) {
  if (!keyPair) throw new Error('createIdentity requires a keyPair');
  if (!subject || !subject.name) throw new Error('createIdentity requires subject.name');
  const identity = {
    id: identityIdFor(keyPair.publicKey),
    alg: keyPair.alg,
    publicKey: toB64u(keyPair.publicKey),
    subject,
    scopes: scopes.map(normalizeScope),
    kind,
    issuedAt,
    expiresAt: new Date(Date.parse(issuedAt) + ttlSeconds * 1000).toISOString(),
    parent,
  };
  identity.selfSignature = toB64u(await sign(keyPair, textBody(identity)));
  return identity;
}

export async function issueIdentityUnderIssuer({ issuerKeyPair, issuerIdentity, ...params }) {
  if (!issuerKeyPair || !issuerIdentity) throw new Error('issueIdentityUnderIssuer requires issuerKeyPair and issuerIdentity');
  const identity = await createIdentity({ ...params, parent: { id: issuerIdentity.id } });
  if (issuerIdentity.id === identity.id) throw new Error('an identity cannot issue itself as a child of itself');
  identity.parent.issuerSignature = toB64u(await sign(issuerKeyPair, textBody(identity)));
  return identity;
}

export async function issueDelegatedIdentity({ issuerKeyPair, issuerIdentity, subject, scopes, ttlSeconds, kind = 'agent', issuedAt, seed }) {
  assertScopesSubset(issuerIdentity.scopes, scopes);
  const keyPair = seed ? await generateSigningKeyPair(issuerIdentity.alg, { seed }) : await generateSigningKeyPair(issuerIdentity.alg);
  return issueIdentityUnderIssuer({
    issuerKeyPair,
    issuerIdentity,
    keyPair,
    subject,
    scopes,
    ttlSeconds,
    kind,
    issuedAt,
  });
}

function textBody(identity) {
  return canonicalize(bodyOf(identity));
}

export function normalizeScope(scope) {
  if (typeof scope === 'string') return { action: scope, resource: '*', constraint: {} };
  const { action = '*', resource = '*', constraint = {} } = scope;
  return { action, resource, constraint };
}

function globToRegExp(pattern) {
  const escaped = String(pattern).replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\\\*/g, '.*').replace(/\\\?/g, '.');
  return new RegExp(`^${escaped}$`, 's');
}

export function globMatch(pattern, value) {
  return globToRegExp(pattern).test(String(value));
}

export function matchesScope(scope, action, resource) {
  return globMatch(scope.action, action) && globMatch(scope.resource, resource);
}

export function findMatchingScopes(identity, action, resource) {
  return (identity.scopes ?? []).filter((scope) => matchesScope(scope, action, resource));
}

export async function verifyIdentitySelfBinding(identity) {
  const publicKey = fromB64u(identity.publicKey);
  if (publicKey.length !== SIGNING_ALGS[identity.alg]?.publicKeyBytes) return false;
  if (identity.id !== identityIdFor(publicKey)) return false;
  return verify(identity.alg, publicKey, textBody(identity), fromB64u(identity.selfSignature));
}

export async function verifyIssuerLink(identity, parentIdentity) {
  if (!identity.parent) return false;
  if (identity.parent.id !== parentIdentity.id) return false;
  const parentKey = fromB64u(parentIdentity.publicKey);
  return verify(parentIdentity.alg, parentKey, textBody(identity), fromB64u(identity.parent.issuerSignature));
}

export function assertScopesSubset(grantedScopes, requestedScopes) {
  const granted = grantedScopes.map(normalizeScope);
  for (const raw of requestedScopes) {
    const requested = normalizeScope(raw);
    const covered = granted.some((scope) => scopeCovers(scope, requested));
    if (!covered) {
      throw new Error(`scope ${requested.action} on ${requested.resource} is not contained in the issuer's own scopes`);
    }
  }
}

function scopeCovers(granted, requested) {
  if (!globToRegExp(granted.action).test(requested.action)) return false;
  if (!globToRegExp(granted.resource).test(requested.resource)) return false;
  for (const [key, limit] of Object.entries(granted.constraint ?? {})) {
    const value = requested.constraint?.[key];
    if (value === undefined) continue;
    if (typeof limit === 'number') {
      if (typeof value !== 'number' || value > limit) return false;
    } else if (typeof limit === 'boolean') {
      if (limit === false && value === true) return false;
    } else if (Array.isArray(limit)) {
      const list = Array.isArray(value) ? value : [value];
      if (!list.every((item) => limit.includes(item))) return false;
    }
  }
  return true;
}

export function executionFingerprint({ modelVersion, promptHash, codeVersion, toolset = [], runtime = {} }) {
  return digestOf(
    {
      modelVersion,
      promptHash,
      codeVersion,
      toolset: [...toolset].sort(),
      runtime,
    },
    'verix:execution-fingerprint:v1',
  );
}

export function revocationDigest(revocation) {
  const { signature, revocationId, ...core } = revocation;
  return digestOf(core, 'verix:revocation:v1');
}

export async function createRevocation({ keyPair, identityId, reason, revokedAt = new Date().toISOString(), revokedBy = null }) {
  // revokedBy defaults to the identity the signing key belongs to, because that is
  // the pairing assertRevocationAuthority checks; naming any other revoker here
  // would produce an entry that cannot pass its own authority check.
  const entry = {
    identityId,
    reason,
    revokedAt,
    revokedBy: revokedBy ?? identityIdFor(keyPair.publicKey),
    alg: keyPair.alg,
    revokerPublicKey: toB64u(keyPair.publicKey),
  };
  entry.revocationId = revocationDigest(entry);
  entry.signature = toB64u(await sign(keyPair, canonicalize(entry)));
  return entry;
}

export async function verifyRevocation(entry) {
  const unsigned = { ...entry };
  delete unsigned.signature;
  if (revocationDigest(unsigned) !== entry.revocationId) return false;
  return verify(entry.alg, fromB64u(entry.revokerPublicKey), canonicalize(unsigned), fromB64u(entry.signature));
}

export function revocationSignerId(entry) {
  return identityIdFor(fromB64u(entry.revokerPublicKey));
}

/*
 * A revocation is only meaningful if the signer may revoke. Without this the
 * control would be forgeable by anyone holding any signing key, which would turn
 * revocation into a denial-of-trust primitive against arbitrary agents.
 */
export function assertRevocationAuthority(entry, identity) {
  const signerId = revocationSignerId(entry);
  if (signerId !== entry.revokedBy) {
    return { ok: false, reason: `revocation claims revoker ${entry.revokedBy} but is signed by ${signerId}` };
  }
  const mayRevoke = [identity.id, identity.parent?.id].filter(Boolean);
  if (!mayRevoke.includes(entry.revokedBy)) {
    return { ok: false, reason: `${entry.revokedBy} is neither the identity nor its issuing authority` };
  }
  return { ok: true, byIssuer: entry.revokedBy !== identity.id };
}

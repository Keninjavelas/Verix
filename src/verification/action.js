import { digestOf, fromB64u, fromHex, toB64u } from '../crypto/hash.js';
import { sign, verify } from '../crypto/pqc.js';
import { recordHashOf } from '../ledger/chain.js';

export function payloadDigestOf(payload) {
  return digestOf(payload ?? null, 'verix:payload:v1');
}

export function buildActionEnvelope({ agentId, action, resource, executedAt, context = {}, executionFingerprint = null, payload = null }) {
  if (!agentId) throw new Error('action envelope requires agentId');
  if (!action) throw new Error('action envelope requires action');
  if (!resource) throw new Error('action envelope requires resource');
  return {
    agentId,
    action,
    resource,
    executedAt: executedAt ?? new Date().toISOString(),
    context,
    executionFingerprint,
    payloadDigest: payloadDigestOf(payload),
  };
}

export function actionDigestOf(envelope) {
  return digestOf(envelope, 'verix:action:v1');
}

export async function signActionEnvelope(keyPair, envelope) {
  const digest = actionDigestOf(envelope);
  const signature = await sign(keyPair, fromHex(digest));
  return { digest, alg: keyPair.alg, signature: toB64u(signature) };
}

export async function verifyActionSignature({ publicKey, alg, digest, signature }) {
  return verify(alg, publicKey, fromHex(digest), fromB64u(signature));
}

export function identitySnapshotOf(identity) {
  return {
    id: identity.id,
    alg: identity.alg,
    publicKey: identity.publicKey,
    kind: identity.kind,
    issuedAt: identity.issuedAt,
    expiresAt: identity.expiresAt,
    parent: identity.parent?.id ?? null,
    scopesDigest: digestOf(identity.scopes ?? [], 'verix:scopes:v1'),
  };
}

export function buildProofRecord({ envelope, signatureDoc, identity, policy, verdict = null }) {
  return {
    agentId: envelope.agentId,
    action: envelope.action,
    resource: envelope.resource,
    executedAt: envelope.executedAt,
    context: envelope.context,
    executionFingerprint: envelope.executionFingerprint,
    payloadDigest: envelope.payloadDigest,
    actionDigest: signatureDoc.digest,
    signatureAlg: signatureDoc.alg,
    actionSignature: signatureDoc.signature,
    identity: identitySnapshotOf(identity),
    policy: {
      authorized: policy.authorized,
      matchedScopes: policy.matchedScopes.map((scope) => ({ action: scope.action, resource: scope.resource })),
      reasons: policy.reasons,
    },
    coordinatorVerdict: verdict,
  };
}

export function submissionFor({ identity, record, signatureDoc }) {
  return {
    identity,
    actionProof: {
      record,
      recordHash: recordHashOf(record),
      digest: signatureDoc.digest,
      signature: signatureDoc.signature,
      alg: signatureDoc.alg,
    },
  };
}

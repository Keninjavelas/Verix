import test from 'node:test';
import assert from 'node:assert/strict';
import { generateSigningKeyPair, sign } from '../src/crypto/pqc.js';
import { canonicalize, fromB64u, toB64u } from '../src/crypto/hash.js';
import {
  assertRevocationAuthority,
  assertScopesSubset,
  createIdentity,
  createRevocation,
  executionFingerprint,
  findMatchingScopes,
  globMatch,
  identityDigest,
  identityIdFor,
  issueDelegatedIdentity,
  issueIdentityUnderIssuer,
  matchesScope,
  normalizeScope,
  revocationDigest,
  revocationSignerId,
  verifyIdentitySelfBinding,
  verifyIssuerLink,
  verifyRevocation,
} from '../src/crypto/identity.js';
import { MAX_DELEGATION_DEPTH, REASON_CODES, evaluateAuthorization, verifyIdentityLineage } from '../src/policy/engine.js';

const seed = (byte) => new Uint8Array(32).fill(byte);

async function issuer(byte = 1, scopes = [{ action: '*', resource: '*', constraint: { role: 'coordinator' } }]) {
  const keyPair = await generateSigningKeyPair('ML-DSA-65', { seed: seed(byte) });
  const identity = await createIdentity({ keyPair, subject: { name: 'coordinator', kind: 'platform' }, scopes, kind: 'coordinator' });
  return { identity, keyPair };
}

async function agent(byte = 2, { scopes = [{ action: 'deploy:*', resource: 'infra:*' }], name = 'Agent-7', parent = null } = {}) {
  const keyPair = await generateSigningKeyPair('ML-DSA-65', { seed: seed(byte) });
  const identity = parent
    ? await issueIdentityUnderIssuer({ issuerKeyPair: parent.keyPair, issuerIdentity: parent.identity, keyPair, subject: { name }, scopes })
    : await createIdentity({ keyPair, subject: { name }, scopes });
  return { identity, keyPair };
}

function codes(result) {
  return result.reasons.map((entry) => entry.code);
}

test('an identity id is derived from its public key alone', async () => {
  const { identity, keyPair } = await agent();
  assert.equal(identity.id, identityIdFor(keyPair.publicKey));
  assert.match(identity.id, /^verix:agent:[A-Za-z0-9_-]{12}$/);
  const twin = await agent(2);
  assert.equal(twin.identity.id, identity.id, 'the same seed key must produce the same subject');
  assert.notEqual((await agent(3)).identity.id, identity.id);
});

test('self-binding proves the subject holds the recorded key', async () => {
  const { identity } = await agent();
  assert.equal(await verifyIdentitySelfBinding(identity), true);
  assert.equal(await verifyIdentitySelfBinding({ ...identity, subject: { name: 'someone-else' } }), false);
  assert.equal(await verifyIdentitySelfBinding({ ...identity, scopes: [{ action: '*', resource: '*' }] }), false);
  assert.equal(await verifyIdentitySelfBinding({ ...identity, expiresAt: '2030-01-01T00:00:00.000Z' }), false);
  assert.equal(await verifyIdentitySelfBinding({ ...identity, id: 'verix:agent:xxxxxxxxxxxx' }), false);
  const flipped = { ...identity, selfSignature: toB64u(Uint8Array.from(fromB64u(identity.selfSignature), (b, i) => (i === 3 ? b ^ 1 : b))) };
  assert.equal(await verifyIdentitySelfBinding(flipped), false);
  assert.equal(await verifyIdentitySelfBinding({ ...identity, publicKey: toB64u(new Uint8Array(64)) }), false);
});

test('the identity digest covers the bound body and ignores the signature', async () => {
  const { identity } = await agent();
  const { selfSignature, ...unsigned } = identity;
  assert.ok(selfSignature);
  assert.equal(identityDigest(identity), identityDigest(unsigned));
  assert.notEqual(identityDigest(identity), identityDigest({ ...unsigned, kind: 'service' }));
});

test('delegation records the issuer and is signed by both sides', async () => {
  const parent = await issuer();
  const child = await agent(5, { parent });
  assert.equal(child.identity.parent.id, parent.identity.id);
  assert.ok(child.identity.parent.issuerSignature);
  assert.equal(await verifyIdentitySelfBinding(child.identity), true);
  assert.equal(await verifyIssuerLink(child.identity, parent.identity), true);
  assert.equal(await verifyIssuerLink(child.identity, (await agent(9)).identity), false, 'a different claimed issuer must not link');
  assert.equal(await verifyIssuerLink({ ...child.identity, parent: { ...child.identity.parent, issuerSignature: 'AAAAAAAA' } }, parent.identity), false);
  assert.equal(await verifyIssuerLink({ ...child.identity, scopes: [] }, parent.identity), false, 'the issuer signs the child body, not just its id');
  const selfIssued = await agent(6);
  assert.equal(await verifyIssuerLink(selfIssued.identity, selfIssued.identity), false, 'a parentless identity has no link to check');
});

test('an identity cannot be issued as its own child', async () => {
  const parent = await issuer();
  await assert.rejects(
    () => issueIdentityUnderIssuer({ issuerKeyPair: parent.keyPair, issuerIdentity: parent.identity, keyPair: parent.keyPair, subject: { name: 'loop' } }),
    /cannot issue itself/,
  );
});

test('delegated scopes must stay inside the issuer’s own authority', async () => {
  const narrow = await issuer(1, [{ action: 'deploy:infra', resource: 'infra:staging-*', constraint: { maxCostUsd: 50 } }]);
  await assert.rejects(
    () => issueDelegatedIdentity({ issuerKeyPair: narrow.keyPair, issuerIdentity: narrow.identity, subject: { name: 'Wide' }, scopes: [{ action: 'terminate:*', resource: 'prod' }] }),
    /not contained in the issuer/,
  );
  const ok = await issueDelegatedIdentity({ issuerKeyPair: narrow.keyPair, issuerIdentity: narrow.identity, subject: { name: 'Narrow' }, scopes: [{ action: 'deploy:infra', resource: 'infra:staging-1', constraint: { maxCostUsd: 20 } }] });
  assert.equal(await verifyIssuerLink(ok, narrow.identity), true);
  assert.throws(() => assertScopesSubset([{ action: 'a', resource: 'b' }], [{ action: 'a', resource: 'c' }]), /not contained/);
  assert.throws(
    () => assertScopesSubset([{ action: '*', resource: '*', constraint: { maxCostUsd: 10 } }], [{ action: '*', resource: '*', constraint: { maxCostUsd: 11 } }]),
    /not contained/,
    'a child may not raise its own cost ceiling',
  );
  assert.doesNotThrow(() => assertScopesSubset([{ action: '*', resource: '*' }], ['anything:at:all']));
});

test('scope matching treats action and resource globs independently', () => {
  assert.equal(globMatch('deploy:*', 'deploy:infra'), true);
  assert.equal(globMatch('deploy:*', 'terminate:infra'), false);
  assert.equal(globMatch('deploy.?', 'deployx'), false);
  assert.equal(globMatch('deploy.*', 'deploy:infra'), false, 'a literal dot in a pattern must not match a colon');
  assert.equal(globMatch('deploy.*', 'deploy.eu-1'), true);
  assert.equal(globMatch('*', 'a:b:c'), true);
  assert.equal(matchesScope({ action: 'deploy:*', resource: 'infra:*' }, 'deploy:infra', 'infra:prod-eu-1'), true);
  assert.equal(matchesScope({ action: 'deploy:*', resource: 'infra:*' }, 'deploy:infra', 'db:prod'), false);
  assert.deepEqual(normalizeScope('read:logs'), { action: 'read:logs', resource: '*', constraint: {} }, 'a string scope must normalise to the same shape as an object scope');
  assert.deepEqual(normalizeScope({ action: 'x' }), { action: 'x', resource: '*', constraint: {} });
});

test('findMatchingScopes returns every scope that covers the request', async () => {
  const { identity } = await agent(7, { scopes: ['read:logs', { action: 'deploy:*', resource: 'infra:*' }, { action: '*', resource: '*' }] });
  assert.equal(findMatchingScopes(identity, 'deploy:infra', 'infra:prod-eu-1').length, 2);
  assert.deepEqual(findMatchingScopes(identity, 'write:file', 'disk:c'), [{ action: '*', resource: '*', constraint: {} }]);
  assert.deepEqual(findMatchingScopes({ scopes: undefined }, 'a', 'b'), []);
});

test('authorization requires a scope and refuses expired or future-dated identities', async () => {
  const { identity } = await agent(8);
  const now = Date.parse('2026-06-01T00:00:00.000Z');
  const granted = evaluateAuthorization({ identity: { ...identity, issuedAt: '2026-01-01T00:00:00.000Z', expiresAt: '2026-12-01T00:00:00.000Z' }, action: 'deploy:infra', resource: 'infra:prod-eu-1', now });
  assert.equal(granted.authorized, true);
  assert.deepEqual(codes(granted), [REASON_CODES.SCOPE_MATCHED]);
  assert.equal(granted.matchedScopes.length, 1);

  const expired = evaluateAuthorization({ identity: { ...identity, expiresAt: '2026-05-01T00:00:00.000Z' }, action: 'deploy:infra', resource: 'infra:prod-eu-1', now });
  assert.equal(expired.authorized, false);
  assert.ok(codes(expired).includes(REASON_CODES.IDENTITY_EXPIRED));

  const future = evaluateAuthorization({ identity: { ...identity, issuedAt: '2026-07-01T00:00:00.000Z' }, action: 'deploy:infra', resource: 'infra:prod-eu-1', now });
  assert.equal(future.authorized, false);
  assert.ok(codes(future).includes(REASON_CODES.IDENTITY_NOT_YET_VALID));

  const unsoped = evaluateAuthorization({ identity: { ...identity, issuedAt: '2026-01-01T00:00:00.000Z', expiresAt: '2026-12-01T00:00:00.000Z' }, action: 'terminate:prod', resource: 'db:main', now });
  assert.equal(unsoped.authorized, false);
  assert.deepEqual(codes(unsoped), [REASON_CODES.NO_SCOPE_MATCH]);
});

test('scope constraints deny on cost, region, destructiveness and approval', async () => {
  const { identity } = await agent(10);
  const base = { action: 'deploy:infra', resource: 'infra:prod-eu-1', now: Date.parse('2026-06-01T00:00:00.000Z'), identity: { ...identity, issuedAt: '2026-01-01T00:00:00.000Z', expiresAt: '2026-12-01T00:00:00.000Z' } };

  const costed = evaluateAuthorization({ ...base, identity: { ...base.identity, scopes: [{ action: 'deploy:*', resource: '*', constraint: { maxCostUsd: 5 } }] }, context: { costUsd: 9 } });
  assert.ok(codes(costed).includes(REASON_CODES.COST_CEILING_EXCEEDED));
  assert.equal(costed.authorized, false);
  assert.equal(codes(evaluateAuthorization({ ...base, identity: { ...base.identity, scopes: [{ action: 'deploy:*', resource: '*', constraint: { maxCostUsd: 5 } }] }, context: { costUsd: 4 } })).includes(REASON_CODES.COST_CEILING_EXCEEDED), false);

  const regioned = evaluateAuthorization({ ...base, identity: { ...base.identity, scopes: [{ action: 'deploy:*', resource: '*', constraint: { allowedRegions: ['eu-*'] } }] }, context: { region: 'us-east-1' } });
  assert.ok(codes(regioned).includes(REASON_CODES.REGION_NOT_ALLOWED));
  const silent = evaluateAuthorization({ ...base, identity: { ...base.identity, scopes: [{ action: 'deploy:*', resource: '*', constraint: { allowedRegions: ['eu-*'] } }] }, context: {} });
  assert.ok(codes(silent).includes(REASON_CODES.REGION_NOT_ALLOWED), 'a region-restricted scope must not pass a request that names no region');
  assert.equal(codes(evaluateAuthorization({ ...base, identity: { ...base.identity, scopes: [{ action: 'deploy:*', resource: '*', constraint: { allowedRegions: ['eu-*'] } }] }, context: { region: 'eu-west-1' } })).includes(REASON_CODES.REGION_NOT_ALLOWED), false);

  const destructive = evaluateAuthorization({ ...base, identity: { ...base.identity, scopes: [{ action: 'deploy:*', resource: '*', constraint: { allowDestructive: false } }] }, context: { destructive: true } });
  assert.equal(destructive.authorized, false);
  assert.ok(codes(destructive).includes(REASON_CODES.DESTRUCTIVE_FORBIDDEN), JSON.stringify(codes(destructive)));
  const clouded = evaluateAuthorization({ ...base, identity: { ...base.identity, scopes: [{ action: 'deploy:*', resource: '*', constraint: { allowedClouds: ['aws'] } }] }, context: { cloud: 'gcp' } });
  assert.ok(codes(clouded).includes(REASON_CODES.REGION_NOT_ALLOWED));
  const approvalScope = { ...base.identity, scopes: [{ action: 'deploy:*', resource: '*', constraint: { requireApproval: true } }] };
  const needingApproval = evaluateAuthorization({ ...base, identity: approvalScope, context: {} });
  assert.ok(codes(needingApproval).includes(REASON_CODES.APPROVAL_REQUIRED));
  assert.equal(codes(evaluateAuthorization({ ...base, identity: approvalScope, context: { approvedBy: 'human:lead' } })).includes(REASON_CODES.APPROVAL_REQUIRED), false);
});

test('the trust floor and delegation depth are enforced as blocking reasons', async () => {
  const { identity } = await agent(11);
  const below = evaluateAuthorization({ identity, action: 'deploy:infra', resource: 'infra:prod-eu-1', trustScore: 30, trustFloor: 45 });
  assert.equal(below.authorized, false);
  assert.ok(codes(below).includes(REASON_CODES.TRUST_BELOW_FLOOR));
  assert.equal(codes(evaluateAuthorization({ identity, action: 'deploy:infra', resource: 'infra:prod-eu-1', trustScore: 46, trustFloor: 45 })).includes(REASON_CODES.TRUST_BELOW_FLOOR), false);
  const deep = evaluateAuthorization({ identity: { ...identity, lineageDepth: MAX_DELEGATION_DEPTH + 1 }, action: 'deploy:infra', resource: 'infra:prod-eu-1' });
  assert.ok(codes(deep).includes(REASON_CODES.LINEAGE_TOO_DEEP));
  assert.equal(deep.blockingReasons.length, 1);
  assert.equal(deep.advisoryReasons.length, 1, 'the scope match is advisory, not blocking');
});

test('lineage only validates up to a configured trust anchor', async () => {
  const root = await issuer();
  const mid = await agent(20, { parent: root });
  const leaf = await agent(21, { parent: mid });
  const registry = new Map([[root.identity.id, root.identity], [mid.identity.id, mid.identity], [leaf.identity.id, leaf.identity]]);
  const resolve = async (id) => registry.get(id) ?? null;

  const anchored = await verifyIdentityLineage({ identity: leaf.identity, resolve, trustAnchors: new Map([[root.identity.id, root.identity.publicKey]]) });
  assert.equal(anchored.valid, true, JSON.stringify(anchored.reasons));
  assert.deepEqual(anchored.lineage, [leaf.identity.id, mid.identity.id, root.identity.id]);
  assert.equal(anchored.depth, 2);

  const unanchored = await verifyIdentityLineage({ identity: leaf.identity, resolve, trustAnchors: new Map() });
  assert.equal(unanchored.valid, false);
  assert.deepEqual(codes(unanchored), [REASON_CODES.LINEAGE_NOT_ANCHORED]);

  const wrongKey = await verifyIdentityLineage({ identity: leaf.identity, resolve, trustAnchors: new Map([[root.identity.id, (await agent(44)).identity.publicKey]]) });
  assert.equal(wrongKey.valid, false, 'an anchor registered under a different key must not validate the root');
  assert.deepEqual(codes(wrongKey), [REASON_CODES.LINEAGE_NOT_ANCHORED]);

  registry.delete(mid.identity.id);
  const broken = await verifyIdentityLineage({ identity: leaf.identity, resolve, trustAnchors: new Map([[root.identity.id, root.identity.publicKey]]) });
  assert.equal(broken.valid, false);
  assert.deepEqual(codes(broken), [REASON_CODES.LINEAGE_UNRESOLVED]);
  assert.deepEqual(broken.lineage, [leaf.identity.id], 'the walk stops at the unresolved issuer, so it is never added to the path');
});

test('lineage rejects a forged issuer signature and chains deeper than the bound', async () => {
  const root = await issuer();
  const child = await agent(22, { parent: root });
  const resolve = async (id) => (id === root.identity.id ? { ...root.identity, scopes: [{ action: 'nothing', resource: 'nothing' }] } : null);
  const forged = { ...child.identity, parent: { ...child.identity.parent, issuerSignature: toB64u(new Uint8Array(64)) } };
  const result = await verifyIdentityLineage({ identity: forged, resolve, trustAnchors: new Map([[root.identity.id, root.identity.publicKey]]) });
  assert.equal(result.valid, false);
  assert.ok(codes(result).includes(REASON_CODES.SELF_BINDING_INVALID), JSON.stringify(codes(result)));

  const tooDeep = await verifyIdentityLineage({ identity: child.identity, resolve, trustAnchors: new Map(), maxDepth: 0 });
  assert.deepEqual(codes(tooDeep), [REASON_CODES.LINEAGE_TOO_DEEP]);
});

test('a revocation is signed by its revoker and bound to one identity', async () => {
  const root = await issuer();
  const child = await agent(23, { parent: root });
  const entry = await createRevocation({ keyPair: root.keyPair, identityId: child.identity.id, reason: 'key compromise drill', revokedBy: root.identity.id });
  assert.equal(await verifyRevocation(entry), true);
  assert.equal(entry.identityId, child.identity.id);
  assert.equal(revocationSignerId(entry), root.identity.id);
  assert.equal(revocationDigest(entry), entry.revocationId);
  assert.equal(await verifyRevocation({ ...entry, reason: 'quiet reason' }), false);
  assert.equal(await verifyRevocation({ ...entry, identityId: root.identity.id }), false);
  assert.equal(await verifyRevocation({ ...entry, revocationId: 'f'.repeat(64) }), false);
  assert.equal(await verifyRevocation({ ...entry, revokedAt: '2030-01-01T00:00:00.000Z' }), false);
});

test('only the identity or its issuing authority may revoke it', async () => {
  const root = await issuer();
  const child = await agent(24, { parent: root });
  const stranger = await agent(25);

  const selfRevoked = await createRevocation({ keyPair: child.keyPair, identityId: child.identity.id, reason: 'retiring', revokedBy: child.identity.id });
  assert.deepEqual(assertRevocationAuthority(selfRevoked, child.identity), { ok: true, byIssuer: false });

  const byIssuer = await createRevocation({ keyPair: root.keyPair, identityId: child.identity.id, reason: 'rotation', revokedBy: root.identity.id });
  assert.deepEqual(assertRevocationAuthority(byIssuer, child.identity), { ok: true, byIssuer: true });

  const forged = await createRevocation({ keyPair: stranger.keyPair, identityId: child.identity.id, reason: 'takeover', revokedBy: root.identity.id });
  const claimed = assertRevocationAuthority(forged, child.identity);
  assert.equal(claimed.ok, false);
  assert.match(claimed.reason, /claims revoker .* but is signed by/);

  const strangerClaimsSelf = await createRevocation({ keyPair: stranger.keyPair, identityId: child.identity.id, reason: 'takeover', revokedBy: stranger.identity.id });
  const noAuthority = assertRevocationAuthority(strangerClaimsSelf, child.identity);
  assert.equal(noAuthority.ok, false);
  assert.match(noAuthority.reason, /neither the identity nor its issuing authority/);
  assert.equal(await verifyRevocation(strangerClaimsSelf), true, 'authority is a policy check, not a signature check');
});

test('an omitted revoker defaults to the signer, so the entry can pass its own authority check', async () => {
  const root = await issuer();
  const child = await agent(27, { parent: root });
  const stranger = await agent(28);

  const byIssuer = await createRevocation({ keyPair: root.keyPair, identityId: child.identity.id, reason: 'rotation' });
  assert.equal(byIssuer.revokedBy, root.identity.id);
  assert.equal(byIssuer.revokedBy, revocationSignerId(byIssuer));
  assert.deepEqual(assertRevocationAuthority(byIssuer, child.identity), { ok: true, byIssuer: true });

  const selfRevoked = await createRevocation({ keyPair: child.keyPair, identityId: child.identity.id, reason: 'retiring' });
  assert.equal(selfRevoked.revokedBy, child.identity.id);
  assert.deepEqual(assertRevocationAuthority(selfRevoked, child.identity), { ok: true, byIssuer: false });

  const strangerSigned = await createRevocation({ keyPair: stranger.keyPair, identityId: child.identity.id, reason: 'takeover' });
  assert.equal(strangerSigned.revokedBy, stranger.identity.id, 'the default cannot be used to impersonate the issuer');
  assert.equal(assertRevocationAuthority(strangerSigned, child.identity).ok, false);
});

test('authorization reports a revocation as a blocking reason', async () => {
  const root = await issuer();
  const child = await agent(26, { parent: root });
  const entry = await createRevocation({ keyPair: root.keyPair, identityId: child.identity.id, reason: 'key compromise', revokedBy: root.identity.id });
  const result = evaluateAuthorization({ identity: child.identity, action: 'deploy:infra', resource: 'infra:prod-eu-1', revocation: entry });
  assert.equal(result.authorized, false);
  assert.ok(codes(result).includes(REASON_CODES.IDENTITY_REVOKED));
  assert.match(result.blockingReasons.find((r) => r.code === REASON_CODES.IDENTITY_REVOKED).detail, /key compromise/);
  assert.equal(codes(evaluateAuthorization({ identity: child.identity, action: 'deploy:infra', resource: 'infra:prod-eu-1' })).includes(REASON_CODES.IDENTITY_REVOKED), false);
});

test('the execution fingerprint orders toolsets and binds runtime facts', () => {
  const a = executionFingerprint({ modelVersion: 'm1', promptHash: 'p', codeVersion: 'v1', toolset: ['kubectl', 'terraform'], runtime: { os: 'linux' } });
  const b = executionFingerprint({ modelVersion: 'm1', promptHash: 'p', codeVersion: 'v1', toolset: ['terraform', 'kubectl'], runtime: { os: 'linux' } });
  assert.equal(a, b, 'toolset order must not change the fingerprint');
  assert.notEqual(a, executionFingerprint({ modelVersion: 'm2', promptHash: 'p', codeVersion: 'v1', toolset: ['kubectl', 'terraform'], runtime: { os: 'linux' } }));
  assert.notEqual(a, executionFingerprint({ modelVersion: 'm1', promptHash: 'p', codeVersion: 'v1', toolset: ['kubectl'], runtime: { os: 'linux' } }));
  assert.equal(a.length, 64);
});

test('revocation signatures cover the canonical body the verifier rebuilds', async () => {
  const root = await issuer();
  const entry = await createRevocation({ keyPair: root.keyPair, identityId: 'verix:agent:zzzzzzzzzzzz', reason: 'r', revokedBy: root.identity.id });
  const unsigned = { ...entry };
  delete unsigned.signature;
  const detached = await sign(root.keyPair, canonicalize(unsigned));
  assert.deepEqual(fromB64u(entry.signature), detached, 'signature must be over the canonical unsigned body');
});

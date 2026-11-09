import test from 'node:test';
import assert from 'node:assert/strict';
import { generateSigningKeyPair, sign, crossVerify } from '../src/crypto/pqc.js';
import { digestOf, fromB64u, fromHex, toB64u } from '../src/crypto/hash.js';
import { createIdentity, verifyIdentitySelfBinding } from '../src/crypto/identity.js';
import { recordHashOf } from '../src/ledger/chain.js';
import {
  ASSESSMENT_TAG,
  assessmentDigestOf,
  assessmentPayloadOf,
  signAssessment,
  verifyAssessment,
} from '../src/verification/assessment.js';

async function coordinator(fill = 1) {
  const keyPair = await generateSigningKeyPair('ML-DSA-65', { seed: new Uint8Array(32).fill(fill) });
  const identity = await createIdentity({
    keyPair,
    subject: { name: 'verix-coordinator', kind: 'platform' },
    scopes: [{ action: '*', resource: '*', constraint: { role: 'coordinator' } }],
    kind: 'coordinator',
  });
  return { keyPair, identity };
}

async function certifiedRecord({ coordFill = 1, agentFill = 2, executedAt = '2026-01-01T00:00:00.000Z', tamper = null } = {}) {
  const coord = await coordinator(coordFill);
  const agent = await generateSigningKeyPair('ML-DSA-65', { seed: new Uint8Array(32).fill(agentFill) });
  const agentIdentity = await createIdentity({ keyPair: agent, subject: { name: 'Agent-7' }, scopes: ['deploy:infra'] });
  let record = {
    agentId: agentIdentity.id,
    action: 'deploy:infra',
    resource: 'infra:prod-eu-1',
    payloadDigest: 'a'.repeat(64),
    executedAt,
    context: {},
    identitySnapshot: { id: agentIdentity.id, alg: agent.alg },
  };
  record = { ...record, recordHash: recordHashOf(record) };
  record = {
    ...record,
    seq: 1,
    witnesses: [{ nodeId: 'node-1', recordHash: record.recordHash }],
    replication: { stored: ['node-1'] },
    timestamp: { certifiedAt: '2026-01-01T00:00:01.000Z' },
    inclusionProof: { root: 'b'.repeat(64) },
    trust: { score: 91.5, band: 'high-trust', status: 'trusted' },
    anomalies: [{ code: 'NOVEL_ACTION', severity: 'high' }],
  };
  if (typeof tamper === 'function') record = tamper(record);
  const withoutAssessment = { ...record };
  delete withoutAssessment.assessment;
  withoutAssessment.assessment = await signAssessment({ keyPair: coord.keyPair, coordinatorId: coord.identity.id, record: withoutAssessment });
  return { record: withoutAssessment, coord, agentIdentity };
}

const resolveWith = (identities) => async (id) => identities.find((entry) => entry.id === id) ?? null;

test('the assessment binds only what the coordinator and nodes add after the payload', () => {
  const payload = { recordHash: 'a'.repeat(64), seq: 3, trust: { score: 1 }, anomalies: [], timestamp: {}, inclusionProof: {}, replication: {} };
  assert.deepEqual(Object.keys(assessmentPayloadOf(payload)).sort(), ['anomalies', 'inclusionProof', 'recordHash', 'replication', 'seq', 'timestamp', 'trust']);
  assert.equal(assessmentPayloadOf({ ...payload, action: 'terminate:all' }).action, undefined);
  assert.equal(assessmentPayloadOf({ ...payload, identitySnapshot: { id: 'x' } }).identitySnapshot, undefined);
  assert.equal(assessmentDigestOf(payload), assessmentDigestOf(payload));
  assert.notEqual(assessmentDigestOf(payload), assessmentDigestOf({ ...payload, trust: { score: 2 } }));
  assert.equal(assessmentDigestOf(payload), assessmentDigestOf({ ...payload, witnesses: [{ nodeId: 'liar' }] }), 'witnesses are bound by their own signatures, not the assessment');
});

test('signing an assessment refuses to guess what it is signing over', async () => {
  const coord = await coordinator();
  await assert.rejects(() => signAssessment({ coordinatorId: coord.identity.id, record: { recordHash: 'a'.repeat(64) } }), /requires keyPair/);
  await assert.rejects(() => signAssessment({ keyPair: coord.keyPair, record: { recordHash: 'a'.repeat(64) } }), /requires coordinatorId/);
  await assert.rejects(() => signAssessment({ keyPair: coord.keyPair, coordinatorId: coord.identity.id, record: {} }), /recordHash/);
  const signed = await signAssessment({ keyPair: coord.keyPair, coordinatorId: coord.identity.id, record: { recordHash: 'a'.repeat(64), seq: 1 } });
  assert.equal(signed.alg, 'ML-DSA-65');
  assert.equal(signed.publicKey, coord.identity.publicKey);
  assert.equal(signed.digest, assessmentDigestOf({ recordHash: 'a'.repeat(64), seq: 1 }));
  assert.equal(await verifyIdentitySelfBinding(coord.identity), true);
});

test('an honest assessment verifies against the coordinator identity and anchor', async () => {
  const { record, coord } = await certifiedRecord();
  const result = await verifyAssessment({ record, resolve: resolveWith([coord.identity]) });
  assert.equal(result.valid, true, JSON.stringify(result.problems));
  assert.deepEqual(result.problems, []);
  assert.equal(result.coordinatorId, coord.identity.id);
  assert.equal(result.alg, 'ML-DSA-65');
  assert.equal(result.digest, assessmentDigestOf(record));
  assert.ok(result.signedAt);
});

test('a record with no assessment is reported as absent, not as valid', async () => {
  const { coord } = await certifiedRecord();
  const bare = { recordHash: 'a'.repeat(64), seq: 1 };
  const result = await verifyAssessment({ record: bare, resolve: resolveWith([coord.identity]) });
  assert.equal(result.valid, false);
  assert.deepEqual(result.problems.map((entry) => entry.code), ['ASSESSMENT_ABSENT']);
});

test('rewriting the trust layer after signing breaks the assessment digest', async () => {
  const { record, coord } = await certifiedRecord();
  const identities = [coord.identity];
  assert.equal((await verifyAssessment({ record, resolve: resolveWith(identities) })).valid, true);
  for (const tampered of [
    { ...record, trust: { score: 99.9, band: 'high-trust', status: 'trusted' } },
    { ...record, anomalies: [] },
    { ...record, timestamp: { certifiedAt: '2020-01-01T00:00:00.000Z' } },
    { ...record, replication: { stored: [] } },
    { ...record, inclusionProof: { root: '0'.repeat(64) } },
    { ...record, seq: 7 },
  ]) {
    const result = await verifyAssessment({ record: tampered, resolve: resolveWith(identities) });
    assert.equal(result.valid, false, JSON.stringify(tampered.trust ?? tampered.seq));
    assert.ok(result.problems.map((entry) => entry.code).includes('ASSESSMENT_DIGEST_MISMATCH'), JSON.stringify(result.problems));
    assert.ok(result.problems.map((entry) => entry.code).includes('ASSESSMENT_SIGNATURE_INVALID'), 'the signature is checked against the recomputed digest, so a rewritten layer fails both ways');
  }
});

test('an assessment signed over one record cannot be replayed onto another', async () => {
  const coord = await coordinator();
  const a = await certifiedRecord({ executedAt: '2026-01-01T00:00:00.000Z' });
  const b = await certifiedRecord({ executedAt: '2026-06-01T00:00:00.000Z' });
  assert.notEqual(a.record.recordHash, b.record.recordHash, 'the fixtures must be different records');
  const resolve = resolveWith([coord.identity]);
  assert.equal((await verifyAssessment({ record: a.record, resolve })).valid, true);
  const replayed = { ...b.record, assessment: a.record.assessment };
  const result = await verifyAssessment({ record: replayed, resolve });
  assert.equal(result.valid, false);
  assert.ok(result.problems.map((entry) => entry.code).includes('ASSESSMENT_DIGEST_MISMATCH'), JSON.stringify(result.problems));
});

test('an unknown or swapped coordinator identity fails closed', async () => {
  const { record, coord } = await certifiedRecord();
  const nobody = await verifyAssessment({ record, resolve: resolveWith([]) });
  assert.equal(nobody.valid, false);
  assert.deepEqual(nobody.problems.map((entry) => entry.code), ['COORDINATOR_UNRESOLVED']);

  const impostor = await coordinator(3);
  assert.notEqual(impostor.identity.id, coord.identity.id, 'the impostor must be a different coordinator');
  const swapped = await verifyAssessment({
    record: { ...record, assessment: { ...record.assessment, coordinatorId: impostor.identity.id } },
    resolve: resolveWith([impostor.identity, coord.identity]),
  });
  assert.equal(swapped.valid, false);
  assert.ok(swapped.problems.map((entry) => entry.code).includes('COORDINATOR_KEY_MISMATCH'), JSON.stringify(swapped.problems));
});

test('a coordinator identity that no longer binds its key invalidates the assessment', async () => {
  const { record, coord } = await certifiedRecord();
  const broken = { ...coord.identity, scopes: [{ action: 'nothing', resource: 'nothing' }] };
  const result = await verifyAssessment({ record, resolve: resolveWith([broken]) });
  assert.equal(result.valid, false);
  assert.deepEqual(result.problems.map((entry) => entry.code), ['COORDINATOR_SELF_BINDING_INVALID'], JSON.stringify(result.problems));
});

test('a forged assessment signature is rejected even when the identity resolves', async () => {
  const { record, coord } = await certifiedRecord();
  const attacker = await generateSigningKeyPair('ML-DSA-65', { seed: new Uint8Array(32).fill(9) });
  const digestBytes = fromHex(assessmentDigestOf(record));
  const forged = { ...record.assessment, signature: toB64u(await sign(attacker, digestBytes)), publicKey: toB64u(attacker.publicKey) };
  const result = await verifyAssessment({ record: { ...record, assessment: forged }, resolve: resolveWith([coord.identity]) });
  assert.equal(result.valid, false);
  assert.ok(result.problems.map((entry) => entry.code).includes('ASSESSMENT_SIGNATURE_INVALID'), JSON.stringify(result.problems));

  const truncated = { ...record.assessment, signature: record.assessment.signature.slice(0, 40) };
  const short = await verifyAssessment({ record: { ...record, assessment: truncated }, resolve: resolveWith([coord.identity]) });
  assert.ok(short.problems.map((entry) => entry.code).includes('ASSESSMENT_SIGNATURE_INVALID'));
});

test('an anchor map decides whether the coordinator lineage is trusted', async () => {
  const { record, coord } = await certifiedRecord();
  const resolve = resolveWith([coord.identity]);
  const anchored = await verifyAssessment({ record, resolve, trustAnchors: new Map([[coord.identity.id, coord.identity.publicKey]]) });
  assert.equal(anchored.valid, true, JSON.stringify(anchored.problems));
  const unanchored = await verifyAssessment({ record, resolve, trustAnchors: new Map() });
  assert.equal(unanchored.valid, false);
  assert.deepEqual(unanchored.problems.map((entry) => entry.code), ['COORDINATOR_LINEAGE_UNANCHORED']);
  const miskeyed = await verifyAssessment({ record, resolve, trustAnchors: new Map([[coord.identity.id, (await coordinator(3)).identity.publicKey]]) });
  assert.equal(miskeyed.valid, false);
  assert.deepEqual(miskeyed.problems.map((entry) => entry.code), ['COORDINATOR_LINEAGE_UNANCHORED']);
});

test('cross-implementation verification agrees on a real coordinator signature', async () => {
  const { record, coord } = await certifiedRecord();
  const result = await verifyAssessment({ record, resolve: resolveWith([coord.identity]), crossCheck: true });
  assert.equal(result.valid, true, JSON.stringify(result.problems));
  const digestBytes = fromHex(assessmentDigestOf(record));
  const cross = await crossVerify(coord.keyPair.publicKey, digestBytes, fromB64u(record.assessment.signature), record.assessment.alg);
  assert.equal(cross.viaJs, true);
  assert.equal(cross.viaWasm, true);
  assert.equal(cross.agreement, true);
  const deterministic = await sign(coord.keyPair, digestBytes, { deterministic: true });
  assert.equal(deterministic.length, 3309, 'the deterministic js signature is standard-sized');
  assert.deepEqual(await sign(coord.keyPair, digestBytes, { deterministic: true }), deterministic);
  const recheck = await crossVerify(coord.keyPair.publicKey, digestBytes, deterministic, 'ML-DSA-65');
  assert.equal(recheck.viaWasm, true, 'the wasm implementation accepts a signature produced by the js one');
});

test('the assessment tag is part of the commitment domain', async () => {
  assert.equal(ASSESSMENT_TAG, 'verix:trust-assessment:v1');
  const record = { recordHash: 'a'.repeat(64), seq: 1, trust: null, anomalies: null, timestamp: null, inclusionProof: null, replication: null };
  assert.notEqual(assessmentDigestOf(record), digestOf(assessmentPayloadOf(record), 'verix:record:v1'));
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { generateSigningKeyPair, kemGenerate } from '../src/crypto/pqc.js';
import { fromB64u, toB64u } from '../src/crypto/hash.js';
import {
  createWitness,
  quorumStatus,
  timestampRecord,
  verifyWitness,
  witnessBody,
  witnessHash,
} from '../src/ledger/timestamp.js';
import { ReplicationGroup } from '../src/nodes/replication.js';

const RECORD = 'a'.repeat(64);
const OTHER = 'b'.repeat(64);

async function witnessNode({ nodeId = 'node-1', cloud = 'aws', region = 'us-east-1', seed = 1 } = {}) {
  const keyPair = await generateSigningKeyPair('ML-DSA-65', { seed: new Uint8Array(32).fill(seed) });
  return { keyPair, node: { nodeId, cloud, region } };
}

async function witness({ keyPair, node }, { recordHash = RECORD, seq = 1, observedAt = '2026-01-01T00:00:00.000Z', entryHash = 'c'.repeat(64) } = {}) {
  return createWitness({ keyPair, node, recordHash, entryHash, seq, observedAt });
}

test('a witness binds the record, the entry and the sequence under the node key', async () => {
  const signer = await witnessNode();
  const entry = await witness(signer, { recordHash: RECORD, seq: 7, observedAt: '2026-01-01T01:02:03.000Z' });
  assert.equal(entry.nodeId, 'node-1');
  assert.equal(entry.cloud, 'aws');
  assert.equal(entry.seq, 7);
  assert.equal(entry.recordHash, RECORD);
  assert.equal(entry.alg, 'ML-DSA-65');
  assert.equal(entry.witnessHash, witnessHash(entry));
  assert.equal(await verifyWitness(entry), true);
});

test('witness signatures cover every claimed field', async () => {
  const honest = await witnessNode();
  const entry = await witness(honest);
  assert.equal(await verifyWitness({ ...entry, recordHash: OTHER }), false);
  assert.equal(await verifyWitness({ ...entry, seq: 99 }), false);
  assert.equal(await verifyWitness({ ...entry, nodeId: 'pretend-node' }), false);
  assert.equal(await verifyWitness({ ...entry, observedAt: '2030-01-01T00:00:00.000Z' }), false);
  assert.equal(await verifyWitness({ ...entry, witnessHash: 'd'.repeat(64) }), false);
  const flipped = { ...entry, signature: toB64u(Uint8Array.from(fromB64u(entry.signature), (b, i) => (i === 2 ? b ^ 1 : b))) };
  assert.equal(await verifyWitness(flipped), false);
  assert.equal(await verifyWitness({ ...entry, signature: undefined }), false);
  assert.equal(await verifyWitness(undefined), false);
});

test('the witness body excludes its own signature fields from the hash', async () => {
  const entry = await witness(await witnessNode());
  assert.equal(witnessBody(entry).signature, undefined);
  assert.equal(witnessBody(entry).witnessHash, undefined);
  assert.deepEqual(Object.keys(witnessBody(entry)).sort(), ['alg', 'cloud', 'entryHash', 'nodeId', 'observedAt', 'publicKey', 'recordHash', 'region', 'seq'].sort());
});

test('createWitness refuses to sign without a key or node identity', async () => {
  const { keyPair } = await witnessNode();
  await assert.rejects(() => createWitness({ keyPair, node: { cloud: 'aws' }, recordHash: RECORD, entryHash: 'c'.repeat(64), seq: 1, observedAt: 'now' }), /nodeId and node.cloud/);
  await assert.rejects(() => createWitness({ node: { nodeId: 'x', cloud: 'aws' }, recordHash: RECORD, entryHash: 'c'.repeat(64), seq: 1, observedAt: 'now' }), /requires keyPair/);
});

test('quorum elects the bucket that agrees on both record hash and sequence', async () => {
  const a = await witness(await witnessNode({ nodeId: 'n-a', seed: 1 }));
  const b = await witness(await witnessNode({ nodeId: 'n-b', seed: 2 }));
  const c = await witness(await witnessNode({ nodeId: 'n-c', seed: 3 }));
  const status = quorumStatus([a, b, c], { required: 2, expectedRecordHash: RECORD, expectedSeq: 1 });
  assert.equal(status.reached, true);
  assert.equal(status.agreeingCount, 3);
  assert.equal(status.total, 3);
  assert.deepEqual(status.consensus, { recordHash: RECORD, seq: 1 });
  assert.deepEqual(status.divergent, []);
  assert.equal(status.mismatch, null);
});

test('a node attesting a different record is pushed into divergence, not consensus', async () => {
  const honest = [await witness(await witnessNode({ nodeId: 'n-a', seed: 1 })), await witness(await witnessNode({ nodeId: 'n-b', seed: 2 }))];
  const lying = await witness(await witnessNode({ nodeId: 'n-liar', seed: 4 }), { recordHash: OTHER });
  const status = quorumStatus([...honest, lying], { required: 2, expectedRecordHash: RECORD });
  assert.equal(status.consensus.recordHash, RECORD);
  assert.equal(status.agreeingCount, 2);
  assert.deepEqual(status.divergent.map((entry) => entry.nodeId), ['n-liar']);
  assert.equal(status.reached, true);
});

test('the same record hash attested at two sequence positions is not consensus', async () => {
  const atOne = await witness(await witnessNode({ nodeId: 'n-a', seed: 1 }), { seq: 1 });
  const atTwo = await witness(await witnessNode({ nodeId: 'n-b', seed: 2 }), { seq: 2 });
  const status = quorumStatus([atOne, atTwo], { required: 2, expectedRecordHash: RECORD, expectedSeq: 1 });
  assert.equal(status.reached, false, 'splitting across positions must not reach a quorum of 2');
  assert.equal(status.agreeingCount, 1);
  assert.equal(status.divergent.length, 1);
});

test('quorum reports what it disagrees with rather than guessing', async () => {
  const empty = quorumStatus([], { required: 2 });
  assert.equal(empty.reached, false);
  assert.equal(empty.consensus, null);
  assert.equal(empty.mismatch, 'no-witnesses');
  const wrongRecord = await witness(await witnessNode({ nodeId: 'n-a', seed: 1 }), { recordHash: OTHER });
  assert.equal(quorumStatus([wrongRecord], { required: 1, expectedRecordHash: RECORD }).mismatch, 'record-hash');
  const wrongSeq = await witness(await witnessNode({ nodeId: 'n-a', seed: 1 }), { seq: 5 });
  assert.equal(quorumStatus([wrongSeq], { required: 1, expectedRecordHash: RECORD, expectedSeq: 4 }).mismatch, 'sequence-position');
});

test('a lone witness cannot satisfy a quorum that needs two', async () => {
  const only = await witness(await witnessNode({ nodeId: 'n-a', seed: 1 }));
  assert.equal(quorumStatus([only], { required: 2, expectedRecordHash: RECORD }).reached, false);
  assert.equal(quorumStatus([only], { required: 1, expectedRecordHash: RECORD }).reached, true);
});

test('certified time is the median witness clock, with skew measured against it', async () => {
  const stamps = ['2026-01-01T00:00:00.000Z', '2026-01-01T00:00:20.000Z', '2026-01-01T00:03:00.000Z'];
  const witnesses = [];
  for (const [index, observedAt] of stamps.entries()) {
    witnesses.push(await witness(await witnessNode({ nodeId: `n-${index}`, seed: index + 1 }), { observedAt }));
  }
  const stamp = timestampRecord({ recordHash: RECORD, seq: 1, witnesses, quorum: { reached: true }, rootAtCertification: 'e'.repeat(64) });
  assert.equal(stamp.certifiedAt, '2026-01-01T00:00:20.000Z');
  assert.equal(stamp.witnessCount, 3);
  assert.deepEqual(stamp.witnessNodeIds, ['n-0', 'n-1', 'n-2']);
  assert.equal(stamp.maxClockSkewSeconds, 160);
  assert.equal(stamp.clockSkewExceeded, true);
  assert.equal(stamp.rootAtCertification, 'e'.repeat(64));
});

test('a tight set of witness clocks stays inside the skew bound', async () => {
  const base = Date.parse('2026-01-01T00:00:00.000Z');
  const witnesses = [];
  for (const [index, offset] of [0, 5_000, -8_000].entries()) {
    witnesses.push(await witness(await witnessNode({ nodeId: `n-${index}`, seed: index + 1 }), { observedAt: new Date(base + offset).toISOString() }));
  }
  const stamp = timestampRecord({ recordHash: RECORD, seq: 2, witnesses, quorum: { reached: true }, maxClockSkewSeconds: 120 });
  assert.equal(stamp.clockSkewExceeded, false);
  assert.equal(stamp.maxClockSkewSeconds, 8);
  assert.match(stamp.certifiedAt, /^2026-01-01T00:00:0/);
});

test('even witness counts average the middle two and unusable clocks are dropped', async () => {
  const good = [await witness(await witnessNode({ nodeId: 'n-1', seed: 1 }), { observedAt: '2026-01-01T00:00:00.000Z' }), await witness(await witnessNode({ nodeId: 'n-2', seed: 2 }), { observedAt: '2026-01-01T00:00:10.000Z' })];
  assert.equal(timestampRecord({ recordHash: RECORD, seq: 1, witnesses: good, quorum: null }).certifiedAt, '2026-01-01T00:00:05.000Z');
  const withJunk = [...good, await witness(await witnessNode({ nodeId: 'n-3', seed: 3 }), { observedAt: 'not a date' })];
  const stamped = timestampRecord({ recordHash: RECORD, seq: 1, witnesses: withJunk, quorum: { reached: true } });
  assert.equal(stamped.witnessCount, 3, 'the junk clock is still counted as a witness');
  assert.equal(stamped.certifiedAt, '2026-01-01T00:00:05.000Z', 'but it cannot move the median');
  const none = timestampRecord({ recordHash: RECORD, seq: 1, witnesses: [], quorum: { reached: false } });
  assert.equal(none.certifiedAt, null);
  assert.equal(none.maxClockSkewSeconds, 0);
  assert.equal(none.quorumReached, false);
});

test('replication seals a copy per recipient and opens it only with their key', async () => {
  const record = { recordHash: RECORD, seq: 1, action: 'deploy:infra' };
  const recipients = await Promise.all([kemGenerate('ML-KEM-768'), kemGenerate('ML-KEM-768')]);
  const kemPublicKeys = recipients.map((keyPair, index) => ({ nodeId: `peer-${index}`, publicKey: toB64u(keyPair.publicKey) }));
  const group = new ReplicationGroup({ clients: [{ nodeId: 'primary' }] });
  const sealed = await group.sealCopies(record, kemPublicKeys);
  assert.equal(sealed.length, 2);
  assert.equal(sealed[0].nodeId, 'peer-0');
  const opened = await ReplicationGroup.openCopy(sealed[0].envelope, recipients[0].secretKey);
  assert.deepEqual(opened, record);
  await assert.rejects(() => ReplicationGroup.openCopy(sealed[0].envelope, recipients[1].secretKey));
  // The record hash is sealed as additional authenticated data, so rebinding an
  // envelope onto a different record breaks the GCM tag instead of decrypting.
  assert.equal(sealed[0].envelope.aad, record.recordHash);
  await assert.rejects(() => ReplicationGroup.openCopy({ ...sealed[0].envelope, aad: 'f'.repeat(64) }, recipients[0].secretKey));
});

test('a replication group needs at least one node and defaults to a majority', () => {
  assert.throws(() => new ReplicationGroup({ clients: [] }), /at least one node client/);
  assert.throws(() => new ReplicationGroup({ clients: null }), /at least one node client/);
  const three = new ReplicationGroup({ clients: [{}, {}, {}] });
  assert.equal(three.required, 2);
  assert.equal(three.size, 3);
  const four = new ReplicationGroup({ clients: [{}, {}, {}, {}] });
  assert.equal(four.required, 3);
  assert.equal(new ReplicationGroup({ clients: [{}], required: 9 }).required, 9);
});

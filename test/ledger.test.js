import test from 'node:test';
import assert from 'node:assert/strict';
import { generateSigningKeyPair, sign } from '../src/crypto/pqc.js';
import { toBytes } from '../src/crypto/hash.js';
import { MemoryStore } from '../src/nodes/memory-store.js';
import {
  GENESIS_PREV_HASH,
  LAYERED_FIELDS,
  ProofChain,
  assertRecordLayering,
  entryHashOf,
  recordHashOf,
} from '../src/ledger/chain.js';
import { inclusionPath, merkleRoot, verifyInclusion } from '../src/ledger/merkle.js';

function payloadRecord(overrides = {}) {
  return {
    agentId: 'verix:agent:AAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    action: 'deploy:infra',
    resource: 'infra:prod-eu-1',
    payloadDigest: 'a'.repeat(64),
    actionSignatureDigest: 'b'.repeat(64),
    executedAt: '2026-01-01T00:00:00.000Z',
    context: { costUsd: 10 },
    identitySnapshot: { id: 'verix:agent:AAAAAAAAAAAAAAAAAAAAAAAAAAAA', alg: 'ML-DSA-65' },
    ...overrides,
  };
}

async function chainWith(count = 0, { nodeId = 'node-1', keyPair = null, store = null } = {}) {
  const signing = keyPair ?? await generateSigningKeyPair('ML-DSA-65');
  const chain = new ProofChain({ nodeId, store: store ?? new MemoryStore({ name: nodeId }), keyPair: signing });
  for (let seq = 1; seq <= count; seq += 1) {
    await chain.append(payloadRecord({ action: `action:${seq}`, executedAt: `2026-01-0${(seq % 9) + 1}T00:00:0${seq % 10}.000Z` }));
  }
  return { chain, signing, store: chain.store };
}

test('recordHash commits the payload and ignores certification layers', () => {
  const base = payloadRecord();
  const withLayers = { ...base, seq: 4, entryHash: 'c'.repeat(64), prevEntryHash: 'd'.repeat(64), prevRecordHash: 'e'.repeat(64), recordHash: 'f'.repeat(64), chainSignature: 'aa', replicatedAt: 'now' };
  for (const field of LAYERED_FIELDS) withLayers[field] = { anything: true };
  assert.equal(recordHashOf(withLayers), recordHashOf(base), 'layered and chain-written fields must not move the payload commitment');
  assert.notEqual(recordHashOf({ ...base, action: 'delete:prod' }), recordHashOf(base));
  assert.notEqual(recordHashOf({ ...base, context: { costUsd: 11 } }), recordHashOf(base), 'nested payload changes must move the commitment');
});

test('assertRecordLayering lets certification layers through but blocks payload edits', () => {
  const stored = { ...payloadRecord(), recordHash: null };
  stored.recordHash = recordHashOf(stored);
  assert.doesNotThrow(() => assertRecordLayering(stored, { ...stored, witnesses: [{ nodeId: 'a' }], trust: { score: 91 }, assessment: { signature: 'x' } }));
  assert.throws(
    () => assertRecordLayering(stored, { ...stored, action: 'terminate:infra' }),
    /payload is immutable/,
  );
  assert.throws(
    () => assertRecordLayering(stored, { ...stored, identitySnapshot: { id: 'other', alg: 'ML-DSA-87' } }),
    /payload is immutable/,
  );
  assert.doesNotThrow(() => assertRecordLayering(null, stored), 'a first write has nothing to conflict with');
});

test('merkle roots are stable, verify for every index, and reject substitution', () => {
  const hashes = Array.from({ length: 7 }, (_, i) => (i + 1).toString(16).padStart(64, '0'));
  const root = merkleRoot(hashes);
  assert.equal(root, merkleRoot(hashes));
  assert.match(root, /^[0-9a-f]{64}$/);
  assert.notEqual(root, merkleRoot([...hashes.slice(0, 6)]));
  for (let index = 0; index < hashes.length; index += 1) {
    const proof = { root, recordHash: hashes[index], seq: index + 1, path: inclusionPath(hashes, index) };
    assert.equal(verifyInclusion(root, hashes[index], index, proof.path), true, `leaf ${index}`);
    assert.equal(verifyInclusion(root, hashes[(index + 1) % hashes.length], index, proof.path), false, 'a sibling must not verify in this slot');
  }
  assert.equal(merkleRoot([]), merkleRoot([]), 'the empty tree still has a defined root');
  assert.notEqual(merkleRoot([]), merkleRoot(hashes));
  assert.throws(() => merkleRoot(['not-hex']), /must be 64 hex characters/);
  assert.throws(() => inclusionPath(hashes, hashes.length), /outside tree/);
});

test('an odd number of leaves duplicates the last node rather than dropping it', () => {
  const hashes = Array.from({ length: 5 }, (_, i) => (i + 1).toString(16).padStart(64, '0'));
  const root = merkleRoot(hashes);
  assert.equal(verifyInclusion(root, hashes[4], 4, inclusionPath(hashes, 4)), true);
  assert.notEqual(merkleRoot(hashes.slice(0, 4)), root, 'a chain that silently dropped the 5th leaf would change the root');
});

test('a fresh chain starts at a signed genesis entry', async () => {
  const { chain } = await chainWith();
  const head = await chain.head();
  assert.equal(head.seq, 0);
  assert.equal(head.lastRecordHash, GENESIS_PREV_HASH);
  assert.equal(head.root, merkleRoot([]));
  const genesis = await chain.get(0);
  assert.equal(genesis.prevEntryHash, GENESIS_PREV_HASH);
  assert.equal(entryHashOf(genesis), genesis.entryHash);
  assert.equal(await chain.verifyEntry(genesis), true);
  assert.ok(genesis.chainSignature, 'genesis must be signed by the node key, not just hashed');
  const mis_signed = { ...genesis, chainSignature: genesis.chainSignature.slice(0, -6) + 'AAAAAA' };
  assert.equal(await chain.verifyEntry(mis_signed), false);
  const empty = await chain.audit();
  assert.equal(empty.intact, true);
  assert.deepEqual(empty.problems, []);
});

test('appending links entries and keeps every commitment consistent', async () => {
  const { chain, store } = await chainWith(4);
  const head = await chain.head();
  assert.equal(head.seq, 4);
  assert.equal(head.root, merkleRoot((await chain.recordHashes())));
  const entries = await store.listChainEntries('node-1', 0, 4);
  assert.equal(entries.length, 5);
  for (const entry of entries) {
    assert.equal(entryHashOf(entry), entry.entryHash);
    assert.equal(await chain.verifyEntry(entry), true);
  }
  for (let seq = 1; seq <= 4; seq += 1) {
    assert.equal(entries[seq].prevEntryHash, entries[seq - 1].entryHash, `seq ${seq} must point at its predecessor`);
    const record = await store.getRecord(entries[seq].recordHash);
    assert.equal(record.seq, seq);
    assert.equal(record.entryHash, entries[seq].entryHash);
    assert.equal(record.prevEntryHash, entries[seq - 1].entryHash);
    assert.equal(recordHashOf(record), entries[seq].recordHash);
  }
  const audit = await chain.audit();
  assert.equal(audit.intact, true, JSON.stringify(audit.problems));
  assert.equal(audit.assessments.unsigned, 4);
});

test('inclusion proofs returned by the chain verify against the stored root', async () => {
  const { chain } = await chainWith(6);
  for (let seq = 1; seq <= 6; seq += 1) {
    const proof = await chain.inclusionProof(seq);
    assert.equal(proof.seq, seq);
    assert.equal(proof.treeSize, 6);
    assert.equal(proof.root, (await chain.head()).root);
    assert.equal(ProofChain.checkInclusionProof(proof), true);
  }
  await assert.rejects(() => chain.inclusionProof(0), /outside the chain/);
  await assert.rejects(() => chain.inclusionProof(7), /outside the chain/);
  const forged = await chain.inclusionProof(3);
  forged.path[0] = { ...forged.path[0], hash: 'f'.repeat(64) };
  assert.equal(ProofChain.checkInclusionProof(forged), false);
});

test('rewriting a stored record is caught as RECORD_TAMPERED', async () => {
  const { chain, store } = await chainWith(3);
  const entry = await chain.get(2);
  const record = await store.getRecord(entry.recordHash);
  const tampered = { ...record, action: 'terminate:all' };
  assert.notEqual(recordHashOf(tampered), entry.recordHash, 'the payload change must move the hash');
  store.records.set(entry.recordHash, tampered);
  const audit = await chain.audit();
  assert.equal(audit.intact, false);
  assert.deepEqual(audit.problems.map((problem) => problem.code), ['RECORD_TAMPERED']);
  assert.equal(audit.problems[0].seq, 2);
});

test('removing a record leaves a dangling chain commitment', async () => {
  const { chain, store } = await chainWith(2);
  const entry = await chain.get(1);
  store.records.delete(entry.recordHash);
  const audit = await chain.audit();
  assert.equal(audit.intact, false);
  assert.deepEqual(audit.problems.map((p) => p.code), ['RECORD_MISSING']);
});

test('editing a chain entry is caught by its own hash and signature', async () => {
  const { chain, store } = await chainWith(3);
  const entry = await chain.get(2);
  const forged = { ...entry, recordHash: '9'.repeat(64) };
  store.chain.set(`node-1:${forged.seq}`, forged);
  const audit = await chain.audit();
  assert.equal(audit.intact, false);
  assert.ok(audit.problems.some((problem) => problem.code === 'ENTRY_HASH_MISMATCH'), JSON.stringify(audit.problems));
});

test('re-signing an entry with a different key is caught as CHAIN_SIGNATURE_INVALID', async () => {
  const { chain, store } = await chainWith(2);
  const attacker = await generateSigningKeyPair('ML-DSA-65');
  const entry = await chain.get(1);
  const forgedEntry = { ...entry };
  forgedEntry.entryHash = entryHashOf(forgedEntry);
  forgedEntry.chainSignature = await sign(attacker, toBytes(forgedEntry.entryHash)).then((sig) => Buffer.from(sig).toString('base64url'));
  store.chain.set(`node-1:${forgedEntry.seq}`, forgedEntry);
  const audit = await chain.audit();
  assert.equal(audit.intact, false);
  assert.ok(audit.problems.some((problem) => problem.code === 'CHAIN_SIGNATURE_INVALID' || problem.code === 'RECORD_MISSING'), JSON.stringify(audit.problems));
});

test('dropping an entry from the middle breaks the linkage check', async () => {
  const { chain, store } = await chainWith(3);
  const entries = await store.listChainEntries('node-1', 0, 3);
  // A deletion attack: re-point seq 3 at seq 1 so the chain looks continuous.
  const relinked = { ...entries[3], prevEntryHash: entries[1].entryHash };
  relinked.entryHash = entryHashOf(relinked);
  relinked.chainSignature = Buffer.from(await sign(chain.keyPair, toBytes(relinked.entryHash))).toString('base64url');
  store.chain.set(`node-1:${relinked.seq}`, relinked);
  const audit = await chain.audit();
  assert.equal(audit.intact, false);
  assert.ok(audit.problems.some((problem) => problem.code === 'LINKAGE_BREAK'), JSON.stringify(audit.problems));
});

test('a head root that no longer matches the entries is caught', async () => {
  const { chain, store } = await chainWith(3);
  const head = await chain.head();
  await store.putHead('node-1', { ...head, root: '0'.repeat(64) });
  const audit = await chain.audit();
  assert.equal(audit.intact, false);
  assert.ok(audit.problems.some((problem) => problem.code === 'ROOT_MISMATCH'), JSON.stringify(audit.problems));
  assert.equal(audit.rootChecked, true);
});

test('auditing a window recomputes without claiming the head root', async () => {
  const { chain } = await chainWith(5);
  const window = await chain.audit({ from: 2, to: 3 });
  assert.equal(window.auditedFrom, 2);
  assert.equal(window.auditedTo, 3);
  assert.equal(window.rootChecked, false);
  assert.equal(window.intact, true, JSON.stringify(window.problems));
  const tail = await chain.audit({ from: 4, to: 5 });
  assert.equal(tail.rootChecked, true);
  assert.equal(tail.intact, true);
});

test('the chain cannot be forged by replaying another node’s entries', async () => {
  const a = await chainWith(2, { nodeId: 'node-a' });
  const b = await chainWith(1, { nodeId: 'node-b' });
  const stolen = await a.store.listChainEntries('node-a', 1, 2);
  for (const entry of stolen) b.store.chain.set(`node-b:${entry.seq}`, entry);
  const audit = await b.chain.audit();
  assert.equal(audit.intact, false);
  const codes = audit.problems.map((problem) => problem.code);
  assert.ok(codes.includes('CHAIN_SIGNATURE_INVALID') || codes.includes('LINKAGE_BREAK'), JSON.stringify(codes));
});

test('the store itself refuses a rewrite of a committed entry or payload', async () => {
  // The audit tests above deliberately write past these guards, because the
  // attacker they model controls the storage layer. These are what an ordinary
  // caller hits first.
  const { chain, store } = await chainWith(2);
  const committed = await chain.get(1);
  await assert.rejects(() => store.putChainEntry('node-1', { ...committed, recordHash: '9'.repeat(64) }), /append-only/);
  const record = await store.getRecord(committed.recordHash);
  await assert.rejects(() => store.putRecord({ ...record, action: 'terminate:all' }), /payload is immutable/);
  await assert.rejects(() => store.putRecord({ agentId: 'x' }), /requires recordHash/);
  await store.putRecord({ ...record, trust: { score: 88, status: 'flagged' } });
  assert.equal((await store.getRecord(committed.recordHash)).trust.score, 88, 'certification layers are the one permitted rewrite');
});

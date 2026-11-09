import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadConfig } from '../src/config.js';
import { createPlatform } from '../src/platform.js';
import { createVerixApp } from '../src/api/server.js';
import { serializeKeyPair } from '../src/crypto/pqc.js';
import { FileStore } from '../src/nodes/file-store.js';

const NODE_PLAN = [
  { nodeId: 'verix-node-aws-1', cloud: 'aws', region: 'us-east-1' },
  { nodeId: 'verix-node-gcp-1', cloud: 'gcp', region: 'us-central1' },
  { nodeId: 'verix-node-edge-1', cloud: 'local', region: 'local' },
];

const ADMIN = 'persist-admin';
const settled = () => new Promise((resolve) => setImmediate(resolve));
const fleets = [];

// A failed assertion must not leave a listening server behind, or the runner
// waits forever for the process to exit.
async function drain() {
  while (fleets.length > 0) await fleets.pop().close();
}

function tempDir(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function jsonlLines(dir, node, collection) {
  const path = join(dir, node, `${collection}.jsonl`);
  if (!existsSync(path)) return 0;
  return readFileSync(path, 'utf8').trim().split('\n').filter(Boolean).length;
}

// A fleet is a process, not a fixture: every test boots the real thing, closes it,
// and boots again from the same directory to prove the state survived.
async function serve(overrides = {}) {
  const config = loadConfig({}, { nodePlan: NODE_PLAN, backend: 'file', crossCheck: false, adminToken: ADMIN, ...overrides });
  const platform = await createPlatform({ config });
  const app = createVerixApp({ platform });
  await new Promise((resolve) => app.server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${app.server.address().port}`;
  async function req(method, path, { body, token } = {}) {
    const response = await fetch(`${origin}${path}`, {
      method,
      headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await response.text();
    return { status: response.status, text, json: text.length > 0 ? JSON.parse(text) : null };
  }
  async function issue(name, scopes) {
    const agent = await platform.issueAgent({ name, scopes });
    return { ...agent, wire: serializeKeyPair(agent.keyPair) };
  }
  async function close() {
    app.server.closeAllConnections?.();
    await new Promise((resolve) => app.server.close(resolve));
    await platform.close();
  }
  const fleet = { origin, config, platform, app, req, issue, close };
  fleets.push(fleet);
  return fleet;
}

test('a file-backed fleet keeps its ledger, identities and assessments across a restart', async () => {
  const dataDir = tempDir('verix-persist-');
  try {
    const first = await serve({ dataDir });
    let proofId = null;
    let coordinatorId = null;
    try {
      const agent = await first.issue('Persist-1', [{ action: 'deploy:*', resource: 'infra:*' }]);
      const proof = await first.req('POST', '/verify-action', { body: { identityId: agent.identity.id, keyPair: agent.wire, action: 'deploy:infra', resource: 'infra:prod-eu-1' } });
      await settled();
      assert.equal(proof.status, 200);
      assert.equal(proof.json.trustScore, 96.4);
      proofId = proof.json.proofId;
      coordinatorId = first.platform.coordinator.id;

      const head = (await first.req('GET', '/nodes/head')).json;
      assert.equal(head.seq, 1);
      assert.equal(head.lastRecordHash, proofId);
      assert.equal((await first.req('GET', '/status')).json.anchorHydration.identities, 0, 'a virgin store has nothing to hydrate before the coordinator registers');
      assert.deepEqual(readdirSync(dataDir).sort(), ['coordinator-key.json', 'verix-node-aws-1', 'verix-node-edge-1', 'verix-node-gcp-1']);
    } finally {
      await first.close();
    }

    const second = await serve({ dataDir });
    try {
      assert.equal(second.platform.coordinator.id, coordinatorId, 'the stored coordinator key is reused, so a new signer is not silently minted');
      const onDisk = JSON.parse(readFileSync(join(dataDir, 'coordinator-key.json'), 'utf8'));
      assert.equal(serializeKeyPair(second.platform.coordinatorKeyPair).publicKey, onDisk.publicKey);
      assert.deepEqual(serializeKeyPair(second.platform.coordinatorKeyPair), onDisk);

      const status = (await second.req('GET', '/status')).json;
      assert.equal(status.eventSequence, 1, 'only the fresh process registered a coordinator event');
      assert.equal(status.indexedProofs, 0, 'the copilot index is in-memory and starts cold');
      assert.deepEqual(status.trustAnchors, [coordinatorId]);
      assert.deepEqual(status.anchorHydration, { anchors: [coordinatorId], identities: 2, nodesReporting: 3, divergent: 0 });
      assert.deepEqual(status.nodes.map((node) => [node.nodeId, node.chainLength, node.records, node.identities, node.revocations, node.recentWindowIntact]), [
        ['verix-node-aws-1', 1, 1, 2, 0, true],
        ['verix-node-gcp-1', 1, 1, 2, 0, true],
        ['verix-node-edge-1', 1, 1, 2, 0, true],
      ]);

      const old = await second.req('GET', `/ledger/records/${proofId}`);
      assert.equal(old.json.present, 3, 'every node recovered the proof');
      assert.equal(old.json.assessment.valid, true, 'the assessment signed before the restart still verifies with the recovered key');
      assert.deepEqual(old.json.assessment.problems, []);
      assert.equal(old.json.assessment.coordinatorId, coordinatorId);
      assert.equal(old.json.assessment.alg, 'ML-DSA-65');
      for (const node of ['verix-node-aws-1', 'verix-node-gcp-1', 'verix-node-edge-1']) {
        const audit = await second.req('POST', '/ledger/audit', { body: { nodeId: node } });
        assert.equal(audit.json.intact, true, node);
        assert.deepEqual(audit.json.problems, [], node);
        assert.equal(audit.json.auditedFrom, 1, node);
        assert.equal(audit.json.auditedTo, 1, node);
        assert.deepEqual(audit.json.assessments, { verified: 1, invalid: 0, unsigned: 0 }, node);
        const inclusion = await second.req('GET', '/ledger/inclusion/1');
        assert.equal(inclusion.json.root, audit.json.root, `${node} root matches its inclusion proof`);
      }

      const agent = await second.issue('Persist-2', [{ action: 'deploy:*', resource: 'infra:*' }]);
      const next = await second.req('POST', '/verify-action', { body: { identityId: agent.identity.id, keyPair: agent.wire, action: 'deploy:infra', resource: 'infra:prod-eu-2' } });
      await settled();
      assert.equal(next.status, 200);
      assert.equal(next.json.nodes[0].seq, 2, 'the sequence continues where the previous process left it');
      assert.equal((await second.req('GET', '/ledger/records')).json.count, 2);
      assert.equal((await second.req('GET', '/nodes/head')).json.seq, 2);
    } finally {
      await second.close();
    }
  } finally {
    await drain();
    rmSync(dataDir, { recursive: true, force: true });
  }
});

test('a revocation written before the restart is still enforced after it', async () => {
  const dataDir = tempDir('verix-revoke-');
  try {
    const first = await serve({ dataDir });
    const agent = await first.issue('Persist-Revoked', [{ action: 'deploy:*', resource: 'infra:*' }]);
    const proof = await first.req('POST', '/verify-action', { body: { identityId: agent.identity.id, keyPair: agent.wire, action: 'deploy:infra', resource: 'infra:prod-eu-1' } });
    assert.equal(proof.status, 200);
    const revoked = await first.req('POST', '/revocations/revoke', { token: ADMIN, body: { identityId: agent.identity.id, reason: 'rotated out' } });
    assert.equal(revoked.status, 200);
    assert.equal(revoked.json.revoked, true);
    assert.equal(revoked.json.revocation.reason, 'rotated out');
    const coordinatorId = first.platform.coordinator.id;
    await first.close();

    const second = await serve({ dataDir });
    try {
      assert.equal((await second.req('GET', '/revocations')).json.revocations.length, 1);
      const listed = await second.req('GET', `/identities/${agent.identity.id}/revocations`);
      assert.equal(listed.json.revocations.length, 1);
      assert.equal(listed.json.revocations[0].reason, 'rotated out');
      assert.equal(listed.json.revocations[0].revokedBy, coordinatorId);
      assert.deepEqual(listed.json.forged, []);
      assert.equal(listed.json.nodesReporting, 3);

      const replay = await second.req('POST', '/verify-action', { body: { identityId: agent.identity.id, keyPair: agent.wire, action: 'deploy:infra', resource: 'infra:prod-eu-9' } });
      assert.equal(replay.status, 201);
      assert.equal(replay.json.status, 'rejected');
      assert.equal(replay.json.allowedMode, 'deny');
      assert.deepEqual(replay.json.checks.revocation, { revoked: true, revokedAt: listed.json.revocations[0].revokedAt, revokedBy: coordinatorId, forgedEntries: 0, nodesReporting: 3 });

      const status = (await second.req('GET', '/status')).json;
      assert.deepEqual(status.nodes.map((node) => node.revocations), [1, 1, 1], 'the revocation is on every node, not only the one that served the request');
    } finally {
      await second.close();
    }
  } finally {
    await drain();
    rmSync(dataDir, { recursive: true, force: true });
  }
});

test('a cold copilot index is rebuilt from the persisted ledger after a restart', async () => {
  const dataDir = tempDir('verix-reindex-');
  try {
    const first = await serve({ dataDir });
    const agent = await first.issue('Persist-Index', [{ action: 'read:*', resource: '*' }]);
    for (const resource of ['svc:a', 'svc:b', 'svc:c']) {
      assert.equal((await first.req('POST', '/verify-action', { body: { identityId: agent.identity.id, keyPair: agent.wire, action: 'read:logs', resource } })).status, 200);
    }
    await settled();
    assert.equal(first.platform.index.size, 3);
    await first.close();

    const second = await serve({ dataDir });
    try {
      assert.equal(second.platform.index.size, 0, 'the index is memory-only, so a restarted process must rebuild it');
      assert.equal((await second.req('GET', '/status')).json.indexedProofs, 0);
      const asked = await second.req('POST', '/copilot/ask', { body: { question: 'how many proofs are there?' } });
      assert.equal(asked.json.answer.match(/Indexed proofs: 0/)[0], 'Indexed proofs: 0', 'before reindexing the copilot must report the truth about its own index');

      const reindexed = await second.req('POST', '/copilot/reindex', { token: ADMIN });
      assert.equal(reindexed.status, 200);
      assert.equal(reindexed.json.documents, (await second.req('GET', '/ledger/records')).json.count, 'every persisted proof becomes a document');
      assert.equal(second.platform.index.size, 3);
      const rebuilt = await second.req('POST', '/copilot/ask', { body: { question: 'how many proofs cover read logs?' } });
      assert.equal(rebuilt.json.evidence.length, 3);
      assert.deepEqual([...new Set(rebuilt.json.evidence.map((item) => item.status))], ['trusted']);
    } finally {
      await second.close();
    }
  } finally {
    await drain();
    rmSync(dataDir, { recursive: true, force: true });
  }
});

test('compacting the append log does not lose any state a restart depends on', async () => {
  const dataDir = tempDir('verix-compact-');
  try {
    const first = await serve({ dataDir });
    const agent = await first.issue('Persist-Compact', [{ action: 'deploy:*', resource: 'infra:*' }]);
    const proof = await first.req('POST', '/verify-action', { body: { identityId: agent.identity.id, keyPair: agent.wire, action: 'deploy:infra', resource: 'infra:prod-eu-1' } });
    await settled();
    assert.equal((await first.req('POST', '/revocations/revoke', { token: ADMIN, body: { identityId: agent.identity.id, reason: 'compacted away' } })).status, 200);
    const headBefore = (await first.req('GET', '/nodes/head')).json;
    const node = 'verix-node-aws-1';
    const COLLECTION_KEYS = {
      chain: (row) => `${row.nodeId}:${row.seq}`,
      records: (row) => row.recordHash,
      identities: (row) => row.id,
      revocations: (row) => row.revocationId,
      heads: (row) => row.nodeId,
      meta: (row) => row.key,
    };
    function logState(dir) {
      const state = {};
      for (const [collection, keyOf] of Object.entries(COLLECTION_KEYS)) {
        const path = join(dir, node, `${collection}.jsonl`);
        const rows = existsSync(path) ? readFileSync(path, 'utf8').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line)) : [];
        state[collection] = { lines: rows.length, keys: new Set(rows.map(keyOf)).size };
      }
      return state;
    }

    const linesOf = (state) => Object.fromEntries(Object.entries(state).map(([collection, counts]) => [collection, counts.lines]));
    const keysOf = (state) => Object.fromEntries(Object.entries(state).map(([collection, counts]) => [collection, counts.keys]));

    const before = logState(dataDir);
    // Genesis is its own chain entry, so one action puts two entries on the chain. The
    // record log holds the pre-assessment write plus the assessment that supersedes it,
    // and the head log holds the seq-0 head the proof advanced past. Those two
    // superseded appends are the only rows compaction is allowed to remove.
    assert.deepEqual(linesOf(before), { chain: 2, records: 2, identities: 2, revocations: 1, heads: 2, meta: 2 });
    assert.deepEqual(keysOf(before), { chain: 2, records: 1, identities: 2, revocations: 1, heads: 1, meta: 2 });
    await first.close();

    await new FileStore({ directory: join(dataDir, node), name: node }).load().then((store) => store.compact());
    const after = logState(dataDir);
    assert.deepEqual(keysOf(after), keysOf(before), 'compaction kept every key');
    assert.deepEqual(linesOf(after), keysOf(after), 'every log holds exactly one row per key after compaction');
    const shrank = Object.entries(before).filter(([collection, counts]) => after[collection].lines < counts.lines).map(([collection]) => collection);
    assert.deepEqual(shrank, ['records', 'heads'], 'the two logs with a superseded append shrank, and nothing else did');
    for (const [collection, counts] of Object.entries(after)) assert.ok(counts.lines >= 1, `${collection} still has rows after compaction`);

    const second = await serve({ dataDir });
    try {
      const head = (await second.req('GET', '/nodes/head')).json;
      assert.deepEqual([head.seq, head.root, head.lastRecordHash], [headBefore.seq, headBefore.root, headBefore.lastRecordHash], 'the compacted chain still produces the same head');
      assert.equal((await second.req('GET', `/ledger/records/${proof.json.proofId}`)).json.assessment.valid, true);
      const audit = await second.req('POST', '/ledger/audit', { body: { nodeId: 'verix-node-aws-1' } });
      assert.equal(audit.json.intact, true, 'a compacted node is still an intact chain');
      assert.deepEqual(audit.json.problems, []);
      assert.equal((await second.req('GET', '/revocations')).json.revocations.length, 1);
    } finally {
      await second.close();
    }
  } finally {
    await drain();
    rmSync(dataDir, { recursive: true, force: true });
  }
});

test('a plan entry with no backend follows the configured backend instead of silently using memory', async () => {
  const dataDir = tempDir('verix-backend-');
  try {
    const fleet = await serve({ dataDir, nodePlan: [{ nodeId: 'verix-node-aws-1', cloud: 'aws', region: 'us-east-1' }, ...NODE_PLAN.slice(1)] });
    try {
      const agent = await fleet.issue('Persist-Backend', [{ action: 'read:*', resource: '*' }]);
      assert.equal((await fleet.req('POST', '/verify-action', { body: { identityId: agent.identity.id, keyPair: agent.wire, action: 'read:logs', resource: 'svc:audit' } })).status, 200);
      assert.equal(fleet.platform.nodes.every((node) => node.store instanceof FileStore), true, 'config.backend=file reaches nodes whose plan entry names no backend');
      assert.equal(jsonlLines(dataDir, 'verix-node-aws-1', 'records') > 0, true, 'the proof is on disk, not only in the process heap');
    } finally {
      await fleet.close();
    }

    const mixed = await serve({ dataDir: tempDir('verix-mixed-'), nodePlan: [{ nodeId: 'verix-node-aws-1', cloud: 'aws', region: 'us-east-1', backend: 'memory' }, ...NODE_PLAN.slice(1)] });
    try {
      assert.deepEqual(mixed.platform.nodes.map((node) => node.store.constructor.name), ['MemoryStore', 'FileStore', 'FileStore'], 'an explicit per-entry backend wins over the global one');
    } finally {
      await mixed.close();
      rmSync(mixed.config.dataDir, { recursive: true, force: true });
    }
  } finally {
    await drain();
    rmSync(dataDir, { recursive: true, force: true });
  }
});

test('a coordinator key for a different algorithm or an unreadable key file refuses to boot', async () => {
  const dataDir = tempDir('verix-key-');
  try {
    const first = await serve({ dataDir });
    const original = readFileSync(join(dataDir, 'coordinator-key.json'), 'utf8');
    const coordinatorId = first.platform.coordinator.id;
    await first.close();

    writeFileSync(join(dataDir, 'coordinator-key.json'), JSON.stringify({ ...JSON.parse(original), alg: 'ML-DSA-44' }));
    await assert.rejects(() => serve({ dataDir }), (error) => {
      assert.match(error.message, /is ML-DSA-44 but VERIX_SIGNING_ALG is ML-DSA-65/);
      assert.match(error.message, /retire that key file deliberately/);
      return true;
    }, 'the assessment signer must not change because a file was swapped');

    writeFileSync(join(dataDir, 'coordinator-key.json'), 'this is not json');
    await assert.rejects(() => serve({ dataDir }), /could not be read/, 'a damaged key file is an error, not an invitation to mint a new root');

    writeFileSync(join(dataDir, 'coordinator-key.json'), original);
    const recovered = await serve({ dataDir });
    try {
      assert.equal(recovered.platform.coordinator.id, coordinatorId, 'the same key file yields the same coordinator after the failed boots');
      assert.equal(JSON.parse(original).implementation, 'wasm', 'a fleet without VERIX_NODE_KEY_MATERIAL signs with the wasm implementation');
    } finally {
      await recovered.close();
    }
  } finally {
    await drain();
    rmSync(dataDir, { recursive: true, force: true });
  }
});

test('a root identity whose public key was swapped on disk while the node was down cannot boot', async () => {
  const dataDir = tempDir('verix-anchor-');
  try {
    const first = await serve({ dataDir });
    const agent = await first.issue('Persist-Anchor', [{ action: 'read:*', resource: '*' }]);
    const coordinatorId = first.platform.coordinator.id;
    await first.close();

    const path = join(dataDir, 'verix-node-aws-1', 'identities.jsonl');
    const rows = readFileSync(path, 'utf8').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line));
    assert.equal(rows.length, 2);
    const swapped = rows.map((row) => (row.parent ? row : { ...row, publicKey: 'z'.repeat(row.publicKey.length) }));
    writeFileSync(path, `${swapped.map((row) => JSON.stringify(row)).join('\n')}\n`);

    // The store refuses to rebind a root to a different key, so the coordinator
    // cannot register on any node and the process never comes up serving a ledger
    // whose lineage it cannot vouch for.
    await assert.rejects(() => serve({ dataDir }), /could not be replicated to 3 of 3 nodes/);
    assert.equal(existsSync(join(dataDir, 'verix-node-gcp-1', 'identities.jsonl')), true, 'the untouched node still holds the genuine root; only the edited node is refused');
    const untouched = JSON.parse(readFileSync(join(dataDir, 'verix-node-gcp-1', 'identities.jsonl'), 'utf8').trim().split('\n')[0]);
    assert.equal(untouched.id, coordinatorId);
    assert.equal(untouched.publicKey === swapped[0].publicKey, false);
    assert.equal(agent.identity.parent.id, coordinatorId);
  } finally {
    await drain();
    rmSync(dataDir, { recursive: true, force: true });
  }
});

test('FileStore loads once, ignores unknown collections and keeps an empty directory empty', async () => {
  const dir = tempDir('verix-store-');
  try {
    const store = await new FileStore({ directory: dir, name: 'node-a' }).load();
    await store.putMeta('counter', 1);
    await store.putMeta('counter', 2);
    await store.putIdentity({ id: 'i1', publicKey: 'AAA', selfSignature: 's' });
    await store.putRevocation({ revocationId: 'r1', identityId: 'i1', revokedAt: '2026-01-01T00:00:00.000Z' });
    assert.equal(store.apply('not-a-collection', { id: 'x' }), undefined, 'an unknown collection is ignored rather than corrupting a file');
    assert.deepEqual(readdirSync(dir).sort(), ['chain.jsonl', 'heads.jsonl', 'identities.jsonl', 'meta.jsonl', 'records.jsonl', 'revocations.jsonl'].filter((name) => existsSync(join(dir, name))).sort());

    await store.load();
    assert.equal((await store.listRevocations()).length, 1, 'a second load is a no-op, so revocations are not duplicated');
    assert.equal(await store.getMeta('counter'), 2, 'the last append wins in the loaded view');
    assert.equal(jsonlLines(dir, '.', 'meta'), 2, 'the log itself keeps both rows until it is compacted');

    const reloaded = await new FileStore({ directory: dir, name: 'node-a' }).load();
    assert.equal(await reloaded.getMeta('counter'), 2);
    assert.equal((await reloaded.getIdentity('i1')).id, 'i1');
    assert.equal(await reloaded.getHead('node-a'), null, 'a node that never wrote a head has no head');
    await reloaded.compact();
    assert.equal(jsonlLines(dir, '.', 'meta'), 1);
    assert.equal(await new FileStore({ directory: dir, name: 'node-a' }).load().then((s) => s.getMeta('counter')), 2);

    const empty = await new FileStore({ directory: join(dir, 'never-used'), name: 'never-used' }).load();
    assert.deepEqual(readdirSync(join(dir, 'never-used')), [], 'load() over an absent log creates no files');
    assert.equal(await empty.getMeta('anything'), null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});


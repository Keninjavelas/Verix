import test from 'node:test';
import assert from 'node:assert/strict';
import { statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { WebSocket } from 'ws';
import { loadConfig } from '../src/config.js';
import { createPlatform } from '../src/platform.js';
import { createVerixApp } from '../src/api/server.js';
import { addressOrigin } from '../src/index.js';
import { deserializeKeyPair, serializeKeyPair } from '../src/crypto/pqc.js';
import { toB64u } from '../src/crypto/hash.js';
import { createRevocation } from '../src/crypto/identity.js';
import { buildActionEnvelope, signActionEnvelope } from '../src/verification/action.js';

const NODE_PLAN = [
  { nodeId: 'verix-node-aws-1', cloud: 'aws', region: 'us-east-1', backend: 'memory' },
  { nodeId: 'verix-node-gcp-1', cloud: 'gcp', region: 'us-central1', backend: 'memory' },
  { nodeId: 'verix-node-edge-1', cloud: 'local', region: 'local', backend: 'memory' },
];

const PUBLIC_INDEX = fileURLToPath(new URL('../public/index.html', import.meta.url));

async function serve(overrides = {}) {
  const config = loadConfig({}, { nodePlan: NODE_PLAN, backend: 'memory', crossCheck: false, ...overrides });
  const platform = await createPlatform({ config });
  const app = createVerixApp({ platform });
  await new Promise((resolve) => app.server.listen(0, '127.0.0.1', resolve));
  const origin = addressOrigin(app.server.address());

  async function req(method, path, { token, body, raw } = {}) {
    const headers = {};
    if (token) headers.authorization = `Bearer ${token}`;
    if (body !== undefined || raw !== undefined) headers['content-type'] = 'application/json';
    const response = await fetch(`${origin}${path}`, { method, headers, body: raw ?? (body === undefined ? undefined : JSON.stringify(body)) });
    const text = await response.text();
    let json = null;
    try { json = JSON.parse(text); } catch { json = null; }
    return { status: response.status, headers: Object.fromEntries(response.headers), json, text };
  }

  async function close() {
    app.server.closeAllConnections?.();
    await new Promise((resolve) => app.server.close(resolve));
    await platform.close();
  }
  return { origin, config, platform, app, req, close };
}

const settled = () => new Promise((resolve) => setImmediate(resolve));
const code = (response) => response.json.error?.code;
const ADMIN = 'admin-secret';
const NODE = 'node-secret';

test('/health advertises the whole surface with its auth gate', async () => {
  const s = await serve();
  try {
    const { status, json } = await s.req('GET', '/health');
    assert.equal(status, 200);
    assert.equal(json.ok, true);
    assert.equal(json.service, 'verix');
    assert.equal(json.crypto.signingAlg, 'ML-DSA-65');
    assert.deepEqual(json.crypto.standards, ['FIPS 203 ML-KEM', 'FIPS 204 ML-DSA', 'FIPS 205 SLH-DSA', 'SHA3-256/512']);
    assert.equal(json.crypto.crossImplementationCheck, false, 'the test fleet runs with crossCheck off');
    assert.deepEqual(Object.keys(json.planned), ['azure_table']);
    assert.equal(json.security.adminTokenConfigured, false);
    assert.equal(json.security.nodeTokenConfigured, false);
    assert.deepEqual(json.security.failClosed, ['/identities/register', '/revocations/revoke']);
    assert.match(json.security.note, /^no tokens configured/);
    assert.deepEqual(
      json.endpoints.map((e) => `${e.method} ${e.path} ${e.gate}`).sort(),
      [
        'GET /events public',
        'GET /health public',
        'GET /identities public',
        'GET /identities/:id public',
        'GET /identities/:id/revocations public',
        'GET /ledger/cross-check/:seq public',
        'GET /ledger/inclusion/:seq public',
        'GET /ledger/records public',
        'GET /ledger/records/:hash public',
        'GET /nodes/head public',
        'GET /nodes/self public',
        'GET /nodes/status public',
        'GET /revocations public',
        'GET /status public',
        'GET /trust/summary public',
        'GET /trust/topology public',
        'POST /copilot/ask public',
        'POST /copilot/reindex admin',
        'POST /events node',
        'POST /identities node',
        'POST /identities/register adminRequired',
        'POST /ledger/audit public',
        'POST /nodes/accept node',
        'POST /nodes/certify node',
        'POST /revocations node',
        'POST /revocations/revoke adminRequired',
        'POST /verify-action public',
      ].sort(),
    );
  } finally {
    await s.close();
  }
});

test('key handout and issuer-side revocation are disabled until an admin token exists', async () => {
  const s = await serve();
  try {
    for (const path of ['/identities/register', '/revocations/revoke']) {
      const response = await s.req('POST', path, { body: { name: 'x', identityId: 'verix:agent:x', reason: 'x' } });
      assert.equal(response.status, 503, path);
      assert.equal(code(response), 'ADMIN_TOKEN_NOT_CONFIGURED', path);
      assert.match(response.json.error.message, /disabled until VERIX_ADMIN_TOKEN is set/);
    }
    const health = await s.req('GET', '/health');
    assert.deepEqual(health.json.security.failClosed, ['/identities/register', '/revocations/revoke']);
  } finally {
    await s.close();
  }
});

test('/identities/register hands out the secret key exactly once and stores nothing', async () => {
  const s = await serve({ adminToken: ADMIN });
  try {
    const noToken = await s.req('POST', '/identities/register', { body: { name: 'Gated' } });
    assert.equal(noToken.status, 401);
    assert.equal(code(noToken), 'ADMIN_TOKEN_REQUIRED');
    const wrongToken = await s.req('POST', '/identities/register', { token: 'not-the-admin', body: { name: 'Gated' } });
    assert.equal(wrongToken.status, 401);
    assert.equal(code(wrongToken), 'ADMIN_TOKEN_REQUIRED');

    const issued = await s.req('POST', '/identities/register', { token: ADMIN, body: { name: 'Issued-1', scopes: [{ action: 'read:*', resource: '*' }] } });
    assert.equal(issued.status, 200);
    assert.deepEqual(Object.keys(issued.json), ['identity', 'privateKey', 'note']);
    assert.equal(issued.json.identity.subject.name, 'Issued-1');
    assert.equal(issued.json.privateKey.alg, 'ML-DSA-65');
    assert.equal(issued.json.privateKey.publicKey, issued.json.identity.publicKey, 'the handed-out key pair is the one the identity binds');
    assert.match(issued.json.note, /not stored by the platform/);
    const keyPair = deserializeKeyPair(issued.json.privateKey);
    assert.equal(keyPair.implementation, 'wasm', 'a key issued without VERIX_NODE_KEY_MATERIAL is generated by the wasm implementation');
    assert.equal(keyPair.publicKey.length, 1952);
    assert.ok(keyPair.privateKey.length > 0);

    const nameless = await s.req('POST', '/identities/register', { token: ADMIN, body: {} });
    assert.equal(nameless.status, 400);
    assert.equal(code(nameless), 'NAME_REQUIRED');

    // The secret must not be recoverable from anything the service serves.
    const [identities, records, events] = await Promise.all([s.req('GET', '/identities'), s.req('GET', '/ledger/records'), s.req('GET', '/events')]);
    const secret = issued.json.privateKey.privateKey;
    for (const body of [identities.text, records.text, events.text]) {
      assert.ok(!body.includes(secret), 'the private key never appears in a served document');
    }
    assert.equal(identities.json.identities.length, 2, 'coordinator plus the issued agent');
    assert.equal((await s.req('GET', '/health')).json.security.adminTokenConfigured, true);
    assert.match((await s.req('GET', '/health')).json.security.note, /^peer replication endpoints require/);
  } finally {
    await s.close();
  }
});

test('peer replication endpoints require the node bearer token', async () => {
  const s = await serve({ nodeToken: NODE });
  try {
    const rejected = await s.req('POST', '/events', { body: { source: 'peer-1', event: { topic: 'action.verified', payload: { proofId: 'x' } } } });
    assert.equal(rejected.status, 401);
    assert.equal(code(rejected), 'NODE_TOKEN_REQUIRED');

    const asAdmin = await s.req('POST', '/nodes/accept', { token: ADMIN, body: {} });
    assert.equal(asAdmin.status, 401, 'an admin token that is not configured cannot satisfy the node gate');
    assert.equal(code(asAdmin), 'NODE_TOKEN_REQUIRED');

    const agent = await s.platform.issueAgent({ name: 'Peer-1' });
    const stored = await s.req('POST', '/identities', { token: NODE, body: { identity: agent.identity } });
    assert.equal(stored.status, 200);
    assert.deepEqual(stored.json, { stored: true, identityId: agent.identity.id, nodes: NODE_PLAN.map((n) => n.nodeId) });

    const withNodeToken = await s.req('POST', '/events', { token: NODE, body: { source: 'peer-1', event: { topic: 'action.verified', payload: { proofId: 'x' } } } });
    assert.equal(withNodeToken.status, 200);
    assert.deepEqual(withNodeToken.json, { accepted: true });
    const events = await s.req('GET', '/events?since=0');
    const forwarded = events.json.events.at(-1);
    assert.equal(forwarded.topic, 'action.verified');
    assert.equal(forwarded.payload.originNodeId, 'peer-1', 'the inbound source is stamped so the peer never sees an echo');

    const malformed = await s.req('POST', '/events', { token: NODE, body: { source: 'peer-1', event: {} } });
    assert.equal(malformed.status, 400);
    assert.equal(code(malformed), 'EVENT_REQUIRED');

    // With no tokens at all the replication surface is open, which is what the
    // health note calls a local development run.
    const open = await serve();
    try {
      const unauthenticated = await open.req('POST', '/events', { body: { source: 'peer-2', event: { topic: 'action.flagged', payload: {} } } });
      assert.equal(unauthenticated.status, 200);
    } finally {
      await open.close();
    }
  } finally {
    await s.close();
  }
});

test('POST /identities refuses an identity that does not bind its own key', async () => {
  const s = await serve({ nodeToken: NODE });
  try {
    const incomplete = await s.req('POST', '/identities', { token: NODE, body: { identity: { id: 'verix:agent:short' } } });
    assert.equal(incomplete.status, 400);
    assert.equal(code(incomplete), 'IDENTITY_INCOMPLETE');

    const issued = await s.platform.issueAgent({ name: 'Swap-1' });
    const swapped = { ...issued.identity, publicKey: (await s.platform.issueAgent({ name: 'Swap-2' })).identity.publicKey };
    const refused = await s.req('POST', '/identities', { token: NODE, body: { identity: swapped } });
    assert.equal(refused.status, 422);
    assert.equal(code(refused), 'IDENTITY_SELF_BINDING_INVALID');
    assert.match(refused.json.error.message, /does not bind its recorded public key/);

    const rewrapped = await s.req('POST', '/identities', { token: NODE, body: { identity: issued.identity } });
    assert.equal(rewrapped.status, 200, 'an honest document is accepted even when it rewrites an existing one');
  } finally {
    await s.close();
  }
});

test('POST /revocations only stores an entry that verifies and has authority', async () => {
  const s = await serve({ nodeToken: NODE });
  try {
    const agent = await s.platform.issueAgent({ name: 'Target-1' });
    const stranger = await s.platform.issueAgent({ name: 'Stranger-1' });

    const incomplete = await s.req('POST', '/revocations', { token: NODE, body: { revocation: { identityId: agent.identity.id } } });
    assert.equal(incomplete.status, 400);
    assert.equal(code(incomplete), 'REVOCATION_INCOMPLETE');

    const unknown = await s.req('POST', '/revocations', {
      token: NODE,
      body: { revocation: await createRevocation({ keyPair: s.platform.coordinatorKeyPair, identityId: 'verix:agent:neverseen', reason: 'ghost' }) },
    });
    assert.equal(unknown.status, 404);
    assert.equal(code(unknown), 'IDENTITY_UNKNOWN');

    const honest = await createRevocation({ keyPair: s.platform.coordinatorKeyPair, identityId: agent.identity.id, reason: 'rotation' });
    // Replaying a coordinator's genuine signature onto a different target: the
    // digest covers identityId, so the borrowed signature no longer matches.
    const forged = { ...honest, identityId: stranger.identity.id };
    const refused = await s.req('POST', '/revocations', { token: NODE, body: { revocation: forged } });
    assert.equal(refused.status, 422);
    assert.equal(code(refused), 'REVOCATION_FORGERY');

    // A valid signature by a key with no claim on the identity is still not authority.
    const claimed = await createRevocation({ keyPair: stranger.keyPair, identityId: agent.identity.id, reason: 'takeover', revokedBy: s.platform.coordinator.id });
    const unauthorized = await s.req('POST', '/revocations', { token: NODE, body: { revocation: claimed } });
    assert.equal(unauthorized.status, 403);
    assert.equal(code(unauthorized), 'REVOCATION_UNAUTHORIZED');
    assert.match(unauthorized.json.error.message, /claims revoker .* but is signed by/);

    const stored = await s.req('POST', '/revocations', { token: NODE, body: { revocation: honest } });
    assert.equal(stored.status, 200);
    assert.equal(stored.json.stored, true);
    assert.equal(stored.json.byIssuer, true);
    assert.deepEqual(stored.json.nodes, NODE_PLAN.map((n) => n.nodeId));

    const listed = await s.req('GET', `/identities/${agent.identity.id}/revocations`);
    assert.equal(listed.json.revocations.length, 1);
    assert.equal(listed.json.revocations[0].reason, 'rotation');
    assert.deepEqual(listed.json.forged, []);
    assert.equal(listed.json.nodesReporting, 3);

    const merged = await s.req('GET', '/revocations');
    assert.equal(merged.json.revocations.length, 1);
    assert.equal(merged.json.revocations[0].agentName, 'Target-1');

    const after = await s.req('POST', '/verify-action', { body: { identityId: agent.identity.id, keyPair: serializeKeyPair(agent.keyPair), action: 'read:logs', resource: 'svc:audit' } });
    assert.equal(after.status, 201);
    assert.equal(after.json.status, 'rejected');
    assert.equal(after.json.checks.revocation.revoked, true);
    assert.equal(after.json.checks.revocation.nodesReporting, 3);
    assert.equal(after.json.allowedMode, 'deny');
  } finally {
    await s.close();
  }
});

test('/revocations/revoke kills an identity and the ledger remembers it', async () => {
  const s = await serve({ adminToken: ADMIN });
  try {
    const agent = await s.platform.issueAgent({ name: 'Kill-1', scopes: [{ action: 'read:*', resource: '*' }] });
    const stranger = await s.platform.issueAgent({ name: 'Kill-2' });

    assert.equal(code(await s.req('POST', '/revocations/revoke', { token: ADMIN, body: { identityId: agent.identity.id } })), 'REASON_REQUIRED');
    assert.equal((await s.req('POST', '/revocations/revoke', { token: ADMIN, body: { identityId: agent.identity.id } })).status, 400);
    assert.equal(code(await s.req('POST', '/revocations/revoke', { token: ADMIN, body: { reason: 'x' } })), 'IDENTITY_REQUIRED');

    const unknown = await s.req('POST', '/revocations/revoke', { token: ADMIN, body: { identityId: 'verix:agent:none', reason: 'x' } });
    assert.equal(unknown.status, 404, 'nothing to revoke is not the same answer as a refused revocation');
    assert.equal(code(unknown), 'IDENTITY_UNKNOWN');

    const revoked = await s.req('POST', '/revocations/revoke', { token: ADMIN, body: { identityId: agent.identity.id, reason: 'key compromise' } });
    assert.equal(revoked.status, 200);
    assert.equal(revoked.json.revoked, true);
    assert.equal(revoked.json.revocation.revokedBy, s.platform.coordinator.id, 'the admin path records the coordinator as revoker');
    assert.match(revoked.json.revocation.reason, /key compromise/);

    const killed = await s.req('POST', '/verify-action', { body: { identityId: agent.identity.id, keyPair: serializeKeyPair(agent.keyPair), action: 'read:logs', resource: 'svc:audit' } });
    assert.equal(killed.status, 201);
    assert.equal(killed.json.status, 'rejected');
    assert.ok(killed.json.reason.includes('policy authorization failed'), killed.json.reason);
    assert.equal(killed.json.checks.revocation.revoked, true);

    const identities = await s.req('GET', '/identities');
    const flags = identities.json.identities.map((identity) => Boolean(identity.revokedAt));
    assert.deepEqual(flags, [false, true, false], 'coordinator, the killed agent, the bystander');

    // A second revocation of a dead identity is a fresh, honest entry, not an error.
    const again = await s.req('POST', '/revocations/revoke', { token: ADMIN, body: { identityId: agent.identity.id, reason: 'cleanup' } });
    assert.equal(again.status, 200);
    const merged = await s.req('GET', '/revocations');
    assert.deepEqual(merged.json.revocations.map((entry) => entry.reason), ['key compromise', 'cleanup']);

    // A stranger cannot use the admin path for someone else's identity: the entry
    // is signed by the coordinator, so authority holds; the guard that matters is
    // that only an admin token reaches this route at all.
    const forbidden = await s.req('POST', '/revocations/revoke', { token: NODE, body: { identityId: stranger.identity.id, reason: 'x' } });
    assert.equal(forbidden.status, 401);
    assert.equal(code(forbidden), 'ADMIN_TOKEN_REQUIRED');
  } finally {
    await s.close();
  }
});

test('/verify-action validates the request before touching the ledger', async () => {
  const s = await serve();
  try {
    const cases = [
      [{ action: 'read:logs', resource: 'svc:audit' }, 400, 'IDENTITY_REQUIRED'],
      [{ identityId: 'verix:agent:x', action: 'read:logs' }, 400, 'ACTION_REQUIRED'],
      [{ identityId: 'verix:agent:nonexistent', action: 'read:logs', resource: 'svc:audit' }, 404, 'IDENTITY_UNKNOWN'],
    ];
    for (const [body, status, expected] of cases) {
      const response = await s.req('POST', '/verify-action', { body });
      assert.deepEqual([response.status, code(response)], [status, expected], JSON.stringify(body));
    }
    const agent = await s.platform.issueAgent({ name: 'Quiet-1', scopes: [{ action: 'read:*', resource: '*' }] });
    const noSignature = await s.req('POST', '/verify-action', { body: { identityId: agent.identity.id, action: 'read:logs', resource: 'svc:audit' } });
    assert.equal(noSignature.status, 400);
    assert.equal(code(noSignature), 'SIGNATURE_REQUIRED');
    assert.match(noSignature.json.error.message, /the platform never holds agent private keys/);

    await settled();
    assert.equal((await s.req('GET', '/ledger/records')).json.count, 0, 'a rejected request never reaches the ledger');
    assert.equal(s.platform.index.size, 0);
    assert.equal((await s.req('GET', `/ledger/records/${'0'.repeat(64)}`)).status, 404);
    assert.equal(code(await s.req('GET', `/ledger/records/${'0'.repeat(64)}`)), 'PROOF_NOT_FOUND');
  } finally {
    await s.close();
  }
});

test('a trusted action answers 200 with a proof the read endpoints agree on', async () => {
  const s = await serve();
  try {
    const agent = await s.platform.issueAgent({ name: 'API-Trust', scopes: [{ action: 'deploy:*', resource: 'infra:*' }] });
    const response = await s.req('POST', '/verify-action', {
      body: { identityId: agent.identity.id, keyPair: serializeKeyPair(agent.keyPair), action: 'deploy:infra', resource: 'infra:prod-eu-1', context: { cloud: 'aws', region: 'us-east-1' } },
    });
    assert.equal(response.status, 200, 'only a trusted status answers 200');
    assert.equal(response.json.status, 'trusted');
    assert.equal(response.json.trustScore, 96.4, 'a first action by a coordinator-issued agent scores 96.4');
    assert.equal(response.json.band, 'high-trust');
    assert.equal(response.json.allowedMode, 'full');
    assert.equal(response.json.meetsFloor, true);
    assert.equal(response.json.proofId.length, 64);
    assert.equal(response.json.checks.actionSignature, true);
    assert.deepEqual(response.json.checks.replication, { reached: true, agreeing: 3, required: 2, total: 3, failures: [] });
    assert.equal(response.json.persistence.complete, true);
    assert.equal(response.json.assessment.selfVerified, true);
    assert.equal(response.json.postCertificationDivergence, false);
    await settled();

    const proof = await s.req('GET', `/ledger/records/${response.json.proofId}`);
    assert.equal(proof.status, 200);
    assert.equal(proof.json.present, 3);
    assert.deepEqual(proof.json.replication.map((copy) => copy.present), [true, true, true]);
    assert.deepEqual(proof.json.replication.map((copy) => copy.error), [null, null, null]);
    assert.equal(proof.json.assessment.valid, true);
    assert.deepEqual(proof.json.assessment.problems, []);
    assert.equal(proof.json.assessment.coordinatorId, s.platform.coordinator.id);
    assert.equal(proof.json.record.recordHash, response.json.proofId);
    assert.equal(proof.json.record.seq, 1);
    assert.equal(proof.json.record.witnesses.length, 3);
    assert.deepEqual([...new Set(proof.json.record.witnesses.map((w) => w.cloud))].sort(), ['aws', 'gcp', 'local']);

    const inclusion = await s.req('GET', '/ledger/inclusion/1');
    assert.equal(inclusion.status, 200);
    assert.equal(inclusion.json.seq, 1);
    assert.equal(inclusion.json.recordHash, response.json.proofId);
    assert.equal(inclusion.json.treeSize, 1);
    assert.deepEqual(inclusion.json.path, []);
    assert.equal(inclusion.json.root, proof.json.record.inclusionProof.root);

    const outOfRange = await s.req('GET', '/ledger/inclusion/99');
    assert.equal(outOfRange.status, 404);
    assert.equal(code(outOfRange), 'SEQUENCE_OUT_OF_RANGE');
    assert.equal(outOfRange.json.error.message, 'seq 99 is outside the chain of length 1');

    const audit = await s.req('POST', '/ledger/audit', { body: { nodeId: 'verix-node-gcp-1' } });
    assert.equal(audit.status, 200);
    assert.equal(audit.json.intact, true);
    assert.equal(audit.json.nodeId, 'verix-node-gcp-1');
    assert.deepEqual([audit.json.auditedFrom, audit.json.auditedTo], [1, 1]);
    assert.equal(audit.json.rootChecked, true);
    assert.equal(audit.json.root, inclusion.json.root, 'every node recomputes the same merkle root');
    assert.deepEqual(audit.json.assessments, { verified: 1, invalid: 0, unsigned: 0 });
    assert.deepEqual(audit.json.problems, []);
    const unknownNode = await s.req('POST', '/ledger/audit', { body: { nodeId: 'verix-node-moon-1' } });
    assert.equal(unknownNode.status, 404);
    assert.equal(code(unknownNode), 'NODE_UNKNOWN');

    const cross = await s.req('GET', '/ledger/cross-check/1');
    assert.equal(cross.json.consistent, true);
    assert.equal(cross.json.nodesReporting, 3);
    assert.equal(cross.json.nodesRequired, 2);
    assert.equal(cross.json.distinctRoots, 1);
    assert.equal(cross.json.consensusRecordHash, response.json.proofId);
    assert.deepEqual(cross.json.divergent, []);
    assert.deepEqual(cross.json.failures, []);
    assert.equal(cross.json.perNode.length, 3);
    for (const node of cross.json.perNode) {
      assert.equal(node.selfVerified, true, node.nodeId);
      assert.equal(node.witnessesValid, true, node.nodeId);
      assert.equal(node.assessment.valid, true, node.nodeId);
      assert.equal(node.recordMatchesCommitment, true, node.nodeId);
    }

    const listed = await s.req('GET', '/ledger/records?limit=10&offset=0');
    assert.equal(listed.json.count, 1);
    assert.equal(listed.json.records[0].recordHash, response.json.proofId);
    const filtered = await s.req('GET', `/ledger/records?agentId=${agent.identity.id}`);
    assert.equal(filtered.json.count, 1);
    const empty = await s.req('GET', `/ledger/records?agentId=verix:agent:none&limit=10`);
    assert.equal(empty.json.count, 0);

    const events = await s.req('GET', '/events?since=0');
    const verified = events.json.events.filter((e) => e.topic === 'action.verified');
    assert.equal(verified.length, 1);
    assert.equal(verified[0].payload.proofId, response.json.proofId);
    assert.equal(verified[0].payload.trustScore, 96.4);
    assert.equal(events.json.sequence, 3, 'the coordinator registration, the agent registration, and the action');
  } finally {
    await s.close();
  }
});

test('a rejected action answers 201 but is still written to the ledger', async () => {
  const s = await serve();
  try {
    const agent = await s.platform.issueAgent({ name: 'API-Refuse', scopes: [{ action: 'deploy:*', resource: 'infra:*' }] });
    const denied = await s.req('POST', '/verify-action', {
      body: { identityId: agent.identity.id, keyPair: serializeKeyPair(agent.keyPair), action: 'delete:everything', resource: 'nope:1' },
    });
    assert.equal(denied.status, 201, 'a proof the platform would not trust is created, not accepted');
    assert.equal(denied.json.status, 'rejected');
    assert.equal(denied.json.allowedMode, 'deny');
    assert.match(denied.json.reason, /policy authorization failed/);
    assert.equal(denied.json.persistence.complete, true, 'a rejected action is still evidence');

    const list = await s.req('GET', '/ledger/records');
    assert.equal(list.json.count, 1);
    assert.equal(list.json.records[0].trust.status, 'rejected');

    const flagged = await s.req('GET', '/events?since=0');
    assert.deepEqual(flagged.json.events.map((e) => e.topic).slice(-2), ['identity.registered', 'action.flagged']);
    assert.equal(s.platform.index.size, 1, 'flagged proofs are indexed too');
  } finally {
    await s.close();
  }
});

test('the agent-side signature path needs no private key at the platform', async () => {
  const s = await serve();
  try {
    const agent = await s.platform.issueAgent({ name: 'API-Client', scopes: [{ action: 'read:*', resource: '*' }] });
    const envelope = buildActionEnvelope({ agentId: agent.identity.id, action: 'read:logs', resource: 'svc:audit', context: { region: 'eu-west-1' } });
    const signatureDoc = await signActionEnvelope(agent.keyPair, envelope);
    const response = await s.req('POST', '/verify-action', {
      body: { identityId: agent.identity.id, envelope, signatureDoc, action: envelope.action, resource: envelope.resource },
    });
    assert.equal(response.status, 200);
    assert.equal(response.json.status, 'trusted');
    assert.equal(response.json.executedAt, envelope.executedAt);
    assert.equal(response.json.checks.actionSignature, true);

    const stranger = await s.platform.issueAgent({ name: 'API-Forged', scopes: [{ action: 'read:*', resource: '*' }] });
    const replayedDoc = await signActionEnvelope(stranger.keyPair, envelope);
    const replayed = await s.req('POST', '/verify-action', {
      body: { identityId: agent.identity.id, envelope, signatureDoc: replayedDoc, action: envelope.action, resource: envelope.resource },
    });
    assert.equal(replayed.status, 201);
    assert.equal(replayed.json.checks.actionSignature, false);
    assert.equal(replayed.json.status, 'rejected');
    assert.equal(replayed.json.trustScore, 15, 'a signature that does not verify is capped at 15');
    assert.equal(replayed.json.band, 'quarantine');
    assert.equal(replayed.json.allowedMode, 'deny');

    // The convenience path (a keyPair for this request only) accepts the
    // serialized document and refuses anything that is not a key.
    const serialized = await s.req('POST', '/verify-action', {
      body: { identityId: stranger.identity.id, keyPair: serializeKeyPair(stranger.keyPair), action: 'read:logs', resource: 'svc:audit' },
    });
    assert.equal(serialized.status, 200);
    assert.equal(serialized.json.status, 'trusted');

    const truncated = await s.req('POST', '/verify-action', {
      body: { identityId: agent.identity.id, keyPair: { alg: 'ML-DSA-65', publicKey: 'AAAA', privateKey: 'BBBB' }, action: 'read:logs', resource: 'svc:audit' },
    });
    assert.equal(truncated.status, 400);
    assert.equal(code(truncated), 'KEYPAIR_MALFORMED');
    assert.equal(truncated.json.error.message, 'ML-DSA-65 public key must be 1952 bytes, got 3');

    const rawObject = await s.req('POST', '/verify-action', {
      body: { identityId: agent.identity.id, keyPair: { alg: 'ML-DSA-65', privateKey: { 0: 1, 1: 2 } }, action: 'read:logs', resource: 'svc:audit' },
    });
    assert.equal(rawObject.status, 400);
    assert.equal(code(rawObject), 'KEYPAIR_MALFORMED');
    assert.match(rawObject.json.error.message, /base64url publicKey and privateKey/);
    assert.equal((await s.req('GET', `/ledger/records/${truncated.json.proofId ?? 'x'}`)).status, 404, 'a malformed keyPair writes nothing');
  } finally {
    await s.close();
  }
});

test('an expired identity is refused over HTTP', async () => {
  const s = await serve();
  try {
    const agent = await s.platform.issueAgent({ name: 'API-Expiry', scopes: [{ action: 'read:*', resource: '*' }], ttlSeconds: -60 });
    const response = await s.req('POST', '/verify-action', {
      body: { identityId: agent.identity.id, keyPair: serializeKeyPair(agent.keyPair), action: 'read:logs', resource: 'svc:audit' },
    });
    assert.equal(response.status, 201);
    assert.equal(response.json.status, 'rejected');
    assert.equal(response.json.allowedMode, 'deny');
    assert.equal(response.json.policy.authorized, false);
    assert.deepEqual(response.json.policy.blockingReasons.map((entry) => entry.code), ['IDENTITY_EXPIRED']);
    assert.equal(response.json.checks.actionSignature, true, 'the signature is valid; the identity is simply out of date');
    const survivor = await s.platform.issueAgent({ name: 'API-Live', scopes: [{ action: 'read:*', resource: '*' }] });
    const stillGood = await s.req('POST', '/verify-action', {
      body: { identityId: survivor.identity.id, keyPair: serializeKeyPair(survivor.keyPair), action: 'read:logs', resource: 'svc:audit' },
    });
    assert.equal(stillGood.status, 200);
    assert.deepEqual(stillGood.json.policy.blockingReasons, []);
  } finally {
    await s.close();
  }
});

test('identity read endpoints report what the fleet agrees on', async () => {
  const s = await serve();
  try {
    const agent = await s.platform.issueAgent({ name: 'API-Read', scopes: [{ action: 'read:*', resource: '*' }] });
    const listed = await s.req('GET', '/identities');
    assert.equal(listed.status, 200);
    assert.deepEqual(listed.json.identities.map((identity) => identity.subject.name), ['verix-coordinator', 'API-Read']);
    assert.equal(listed.json.nodesReporting, 3);
    assert.equal(listed.json.divergent, 0);
    assert.deepEqual(listed.json.trustAnchors, [s.platform.coordinator.id]);
    assert.deepEqual(listed.json.identities.map((identity) => identity.kind), ['coordinator', 'agent']);

    const byKind = await s.req('GET', '/identities?kind=agent');
    assert.deepEqual(byKind.json.identities.map((identity) => identity.subject.name), ['API-Read']);

    const one = await s.req('GET', `/identities/${agent.identity.id}`);
    assert.equal(one.status, 200);
    assert.equal(one.json.identity.id, agent.identity.id);
    assert.equal(one.json.copies, 3);
    assert.equal(one.json.disagreement, 0);

    const missing = await s.req('GET', '/identities/verix:agent:unknown');
    assert.equal(missing.status, 404);
    assert.equal(code(missing), 'IDENTITY_UNKNOWN');

    const nodes = await Promise.all([s.req('GET', '/nodes/self'), s.req('GET', '/nodes/head'), s.req('GET', '/nodes/status')]);
    assert.equal(nodes[0].json.nodeId, 'verix-node-aws-1');
    assert.equal(nodes[1].json.seq, 0);
    assert.equal(nodes[2].json.chainLength, 0);
    assert.equal(nodes[2].json.records, 0);
    assert.equal(nodes[2].json.identities, 2, 'both identities replicated to every node');

    const status = await s.req('GET', '/status');
    assert.equal(status.json.quorumRequired, 2);
    assert.deepEqual(status.json.trustAnchors, [s.platform.coordinator.id]);
    assert.deepEqual(status.json.anchorHydration, { anchors: [], identities: 0, nodesReporting: 3, divergent: 0 });
    assert.equal(status.json.indexedProofs, 0);
    assert.equal(status.json.eventForwarding, null, 'a single process has no peers to forward to');
    assert.equal(status.json.eventSequence, 2, 'the coordinator and agent registrations at boot');
    assert.deepEqual(status.json.nodes.map((node) => node.cloud).sort(), ['aws', 'gcp', 'local']);
  } finally {
    await s.close();
  }
});

test('trust summary and topology aggregate the ledger for the UI', async () => {
  const s = await serve();
  try {
    const agent = await s.platform.issueAgent({ name: 'API-Summary', scopes: [{ action: 'deploy:*', resource: 'infra:*' }] });
    const trusted = await s.req('POST', '/verify-action', { body: { identityId: agent.identity.id, keyPair: serializeKeyPair(agent.keyPair), action: 'deploy:infra', resource: 'infra:prod-eu-1' } });
    await settled();
    const denied = await s.req('POST', '/verify-action', { body: { identityId: agent.identity.id, keyPair: serializeKeyPair(agent.keyPair), action: 'delete:everything', resource: 'nope:1' } });
    await settled();

    const summary = await s.req('GET', '/trust/summary');
    assert.equal(summary.status, 200);
    assert.deepEqual(summary.json.totals, { proofs: 2, agents: 1, byStatus: { trusted: 1, rejected: 1 }, indexed: 2 });
    assert.deepEqual(summary.json.quorum, { required: 2, of: 3 });
    assert.equal(summary.json.coordinatorId, s.platform.coordinator.id);
    assert.ok(Date.parse(summary.json.generatedAt) > 0);

    const [entry] = summary.json.agents;
    assert.equal(entry.name, 'API-Summary');
    assert.equal(entry.proofs, 2);
    assert.equal(entry.trusted, 1);
    assert.equal(entry.rejected, 1);
    assert.equal(entry.flagged, 0);
    assert.equal(entry.unattested, 0);
    assert.equal(entry.revoked, false);
    assert.equal(entry.score, denied.json.trustScore, 'the agent card carries the newest score');
    assert.deepEqual(entry.anomalies.map((a) => a.code), ['IDENTITY_FIRST_SIGHTING']);
    assert.equal(entry.anomalies[0].count, 1);

    assert.equal(summary.json.timeline.length, 2);
    assert.deepEqual(summary.json.timeline.map((row) => row.seq), [1, 2]);
    assert.deepEqual(summary.json.timeline.map((row) => row.status), ['trusted', 'rejected']);
    assert.deepEqual(summary.json.timeline[0].clouds.sort(), ['aws', 'gcp', 'local']);
    assert.deepEqual(summary.json.timeline[0].nodes, NODE_PLAN.map((n) => n.nodeId));
    assert.equal(summary.json.timeline[0].recordHash, trusted.json.proofId);
    assert.equal(summary.json.timeline[0].signedBy, s.platform.coordinator.id);
    assert.equal(summary.json.timeline[0].band, 'high-trust');
    assert.equal(summary.json.timeline[0].anomalies[0].severity, 'low');
    assert.ok(summary.json.timeline[0].certifiedAt);

    assert.equal(summary.json.nodes.length, 3);
    assert.deepEqual(summary.json.nodes.map((node) => node.chainLength), [2, 2, 2]);

    const topology = await s.req('GET', '/trust/topology');
    assert.equal(topology.json.coordinatorId, s.platform.coordinator.id);
    assert.equal(topology.json.proofs, 2);
    assert.deepEqual(topology.json.agents, [{ id: agent.identity.id }]);
    assert.deepEqual(topology.json.nodes.map((node) => [node.id, node.chainLength, node.intact, node.problems]), [
      ['verix-node-aws-1', 2, true, 0],
      ['verix-node-gcp-1', 2, true, 0],
      ['verix-node-edge-1', 2, true, 0],
    ]);
    assert.equal(topology.json.edges.length, 3);
    for (const edge of topology.json.edges) {
      assert.equal(edge.proofs, 2);
      assert.equal(edge.from, agent.identity.id);
      assert.deepEqual(edge.statuses, { trusted: 1, rejected: 1 });
      assert.equal(edge.lastScore, denied.json.trustScore);
      assert.equal(edge.lastSeq, 2);
      assert.equal(edge.cloud, topology.json.nodes.find((node) => node.id === edge.to).cloud);
    }
    const limited = await s.req('GET', '/trust/topology?limit=1');
    assert.equal(limited.json.proofs, 1);

    const summaryLimited = await s.req('GET', '/trust/summary?limit=1');
    assert.equal(summaryLimited.json.totals.proofs, 1);
  } finally {
    await s.close();
  }
});

test('the copilot answers over HTTP and reindexes on demand', async () => {
  const s = await serve();
  try {
    const missing = await s.req('POST', '/copilot/ask', { body: {} });
    assert.equal(missing.status, 400);
    assert.equal(code(missing), 'QUESTION_REQUIRED');
    const notText = await s.req('POST', '/copilot/ask', { body: { question: 42 } });
    assert.equal(notText.status, 400);
    assert.equal(code(notText), 'QUESTION_REQUIRED');

    const empty = await s.req('POST', '/copilot/ask', { body: { question: 'how many proofs are there?' } });
    assert.equal(empty.status, 200);
    assert.equal(empty.json.intent, 'status-summary');
    assert.equal(empty.json.intentConfidence, 0.9);
    assert.match(empty.json.answer, /Indexed proofs: 0/);
    assert.deepEqual(empty.json.evidence, []);
    assert.equal(empty.json.retrieved, 0);

    const agent = await s.platform.issueAgent({ name: 'API-Copilot', scopes: [{ action: 'read:*', resource: '*' }] });
    await s.req('POST', '/verify-action', { body: { identityId: agent.identity.id, keyPair: serializeKeyPair(agent.keyPair), action: 'read:logs', resource: 'svc:audit' } });
    await settled();

    // "read" and "logs" are indexed tokens of the read:logs action, so the lexical
    // score is positive by construction instead of by a hashing coincidence.
    const asked = await s.req('POST', '/copilot/ask', { body: { question: 'how many proofs cover read logs?' } });
    assert.equal(asked.json.mode, 'rag-only', 'no LLM is configured in this run');
    assert.equal(asked.json.intent, 'status-summary');
    assert.match(asked.json.answer, /Indexed proofs: 1\. Returned in this answer: 1\./);
    assert.equal(asked.json.retrieved, asked.json.evidence.length);
    assert.equal(asked.json.evidence.length, 1);
    assert.equal(asked.json.evidence[0].status, 'trusted');
    assert.equal(asked.json.evidence[0].score, 96.4);
    assert.ok(asked.json.evidence[0].relevance.lexical > 0, 'the hit is a lexical match, not a coincidental embedding');

    const reindexed = await s.req('POST', '/copilot/reindex');
    assert.equal(reindexed.status, 200);
    assert.equal(reindexed.json.documents, 1);
    assert.equal(reindexed.json.embeddingDimensions, 512);

    const gated = await serve({ adminToken: ADMIN });
    try {
      assert.equal((await gated.req('POST', '/copilot/reindex')).status, 401);
      assert.equal(code(await gated.req('POST', '/copilot/reindex')), 'ADMIN_TOKEN_REQUIRED');
      assert.equal((await gated.req('POST', '/copilot/reindex', { token: ADMIN })).status, 200);
    } finally {
      await gated.close();
    }
  } finally {
    await s.close();
  }
});

test('the event stream replays over HTTP and pushes over the socket', async () => {
  const s = await serve();
  try {
    const agent = await s.platform.issueAgent({ name: 'API-Socket', scopes: [{ action: 'read:*', resource: '*' }] });
    const topics = await s.req('GET', '/events?since=0');
    assert.deepEqual(topics.json.events.map((e) => e.topic), ['identity.registered', 'identity.registered']);
    assert.deepEqual(topics.json.events.map((e) => e.payload.kind), ['coordinator', 'agent']);
    assert.equal(topics.json.sequence, 2);
    const afterFirst = await s.req('GET', `/events?since=${topics.json.events[0].seq}`);
    assert.equal(afterFirst.json.events.length, 1);
    const filtered = await s.req('GET', '/events?since=0&topic=identity.registered');
    assert.equal(filtered.json.events.length, 2);
    const none = await s.req('GET', '/events?since=0&topic=action.verified');
    assert.deepEqual(none.json.events, []);

    const messages = await new Promise((resolve, reject) => {
      const socket = new WebSocket(`${s.origin.replace('http', 'ws')}/ws`);
      const collected = [];
      socket.on('message', (data) => {
        collected.push(JSON.parse(data.toString()));
        if (collected.length === 1) {
          s.req('POST', '/verify-action', { body: { identityId: agent.identity.id, keyPair: serializeKeyPair(agent.keyPair), action: 'read:logs', resource: 'svc:audit' } })
            .then(() => settled())
            .then(() => settled())
            .then(() => socket.close());
        }
      });
      socket.on('close', () => resolve(collected));
      socket.on('error', reject);
    });

    assert.equal(messages[0].topic, 'stream.hello');
    assert.equal(messages[0].seq, 0);
    assert.equal(messages[0].payload.coordinatorId, s.platform.coordinator.id);
    assert.equal(messages[0].payload.sequence, 2, 'the hello reports the watermark the replay starts from');
    assert.deepEqual(messages[0].payload.nodes, NODE_PLAN.map((n) => n.nodeId));
    assert.deepEqual(messages.slice(1).map((m) => m.topic), ['identity.registered', 'identity.registered', 'action.verified']);
    assert.deepEqual(messages.slice(1).map((m) => m.seq), [1, 2, 3]);
    assert.equal(messages.at(-1).payload.proofId.length, 64);
    assert.equal(messages.at(-1).payload.status, 'trusted');

    const live = await new Promise((resolve, reject) => {
      const socket = new WebSocket(`${s.origin.replace('http', 'ws')}/ws`);
      socket.on('message', (data) => {
        const event = JSON.parse(data.toString());
        if (event.topic === 'stream.hello') {
          s.platform.eventBus.publish('action.flagged', { proofId: 'f'.repeat(64), trustScore: 12 });
          return;
        }
        if (event.topic === 'action.flagged') {
          socket.close();
          resolve(event);
        }
      });
      socket.on('error', reject);
    });
    assert.equal(live.payload.trustScore, 12);
    assert.equal(live.seq, 4, 'the live push continues the sequence after the replayed events');
  } finally {
    await s.close();
  }
});

test('malformed and oversized requests are refused, and static files are served', async () => {
  const s = await serve();
  try {
    const badJson = await s.req('POST', '/verify-action', { raw: 'this is not json' });
    assert.equal(badJson.status, 400);
    assert.equal(code(badJson), 'INVALID_JSON');
    assert.equal(badJson.json.error.details, null);

    const empty = await s.req('POST', '/verify-action');
    assert.equal(empty.status, 400);
    assert.equal(code(empty), 'IDENTITY_REQUIRED', 'a bodyless POST is a validation error, not a crash');

    const oversized = await s.req('POST', '/copilot/ask', { raw: JSON.stringify({ question: 'x'.repeat(9 * 1024 * 1024) }) });
    assert.equal(oversized.status, 413);
    assert.equal(code(oversized), 'BODY_TOO_LARGE');
    assert.equal(oversized.json.error.message, 'request body exceeds 8388608 bytes');
    assert.equal(oversized.json.error.details, null);

    const notFound = await s.req('POST', '/nope', { body: {} });
    assert.equal(notFound.status, 404);
    assert.equal(code(notFound), 'ROUTE_NOT_FOUND');
    assert.equal(notFound.json.error.message, 'no route for POST /nope');

    const index = await s.req('GET', '/');
    assert.equal(index.status, 200);
    assert.equal(index.headers['content-type'], 'text/html; charset=utf-8');
    assert.equal(Number(index.headers['content-length']), statSync(PUBLIC_INDEX).size);
    assert.match(index.text, /<!DOCTYPE html>/i);
    assert.ok(index.text.includes('VERIX'), 'the dashboard is the product surface');

    const app = await s.req('GET', '/app.js');
    assert.equal(app.status, 200);
    assert.equal(app.headers['content-type'], 'text/javascript; charset=utf-8');
    const css = await s.req('GET', '/styles.css');
    assert.equal(css.status, 200);
    assert.equal(css.headers['content-type'], 'text/css; charset=utf-8');
    const component = await s.req('GET', '/components/topology.js');
    assert.equal(component.status, 200);
    assert.equal(component.headers['content-type'], 'text/javascript; charset=utf-8');

    for (const path of ['/../src/config.js', '/../../package.json', '/%2e%2e/%2e%2e/package.json', '/..%2f..%2fpackage.json']) {
      const response = await fetch(`${s.origin}${path}`);
      const body = await response.text();
      assert.ok(!body.includes('"name": "verix"'), `source must not leak through ${path}`);
      assert.ok(!body.includes('export function loadConfig'), `source must not leak through ${path}`);
      assert.ok([403, 404].includes(response.status), `${path} answered ${response.status}`);
    }

    const missing = await s.req('GET', '/does-not-exist');
    assert.equal(missing.status, 404);
    assert.equal(code(missing), 'NOT_FOUND');
    assert.match(missing.json.error.hint, /listed at \/health/);
    assert.equal((await s.req('GET', '/health')).json.ok, true, 'the server is still serving after all of that');
  } finally {
    await s.close();
  }
});

test('a second process joins the fleet and replicates proofs over HTTP', async () => {
  // A runs with the node token configured: an open peer surface would make the
  // gated assertions below vacuous, and B authenticates to A with the same token.
  const a = await serve({ nodeToken: NODE });
  let b = null;
  try {
    b = await serve({
      nodeToken: NODE,
      publicOrigin: 'http://127.0.0.1:4599',
      nodePlan: [
        { baseUrl: a.origin, nodeId: 'verix-node-aws-1' },
        { nodeId: 'verix-node-gcp-1', cloud: 'gcp', region: 'us-central1', backend: 'memory' },
        { nodeId: 'verix-node-edge-1', cloud: 'local', region: 'local', backend: 'memory' },
      ],
    });
    assert.deepEqual(b.platform.clients.map((client) => client.nodeId), ['verix-node-aws-1', 'verix-node-gcp-1', 'verix-node-edge-1']);
    assert.equal(b.platform.nodes.length, 2, 'only the two planned local nodes are owned by process B');
    assert.deepEqual(b.platform.nodes.map((node) => node.nodeId), ['verix-node-gcp-1', 'verix-node-edge-1']);

    const agent = await b.platform.issueAgent({ name: 'API-Fleet', scopes: [{ action: 'deploy:*', resource: 'infra:*' }] });
    const onA = await a.req('GET', `/identities/${agent.identity.id}`);
    assert.equal(onA.status, 200, 'process A received the identity over POST /identities');
    assert.equal(onA.json.identity.subject.name, 'API-Fleet');
    assert.equal(onA.json.copies, 3, 'process A wrote the identity to each of its own three nodes');
    assert.equal(onA.json.disagreement, 0);

    const unauthenticated = await fetch(`${a.origin}/nodes/accept`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    assert.equal(unauthenticated.status, 401, 'the replication endpoint is not open to the internet');
    assert.equal((await unauthenticated.json()).error.code, 'NODE_TOKEN_REQUIRED');

    // A peer that is allowed in but sends garbage is refused, not appended to.
    const badSubmission = await a.req('POST', '/nodes/accept', { token: NODE, body: {} });
    assert.equal(badSubmission.status, 400);
    assert.equal(code(badSubmission), 'SUBMISSION_INCOMPLETE');
    const badCertify = await a.req('POST', '/nodes/certify', { token: NODE, body: {} });
    assert.equal(badCertify.status, 400);
    assert.equal(code(badCertify), 'CERTIFY_INCOMPLETE');

    const response = await b.req('POST', '/verify-action', {
      body: { identityId: agent.identity.id, keyPair: serializeKeyPair(agent.keyPair), action: 'deploy:infra', resource: 'infra:prod-eu-1', context: { cloud: 'aws' } },
    });
    assert.equal(response.status, 200);
    assert.equal(response.json.status, 'trusted');
    assert.equal(response.json.checks.replication.agreeing, 3);
    assert.deepEqual(response.json.nodes.map((node) => node.cloud), ['aws', 'gcp', 'local']);
    assert.equal(response.json.persistence.complete, true, 'certify reached the remote node through POST /nodes/certify');
    await settled();

    const onALedger = await a.req('GET', '/ledger/records');
    assert.equal(onALedger.json.count, 1, 'process A holds the proof it witnessed');
    const [record] = onALedger.json.records;
    assert.equal(record.recordHash, response.json.proofId);
    assert.equal(record.seq, 1);
    assert.equal(record.action, 'deploy:infra');
    assert.equal(record.verification.nodeId, 'verix-node-aws-1');
    assert.equal(record.witnesses.length, 3);
    assert.deepEqual(record.witnesses.map((w) => w.nodeId), ['verix-node-aws-1', 'verix-node-gcp-1', 'verix-node-edge-1']);

    const copy = await a.req('GET', `/ledger/records/${response.json.proofId}`);
    assert.equal(copy.json.present, 1, 'only A owns this ledger');
    assert.equal(copy.json.assessment.valid, true, "A re-verifies B's coordinator assessment");
    assert.equal(copy.json.assessment.coordinatorId, b.platform.coordinator.id);

    const aEvents = await a.req('GET', '/events?since=0');
    const forwarded = aEvents.json.events.filter((event) => event.payload.originNodeId);
    assert.deepEqual(forwarded.map((event) => event.topic), ['identity.registered', 'action.verified']);
    assert.equal(forwarded.at(-1).payload.proofId, response.json.proofId);
    assert.equal(forwarded[0].payload.originNodeId, 'http://127.0.0.1:4599', 'the forwarder stamps the sender publicOrigin');

    // An event that arrives from a peer must not be forwarded straight back.
    const injected = await b.req('POST', '/events', { token: NODE, body: { source: 'http://127.0.0.1:9999', event: { topic: 'action.flagged', payload: { proofId: 'e'.repeat(64) } } } });
    assert.equal(injected.status, 200);
    await settled();
    const onAAfter = await a.req('GET', '/events?since=0');
    assert.equal(onAAfter.json.events.length, aEvents.json.events.length, 'the injected event did not bounce back to A');
    assert.ok(!onAAfter.text.includes('e'.repeat(64)), 'A never saw the event it did not send');

    const bStatus = await b.req('GET', '/status');
    assert.deepEqual(bStatus.json.eventForwarding, { peers: 1, delivered: 2, failed: 0, skippedEcho: 1 });
    assert.equal(bStatus.json.quorumRequired, 2);
    assert.equal(bStatus.json.indexedProofs, 1);
    assert.deepEqual(bStatus.json.nodes.map((node) => node.chainLength), [1, 1, 1]);

    const aStatus = await a.req('GET', '/status');
    assert.equal(aStatus.json.eventForwarding, null);
    assert.equal(aStatus.json.anchorHydration.identities, 0);
  } finally {
    await b?.close();
    await a.close();
  }
});

test('a divergent node is reported as divergent through the API', async () => {
  const s = await serve({ trustFloor: 30 });
  try {
    const agent = await s.platform.issueAgent({ name: 'API-Diverge', scopes: [{ action: 'deploy:*', resource: 'infra:*' }] });
    const response = await s.req('POST', '/verify-action', {
      body: { identityId: agent.identity.id, keyPair: serializeKeyPair(agent.keyPair), action: 'deploy:infra', resource: 'infra:prod-eu-1' },
    });
    assert.equal(response.status, 200, 'the honest fleet still trusts the first action');
    assert.equal(response.json.status, 'trusted');
    assert.equal(response.json.checks.consistency.distinctRoots, 1);

    const liar = s.platform.nodes.find((node) => node.nodeId === 'verix-node-edge-1');
    const entry = await liar.store.chain.get('verix-node-edge-1:1');
    await liar.store.chain.set('verix-node-edge-1:1', { ...entry, recordHash: 'f'.repeat(64) });

    const second = await s.req('POST', '/verify-action', {
      body: { identityId: agent.identity.id, keyPair: serializeKeyPair(agent.keyPair), action: 'deploy:infra', resource: 'infra:prod-eu-2' },
    });
    await settled();
    assert.equal(second.status, 201);
    assert.equal(second.json.status, 'flagged');
    assert.equal(second.json.checks.consistency.distinctRoots, 2);
    assert.equal(second.json.trustScore, 35);
    assert.equal(second.json.allowedMode, 'read-only');

    const cross = await s.req('GET', `/ledger/cross-check/${second.json.nodes[0].seq}`);
    assert.equal(cross.json.consistent, false);
    assert.equal(cross.json.distinctRoots, 2);
    assert.deepEqual(cross.json.divergent.map((node) => node.nodeId), ['verix-node-edge-1']);
    // The flag only inspects the elected majority bucket, so one liar among three
    // is reported through divergent/distinctRoots instead of here.
    assert.equal(cross.json.recordHashDivergence, false);

    const firstSeq = response.json.nodes[0].seq;
    const crossTampered = await s.req('GET', `/ledger/cross-check/${firstSeq}`);
    assert.equal(crossTampered.json.consistent, false);
    assert.equal(crossTampered.json.consensusRecordHash, response.json.proofId, 'the honest nodes still agree on the record the liar overwrote');
    assert.deepEqual(crossTampered.json.missingRecords, ['verix-node-edge-1'], 'the liar no longer holds the record its own chain commits to');
    assert.deepEqual(crossTampered.json.witnessVerificationFailed, ['verix-node-edge-1']);
    assert.deepEqual(crossTampered.json.divergent.map((node) => node.nodeId), ['verix-node-edge-1']);

    const audit = await s.req('POST', '/ledger/audit', { body: { nodeId: 'verix-node-edge-1' } });
    assert.equal(audit.json.intact, false);
    assert.ok(audit.json.problems.some((problem) => problem.code === 'ENTRY_HASH_MISMATCH'), JSON.stringify(audit.json.problems));
    const honest = await s.req('POST', '/ledger/audit', { body: { nodeId: 'verix-node-aws-1' } });
    assert.equal(honest.json.intact, true);

    const summary = await s.req('GET', '/trust/summary');
    assert.equal(summary.json.totals.byStatus.flagged, 1);
    assert.equal(summary.json.agents[0].flagged, 1);
    assert.ok(summary.json.timeline.some((row) => row.status === 'flagged'));
    assert.equal(s.platform.index.size, 2, 'both proofs stay queryable even while the fleet disagrees');
  } finally {
    await s.close();
  }
});

test('the coordinator identity is self-binding on the wire', async () => {
  const s = await serve();
  try {
    const identities = await s.req('GET', '/identities');
    const coordinator = identities.json.identities.find((identity) => identity.kind === 'coordinator');
    assert.equal(coordinator.subject.name, 'verix-coordinator');
    assert.deepEqual(coordinator.scopes, [{ action: '*', resource: '*', constraint: { role: 'coordinator' } }]);
    assert.equal(coordinator.parent, null);
    assert.equal(toB64u(s.platform.coordinatorKeyPair.publicKey), coordinator.publicKey);
    assert.equal(coordinator.expiresAt, new Date(new Date(coordinator.issuedAt).getTime() + 30 * 24 * 60 * 60 * 1000).toISOString());
  } finally {
    await s.close();
  }
});

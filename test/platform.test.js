import test from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../src/config.js';
import { createPlatform } from '../src/platform.js';
import { buildActionEnvelope, signActionEnvelope } from '../src/verification/action.js';
import { verifyAssessment, assessmentDigestOf } from '../src/verification/assessment.js';
import { ProofChain } from '../src/ledger/chain.js';
import { trustStatusFrom } from '../src/intelligence/anomaly.js';
import { generateSigningKeyPair } from '../src/crypto/pqc.js';

const NODE_PLAN = [
  { nodeId: 'verix-node-aws-1', cloud: 'aws', region: 'us-east-1', backend: 'memory' },
  { nodeId: 'verix-node-gcp-1', cloud: 'gcp', region: 'us-central1', backend: 'memory' },
  { nodeId: 'verix-node-edge-1', cloud: 'local', region: 'local', backend: 'memory' },
];

async function platform(overrides = {}) {
  return createPlatform({ config: loadConfig({}, { nodePlan: NODE_PLAN, backend: 'memory', crossCheck: false, ...overrides }) });
}

// The event bus delivers through queueMicrotask, so the index and subscribers see
// a proof one tick after verifyAction returns.
function settled() {
  return new Promise((resolve) => setImmediate(resolve));
}

test('a trusted action is attested by every node and certified by the coordinator', async () => {
  const p = await platform();
  try {
    const { identity, keyPair } = await p.issueAgent({ name: 'Trusted-1', scopes: ['deploy:infra'] });
    const result = await p.service.verifyAction({
      identityId: identity.id,
      keyPair,
      action: 'deploy:infra',
      resource: 'infra:prod-eu-1',
      context: { cloud: 'aws', region: 'us-east-1' },
    });
    await settled();

    assert.equal(result.status, 'trusted', result.reason);
    assert.equal(result.agentId, identity.id);
    assert.equal(result.proofId.length, 64);
    assert.equal(result.band, 'high-trust');
    assert.equal(result.allowedMode, 'full');
    assert.equal(result.meetsFloor, true);

    assert.equal(result.checks.actionSignature, true);
    assert.equal(result.checks.identitySelfBinding, true);
    assert.equal(result.checks.lineage.valid, true);
    assert.deepEqual(result.checks.replication, { reached: true, agreeing: 3, required: 2, total: 3, failures: [] });
    assert.deepEqual(result.checks.tamperEvidence, {
      attestationSignaturesValid: true,
      merkleProofValid: true,
      chainWindowIntact: true,
      assessmentSignatureValid: true,
    });
    assert.equal(result.checks.consistency.consistent, true);
    assert.equal(result.checks.consistency.distinctRoots, 1);
    assert.equal(result.checks.consistency.nodesReporting, 3);

    assert.deepEqual(result.nodes.map((node) => node.cloud).sort(), ['aws', 'gcp', 'local']);
    assert.ok(result.nodes.every((node) => node.localAuthorized === true), JSON.stringify(result.nodes));
    assert.equal(result.quorum.agreeingCount, 3);
    assert.equal(result.timestamp.witnessCount, 3);
    assert.equal(result.timestamp.quorumReached, true);
    assert.equal(result.timestamp.clockSkewExceeded, false);
    assert.equal(new Set(result.timestamp.witnessClouds).size, 3);
    assert.ok(Date.parse(result.timestamp.certifiedAt) > 0);
    assert.equal(ProofChain.checkInclusionProof(result.inclusionProof), true);

    assert.equal(result.assessment.coordinatorId, p.coordinator.id);
    assert.equal(result.assessment.selfVerified, true);
    assert.equal(result.persistence.complete, true);
    assert.equal(result.persistence.stored.length, 3);
    assert.deepEqual(result.failures, []);
    assert.equal(result.chainAudit.intact, true);
    assert.equal(result.postCertificationDivergence, false);

    const proof = await p.service.getProof(result.proofId);
    assert.equal(proof.present, 3, 'the certified proof is readable from all three nodes');
    assert.equal(proof.record.trust.status, 'trusted');
    assert.equal(proof.record.assessment.digest, assessmentDigestOf(proof.record));
    const reverified = await verifyAssessment({
      record: proof.record,
      resolve: async (id) => (await p.registry.get(id))?.identity ?? null,
      trustAnchors: p.trustAnchors,
    });
    assert.equal(reverified.valid, true, JSON.stringify(reverified.problems));

    for (const node of p.nodes) assert.equal((await p.service.auditNode(node.nodeId)).intact, true);

    const events = p.eventBus.replay({});
    const verified = events.filter((event) => event.topic === 'action.verified');
    assert.equal(verified.length, 1);
    assert.equal(verified[0].payload.proofId, result.proofId);
    assert.equal(verified[0].payload.status, 'trusted');
    assert.equal(events.filter((event) => event.topic === 'identity.registered').length, 2, 'the coordinator and the agent both registered');
    assert.equal(p.index.size, 1, 'the published proof is indexed for the copilot');
    assert.equal((await p.status()).indexedProofs, 1);
  } finally {
    await p.close();
  }
});

test('a fresh agent starts on the neutral prior, not at the ceiling', async () => {
  const p = await platform();
  try {
    const { identity, keyPair } = await p.issueAgent({ name: 'Trusted-2', scopes: ['read:logs'] });
    const first = await p.service.verifyAction({ identityId: identity.id, keyPair, action: 'read:logs', resource: 'logs:app' });
    const components = Object.fromEntries(first.scored.components.map((entry) => [entry.key, entry.achieved]));
    assert.deepEqual(components, { signature: 1, policy: 1, lineage: 0.8889, replication: 1, consistency: 1, behaviour: 0.8075 }, 'a delegated agent loses a little lineage credit for the one hop to the root');
    assert.equal(first.trustScore, 96.4, 'first-sighting is a low anomaly, so behaviour loses 5% of the prior');
    assert.equal(first.scored.components.find((entry) => entry.key === 'behaviour').detail, 'no prior history; reliability starts at the neutral prior');
    assert.deepEqual(first.anomalies.map((entry) => entry.code), ['IDENTITY_FIRST_SIGHTING']);
    assert.equal(first.status, 'trusted');

    const second = await p.service.verifyAction({ identityId: identity.id, keyPair, action: 'read:logs', resource: 'logs:app' });
    assert.equal(second.anomalies.length, 0, 'the same action twice is no longer novel');
    assert.equal(second.scored.components.find((entry) => entry.key === 'behaviour').detail, '1/1 prior actions verified (smoothed reliability 88.8%)');
    assert.equal(second.trustScore, 97.21);
    assert.deepEqual(second.nodes.map((node) => node.seq), [2, 2, 2], 'each node appended the second proof at sequence 2');
  } finally {
    await p.close();
  }
});

test('an action signed by someone else cannot be attributed and is quarantined', async () => {
  const p = await platform();
  try {
    const { identity } = await p.issueAgent({ name: 'Forged-1', scopes: ['deploy:infra'] });
    const attacker = await generateSigningKeyPair('ML-DSA-65', { seed: new Uint8Array(32).fill(7) });
    const result = await p.service.verifyAction({
      identityId: identity.id,
      keyPair: attacker,
      action: 'deploy:infra',
      resource: 'infra:prod-eu-1',
    });
    assert.equal(result.checks.actionSignature, false);
    assert.equal(result.status, 'rejected');
    assert.equal(result.trustScore, 15);
    assert.equal(result.scored.cappedAt, 15);
    assert.equal(result.band, 'quarantine');
    assert.equal(result.allowedMode, 'deny');
    assert.ok(result.nodes.every((node) => node.localAuthorized === false));
    assert.ok(result.nodes.every((node) => node.localProblems.some((problem) => problem.code === 'ACTION_SIGNATURE_INVALID')));
    const proof = await p.service.getProof(result.proofId);
    assert.equal(proof.record.trust.status, 'rejected');
    assert.equal(proof.record.trust.cappedAt, 15);
  } finally {
    await p.close();
  }
});

test('a denied scope keeps its cryptographic credit but loses the authorization verdict', async () => {
  const p = await platform();
  try {
    const { identity, keyPair } = await p.issueAgent({ name: 'Scopeless-1', scopes: ['read:logs'] });
    const result = await p.service.verifyAction({ identityId: identity.id, keyPair, action: 'deploy:infra', resource: 'infra:prod-eu-1' });
    assert.equal(result.status, 'rejected');
    assert.equal(result.reason, 'policy authorization failed');
    assert.equal(result.policy.authorized, false);
    assert.deepEqual(result.policy.blockingReasons.map((entry) => entry.code), ['NO_SCOPE_MATCH']);
    assert.equal(result.scored.cappedAt, null, 'the proof is authentic; only the verdict says no');
    assert.equal(result.checks.actionSignature, true);
    assert.equal(result.allowedMode, 'deny');
    assert.ok(result.scored.signals.includes('deny:NO_SCOPE_MATCH'));
    assert.equal(result.trustScore, 76.4);
    assert.equal(result.persistence.complete, true, 'a refused action is still evidence worth replicating');
  } finally {
    await p.close();
  }
});

test('a revoked agent is refused by the coordinator and by every witness node', async () => {
  const p = await platform();
  try {
    const { identity, keyPair } = await p.issueAgent({ name: 'Revoked-1', scopes: ['transfer:funds'] });
    const before = await p.service.verifyAction({ identityId: identity.id, keyPair, action: 'transfer:funds', resource: 'funds:acct-1' });
    assert.equal(before.status, 'trusted');
    assert.equal(before.checks.revocation.revoked, false);

    const entry = await p.registry.revoke({ keyPair: p.coordinatorKeyPair, identityId: identity.id, reason: 'key material leaked' });
    await settled();
    assert.equal(entry.revokedBy, p.coordinator.id, 'the issuer that signed the identity is the revocation authority');

    const after = await p.service.verifyAction({ identityId: identity.id, keyPair, action: 'transfer:funds', resource: 'funds:acct-1' });
    assert.equal(after.checks.revocation.revoked, true);
    assert.equal(after.checks.revocation.revokedBy, p.coordinator.id);
    assert.equal(after.checks.revocation.forgedEntries, 0);
    assert.equal(after.checks.revocation.nodesReporting, 3);
    assert.ok(after.policy.blockingReasons.some((reason) => reason.code === 'IDENTITY_REVOKED'), JSON.stringify(after.policy.reasons));
    assert.equal(after.status, 'rejected');
    assert.equal(after.allowedMode, 'deny');
    for (const node of after.nodes) {
      assert.equal(node.localAuthorized, false, `${node.nodeId} accepted a revoked agent`);
      assert.ok(node.localProblems.some((problem) => problem.code === 'IDENTITY_REVOKED'), JSON.stringify(node.localProblems));
    }
    assert.ok(p.eventBus.replay({ topic: 'identity.revoked' }).some((event) => event.payload.identityId === identity.id));
  } finally {
    await p.close();
  }
});

test('an expired identity is refused before it can earn a proof', async () => {
  const p = await platform();
  try {
    const { identity, keyPair } = await p.issueAgent({ name: 'Expired-1', scopes: ['read:logs'], ttlSeconds: -60 });
    const result = await p.service.verifyAction({ identityId: identity.id, keyPair, action: 'read:logs', resource: 'logs:app' });
    assert.equal(result.status, 'rejected');
    assert.deepEqual(result.policy.blockingReasons.map((entry) => entry.code), ['IDENTITY_EXPIRED']);
    assert.ok(result.nodes.every((node) => node.localProblems.some((problem) => problem.code === 'IDENTITY_EXPIRED')));
    assert.equal(result.checks.actionSignature, true, 'the signature is valid; the identity is simply out of date');
  } finally {
    await p.close();
  }
});

test('scope constraints are enforced through the full pipeline', async () => {
  const p = await platform();
  try {
    const { identity, keyPair } = await p.issueAgent({
      name: 'Bounded-1',
      scopes: [{ action: 'transfer:funds', resource: 'funds:*', constraint: { maxCostUsd: 10, allowedRegions: ['us-east-*'], allowDestructive: false } }],
    });
    const over = await p.service.verifyAction({ identityId: identity.id, keyPair, action: 'transfer:funds', resource: 'funds:acct-1', context: { costUsd: 50, region: 'us-east-1' } });
    assert.equal(over.status, 'rejected');
    assert.deepEqual(over.policy.blockingReasons.map((entry) => entry.code), ['COST_CEILING_EXCEEDED']);

    const elsewhere = await p.service.verifyAction({ identityId: identity.id, keyPair, action: 'transfer:funds', resource: 'funds:acct-1', context: { costUsd: 1, region: 'eu-west-1' } });
    assert.deepEqual(elsewhere.policy.blockingReasons.map((entry) => entry.code), ['REGION_NOT_ALLOWED']);

    const allowed = await p.service.verifyAction({ identityId: identity.id, keyPair, action: 'transfer:funds', resource: 'funds:acct-1', context: { costUsd: 1, region: 'us-east-2' } });
    assert.equal(allowed.status, 'trusted');
    assert.deepEqual(allowed.policy.reasons.map((entry) => entry.code), ['SCOPE_MATCHED']);
  } finally {
    await p.close();
  }
});

test('repeated behaviour is detected from the ledger history', async () => {
  const p = await platform();
  try {
    const { identity, keyPair } = await p.issueAgent({ name: 'Busy-1', scopes: ['*'] });
    const history = [
      ['read:logs', 'logs:app'],
      ['read:metrics', 'logs:metrics'],
      ['read:config', 'logs:config'],
      ['write:cache', 'logs:cache'],
      ['read:logs', 'logs:audit'],
      ['write:state', 'logs:state'],
      ['deploy:staging', 'infra:core'],
    ];
    const results = [];
    for (const [action, resource] of history) {
      results.push(await p.service.verifyAction({ identityId: identity.id, keyPair, action, resource }));
    }
    const first = results[0];
    assert.deepEqual(first.anomalies.map((entry) => entry.code), ['IDENTITY_FIRST_SIGHTING']);
    const novel = results[results.length - 1];
    const codes = novel.anomalies.map((entry) => entry.code);
    assert.ok(codes.includes('NOVEL_ACTION'), JSON.stringify(codes));
    assert.ok(codes.includes('NOVEL_RESOURCE_ROOT'), JSON.stringify(codes));
    assert.ok(codes.includes('ACTION_RATE_BURST'), JSON.stringify(codes));
    assert.equal(novel.status, 'trusted', 'novelty is an advisory signal, not a rejection');
    assert.ok(novel.trustScore < first.trustScore);
    assert.equal(novel.scored.signals.filter((signal) => signal.startsWith('medium:')).length, 3, JSON.stringify(novel.scored.signals));
    assert.equal(await p.service.historyFor(identity.id).then((h) => h.attempts), 7);
  } finally {
    await p.close();
  }
});

test('a node whose chain was rewritten while the platform was running is flagged, not trusted', async () => {
  const p = await platform({ trustFloor: 30 });
  try {
    const { identity, keyPair } = await p.issueAgent({ name: 'Diverge-1', scopes: ['deploy:infra'] });
    const clean = await p.service.verifyAction({ identityId: identity.id, keyPair, action: 'deploy:infra', resource: 'infra:prod-eu-1' });
    assert.equal(clean.status, 'trusted');

    const liar = p.nodes.find((node) => node.nodeId === 'verix-node-edge-1');
    const entry = await liar.store.getChainEntry(liar.nodeId, 1);
    assert.ok(entry, 'the first action is on the liar chain');
    liar.store.chain.set('verix-node-edge-1:1', { ...entry, recordHash: 'f'.repeat(64) });

    const next = await p.service.verifyAction({ identityId: identity.id, keyPair, action: 'deploy:infra', resource: 'infra:prod-eu-2' });
    assert.equal(next.status, 'flagged', next.reason);
    assert.equal(next.scored.floorWouldDeny, false, 'the floor was lowered on purpose so divergence decides');
    assert.equal(trustStatusFrom({ score: next.trustScore, band: next.band, anomalies: next.anomalies, authorized: true, quorumReached: true, floorDeny: true }).status, 'rejected', 'under the shipped default floor the same divergence is rejected outright');
    assert.equal(next.divergence.consistent, false);
    assert.equal(next.divergence.distinctRoots, 2);
    assert.deepEqual(next.divergence.divergent.map((node) => node.nodeId), ['verix-node-edge-1']);
    assert.equal(next.scored.cappedAt, 35);
    assert.equal(next.trustScore, 35);
    assert.equal(next.band, 'restricted');
    assert.equal(next.allowedMode, 'read-only');
    assert.ok(next.anomalies.some((anomaly) => anomaly.code === 'REPLICATION_DIVERGENCE'), JSON.stringify(next.anomalies));
    assert.ok(next.scored.signals.includes('critical:cross-cloud-divergence'));
    assert.equal(next.postCertificationDivergence, true);

    const audited = await p.service.auditNode('verix-node-edge-1');
    assert.equal(audited.intact, false);
    assert.ok(audited.problems.some((problem) => problem.code === 'ENTRY_HASH_MISMATCH'), JSON.stringify(audited.problems));
    assert.equal((await p.service.auditNode('verix-node-aws-1')).intact, true);

    const stored = await p.service.getProof(next.proofId);
    assert.equal(stored.record.trust.status, 'flagged');
  } finally {
    await p.close();
  }
});

test('without a quorum the proof is unattested and never certified', async () => {
  const p = await platform();
  try {
    const { identity, keyPair } = await p.issueAgent({ name: 'Lonely-1', scopes: ['read:logs'] });
    const dead = (nodeId) => {
      const reject = () => Promise.reject(new Error(`${nodeId} is unreachable`));
      return {
        nodeId,
        cloud: 'unknown',
        accept: reject,
        certify: reject,
        head: reject,
        status: reject,
        descriptor: reject,
        inclusionProof: reject,
        getRecord: reject,
        listRecords: reject,
        getIdentity: reject,
        listIdentities: reject,
        putIdentity: reject,
        listRevocations: reject,
        putRevocation: reject,
        audit: reject,
      };
    };
    p.group.clients[1] = dead('verix-node-gcp-1');
    p.group.clients[2] = dead('verix-node-edge-1');

    const result = await p.service.verifyAction({ identityId: identity.id, keyPair, action: 'read:logs', resource: 'logs:app' });
    assert.equal(result.status, 'unattested');
    assert.match(result.reason, /not independently attested/);
    assert.equal(result.quorum.reached, false);
    assert.equal(result.quorum.agreeingCount, 1);
    assert.equal(result.scored.cappedAt, 40);
    assert.equal(result.trustScore, 40);
    assert.equal(result.allowedMode, 'read-only');
    assert.equal(result.assessment, null, 'the coordinator will not sign an assessment over a proof nobody replicated');
    assert.deepEqual(result.persistence, { stored: [], failures: [{ nodeId: 'coordinator', error: 'quorum not reached; refusing to certify' }], complete: false });
    assert.equal(result.failures.length, 2);
    const stored = await p.service.getProof(result.proofId);
    assert.equal(stored.present, 1, 'only the surviving node holds the record');
    assert.deepEqual(stored.replication.map((entry) => entry.present), [true, false, false]);
    assert.equal(stored.replication[1].error, 'verix-node-gcp-1 is unreachable');
    await settled();
    assert.ok(p.eventBus.replay({ topic: 'action.flagged' }).some((event) => event.payload.proofId === result.proofId));
    assert.equal(p.index.size, 1);
  } finally {
    await p.close();
  }
});

test('cross-implementation verification is used end to end when configured', async () => {
  const p = await platform({ crossCheck: true });
  try {
    const { identity, keyPair } = await p.issueAgent({ name: 'Cross-1', scopes: ['read:logs'] });
    const result = await p.service.verifyAction({ identityId: identity.id, keyPair, action: 'read:logs', resource: 'logs:app' });
    assert.equal(result.status, 'trusted');
    assert.equal(result.checks.tamperEvidence.chainWindowIntact, true);
    assert.equal(result.checks.tamperEvidence.assessmentSignatureValid, true);
    const audit = await p.service.auditNode('verix-node-aws-1');
    assert.equal(audit.intact, true);
    assert.equal(audit.assessments.verified, 1);
    assert.equal(audit.assessments.invalid, 0);
  } finally {
    await p.close();
  }
});

test('the platform refuses to verify against an identity it cannot bind to the request', async () => {
  const p = await platform();
  try {
    const { identity, keyPair } = await p.issueAgent({ name: 'Mismatch-1', scopes: ['read:logs'] });
    const other = await p.issueAgent({ name: 'Mismatch-2', scopes: ['read:logs'] });
    const envelope = buildActionEnvelope({ agentId: other.identity.id, action: 'read:logs', resource: 'logs:app' });
    const signatureDoc = await signActionEnvelope(other.keyPair, envelope);
    await assert.rejects(
      () => p.service.verifyAction({ identityId: identity.id, envelope, signatureDoc }),
      /envelope agentId does not match the identity/,
    );
    await assert.rejects(() => p.service.verifyAction({ identityId: 'verix:agent:notregistered', keyPair, action: 'read:logs', resource: 'logs:app' }), /is not registered/);
    await assert.rejects(() => p.service.verifyAction({ identityId: identity.id, action: 'read:logs', resource: 'logs:app' }), /requires keyPair, signatureDoc, or a pre-built envelope signature/);
    assert.equal(p.index.size, 0, 'a refused submission never reaches the ledger');
  } finally {
    await p.close();
  }
});

test('status reports the fleet, the anchors and the event plane', async () => {
  const p = await platform();
  try {
    const status = await p.status();
    assert.equal(status.coordinatorId, p.coordinator.id);
    assert.equal(status.quorumRequired, 2);
    assert.deepEqual(status.trustAnchors, [p.coordinator.id]);
    assert.equal(status.nodes.length, 3);
    for (const node of status.nodes) {
      assert.equal(node.chainLength, 0, 'a fresh fleet has an empty chain');
      assert.equal(node.head.seq, 0);
      assert.equal(node.recentWindowIntact, true);
      assert.ok(node.publicKey.length > 1000, 'the node publishes its signing key');
    }
    assert.deepEqual(status.nodes.map((node) => node.cloud).sort(), ['aws', 'gcp', 'local']);
    assert.equal(status.eventForwarding, null, 'a single-process fleet has no peers to forward to');
    assert.equal(status.indexedProofs, 0);
    assert.equal(status.eventSequence, 1, 'booting publishes the coordinator registration');
    assert.deepEqual(status.nodes.map((node) => node.identities), [1, 1, 1]);
  } finally {
    await p.close();
  }
});

test('reindex rebuilds the copilot view from the ledger', async () => {
  const p = await platform();
  try {
    const { identity, keyPair } = await p.issueAgent({ name: 'Indexed-1', scopes: ['read:logs'] });
    for (const resource of ['logs:a', 'logs:b', 'logs:c']) {
      await p.service.verifyAction({ identityId: identity.id, keyPair, action: 'read:logs', resource });
    }
    await settled();
    assert.equal(p.index.size, 3);
    const rebuilt = await p.reindex();
    assert.equal(rebuilt.documents, 3);
    assert.equal(rebuilt.embeddingDimensions > 0, true);
    assert.equal(p.index.size, 3);
    const answer = await p.copilot.ask('how many proofs are recorded for Indexed-1?');
    assert.equal(answer.mode, 'rag-only');
    assert.match(answer.answer, /Indexed proofs: 3/);
  } finally {
    await p.close();
  }
});

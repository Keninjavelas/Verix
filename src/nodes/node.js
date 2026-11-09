import { MemoryStore } from './memory-store.js';
import { ProofChain, recordHashOf } from '../ledger/chain.js';
import { createWitness, verifyWitness } from '../ledger/timestamp.js';
import { fromB64u, fromHex, toB64u } from '../crypto/hash.js';
import { DEFAULT_KEM_ALG, DEFAULT_SIGNING_ALG, deserializeKemKeyPair, deserializeKeyPair, generateSigningKeyPair, kemGenerate, serializeKemKeyPair, serializeKeyPair, verify } from '../crypto/pqc.js';
import { assertRevocationAuthority, verifyIdentitySelfBinding, verifyRevocation } from '../crypto/identity.js';
import { verifyIdentityLineage } from '../policy/engine.js';
import { verifyAssessment } from '../verification/assessment.js';

export class VerixNode {
  constructor({ nodeId, cloud, region = null, store, keyPair, kemKeyPair = null, trustAnchors = new Map(), crossCheck = false }) {
    if (!nodeId || !cloud) throw new Error('VerixNode requires nodeId and cloud');
    this.nodeId = nodeId;
    this.cloud = cloud;
    this.region = region;
    this.store = store ?? new MemoryStore({ name: nodeId });
    this.keyPair = keyPair;
    this.kemKeyPair = kemKeyPair;
    this.trustAnchors = trustAnchors;
    this.chain = new ProofChain({ nodeId, store: this.store, keyPair, crossCheck, trustAnchors });
  }

  static async create({ nodeId, cloud, region, seed, store, trustAnchors, crossCheck, kemSeed }) {
    const keyPair = await nodeSigningKey({ store, nodeId, seed });
    const kemKeyPair = await nodeKemKey({ store, nodeId, seed: kemSeed });
    return new VerixNode({ nodeId, cloud, region, store, keyPair, kemKeyPair, trustAnchors, crossCheck });
  }

  descriptor() {
    return {
      nodeId: this.nodeId,
      cloud: this.cloud,
      region: this.region,
      publicKey: this.keyPair ? toB64u(this.keyPair.publicKey) : null,
      kemPublicKey: this.kemKeyPair?.publicKey ? toB64u(this.kemKeyPair.publicKey) : null,
      trustAnchorIds: [...this.trustAnchors.keys()],
    };
  }

  async localVerify(submission) {
    const problems = [];
    const { actionProof, identity } = submission;
    if (!identity) return { ok: false, problems: [{ code: 'IDENTITY_ABSENT', detail: 'submission carries no identity document' }] };
    if (!(await verifyIdentitySelfBinding(identity))) {
      problems.push({ code: 'IDENTITY_SELF_BINDING_INVALID', detail: `${identity.id} does not bind its recorded public key` });
    }
    const lineage = await verifyIdentityLineage({ identity, resolve: async (id) => this.store.getIdentity(id), trustAnchors: this.trustAnchors });
    for (const issue of lineage.reasons.filter((r) => r.severity === 'deny')) {
      problems.push({ code: issue.code, detail: issue.detail });
    }
    const agentPublicKey = fromB64u(identity.publicKey);
    const signedBytes = fromHex(actionProof.digest);
    if (!(await verify(actionProof.alg ?? identity.alg, agentPublicKey, signedBytes, fromB64u(actionProof.signature)))) {
      problems.push({ code: 'ACTION_SIGNATURE_INVALID', detail: `action signature does not verify under ${identity.id}` });
    }
    const recomputed = recordHashOf(actionProof.record);
    if (recomputed !== actionProof.recordHash) {
      problems.push({ code: 'RECORD_HASH_MISMATCH', detail: `record hash ${recomputed.slice(0, 12)} does not match claimed ${actionProof.recordHash.slice(0, 12)}` });
    }
    if (identity.expiresAt && Date.parse(identity.expiresAt) <= Date.now()) {
      problems.push({ code: 'IDENTITY_EXPIRED', detail: `${identity.id} expired at ${identity.expiresAt}` });
    }
    for (const entry of await this.store.listRevocations(identity.id)) {
      if (!(await verifyRevocation(entry))) {
        problems.push({ code: 'REVOCATION_FORGERY', detail: `revocation ${String(entry.revocationId).slice(0, 12)} recorded for ${identity.id} does not carry a valid signature` });
        continue;
      }
      const authority = assertRevocationAuthority(entry, identity);
      if (!authority.ok) {
        problems.push({ code: 'REVOCATION_FORGERY', detail: `revocation ${String(entry.revocationId).slice(0, 12)} for ${identity.id} is unsigned by an authority: ${authority.reason}` });
        continue;
      }
      problems.push({ code: 'IDENTITY_REVOKED', detail: `${identity.id} revoked at ${entry.revokedAt} by ${entry.revokedBy}: ${entry.reason}` });
    }
    return { ok: problems.length === 0, problems, agentPublicKey, lineage: { path: lineage.lineage, depth: lineage.depth } };
  }

  async accept(submission) {
    const verdict = await this.localVerify(submission);
    const record = { ...submission.actionProof.record, agentId: submission.identity.id, recordHash: submission.actionProof.recordHash, verification: { authorized: verdict.ok, problems: verdict.problems, nodeId: this.nodeId } };
    const { entry } = await this.chain.append(record);
    const witness = await createWitness({
      keyPair: this.keyPair,
      node: this,
      recordHash: record.recordHash,
      entryHash: entry.entryHash,
      seq: entry.seq,
      observedAt: new Date().toISOString(),
    });
    return { nodeId: this.nodeId, cloud: this.cloud, entry, record, witness, verdict };
  }

  async certify({ record, witnesses, timestamp, inclusionProof }) {
    const checked = [];
    for (const witness of witnesses) {
      if (!(await verifyWitness(witness))) throw new Error(`witness from ${witness.nodeId} failed signature verification`);
      checked.push(witness);
    }
    const existing = await this.store.getRecord(record.recordHash);
    const certified = { ...(existing ?? {}), ...record, witnesses: checked, timestamp, inclusionProof };
    const assessment = await verifyAssessment({
      record: certified,
      resolve: async (id) => this.store.getIdentity(id),
      trustAnchors: this.trustAnchors,
      crossCheck: this.chain.crossCheck,
    });
    if (!assessment.valid) {
      throw new Error(`refusing to certify ${String(record.recordHash).slice(0, 12)}: ${assessment.problems.map((problem) => `${problem.code} (${problem.detail})`).join('; ')}`);
    }
    await this.store.putRecord(certified);
    return certified;
  }

  async head() {
    return this.chain.head();
  }

  async status() {
    const head = await this.chain.head();
    const audit = await this.chain.audit({ from: Math.max(1, head.seq - 49) });
    return {
      ...this.descriptor(),
      head,
      chainLength: head.seq,
      recentWindowIntact: audit.intact,
      recentProblems: audit.problems,
      records: await this.store.countRecords(),
      identities: (await this.store.listIdentities()).length,
      revocations: (await this.store.listRevocations()).length,
    };
  }

  async getRecord(recordHash) {
    return this.store.getRecord(recordHash);
  }

  async listRecords(filter) {
    return this.store.listRecords(filter);
  }

  async inclusionProof(seq) {
    return this.chain.inclusionProof(seq);
  }

  async audit(range) {
    return this.chain.audit(range);
  }

  async putIdentity(identity) {
    const existing = await this.store.getIdentity(identity.id);
    if (existing && existing.publicKey !== identity.publicKey) {
      throw new Error(`refusing to rebind ${identity.id} from key ${String(existing.publicKey).slice(0, 12)}… to ${String(identity.publicKey).slice(0, 12)}…`);
    }
    await this.store.putIdentity(identity);
    if (!identity.parent) {
      const anchored = this.trustAnchors.get(identity.id);
      if (anchored && anchored !== identity.publicKey) {
        throw new Error(`refusing to re-anchor trust root ${identity.id} under a different public key`);
      }
      this.trustAnchors.set(identity.id, identity.publicKey);
    }
  }

  async getIdentity(id) {
    return this.store.getIdentity(id);
  }

  async listIdentities(filter = {}) {
    return this.store.listIdentities(filter);
  }

  async listRevocations(agentId = null) {
    return this.store.listRevocations(agentId);
  }

  async putRevocation(entry) {
    await this.store.putRevocation(entry);
  }
}

const NODE_SIGNING_KEY_META = 'node-signing-key';
const NODE_KEM_KEY_META = 'node-kem-key';

// A node's signing key is the identity its chain signatures bind to, so it is
// written beside the ledger: a restart that regenerated it would leave every
// entry the node already appended unverifiable. When key material is also
// configured the derived key must agree with the stored one, or the operator is
// pointing at a ledger created under different material.
async function nodeSigningKey({ store, nodeId, seed }) {
  if (!store?.getMeta || !store?.putMeta) return generateSigningKeyPair(DEFAULT_SIGNING_ALG, seed ? { seed } : {});
  const persisted = await store.getMeta(NODE_SIGNING_KEY_META);
  if (persisted?.alg) {
    const restored = deserializeKeyPair(persisted);
    if (seed !== undefined) {
      const derived = await generateSigningKeyPair(persisted.alg, { seed });
      if (toB64u(derived.publicKey) !== toB64u(restored.publicKey)) {
        throw new Error(`node ${nodeId}: VERIX_NODE_KEY_MATERIAL derives ${toB64u(derived.publicKey).slice(0, 12)}… but this ledger was signed under ${toB64u(restored.publicKey).slice(0, 12)}…; boot with the material the ledger was created with, or start a new data directory`);
      }
    }
    return restored;
  }
  const generated = await generateSigningKeyPair(DEFAULT_SIGNING_ALG, seed ? { seed } : {});
  await store.putMeta(NODE_SIGNING_KEY_META, serializeKeyPair(generated));
  return generated;
}

async function nodeKemKey({ store, nodeId, seed }) {
  if (!store?.getMeta || !store?.putMeta) return kemGenerate(DEFAULT_KEM_ALG, seed ? { seed } : {});
  const persisted = await store.getMeta(NODE_KEM_KEY_META);
  if (persisted?.alg) {
    const restored = deserializeKemKeyPair(persisted);
    if (seed !== undefined) {
      const derived = await kemGenerate(persisted.alg, { seed });
      if (toB64u(derived.publicKey) !== toB64u(restored.publicKey)) {
        throw new Error(`node ${nodeId}: the KEM key derived from VERIX_NODE_KEY_MATERIAL is not the key this store was sealed under`);
      }
    }
    return restored;
  }
  const generated = await kemGenerate(DEFAULT_KEM_ALG, seed ? { seed } : {});
  await store.putMeta(NODE_KEM_KEY_META, serializeKemKeyPair(generated));
  return generated;
}

import { quorumStatus, verifyWitness } from '../ledger/timestamp.js';
import { open, seal } from '../crypto/pqc.js';
import { verifyAssessment } from '../verification/assessment.js';
import { ProofChain, recordHashOf } from '../ledger/chain.js';
import { fromB64u } from '../crypto/hash.js';

export class ReplicationGroup {
  constructor({ clients, required = null, name = 'verix-replication' }) {
    if (!Array.isArray(clients) || clients.length === 0) throw new Error('ReplicationGroup requires at least one node client');
    this.clients = clients;
    this.required = required ?? Math.floor(clients.length / 2) + 1;
    this.name = name;
  }

  get size() {
    return this.clients.length;
  }

  async fanOut(submission) {
    const settled = await Promise.allSettled(this.clients.map((client) => client.accept(submission)));
    const accepted = [];
    const failures = [];
    settled.forEach((outcome, index) => {
      const target = this.clients[index];
      if (outcome.status === 'fulfilled') {
        accepted.push({ client: target, ...outcome.value });
      } else {
        failures.push({ nodeId: target.nodeId ?? `client-${index}`, cloud: target.node?.cloud ?? 'unknown', error: String(outcome.reason?.message ?? outcome.reason) });
      }
    });
    const witnesses = accepted.map((entry) => entry.witness);
    const quorum = quorumStatus(witnesses, {
      required: this.required,
      expectedRecordHash: submission.actionProof.recordHash,
    });
    return { accepted, failures, witnesses, quorum, reached: quorum.reached };
  }

  async certifyAll({ record, witnesses, timestamp, inclusionProof }) {
    const results = await Promise.allSettled(this.clients.map((client) => client.certify({ record, witnesses, timestamp, inclusionProof })));
    const stored = [];
    const failures = [];
    results.forEach((outcome, index) => {
      if (outcome.status === 'fulfilled') stored.push({ nodeId: this.clients[index].nodeId ?? `client-${index}`, record: outcome.value });
      else failures.push({ nodeId: this.clients[index].nodeId ?? `client-${index}`, error: String(outcome.reason?.message ?? outcome.reason) });
    });
    return { stored, failures, complete: failures.length === 0 };
  }

  async crossCloudCheck(seq, { witnesses = null } = {}) {
    const gathered = await Promise.allSettled(this.clients.map(async (client) => {
      const proof = await client.inclusionProof(seq);
      const selfVerified = ProofChain.checkInclusionProof(proof);
      const record = await client.getRecord(proof.recordHash);
      const witnessSet = witnesses ?? record?.witnesses ?? [];
      const witnessResults = await Promise.all(witnessSet.map((witness) => verifyWitness(witness)));
      return {
        nodeId: proof.nodeId,
        root: proof.root,
        recordHash: proof.recordHash,
        treeSize: proof.treeSize,
        selfVerified,
        recordPresent: Boolean(record),
        recordMatchesCommitment: Boolean(record) && recordHashOf(record) === proof.recordHash,
        witnessCount: witnessSet.length,
        validWitnessCount: witnessResults.filter(Boolean).length,
        witnessesValid: witnessResults.length > 0 && witnessResults.every(Boolean),
        witnessSource: witnesses ? 'live' : 'stored',
        assessment: record?.assessment ? {
          coordinatorId: record.assessment.coordinatorId,
          valid: (await verifyAssessment({
            record,
            resolve: async (id) => {
              try {
                return await client.getIdentity(id);
              } catch {
                return null;
              }
            },
            trustAnchors: client.trustAnchors ?? null,
          })).valid,
        } : null,
      };
    }));
    const perNode = [];
    const failures = [];
    gathered.forEach((outcome, index) => {
      if (outcome.status === 'fulfilled') perNode.push(outcome.value);
      else failures.push({ client: this.clients[index].nodeId ?? `client-${index}`, error: String(outcome.reason?.message ?? outcome.reason) });
    });
    const byRoot = new Map();
    for (const node of perNode) {
      const bucket = byRoot.get(node.root) ?? [];
      bucket.push(node);
      byRoot.set(node.root, bucket);
    }
    const elected = [...byRoot.entries()].sort((a, b) => b[1].length - a[1].length)[0] ?? null;
    const majority = elected ? elected[1] : [];
    const divergent = [...byRoot.entries()].filter(([root]) => root !== elected?.[0]).flatMap(([, list]) => list);
    const recordHashDivergence = new Set(majority.map((n) => n.recordHash)).size > 1;
    return {
      seq,
      consistent: failures.length === 0
        && byRoot.size === 1
        && !recordHashDivergence
        && perNode.length >= this.required
        && perNode.every((n) => n.selfVerified && n.recordPresent && n.recordMatchesCommitment && n.witnessesValid && n.assessment?.valid !== false),
      nodesReporting: perNode.length,
      nodesRequired: this.required,
      distinctRoots: byRoot.size,
      electedRoot: elected?.[0] ?? null,
      consensusRecordHash: majority[0]?.recordHash ?? null,
      recordHashDivergence,
      selfVerificationFailed: perNode.filter((n) => !n.selfVerified).map((n) => n.nodeId),
      witnessVerificationFailed: perNode.filter((n) => !n.witnessesValid).map((n) => n.nodeId),
      missingRecords: perNode.filter((n) => !n.recordPresent).map((n) => n.nodeId),
      tamperedRecords: perNode.filter((n) => n.recordPresent && !n.recordMatchesCommitment).map((n) => n.nodeId),
      assessmentsInvalid: perNode.filter((n) => n.assessment && n.assessment.valid === false).map((n) => n.nodeId),
      perNode,
      divergent,
      failures,
    };
  }

  async sealCopies(record, kemPublicKeys = []) {
    const sealed = [];
    for (const [index, entry] of kemPublicKeys.entries()) {
      const envelope = await seal(fromB64u(entry.publicKey ?? entry), JSON.stringify(record), { aad: record.recordHash });
      sealed.push({ nodeId: entry.nodeId ?? `peer-${index}`, envelope });
    }
    return sealed;
  }

  static async openCopy(envelope, kemSecretKey) {
    return JSON.parse(Buffer.from(await open(envelope, kemSecretKey)).toString('utf8'));
  }
}

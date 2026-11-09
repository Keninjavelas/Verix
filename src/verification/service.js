import { buildActionEnvelope, buildProofRecord, signActionEnvelope, submissionFor, verifyActionSignature } from './action.js';
import { evaluateAuthorization, verifyIdentityLineage } from '../policy/engine.js';
import { computeTrustScore, applyTrustFloor } from '../intelligence/scoring.js';
import { detectAnomalies, trustStatusFrom } from '../intelligence/anomaly.js';
import { timestampRecord, verifyWitness } from '../ledger/timestamp.js';
import { ProofChain, recordHashOf } from '../ledger/chain.js';
import { fromB64u } from '../crypto/hash.js';
import { verifyIdentitySelfBinding } from '../crypto/identity.js';
import { signAssessment, verifyAssessment } from './assessment.js';

export class VerificationService {
  constructor({ nodes, group, registry, eventBus = null, config, primary = null, coordinator = null }) {
    if (!group) throw new Error('VerificationService requires a ReplicationGroup');
    if (!registry) throw new Error('VerificationService requires an IdentityRegistry');
    if (!coordinator?.keyPair || !coordinator?.identityId) {
      throw new Error('VerificationService requires coordinator { keyPair, identityId }; the trust assessment is unsigned without it');
    }
    this.nodes = nodes;
    this.group = group;
    this.registry = registry;
    this.eventBus = eventBus;
    this.config = config;
    this.primary = primary ?? nodes[0];
    this.coordinator = coordinator;
  }

  async historyFor(agentId, { limit = 200 } = {}) {
    const records = await this.primary.listRecords({ agentId, limit });
    const attempts = records.length;
    const successes = records.filter((record) => record.verification?.authorized !== false && record.policy?.authorized !== false).length;
    return { records, attempts, successes };
  }

  async verifyAction(request) {
    const identity = request.identity ?? await this.registry.require(request.identityId);
    const envelope = request.envelope ?? buildActionEnvelope({
      agentId: identity.id,
      action: request.action,
      resource: request.resource,
      executedAt: request.executedAt,
      context: request.context ?? {},
      executionFingerprint: request.executionFingerprint ?? null,
      payload: request.payload ?? null,
    });
    if (envelope.agentId !== identity.id) throw new Error('action envelope agentId does not match the identity being verified');

    const signatureDoc = request.signatureDoc ?? (request.keyPair
      ? await signActionEnvelope(request.keyPair, envelope)
      : (() => {
        throw new Error('verifyAction requires keyPair, signatureDoc, or a pre-built envelope signature');
      })());

    const checks = {};
    checks.actionSignature = await verifyActionSignature({
      publicKey: fromB64u(identity.publicKey),
      alg: signatureDoc.alg,
      digest: signatureDoc.digest,
      signature: signatureDoc.signature,
    });
    checks.identitySelfBinding = await verifyIdentitySelfBinding(identity);
    const lineage = await verifyIdentityLineage({
      identity,
      resolve: async (id) => {
        try {
          return await this.registry.require(id);
        } catch {
          return null;
        }
      },
      trustAnchors: this.registry.trustAnchors,
    });
    checks.lineage = lineage;
    // Revocation is recorded in the append-only log, not on the identity document,
    // so the coordinator has to read the log itself. Without this a revoked agent
    // keeps earning trusted proofs here even though every witness node denies it.
    const revocationLog = await this.registry.revocationsFor(identity.id);
    const activeRevocation = revocationLog.revocations.at(-1) ?? null;
    checks.revocation = {
      revoked: Boolean(activeRevocation),
      revokedAt: activeRevocation?.revokedAt ?? null,
      revokedBy: activeRevocation?.revokedBy ?? null,
      forgedEntries: revocationLog.forged.length,
      nodesReporting: revocationLog.nodesReporting,
    };

    const prior = await this.historyFor(identity.id);
    const scoredPrior = prior.records.at(-1)?.trust?.score ?? null;
    const authorization = evaluateAuthorization({
      identity,
      action: envelope.action,
      resource: envelope.resource,
      context: envelope.context,
      now: Date.parse(envelope.executedAt),
      trustScore: scoredPrior,
      trustFloor: this.config.trustFloor,
      revocation: activeRevocation,
    });

    const record = buildProofRecord({ envelope, signatureDoc, identity, policy: authorization });
    const recordHash = recordHashOf(record);
    const submission = submissionFor({ identity, record, signatureDoc });
    if (submission.actionProof.recordHash !== recordHash) {
      throw new Error('record hash disagreement between coordinator and submission builder');
    }

    const { accepted, failures, witnesses, quorum } = await this.group.fanOut(submission);
    checks.replication = { reached: quorum.reached, agreeing: quorum.agreeingCount, required: quorum.required, total: quorum.total, failures: failures.map((f) => ({ nodeId: f.nodeId, error: f.error })) };
    checks.tamperEvidence = { attestationSignaturesValid: (await Promise.all(witnesses.map((witness) => verifyWitness(witness)))).every(Boolean) };

    const timestamp = timestampRecord({
      recordHash,
      seq: accepted[0]?.entry?.seq ?? null,
      witnesses: accepted.map((entry) => entry.witness),
      quorum,
      maxClockSkewSeconds: this.config.maxClockSkewSeconds,
      rootAtCertification: accepted[0]?.entry ? (await this.primary.head()).root : null,
    });
    const inclusionProof = accepted[0]?.entry ? await this.primary.inclusionProof(accepted[0].entry.seq) : null;
    checks.tamperEvidence.merkleProofValid = inclusionProof ? ProofChain.checkInclusionProof(inclusionProof) : false;

    const divergence = accepted[0]?.entry
      ? await this.group.crossCloudCheck(accepted[0].entry.seq, { witnesses })
      : null;
    checks.consistency = divergence ? { consistent: divergence.consistent, distinctRoots: divergence.distinctRoots, nodesReporting: divergence.nodesReporting, divergent: divergence.divergent.map((node) => node.nodeId) } : null;

    const outcome = {
      identityId: identity.id,
      checks: {
        actionSignature: checks.actionSignature,
        identitySelfBinding: checks.identitySelfBinding,
        lineage,
      },
      policy: authorization,
      timestamp,
    };

    const anomalies = detectAnomalies({ current: record, history: prior.records, identity, divergence, outcome, now: Date.parse(envelope.executedAt) });
    const scored = applyTrustFloor(computeTrustScore({
      outcome,
      history: { attempts: prior.attempts, successes: prior.successes },
      anomalies,
      divergence,
      quorum,
      lineage,
    }), { trustFloor: this.config.trustFloor, requestedMode: request.enforce === false ? 'advise' : 'enforce' });

    const status = trustStatusFrom({
      score: scored.score,
      band: scored.band,
      anomalies,
      authorized: authorization.authorized && checks.actionSignature && checks.identitySelfBinding && lineage.valid,
      quorumReached: quorum.reached,
      floorDeny: scored.floorWouldDeny,
    });

    const firstEntry = accepted[0]?.entry ?? null;
    const certifiedRecord = {
      ...record,
      recordHash,
      seq: firstEntry?.seq ?? null,
      entryHash: firstEntry?.entryHash ?? null,
      prevEntryHash: firstEntry?.prevEntryHash ?? null,
      trust: {
        score: scored.score,
        band: scored.band,
        components: scored.components,
        signals: scored.signals,
        status: status.status,
        reason: status.reason,
        cappedAt: scored.cappedAt,
        trustFloor: scored.trustFloor,
        meetsFloor: scored.meetsFloor,
        allowedMode: scored.allowedMode,
      },
      anomalies,
    };

    const assessable = { ...certifiedRecord, timestamp, inclusionProof };
    let assessment = null;
    let persistence;
    if (quorum.reached) {
      assessment = await signAssessment({
        keyPair: this.coordinator.keyPair,
        coordinatorId: this.coordinator.identityId,
        record: assessable,
      });
      const withAssessment = { ...assessable, assessment };
      const selfCheck = await verifyAssessment({
        record: withAssessment,
        resolve: async (id) => {
          try {
            return await this.registry.require(id);
          } catch {
            return null;
          }
        },
        trustAnchors: this.registry.trustAnchors,
        crossCheck: this.config.crossCheck,
      });
      if (!selfCheck.valid) {
        throw new Error(`coordinator assessment does not verify before publication: ${selfCheck.problems.map((problem) => `${problem.code} (${problem.detail})`).join('; ')}`);
      }
      checks.tamperEvidence.assessmentSignatureValid = true;
      persistence = await this.group.certifyAll({ record: withAssessment, witnesses, timestamp, inclusionProof });
    } else {
      persistence = { stored: [], failures: [{ nodeId: 'coordinator', error: 'quorum not reached; refusing to certify' }], complete: false };
    }

    const consistencyAfterCertify = quorum.reached && firstEntry
      ? await this.group.crossCloudCheck(firstEntry.seq)
      : null;
    const postCertificationDivergence = consistencyAfterCertify ? consistencyAfterCertify.consistent === false : false;

    const chainAudit = accepted[0]?.entry ? await this.primary.audit({ from: Math.max(1, accepted[0].entry.seq - 24), to: accepted[0].entry.seq }) : null;
    checks.tamperEvidence.chainWindowIntact = chainAudit ? chainAudit.intact : false;

    const result = {
      proofId: recordHash,
      status: status.status,
      reason: status.reason,
      verifiedAt: new Date().toISOString(),
      agentId: identity.id,
      action: envelope.action,
      resource: envelope.resource,
      executedAt: envelope.executedAt,
      trustScore: scored.score,
      band: scored.band,
      allowedMode: scored.allowedMode,
      meetsFloor: scored.meetsFloor,
      checks,
      policy: authorization,
      lineage: { valid: lineage.valid, depth: lineage.depth, path: lineage.lineage },
      quorum,
      timestamp,
      inclusionProof,
      divergence,
      anomalies,
      scored,
      assessment: assessment === null ? null : { coordinatorId: assessment.coordinatorId, alg: assessment.alg, digest: assessment.digest, signature: assessment.signature, signedAt: assessment.signedAt, selfVerified: true },
      nodes: accepted.map((entry) => ({ nodeId: entry.nodeId, cloud: entry.cloud, seq: entry.entry.seq, entryHash: entry.entry.entryHash, localAuthorized: entry.verdict.ok, localProblems: entry.verdict.problems })),
      failures,
      persistence,
      consistencyAfterCertify,
      postCertificationDivergence,
      chainAudit,
    };

    const publishStatus = status.status === 'trusted' && !postCertificationDivergence ? 'action.verified' : 'action.flagged';
    this.eventBus?.publish(publishStatus, {
      proofId: recordHash,
      agentId: identity.id,
      action: envelope.action,
      resource: envelope.resource,
      status: postCertificationDivergence && status.status === 'trusted' ? 'flagged' : status.status,
      reason: postCertificationDivergence && status.status === 'trusted'
        ? 'stored copies diverge after certification; see consistencyAfterCertify'
        : status.reason,
      trustScore: scored.score,
      at: result.verifiedAt,
    });
    return result;
  }

  async getProof(proofId) {
    const copies = await Promise.allSettled(this.nodes.map((node) => node.getRecord(proofId)));
    const perNode = copies.map((outcome, index) => ({
      nodeId: this.nodes[index].nodeId,
      cloud: this.nodes[index].cloud ?? null,
      present: outcome.status === 'fulfilled' && Boolean(outcome.value),
      error: outcome.status === 'rejected' ? String(outcome.reason?.message ?? outcome.reason).slice(0, 200) : null,
    }));
    const found = copies.filter((outcome) => outcome.status === 'fulfilled' && outcome.value).map((outcome) => outcome.value);
    if (found.length === 0) return null;
    return { record: found[0], replication: perNode, present: found.length };
  }

  async auditNode(nodeId, range) {
    const node = this.nodes.find((candidate) => candidate.nodeId === nodeId);
    if (!node) throw new Error(`unknown node ${nodeId}`);
    return node.audit(range);
  }

  async crossCloud(seq) {
    return this.group.crossCloudCheck(seq);
  }

  async status() {
    return Promise.all(this.nodes.map((node) => node.status()));
  }
}

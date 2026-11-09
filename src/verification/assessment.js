import { digestOf, fromB64u, fromHex, toB64u } from '../crypto/hash.js';
import { crossVerify, sign, verify } from '../crypto/pqc.js';
import { verifyIdentitySelfBinding } from '../crypto/identity.js';
import { verifyIdentityLineage } from '../policy/engine.js';

export const ASSESSMENT_TAG = 'verix:trust-assessment:v1';

// The payload hash binds what the agent did. Everything the coordinator and the
// nodes add afterwards is bound by this signature instead, so it cannot be
// rewritten by whoever controls a storage copy.
export function assessmentPayloadOf(record) {
  return {
    recordHash: record.recordHash ?? null,
    seq: record.seq ?? null,
    trust: record.trust ?? null,
    anomalies: record.anomalies ?? null,
    timestamp: record.timestamp ?? null,
    inclusionProof: record.inclusionProof ?? null,
    replication: record.replication ?? null,
  };
}

export function assessmentDigestOf(record) {
  return digestOf(assessmentPayloadOf(record), ASSESSMENT_TAG);
}

export async function signAssessment({ keyPair, coordinatorId, record }) {
  if (!keyPair) throw new Error('signAssessment requires keyPair');
  if (!coordinatorId) throw new Error('signAssessment requires coordinatorId');
  if (!record?.recordHash) throw new Error('signAssessment requires a record with a recordHash');
  const digest = assessmentDigestOf(record);
  const signature = await sign(keyPair, fromHex(digest));
  return {
    coordinatorId,
    alg: keyPair.alg,
    publicKey: toB64u(keyPair.publicKey),
    signedAt: new Date().toISOString(),
    digest,
    signature: toB64u(signature),
  };
}

export async function verifyAssessment({ record, resolve, trustAnchors = null, crossCheck = false }) {
  const assessment = record?.assessment;
  if (!assessment) return { valid: false, problems: [{ code: 'ASSESSMENT_ABSENT', detail: 'record carries no coordinator assessment signature' }], digest: null };
  const problems = [];
  const digest = assessmentDigestOf(record);
  if (assessment.digest !== digest) {
    problems.push({ code: 'ASSESSMENT_DIGEST_MISMATCH', detail: `assessment commits ${String(assessment.digest).slice(0, 12)} but the stored trust layer hashes to ${digest.slice(0, 12)}` });
  }
  const coordinator = await Promise.resolve(resolve(assessment.coordinatorId)).catch(() => null);
  if (!coordinator) {
    problems.push({ code: 'COORDINATOR_UNRESOLVED', detail: `coordinator identity ${assessment.coordinatorId} is not registered on this node` });
  } else if (coordinator.publicKey !== assessment.publicKey) {
    problems.push({ code: 'COORDINATOR_KEY_MISMATCH', detail: 'assessment public key is not the key bound into the coordinator identity' });
  } else if (!(await verifyIdentitySelfBinding(coordinator))) {
    problems.push({ code: 'COORDINATOR_SELF_BINDING_INVALID', detail: `${coordinator.id} does not bind its recorded public key` });
  }
  const signed = fromHex(digest);
  const signature = fromB64u(assessment.signature);
  const signatureValid = coordinator
    ? await verify(assessment.alg, fromB64u(coordinator.publicKey), signed, signature)
    : await verify(assessment.alg, fromB64u(assessment.publicKey), signed, signature);
  if (!signatureValid) problems.push({ code: 'ASSESSMENT_SIGNATURE_INVALID', detail: `assessment signature does not verify under ${assessment.alg}` });
  if (signatureValid && crossCheck && coordinator) {
    const cross = await crossVerify(fromB64u(coordinator.publicKey), signed, signature, assessment.alg);
    if (!cross.viaJs || cross.agreement === false) {
      problems.push({ code: 'ASSESSMENT_CROSS_IMPLEMENTATION_DISAGREEMENT', detail: `independent ML-DSA implementations disagree on the assessment signature (${JSON.stringify({ viaWasm: cross.viaWasm, viaJs: cross.viaJs })})` });
    }
  }
  if (trustAnchors && coordinator) {
    const lineage = await verifyIdentityLineage({ identity: coordinator, resolve: (id) => Promise.resolve(resolve(id)).catch(() => null), trustAnchors });
    if (!lineage.valid) {
      problems.push({ code: 'COORDINATOR_LINEAGE_UNANCHORED', detail: `coordinator lineage does not reach a configured trust root: ${lineage.reasons.map((entry) => entry.code).join(', ')}` });
    }
  }
  return { valid: problems.length === 0, problems, digest, coordinatorId: assessment.coordinatorId, signedAt: assessment.signedAt, alg: assessment.alg };
}

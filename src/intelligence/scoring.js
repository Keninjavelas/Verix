export const WEIGHTS = {
  signature: 20,
  policy: 20,
  lineage: 15,
  replication: 20,
  consistency: 15,
  behaviour: 10,
};

export const BANDS = [
  { min: 85, label: 'high-trust', allowed: 'full' },
  { min: 68, label: 'monitored', allowed: 'full' },
  { min: 50, label: 'elevated-risk', allowed: 'scoped' },
  { min: 30, label: 'restricted', allowed: 'read-only' },
  { min: 0, label: 'quarantine', allowed: 'deny' },
];

const TOTAL_WEIGHT = Object.values(WEIGHTS).reduce((sum, weight) => sum + weight, 0);

export function bandFor(score) {
  return BANDS.find((band) => score >= band.min) ?? BANDS.at(-1);
}

function betaSmoothed(successes, attempts, priorWeight = 3, priorMean = 0.85) {
  const total = attempts + priorWeight;
  return (successes + priorMean * priorWeight) / total;
}

function component(key, achieved, detail, extra = {}) {
  return { key, weight: WEIGHTS[key], achieved: Number(achieved.toFixed(4)), points: Number((WEIGHTS[key] * achieved).toFixed(2)), detail, ...extra };
}

export function computeTrustScore({ outcome, history = {}, anomalies = [], divergence = null, quorum = null, lineage = null, maxDelegationDepth = 8 }) {
  const components = [];
  const signals = [];

  const signatureOk = outcome?.checks?.actionSignature !== false && outcome?.checks?.identitySelfBinding !== false;
  components.push(component('signature', signatureOk ? 1 : 0, signatureOk
    ? `${outcome?.identityId ?? 'agent'} action signature and identity self-binding verify`
    : 'cryptographic binding failed; the recorded action cannot be attributed to this identity'));

  const denyReasons = (outcome?.policy?.reasons ?? []).filter((entry) => entry.severity === 'deny');
  const advisory = (outcome?.policy?.reasons ?? []).filter((entry) => entry.severity === 'warn');
  const policyAchieved = denyReasons.length > 0 ? 0 : advisory.length > 0 ? 1 - Math.min(0.4, advisory.length * 0.1) : 1;
  components.push(component('policy', policyAchieved, denyReasons.length > 0
    ? `authorization denied: ${denyReasons.map((entry) => entry.code).join(', ')}`
    : advisory.length > 0 ? `authorized with ${advisory.length} advisory finding(s)` : 'authorized with no findings', { denyReasons: denyReasons.map((entry) => entry.code), advisory: advisory.map((entry) => entry.code) }));

  const depth = lineage?.depth ?? 0;
  const unresolved = lineage?.valid === false;
  const lineageAchieved = unresolved ? 0 : Math.max(0.25, 1 - depth / (maxDelegationDepth + 1));
  components.push(component('lineage', lineageAchieved, unresolved
    ? 'delegation lineage could not be anchored to a configured trust root'
    : `delegation chain resolves at depth ${depth} of ${maxDelegationDepth}`, { depth, anchored: !unresolved }));

  const agreeing = quorum?.agreeingCount ?? 0;
  const required = quorum?.required ?? 1;
  const replicationAchieved = quorum?.reached ? Math.min(1, agreeing / Math.max(required, 1)) : Math.min(0.5, agreeing / Math.max(required, 1) * 0.5);
  components.push(component('replication', replicationAchieved, quorum?.reached
    ? `${agreeing} of ${quorum.total} independent nodes attest to this proof`
    : `quorum unreachable: ${agreeing} attestation(s) below the required ${required}`, { agreeing, required, total: quorum?.total ?? 0 }));

  const consistent = divergence ? divergence.consistent : true;
  const skewExceeded = outcome?.timestamp?.clockSkewExceeded === true;
  const witnessFailure = (divergence?.witnessVerificationFailed ?? []).length > 0;
  let consistencyAchieved = 1;
  const consistencyNotes = [];
  if (!consistent) { consistencyAchieved -= 0.7; consistencyNotes.push('cross-cloud roots diverge'); }
  if (skewExceeded) { consistencyAchieved -= 0.2; consistencyNotes.push('witness clock skew exceeded the configured bound'); }
  if (witnessFailure) { consistencyAchieved -= 0.3; consistencyNotes.push('one or more node copies carry invalid witness signatures'); }
  consistencyAchieved = Math.max(0, consistencyAchieved);
  components.push(component('consistency', consistencyAchieved, consistencyNotes.length > 0 ? consistencyNotes.join('; ') : 'all reporting nodes agree on root, record content and attestation validity'));

  const severityCost = anomalies.reduce((sum, anomaly) => sum + (anomaly.severity === 'critical' ? 0.6 : anomaly.severity === 'high' ? 0.35 : anomaly.severity === 'medium' ? 0.15 : 0.05), 0);
  const attempts = history.attempts ?? 0;
  const successes = history.successes ?? 0;
  const reliability = betaSmoothed(successes, attempts);
  const behaviourAchieved = Math.max(0, Math.min(1, reliability * (1 - Math.min(1, severityCost))));
  components.push(component('behaviour', behaviourAchieved, attempts > 0
    ? `${successes}/${attempts} prior actions verified (smoothed reliability ${(reliability * 100).toFixed(1)}%)`
    : 'no prior history; reliability starts at the neutral prior', { reliability: Number(reliability.toFixed(4)), anomalies: anomalies.map((a) => a.code) }));

  if (anomalies.length > 0) signals.push(...anomalies.map((anomaly) => `${anomaly.severity}:${anomaly.code}`));
  if (!consistent) signals.push('critical:cross-cloud-divergence');
  if (!quorum?.reached) signals.push('critical:quorum-unreachable');
  if (denyReasons.length > 0) signals.push(...denyReasons.map((entry) => `deny:${entry.code}`));

  const weighted = components.reduce((sum, entry) => sum + entry.points, 0);
  const rawScore = (weighted / TOTAL_WEIGHT) * 100;
  const hardCap = !signatureOk ? 15 : !quorum?.reached ? 40 : !consistent ? 35 : null;
  const score = Number((hardCap === null ? rawScore : Math.min(rawScore, hardCap)).toFixed(2));
  const band = bandFor(score);
  // The band is a graded label; allowedMode is a verdict, so an explicit denial overrides it.
  return {
    score,
    band: band.label,
    allowedMode: denyReasons.length > 0 ? 'deny' : band.allowed,
    components,
    signals,
    cappedAt: hardCap,
    trustFloorEffect: null,
  };
}

export function applyTrustFloor(scored, { trustFloor = null, requestedMode = null }) {
  const floor = trustFloor ?? null;
  const meets = floor === null ? true : scored.score >= floor;
  return {
    ...scored,
    trustFloor: floor,
    meetsFloor: meets,
    floorWouldDeny: Boolean(requestedMode === 'enforce' && floor !== null && !meets),
    trustFloorEffect: floor === null ? null : meets ? 'pass' : 'below-floor',
  };
}

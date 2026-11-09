export const ANOMALY_CODES = {
  REPLICATION_DIVERGENCE: 'REPLICATION_DIVERGENCE',
  ATTESTATION_UNTRUSTED: 'ATTESTATION_UNTRUSTED',
  LINEAGE_BROKEN: 'LINEAGE_BROKEN',
  EXECUTION_FINGERPRINT_CHANGED: 'EXECUTION_FINGERPRINT_CHANGED',
  NOVEL_ACTION: 'NOVEL_ACTION',
  NOVEL_RESOURCE_ROOT: 'NOVEL_RESOURCE_ROOT',
  ACTION_RATE_BURST: 'ACTION_RATE_BURST',
  COST_OUTLIER: 'COST_OUTLIER',
  PRIOR_DENIAL_STREAK: 'PRIOR_DENIAL_STREAK',
  WITNESS_CLOCK_SKEW: 'WITNESS_CLOCK_SKEW',
  IDENTITY_FIRST_SIGHTING: 'IDENTITY_FIRST_SIGHTING',
};

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

function anomaly(code, severity, detail, evidence = {}) {
  return { code, severity, detail, evidence };
}

function mean(values) {
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function stdDev(values) {
  if (values.length < 2) return 0;
  const avg = mean(values);
  return Math.sqrt(values.reduce((sum, value) => sum + (value - avg) ** 2, 0) / (values.length - 1));
}

function resourceRoot(resource) {
  return String(resource).split(':')[0] || String(resource);
}

export function detectAnomalies({ current, history = [], identity = null, divergence = null, outcome = null, now = Date.now(), windowMinutes = 60, burstThreshold = 6 }) {
  const found = [];
  const prior = history.filter((record) => record.agentId === current.agentId && Date.parse(record.executedAt) < Date.parse(current.executedAt));

  if (divergence && divergence.consistent === false) {
    found.push(anomaly(ANOMALY_CODES.REPLICATION_DIVERGENCE, 'critical',
      `nodes disagree about the ledger root at sequence ${divergence.seq}: ${divergence.distinctRoots} distinct roots across ${divergence.nodesReporting} reporting nodes`,
      { electedRoot: divergence.electedRoot, divergent: divergence.divergent.map((node) => node.nodeId), failures: divergence.failures }));
    if ((divergence.witnessVerificationFailed ?? []).length > 0) {
      found.push(anomaly(ANOMALY_CODES.ATTESTATION_UNTRUSTED, 'critical',
        `node copies carry witness signatures that do not verify: ${divergence.witnessVerificationFailed.join(', ')}`,
        { nodes: divergence.witnessVerificationFailed }));
    }
  }

  if (outcome?.checks?.lineage?.valid === false) {
    found.push(anomaly(ANOMALY_CODES.LINEAGE_BROKEN, 'critical',
      `delegation lineage for ${current.agentId} cannot be anchored: ${outcome.checks.lineage.reasons?.map((entry) => entry.code).join(', ') ?? 'unspecified'}`,
      { lineage: outcome.checks.lineage }));
  }

  const fingerprints = [...prior, current].map((record) => record.executionFingerprint).filter(Boolean);
  if (fingerprints.length > 2) {
    const stable = new Set(fingerprints.slice(0, -1));
    if (stable.size === 1 && current.executionFingerprint && !stable.has(current.executionFingerprint)) {
      found.push(anomaly(ANOMALY_CODES.EXECUTION_FINGERPRINT_CHANGED, 'high',
        `execution fingerprint changed for ${current.agentId} after ${stable.size} consistent observation(s)`,
        { previous: [...stable][0], current: current.executionFingerprint }));
    }
  }

  if (prior.length >= 5) {
    const seenActions = new Set(prior.map((record) => record.action));
    if (!seenActions.has(current.action)) {
      found.push(anomaly(ANOMALY_CODES.NOVEL_ACTION, current.context?.destructive ? 'high' : 'medium',
        `${current.agentId} invoked ${current.action} for the first time after ${prior.length} prior actions`,
        { seenActions: [...seenActions], firstUse: current.action }));
    }
    const seenRoots = new Set(prior.map((record) => resourceRoot(record.resource)));
    const currentRoot = resourceRoot(current.resource);
    if (!seenRoots.has(currentRoot)) {
      found.push(anomaly(ANOMALY_CODES.NOVEL_RESOURCE_ROOT, current.context?.destructive ? 'high' : 'medium',
        `first use of resource namespace ${currentRoot} by ${current.agentId}`,
        { seenRoots: [...seenRoots], firstUse: currentRoot }));
    }
    const costs = prior.map((record) => Number(record.context?.costUsd ?? 0)).filter((value) => value > 0);
    const currentCost = Number(current.context?.costUsd ?? 0);
    if (costs.length >= 4 && currentCost > 0 && stdDev(costs) > 0) {
      const z = (currentCost - mean(costs)) / stdDev(costs);
      if (z > 3) {
        found.push(anomaly(ANOMALY_CODES.COST_OUTLIER, 'medium',
          `cost $${currentCost} is ${z.toFixed(1)} standard deviations above the ${costs.length}-action baseline (mean $${mean(costs).toFixed(2)})`,
          { zScore: Number(z.toFixed(2)), baselineMean: Number(mean(costs).toFixed(2)), sampleSize: costs.length }));
      }
    }
    const windowMs = windowMinutes * 60_000;
    const recent = prior.filter((record) => now - Date.parse(record.executedAt) <= windowMs);
    if (recent.length >= burstThreshold) {
      found.push(anomaly(ANOMALY_CODES.ACTION_RATE_BURST, 'medium',
        `${recent.length} actions in the last ${windowMinutes} minute(s), at or above the burst threshold of ${burstThreshold}`,
        { count: recent.length, windowMinutes, threshold: burstThreshold }));
    }
    const denials = prior.filter((record) => record.verification?.authorized === false || record.policy?.authorized === false);
    if (denials.length >= 3 && denials.length / prior.length > 0.5) {
      found.push(anomaly(ANOMALY_CODES.PRIOR_DENIAL_STREAK, 'high',
        `${denials.length} of ${prior.length} prior actions by ${current.agentId} were denied`,
        { denials: denials.length, prior: prior.length, ratio: Number((denials.length / prior.length).toFixed(2)) }));
    }
  }

  if (prior.length === 0 && identity) {
    found.push(anomaly(ANOMALY_CODES.IDENTITY_FIRST_SIGHTING, 'low',
      `${current.agentId} has no prior verified history; scoring starts from the neutral reliability prior`,
      { issuedAt: identity.issuedAt }));
  }

  if (outcome?.timestamp?.clockSkewExceeded) {
    found.push(anomaly(ANOMALY_CODES.WITNESS_CLOCK_SKEW, 'medium',
      `witness clock spread of ${outcome.timestamp.maxClockSkewSeconds}s exceeded the configured bound`,
      { maxClockSkewSeconds: outcome.timestamp.maxClockSkewSeconds, witnessNodeIds: outcome.timestamp.witnessNodeIds }));
  }

  return found.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
}

export function worstSeverity(anomalies = []) {
  return anomalies.map((a) => a.severity).sort((a, b) => SEVERITY_ORDER[a] - SEVERITY_ORDER[b])[0] ?? 'none';
}

export function trustStatusFrom({ score, band, anomalies = [], authorized, quorumReached, floorDeny = false }) {
  if (!quorumReached) return { status: 'unattested', reason: 'no replication quorum was reached, so the proof is not independently attested' };
  if (!authorized || floorDeny) return { status: 'rejected', reason: floorDeny ? 'trust score is below the configured enforcement floor' : 'policy authorization failed' };
  if (anomalies.some((a) => a.severity === 'critical')) return { status: 'flagged', reason: `critical anomaly ${worstSeverity(anomalies)}: ${anomalies[0].code}` };
  if (score < 50) return { status: 'flagged', reason: `trust score ${score} sits in the ${band} band` };
  return { status: 'trusted', reason: `trust score ${score} in band ${band} with no critical anomalies` };
}

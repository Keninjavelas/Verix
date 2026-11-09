import test from 'node:test';
import assert from 'node:assert/strict';
import { BANDS, WEIGHTS, applyTrustFloor, bandFor, computeTrustScore } from '../src/intelligence/scoring.js';
import { trustStatusFrom } from '../src/intelligence/anomaly.js';

const cleanOutcome = (overrides = {}) => ({
  identityId: 'verix:agent:clean',
  checks: { actionSignature: true, identitySelfBinding: true },
  policy: { reasons: [] },
  timestamp: {},
  ...overrides,
});
const cleanQuorum = { reached: true, agreeingCount: 3, required: 2, total: 3 };
const cleanLineage = { valid: true, depth: 0 };
const cleanDivergence = { consistent: true, witnessVerificationFailed: [] };
const flawless = { attempts: 20, successes: 20 };

function score(overrides = {}) {
  return computeTrustScore({
    outcome: cleanOutcome(overrides.outcome),
    history: overrides.history ?? flawless,
    anomalies: overrides.anomalies ?? [],
    divergence: overrides.divergence ?? cleanDivergence,
    quorum: overrides.quorum ?? cleanQuorum,
    lineage: overrides.lineage ?? cleanLineage,
    maxDelegationDepth: overrides.maxDelegationDepth,
  });
}

function componentOf(result, key) {
  return result.components.find((entry) => entry.key === key);
}

test('the component weights are a percentage budget', () => {
  assert.deepEqual(WEIGHTS, { signature: 20, policy: 20, lineage: 15, replication: 20, consistency: 15, behaviour: 10 });
  assert.equal(Object.values(WEIGHTS).reduce((sum, weight) => sum + weight, 0), 100);
});

test('band thresholds are contiguous and map to an allowed mode', () => {
  assert.deepEqual(BANDS.map((band) => band.min), [85, 68, 50, 30, 0]);
  assert.deepEqual(BANDS.map((band) => band.allowed), ['full', 'full', 'scoped', 'read-only', 'deny']);
  for (const [value, label] of [[100, 'high-trust'], [85, 'high-trust'], [84.99, 'monitored'], [68, 'monitored'], [67.9, 'elevated-risk'], [50, 'elevated-risk'], [49.99, 'restricted'], [30, 'restricted'], [29.9, 'quarantine'], [0, 'quarantine'], [-5, 'quarantine']]) {
    assert.equal(bandFor(value).label, label, `bandFor(${value})`);
  }
});

test('a clean proof from a flawless history lands in the top band', () => {
  const result = score();
  assert.equal(result.score, 99.8);
  assert.equal(result.band, 'high-trust');
  assert.equal(result.allowedMode, 'full');
  assert.equal(result.cappedAt, null);
  assert.deepEqual(result.signals, []);
  assert.deepEqual(result.components.map((entry) => entry.key), ['signature', 'policy', 'lineage', 'replication', 'consistency', 'behaviour']);
  for (const component of result.components) {
    assert.equal(component.points, Number((component.weight * component.achieved).toFixed(2)));
    assert.ok(component.detail.length > 0);
  }
  assert.equal(componentOf(result, 'behaviour').achieved, 0.9804);
  assert.equal(componentOf(result, 'behaviour').points, 9.8);
});

test('the beta prior holds a fresh agent back and a flawless history converges on the ceiling', () => {
  const fresh = score({ history: {} });
  assert.equal(fresh.score, 98.5, 'no history starts at the 0.85 reliability prior');
  assert.equal(bandFor(fresh.score).label, 'high-trust');
  assert.equal(componentOf(fresh, 'behaviour').detail, 'no prior history; reliability starts at the neutral prior');
  const trusted = score({ history: { attempts: 40, successes: 40 } });
  assert.equal(trusted.score, 99.9);
  const seasoned = score({ history: { attempts: 1000, successes: 1000 } });
  assert.equal(seasoned.score, 100, 'at a thousand flawless actions the prior is rounded away and the ceiling is reachable');
  const failing = score({ history: { attempts: 20, successes: 5 } });
  assert.equal(failing.score, 93.28);
  assert.equal(componentOf(failing, 'behaviour').detail, '5/20 prior actions verified (smoothed reliability 32.8%)');
});

test('a failed signature hard-caps the score in the quarantine band', () => {
  for (const broken of [
    { actionSignature: false, identitySelfBinding: true },
    { actionSignature: true, identitySelfBinding: false },
  ]) {
    const result = score({ outcome: cleanOutcome({ checks: broken }) });
    assert.equal(componentOf(result, 'signature').achieved, 0);
    assert.equal(result.cappedAt, 15);
    assert.equal(result.score, 15);
    assert.equal(result.band, 'quarantine');
    assert.equal(result.allowedMode, 'deny');
  }
});

test('a policy denial zeroes the policy component and is recorded as a deny signal', () => {
  const result = score({ outcome: cleanOutcome({ policy: { reasons: [{ severity: 'deny', code: 'SCOPE_MISSING' }, { severity: 'deny', code: 'REVOKED' }] } }) });
  const policy = componentOf(result, 'policy');
  assert.equal(policy.achieved, 0);
  assert.equal(policy.points, 0);
  assert.deepEqual(policy.denyReasons, ['SCOPE_MISSING', 'REVOKED']);
  assert.deepEqual(policy.advisory, []);
  assert.ok(result.signals.includes('deny:SCOPE_MISSING') && result.signals.includes('deny:REVOKED'));
  assert.equal(result.cappedAt, null, 'a denial is signalled, not capped; the score stays a graded quantity');
  assert.equal(result.score, 79.8);
  assert.equal(result.band, 'monitored');
  assert.equal(result.allowedMode, 'deny', 'the band is a label, the allowed mode is the verdict');
});

test('advisory findings shave the policy component and stop at a 40% deduction', () => {
  const one = score({ outcome: cleanOutcome({ policy: { reasons: [{ severity: 'warn', code: 'COST_HEADING_UP' }] } }) });
  assert.equal(componentOf(one, 'policy').achieved, 0.9);
  assert.equal(one.score, 97.8);
  assert.equal(one.allowedMode, 'full', 'an advisory finding reduces credit but does not revoke the mode');
  const five = score({ outcome: cleanOutcome({ policy: { reasons: Array.from({ length: 5 }, (_, i) => ({ severity: 'warn', code: `WARN_${i}` })) } }) });
  assert.equal(componentOf(five, 'policy').achieved, 0.6);
  assert.equal(five.score, 91.8);
  assert.deepEqual(componentOf(five, 'policy').advisory, ['WARN_0', 'WARN_1', 'WARN_2', 'WARN_3', 'WARN_4']);
  const mixed = score({ outcome: cleanOutcome({ policy: { reasons: [{ severity: 'warn', code: 'W1' }, { severity: 'deny', code: 'D1' }] } }) });
  assert.equal(componentOf(mixed, 'policy').achieved, 0, 'a single deny outweighs any number of advisories');
});

test('delegation depth decays the lineage component down to a floor, then unresolved chains score zero', () => {
  assert.equal(componentOf(score({ lineage: { valid: true, depth: 4 } }), 'lineage').achieved, 0.5556);
  assert.equal(score({ lineage: { valid: true, depth: 4 } }).cappedAt, null);
  const deepest = score({ lineage: { valid: true, depth: 8 } });
  assert.equal(componentOf(deepest, 'lineage').achieved, 0.25, 'lineage decay bottoms out at 0.25 rather than vanishing');
  const beyond = score({ lineage: { valid: true, depth: 20 }, maxDelegationDepth: 8 });
  assert.equal(componentOf(beyond, 'lineage').achieved, 0.25);
  assert.equal(beyond.score, deepest.score);
  const unresolved = score({ lineage: { valid: false, depth: 3 } });
  assert.equal(componentOf(unresolved, 'lineage').achieved, 0);
  assert.equal(unresolved.cappedAt, null);
  assert.equal(unresolved.score, 84.8);
  assert.equal(componentOf(unresolved, 'lineage').detail, 'delegation lineage could not be anchored to a configured trust root');
});

test('an unreachable quorum caps the score at 40 and halves the replication credit', () => {
  const result = score({ quorum: { reached: false, agreeingCount: 1, required: 2, total: 3 } });
  const replication = componentOf(result, 'replication');
  assert.equal(replication.achieved, 0.25);
  assert.equal(replication.detail, 'quorum unreachable: 1 attestation(s) below the required 2');
  assert.ok(result.signals.includes('critical:quorum-unreachable'));
  assert.equal(result.cappedAt, 40);
  assert.equal(result.score, 40);
  assert.equal(result.band, 'restricted');
  assert.equal(result.allowedMode, 'read-only');
  const none = score({ quorum: { reached: false, agreeingCount: 0, required: 2, total: 3 } });
  assert.equal(componentOf(none, 'replication').achieved, 0);
});

test('replication credit is capped by the attestation count, not by unanimity', () => {
  assert.equal(componentOf(score({ quorum: { reached: true, agreeingCount: 2, required: 2, total: 5 } }), 'replication').achieved, 1);
  assert.equal(componentOf(score({ quorum: { reached: true, agreeingCount: 2, required: 3, total: 3 } }), 'replication').achieved, 0.6667);
});

test('cross-cloud divergence caps at 35 and is the largest consistency penalty', () => {
  const diverged = score({ divergence: { consistent: false, witnessVerificationFailed: [], distinctRoots: 2 } });
  assert.equal(componentOf(diverged, 'consistency').achieved, 0.3);
  assert.equal(componentOf(diverged, 'consistency').detail, 'cross-cloud roots diverge');
  assert.ok(diverged.signals.includes('critical:cross-cloud-divergence'));
  assert.equal(diverged.cappedAt, 35);
  assert.equal(diverged.score, 35);
  assert.equal(diverged.band, 'restricted');
  assert.equal(diverged.allowedMode, 'read-only');
});

test('consistency penalties for skew and bad attestations stack and clamp at zero', () => {
  const skewed = score({ outcome: cleanOutcome({ timestamp: { clockSkewExceeded: true } }) });
  assert.equal(componentOf(skewed, 'consistency').achieved, 0.8);
  assert.equal(componentOf(skewed, 'consistency').detail, 'witness clock skew exceeded the configured bound');
  const forged = score({ divergence: { consistent: true, witnessVerificationFailed: ['verix-node-aws-1'] } });
  assert.equal(componentOf(forged, 'consistency').achieved, 0.7);
  assert.equal(componentOf(forged, 'consistency').detail, 'one or more node copies carry invalid witness signatures');
  const both = score({ outcome: cleanOutcome({ timestamp: { clockSkewExceeded: true } }), divergence: { consistent: true, witnessVerificationFailed: ['a'] } });
  assert.equal(componentOf(both, 'consistency').achieved, 0.5);
  assert.equal(componentOf(both, 'consistency').detail, 'witness clock skew exceeded the configured bound; one or more node copies carry invalid witness signatures');
  const all = score({ outcome: cleanOutcome({ timestamp: { clockSkewExceeded: true } }), divergence: { consistent: false, witnessVerificationFailed: ['a', 'b'] } });
  assert.equal(componentOf(all, 'consistency').achieved, 0, '0.3 - 0.2 - 0.3 clamps to 0 instead of going negative');
  assert.equal(all.cappedAt, 35, 'divergence outranks the other consistency failures');
});

test('anomaly severities are priced into the behaviour component', () => {
  const prices = { critical: 0.6, high: 0.35, medium: 0.15, low: 0.05 };
  for (const [severity, cost] of Object.entries(prices)) {
    const result = score({ anomalies: [{ code: `A_${severity}`, severity }] });
    assert.equal(componentOf(result, 'behaviour').achieved, Number((0.9804347826086956 * (1 - cost)).toFixed(4)), severity);
    assert.ok(result.signals.includes(`${severity}:A_${severity}`));
  }
  const stacked = score({ anomalies: [{ code: 'X', severity: 'critical' }, { code: 'Y', severity: 'critical' }] });
  assert.equal(componentOf(stacked, 'behaviour').achieved, 0, 'two critical findings exhaust the behaviour component');
  assert.deepEqual(stacked.signals, ['critical:X', 'critical:Y']);
});

test('the strictest cap wins when several core checks fail', () => {
  const result = score({
    outcome: cleanOutcome({ checks: { actionSignature: false, identitySelfBinding: true }, policy: { reasons: [{ severity: 'deny', code: 'NO_SCOPE' }] } }),
    divergence: { consistent: false, witnessVerificationFailed: ['a'] },
    quorum: { reached: false, agreeingCount: 1, required: 2, total: 2 },
    lineage: { valid: false },
  });
  assert.equal(result.cappedAt, 15);
  assert.equal(result.score, 14.8, 'the raw total (5 replication + 9.8 behaviour) already sits below the signature cap');
  assert.equal(result.band, 'quarantine');
  assert.equal(result.allowedMode, 'deny');
  assert.deepEqual(result.signals, ['critical:cross-cloud-divergence', 'critical:quorum-unreachable', 'deny:NO_SCOPE']);
});

test('the trust floor is reported separately from the score', () => {
  const scored = score({ history: {} });
  assert.equal(scored.score, 98.5);
  const noFloor = applyTrustFloor(scored, { requestedMode: 'enforce' });
  assert.equal(noFloor.trustFloor, null);
  assert.equal(noFloor.meetsFloor, true);
  assert.equal(noFloor.floorWouldDeny, false);
  assert.equal(noFloor.trustFloorEffect, null);

  const above = applyTrustFloor(scored, { trustFloor: 90, requestedMode: 'enforce' });
  assert.equal(above.meetsFloor, true);
  assert.equal(above.trustFloorEffect, 'pass');
  assert.equal(above.floorWouldDeny, false);

  const below = applyTrustFloor(scored, { trustFloor: 99, requestedMode: 'enforce' });
  assert.equal(below.meetsFloor, false);
  assert.equal(below.trustFloorEffect, 'below-floor');
  assert.equal(below.floorWouldDeny, true);

  const advisory = applyTrustFloor(scored, { trustFloor: 99, requestedMode: 'advise' });
  assert.equal(advisory.meetsFloor, false);
  assert.equal(advisory.floorWouldDeny, false, 'in advise mode the floor is reported but does not deny');
  assert.equal(applyTrustFloor(scored, { trustFloor: 99 }).floorWouldDeny, false, 'no requested mode means no enforcement');

  for (const absent of [undefined, null]) {
    const unset = applyTrustFloor(scored, { trustFloor: absent, requestedMode: 'enforce' });
    assert.equal(unset.meetsFloor, true, `an unset floor (${String(absent)}) must not read as below-floor`);
    assert.equal(unset.floorWouldDeny, false);
    assert.equal(unset.trustFloorEffect, null);
    assert.equal(unset.trustFloor, null);
  }
});

test('status resolution: no quorum outranks every verdict', () => {
  const status = trustStatusFrom({ score: 94.8, band: 'high-trust', anomalies: [], authorized: false, quorumReached: false });
  assert.equal(status.status, 'unattested');
  assert.match(status.reason, /not independently attested/);
});

test('status resolution: denial and floor breaches reject, critical anomalies flag, low scores flag', () => {
  assert.equal(trustStatusFrom({ score: 94.8, band: 'high-trust', anomalies: [], authorized: true, quorumReached: true }).status, 'trusted');
  assert.equal(trustStatusFrom({ score: 94.8, band: 'high-trust', anomalies: [], authorized: false, quorumReached: true }).status, 'rejected');
  const floored = trustStatusFrom({ score: 94.8, band: 'high-trust', anomalies: [], authorized: true, quorumReached: true, floorDeny: true });
  assert.equal(floored.status, 'rejected');
  assert.match(floored.reason, /enforcement floor/);
  const critical = trustStatusFrom({ score: 94.8, band: 'high-trust', anomalies: [{ code: 'REPLICATION_DIVERGENCE', severity: 'critical' }], authorized: true, quorumReached: true });
  assert.equal(critical.status, 'flagged');
  assert.equal(critical.reason, 'critical anomaly critical: REPLICATION_DIVERGENCE');
  const low = trustStatusFrom({ score: 40, band: 'restricted', anomalies: [{ code: 'NOVEL_ACTION', severity: 'medium' }], authorized: true, quorumReached: true });
  assert.equal(low.status, 'flagged');
  assert.match(low.reason, /trust score 40 sits in the restricted band/);
  const borderline = trustStatusFrom({ score: 49.99, band: 'restricted', anomalies: [], authorized: true, quorumReached: true });
  assert.equal(borderline.status, 'flagged');
  assert.equal(trustStatusFrom({ score: 50, band: 'elevated-risk', anomalies: [], authorized: true, quorumReached: true }).status, 'trusted');
});

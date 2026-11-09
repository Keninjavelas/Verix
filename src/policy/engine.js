import { findMatchingScopes, globMatch, verifyIssuerLink, verifyIdentitySelfBinding } from '../crypto/identity.js';

const SEVERITY = { deny: 'deny', warn: 'warn', info: 'info' };

export const REASON_CODES = {
  SCOPE_MATCHED: 'SCOPE_MATCHED',
  NO_SCOPE_MATCH: 'NO_SCOPE_MATCH',
  IDENTITY_EXPIRED: 'IDENTITY_EXPIRED',
  IDENTITY_NOT_YET_VALID: 'IDENTITY_NOT_YET_VALID',
  IDENTITY_REVOKED: 'IDENTITY_REVOKED',
  SELF_BINDING_INVALID: 'SELF_BINDING_INVALID',
  LINEAGE_UNRESOLVED: 'LINEAGE_UNRESOLVED',
  LINEAGE_NOT_ANCHORED: 'LINEAGE_NOT_ANCHORED',
  LINEAGE_TOO_DEEP: 'LINEAGE_TOO_DEEP',
  COST_CEILING_EXCEEDED: 'COST_CEILING_EXCEEDED',
  REGION_NOT_ALLOWED: 'REGION_NOT_ALLOWED',
  DESTRUCTIVE_FORBIDDEN: 'DESTRUCTIVE_FORBIDDEN',
  APPROVAL_REQUIRED: 'APPROVAL_REQUIRED',
  TRUST_BELOW_FLOOR: 'TRUST_BELOW_FLOOR',
};

export const MAX_DELEGATION_DEPTH = 8;

function reason(code, detail, severity = SEVERITY.deny) {
  return { code, detail, severity };
}

export function evaluateAuthorization({
  identity,
  action,
  resource,
  context = {},
  now = Date.now(),
  trustScore = null,
  trustFloor = null,
  maxDelegationDepth = MAX_DELEGATION_DEPTH,
  revocation = null,
}) {
  const reasons = [];
  let matched = [];
  const issuedAtMs = Date.parse(identity.issuedAt);
  const expiresAtMs = Date.parse(identity.expiresAt);
  if (Number.isFinite(expiresAtMs) && now > expiresAtMs) {
    reasons.push(reason(REASON_CODES.IDENTITY_EXPIRED, `expired at ${identity.expiresAt}`));
  }
  if (Number.isFinite(issuedAtMs) && now < issuedAtMs) {
    reasons.push(reason(REASON_CODES.IDENTITY_NOT_YET_VALID, `not valid before ${identity.issuedAt}`));
  }
  matched = selectMatchingScopes(identity, action, resource);
  if (matched.length === 0) {
    reasons.push(reason(REASON_CODES.NO_SCOPE_MATCH, `no scope covers ${action} on ${resource}`));
  } else {
    reasons.push(reason(REASON_CODES.SCOPE_MATCHED, `scope ${matched[0].action}:${matched[0].resource}`, SEVERITY.info));
  }
  for (const scope of matched) {
    reasons.push(...evaluateConstraints(scope, context, action, resource));
  }
  if (revocation || identity.revokedAt) {
    const at = revocation?.revokedAt ?? identity.revokedAt;
    const why = revocation?.reason ?? identity.revocationReason ?? 'no reason recorded';
    reasons.push(reason(REASON_CODES.IDENTITY_REVOKED, `revoked at ${at} by ${revocation?.revokedBy ?? 'the recorded authority'}: ${why}`));
  }
  if (trustScore !== null && trustFloor !== null && trustScore < trustFloor) {
    reasons.push(reason(REASON_CODES.TRUST_BELOW_FLOOR, `trust score ${trustScore.toFixed(1)} is below the required floor ${trustFloor}`));
  }
  if (identity.lineageDepth > maxDelegationDepth) {
    reasons.push(reason(REASON_CODES.LINEAGE_TOO_DEEP, `delegation depth ${identity.lineageDepth} exceeds ${maxDelegationDepth}`));
  }
  const blocking = reasons.filter((r) => r.severity === SEVERITY.deny);
  return {
    authorized: blocking.length === 0,
    matchedScopes: matched,
    reasons,
    blockingReasons: blocking,
    advisoryReasons: reasons.filter((r) => r.severity !== SEVERITY.deny),
  };
}

export function selectMatchingScopes(identity, action, resource) {
  return findMatchingScopes(identity, action, resource);
}

function evaluateConstraints(scope, context, action, resource) {
  const constraint = scope.constraint ?? {};
  const out = [];
  if (typeof constraint.maxCostUsd === 'number') {
    const cost = Number(context.costUsd ?? 0);
    if (cost > constraint.maxCostUsd) {
      out.push(reason(REASON_CODES.COST_CEILING_EXCEEDED, `cost $${cost} exceeds ceiling $${constraint.maxCostUsd} for ${action} on ${resource}`));
    }
  }
  if (Array.isArray(constraint.allowedRegions)) {
    const requested = [context.cloud, context.region].filter((v) => v != null);
    if (requested.length === 0) {
      out.push(reason(REASON_CODES.REGION_NOT_ALLOWED, `scope ${scope.action}:${scope.resource} is region-restricted but the request carries no cloud or region`));
    }
    const disallowed = requested.filter((value) => !constraint.allowedRegions.some((pattern) => globMatch(pattern, value)));
    if (disallowed.length > 0) {
      out.push(reason(REASON_CODES.REGION_NOT_ALLOWED, `${disallowed.join(', ')} outside allowedRegions ${constraint.allowedRegions.join(', ')}`));
    }
  }
  if (constraint.allowDestructive === false && context.destructive === true) {
    out.push(reason(REASON_CODES.DESTRUCTIVE_FORBIDDEN, `action ${action} is destructive and the matching scope forbids it`));
  }
  if (constraint.requireApproval === true && context.approvedBy == null) {
    out.push(reason(REASON_CODES.APPROVAL_REQUIRED, `scope ${scope.action}:${scope.resource} requires an approver identity in context.approvedBy`));
  }
  if (Array.isArray(constraint.allowedClouds) && context.cloud != null && !constraint.allowedClouds.includes(context.cloud)) {
    out.push(reason(REASON_CODES.REGION_NOT_ALLOWED, `cloud ${context.cloud} is not in allowedClouds ${constraint.allowedClouds.join(', ')}`));
  }
  return out;
}

export async function verifyIdentityLineage({ identity, resolve, trustAnchors = new Map(), maxDepth = MAX_DELEGATION_DEPTH }) {
  const path = [];
  const reasons = [];
  let current = identity;
  let depth = 0;
  while (true) {
    path.push(current.id);
    if (!(await verifyIdentitySelfBinding(current))) {
      reasons.push(reason(REASON_CODES.SELF_BINDING_INVALID, `${current.id} does not cryptographically bind its public key and attributes`));
      break;
    }
    if (!current.parent) {
      const anchor = trustAnchors.get(current.id);
      if (!anchor || anchor !== current.publicKey) {
        reasons.push(reason(REASON_CODES.LINEAGE_NOT_ANCHORED, `${current.id} is a root claim but is not a configured trust anchor`));
      }
      break;
    }
    depth += 1;
    if (depth > maxDepth) {
      reasons.push(reason(REASON_CODES.LINEAGE_TOO_DEEP, `delegation chain exceeds ${maxDepth} hops at ${current.id}`));
      break;
    }
    const parent = await resolve(current.parent.id);
    if (!parent) {
      reasons.push(reason(REASON_CODES.LINEAGE_UNRESOLVED, `issuer ${current.parent.id} is not present in the registry`));
      break;
    }
    if (!(await verifyIssuerLink(current, parent))) {
      reasons.push(reason(REASON_CODES.SELF_BINDING_INVALID, `issuer signature on ${current.id} does not verify under ${parent.id}`));
      break;
    }
    current = parent;
  }
  return { valid: reasons.length === 0, lineage: path, depth, reasons };
}

export { SEVERITY };

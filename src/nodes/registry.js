import { assertRevocationAuthority, createRevocation, verifyRevocation } from '../crypto/identity.js';

export class IdentityRegistry {
  constructor({ clients, eventBus = null, trustAnchors = new Map() }) {
    if (!Array.isArray(clients) || clients.length === 0) throw new Error('IdentityRegistry requires at least one node client');
    this.clients = clients;
    this.eventBus = eventBus;
    this.trustAnchors = trustAnchors;
  }

  async register(identity) {
    const results = await Promise.allSettled(this.clients.map((client) => client.putIdentity(identity)));
    const failed = results.filter((outcome) => outcome.status === 'rejected');
    if (failed.length > 0) {
      throw new Error(`identity ${identity.id} could not be replicated to ${failed.length} of ${this.clients.length} nodes`);
    }
    if (!identity.parent) this.trustAnchors.set(identity.id, identity.publicKey);
    this.eventBus?.publish('identity.registered', { id: identity.id, kind: identity.kind, parent: identity.parent?.id ?? null });
    return identity;
  }

  async get(id) {
    const outcomes = await Promise.allSettled(this.clients.map((client) => client.getIdentity(id)));
    const found = outcomes.filter((outcome) => outcome.status === 'fulfilled' && outcome.value).map((outcome) => outcome.value);
    if (found.length === 0) return null;
    const canonical = found[0];
    const disagreeing = found.filter((candidate) => candidate.selfSignature !== canonical.selfSignature);
    return { identity: canonical, copies: found.length, disagreement: disagreeing.length };
  }

  async require(id) {
    const resolved = await this.get(id);
    if (!resolved) throw new Error(`identity ${id} is not registered`);
    if (resolved.disagreement > 0) {
      throw new Error(`identity ${id} differs across ${resolved.disagreement} node copies; registry state is not trustworthy`);
    }
    return resolved.identity;
  }

  async list({ subjectKind = null } = {}) {
    const reports = await Promise.allSettled(this.clients.map((client) => client.listIdentities({ subjectKind })));
    const perNode = reports.filter((outcome) => outcome.status === 'fulfilled').map((outcome) => outcome.value);
    if (perNode.length < this.clients.length) {
      throw new Error(`only ${perNode.length} of ${this.clients.length} nodes reported their identity registry`);
    }
    const canonical = perNode[0];
    const canonicalIds = new Set(canonical.map((identity) => `${identity.id}:${identity.selfSignature}`));
    const divergent = perNode.slice(1).flatMap((node) => node.filter((identity) => !canonicalIds.has(`${identity.id}:${identity.selfSignature}`)));
    return { identities: canonical, nodesReporting: perNode.length, divergent };
  }

  // Trust anchors live in memory, so a restarted process has to rebuild them
  // from the stored documents: an identity with no issuer is a root. Doing this
  // before the coordinator registers also makes putIdentity's rebind guard
  // effective against a store whose root key was edited while the node was down.
  async hydrateAnchors() {
    const listed = await this.list();
    for (const identity of listed.identities) {
      if (identity.parent) continue;
      const anchored = this.trustAnchors.get(identity.id);
      if (anchored && anchored !== identity.publicKey) {
        throw new Error(`trust root ${identity.id} is stored under two public keys (${anchored.slice(0, 12)}… vs ${identity.publicKey.slice(0, 12)}…); refusing to anchor either`);
      }
      this.trustAnchors.set(identity.id, identity.publicKey);
    }
    return { anchors: [...this.trustAnchors.keys()], identities: listed.identities.length, nodesReporting: listed.nodesReporting, divergent: listed.divergent.length };
  }

  async revoke({ keyPair, identityId, reason, revokedBy = null }) {
    const target = await this.require(identityId);
    const entry = await createRevocation({ keyPair, identityId, reason, revokedBy });
    if (!(await verifyRevocation(entry))) throw new Error('revocation failed self-verification before publication');
    const authority = assertRevocationAuthority(entry, target);
    if (!authority.ok) throw new Error(`refusing to publish revocation for ${identityId}: ${authority.reason}`);
    const results = await Promise.allSettled(this.clients.map((client) => client.putRevocation(entry)));
    const failed = results.filter((outcome) => outcome.status === 'rejected');
    if (failed.length > 0) throw new Error(`revocation reached only ${results.length - failed.length} of ${results.length} nodes; refusing to report success`);
    this.eventBus?.publish('identity.revoked', { identityId, revocationId: entry.revocationId, reason, revokedBy: entry.revokedBy });
    return entry;
  }

  async revocationsFor(identityId) {
    const reports = await Promise.allSettled(this.clients.map((client) => client.listRevocations(identityId)));
    const perNode = reports.filter((outcome) => outcome.status === 'fulfilled').map((outcome) => outcome.value);
    const merged = new Map();
    for (const list of perNode) for (const entry of list) merged.set(entry.revocationId, entry);
    const validated = [];
    for (const entry of merged.values()) {
      validated.push({ entry, authentic: await verifyRevocation(entry) });
    }
    validated.sort((a, b) => Date.parse(a.entry.revokedAt) - Date.parse(b.entry.revokedAt));
    return { revocations: validated.filter((v) => v.authentic).map((v) => v.entry), forged: validated.filter((v) => !v.authentic).map((v) => v.entry), nodesReporting: perNode.length };
  }
}

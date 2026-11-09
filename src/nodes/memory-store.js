import { assertRecordLayering } from '../ledger/chain.js';
function bySeq(entries) {
  return [...entries].sort((a, b) => a.seq - b.seq);
}

export class MemoryStore {
  constructor({ name = 'memory' } = {}) {
    this.name = name;
    this.heads = new Map();
    this.chain = new Map();
    this.records = new Map();
    this.identities = new Map();
    this.revocations = [];
    this.meta = new Map();
    this.writeCount = 0;
  }

  async getHead(nodeId) {
    return this.heads.get(nodeId) ?? null;
  }

  async putHead(nodeId, head) {
    this.heads.set(nodeId, head);
    this.writeCount += 1;
  }

  async putChainEntry(nodeId, entry) {
    const key = `${nodeId}:${entry.seq}`;
    if (this.chain.has(key)) throw new Error(`chain entry ${key} already committed; ledger is append-only`);
    this.chain.set(key, structuredClone(entry));
    this.writeCount += 1;
  }

  async getChainEntry(nodeId, seq) {
    return this.chain.get(`${nodeId}:${seq}`) ?? null;
  }

  async listChainEntries(nodeId, from = 1, to = null) {
    const out = [];
    for (const [key, entry] of this.chain) {
      if (!key.startsWith(`${nodeId}:`)) continue;
      if (entry.seq < from) continue;
      if (to !== null && entry.seq > to) continue;
      out.push(entry);
    }
    return bySeq(out);
  }

  async putRecord(record) {
    const hash = record.recordHash;
    if (!hash) throw new Error('putRecord requires recordHash');
    assertRecordLayering(this.records.get(hash), record);
    this.records.set(hash, structuredClone(record));
    this.writeCount += 1;
  }

  async getRecord(recordHash) {
    return this.records.get(recordHash) ?? null;
  }

  async listRecords({ limit = 100, offset = 0, agentId = null, from = null, to = null, authorized = null } = {}) {
    let list = [...this.records.values()];
    if (agentId) list = list.filter((r) => r.agentId === agentId);
    if (authorized !== null) list = list.filter((r) => Boolean(r.verification?.authorized) === authorized);
    if (from) list = list.filter((r) => Date.parse(r.executedAt) >= Date.parse(from));
    if (to) list = list.filter((r) => Date.parse(r.executedAt) <= Date.parse(to));
    list.sort((a, b) => a.seq - b.seq);
    return list.slice(offset, offset + limit);
  }

  async countRecords(filter = {}) {
    return (await this.listRecords({ ...filter, limit: Number.MAX_SAFE_INTEGER })).length;
  }

  async putIdentity(identity) {
    this.identities.set(identity.id, structuredClone(identity));
    this.writeCount += 1;
  }

  async getIdentity(id) {
    return this.identities.get(id) ?? null;
  }

  async listIdentities({ subjectKind = null } = {}) {
    let list = [...this.identities.values()];
    if (subjectKind) list = list.filter((i) => i.kind === subjectKind);
    return list;
  }

  async putRevocation(revocation) {
    if (this.revocations.some((r) => r.revocationId === revocation.revocationId)) return;
    this.revocations.push(structuredClone(revocation));
    const identity = this.identities.get(revocation.identityId);
    if (identity) this.identities.set(identity.id, { ...identity, revokedAt: revocation.revokedAt, revocationReason: revocation.reason });
    this.writeCount += 1;
  }

  async listRevocations(agentId = null) {
    return agentId ? this.revocations.filter((r) => r.identityId === agentId) : [...this.revocations];
  }

  async getMeta(key) {
    return this.meta.get(key) ?? null;
  }

  async putMeta(key, value) {
    this.meta.set(key, structuredClone(value));
    this.writeCount += 1;
  }

  async snapshot() {
    return {
      heads: [...this.heads],
      chain: [...this.chain],
      records: [...this.records],
      identities: [...this.identities],
      revocations: this.revocations,
      meta: [...this.meta],
    };
  }
}

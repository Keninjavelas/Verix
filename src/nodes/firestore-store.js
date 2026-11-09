import { assertRecordLayering } from '../ledger/chain.js';
const COLLECTIONS = {
  records: 'verix_records',
  chain: 'verix_chain',
  identities: 'verix_identities',
  heads: 'verix_heads',
  revocations: 'verix_revocations',
  meta: 'verix_meta',
};

async function loadFirestore(projectId = null) {
  try {
    const module = await import('@google-cloud/firestore');
    return new module.Firestore(projectId ? { projectId } : {});
  } catch (error) {
    if (error?.code === 'ERR_MODULE_NOT_FOUND') {
      throw new Error('the GCP node requires the optional SDK: run `npm install @google-cloud/firestore` and configure GOOGLE_APPLICATION_CREDENTIALS');
    }
    throw error;
  }
}

function alreadyExists(error) {
  return error?.code === 6 || error?.code === 'ALREADY_EXISTS' || /already exists/i.test(String(error?.message));
}

export class FirestoreStore {
  constructor({ firestore, projectId = null, collections = COLLECTIONS, name = 'gcp-firestore' } = {}) {
    this.name = name;
    this.collections = { ...COLLECTIONS, ...collections };
    this.db = firestore ?? null;
    this.projectId = projectId;
    this.ready = firestore ? Promise.resolve(firestore) : loadFirestore(projectId);
  }

  async client() {
    if (!this.db) this.db = await this.ready;
    return this.db;
  }

  collection(name) {
    return this.collections[name];
  }

  async getHead(nodeId) {
    const db = await this.client();
    const snapshot = await db.collection(this.collection('heads')).doc(nodeId).get();
    return snapshot.exists ? snapshot.data() : null;
  }

  async putHead(nodeId, head) {
    const db = await this.client();
    await db.collection(this.collection('heads')).doc(nodeId).set(head);
  }

  async putChainEntry(nodeId, entry) {
    const db = await this.client();
    const ref = db.collection(this.collection('chain')).doc(`${nodeId}__${entry.seq}`);
    try {
      await ref.create(entry);
    } catch (error) {
      if (!alreadyExists(error)) throw error;
      const existing = await ref.get();
      if (JSON.stringify(existing.data()) !== JSON.stringify(entry)) {
        throw new Error(`chain entry ${nodeId}:${entry.seq} already committed with different content`);
      }
    }
  }

  async getChainEntry(nodeId, seq) {
    const db = await this.client();
    const snapshot = await db.collection(this.collection('chain')).doc(`${nodeId}__${seq}`).get();
    return snapshot.exists ? snapshot.data() : null;
  }

  async listChainEntries(nodeId, from = 1, to = null) {
    const db = await this.client();
    const pageSize = 500;
    const gathered = [];
    let cursor = null;
    for (;;) {
      let query = db.collection(this.collection('chain')).where('nodeId', '==', nodeId).where('seq', '>=', from).orderBy('seq');
      if (to !== null) query = query.where('seq', '<=', to);
      if (cursor) query = query.startAfter(cursor);
      const snapshot = await query.limit(pageSize).get();
      const docs = snapshot.docs;
      gathered.push(...docs.map((doc) => doc.data()));
      if (docs.length < pageSize) break;
      cursor = docs.at(-1);
    }
    return gathered;
  }

  async putRecord(record) {
    const db = await this.client();
    const ref = db.collection(this.collection('records')).doc(record.recordHash);
    try {
      await ref.create(record);
    } catch (error) {
      if (!alreadyExists(error)) throw error;
      const existing = await ref.get();
      assertRecordLayering(existing.data(), record);
      await ref.set(record);
    }
  }

  async getRecord(recordHash) {
    const db = await this.client();
    const snapshot = await db.collection(this.collection('records')).doc(recordHash).get();
    return snapshot.exists ? snapshot.data() : null;
  }

  async listRecords({ limit = 100, offset = 0, agentId = null, from = null, to = null, authorized = null } = {}) {
    const db = await this.client();
    let query = db.collection(this.collection('records'));
    if (agentId) query = query.where('agentId', '==', agentId);
    if (from) query = query.where('executedAt', '>=', from);
    if (to) query = query.where('executedAt', '<=', to);
    if (authorized !== null) query = query.where('verification.authorized', '==', authorized);
    query = query.orderBy('seq', 'asc');
    if (offset > 0) query = query.offset(offset);
    const snapshot = await query.limit(limit).get();
    return snapshot.docs.map((doc) => doc.data());
  }

  async countRecords(filter = {}) {
    const db = await this.client();
    let query = db.collection(this.collection('records'));
    if (filter.agentId) query = query.where('agentId', '==', filter.agentId);
    if (filter.authorized !== null && filter.authorized !== undefined) query = query.where('verification.authorized', '==', filter.authorized);
    const snapshot = await query.count().get();
    return Number(snapshot.data?.().count ?? 0);
  }

  async putIdentity(identity) {
    const db = await this.client();
    await db.collection(this.collection('identities')).doc(identity.id).set(identity);
  }

  async getIdentity(id) {
    const db = await this.client();
    const snapshot = await db.collection(this.collection('identities')).doc(id).get();
    return snapshot.exists ? snapshot.data() : null;
  }

  async listIdentities({ subjectKind = null } = {}) {
    const db = await this.client();
    let query = db.collection(this.collection('identities'));
    if (subjectKind) query = query.where('kind', '==', subjectKind);
    const snapshot = await query.get();
    return snapshot.docs.map((doc) => doc.data());
  }

  async putRevocation(revocation) {
    const db = await this.client();
    await db.collection(this.collection('revocations')).doc(revocation.revocationId).create(revocation);
    const identity = await this.getIdentity(revocation.identityId);
    if (identity) await this.putIdentity({ ...identity, revokedAt: revocation.revokedAt, revocationReason: revocation.reason });
  }

  async listRevocations(agentId = null) {
    const db = await this.client();
    let query = db.collection(this.collection('revocations'));
    if (agentId) query = query.where('identityId', '==', agentId);
    const snapshot = await query.get();
    return snapshot.docs.map((doc) => doc.data());
  }

  async getMeta(key) {
    const db = await this.client();
    const snapshot = await db.collection(this.collection('meta')).doc(key).get();
    return snapshot.exists ? snapshot.data().value : null;
  }

  async putMeta(key, value) {
    const db = await this.client();
    await db.collection(this.collection('meta')).doc(key).set({ value });
  }
}

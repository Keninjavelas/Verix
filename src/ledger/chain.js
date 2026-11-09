import { digestOf, fromB64u, toB64u, toBytes } from '../crypto/hash.js';
import { crossVerify, sign, verify } from '../crypto/pqc.js';
import { inclusionPath, merkleRoot, verifyInclusion } from './merkle.js';
import { verifyAssessment } from '../verification/assessment.js';

export const GENESIS_PREV_HASH = '0'.repeat(64);

// Fields a node or the coordinator writes onto a record *after* the payload has
// been hashed. Each of them is bound by its own signature (witness signatures
// for attestation data, the coordinator assessment for the trust layer) rather
// than by the payload commitment, because they do not exist when it is computed.
export const LAYERED_FIELDS = ['witnesses', 'replication', 'verification', 'timestamp', 'inclusionProof', 'trust', 'anomalies', 'assessment'];

const PAYLOAD_EXCLUDED_FIELDS = ['seq', 'entryHash', 'prevEntryHash', 'prevRecordHash', 'recordHash', 'chainSignature', 'replicatedAt', ...LAYERED_FIELDS];
const ENTRY_EXCLUDED_FIELDS = ['chainSignature', 'entryHash'];

function omit(value, fields) {
  const copy = { ...value };
  for (const field of fields) delete copy[field];
  return copy;
}

export function recordHashOf(record) {
  return digestOf(omit(record, PAYLOAD_EXCLUDED_FIELDS), 'verix:record:v1');
}

export function assertRecordLayering(existing, incoming) {
  if (!existing) return;
  const committed = recordHashOf(existing);
  const proposed = recordHashOf(incoming);
  if (committed !== proposed) {
    throw new Error(`record ${String(incoming.recordHash).slice(0, 12)} payload is immutable (committed ${short(committed)}, proposed ${short(proposed)}); only signature-bearing certification layers may be added`);
  }
}

export function entryHashOf(entry) {
  return digestOf(omit(entry, ENTRY_EXCLUDED_FIELDS), 'verix:chain-entry:v1');
}

export class ProofChain {
  constructor({ nodeId, store, keyPair, crossCheck = false, trustAnchors = null }) {
    if (!nodeId) throw new Error('ProofChain requires nodeId');
    if (!store) throw new Error('ProofChain requires store');
    if (!keyPair) throw new Error('ProofChain requires keyPair');
    this.nodeId = nodeId;
    this.store = store;
    this.keyPair = keyPair;
    this.crossCheck = crossCheck;
    this.trustAnchors = trustAnchors;
  }

  async head() {
    const head = await this.store.getHead(this.nodeId);
    if (head) return head;
    const genesis = {
      nodeId: this.nodeId,
      seq: 0,
      prevEntryHash: GENESIS_PREV_HASH,
      recordHash: GENESIS_PREV_HASH,
      root: merkleRoot([]),
      updatedAt: new Date(0).toISOString(),
    };
    genesis.entryHash = entryHashOf(genesis);
    genesis.chainSignature = toB64u(await sign(this.keyPair, toBytes(genesis.entryHash)));
    await this.store.putChainEntry(this.nodeId, genesis);
    await this.store.putHead(this.nodeId, headFrom(genesis));
    return headFrom(genesis);
  }

  async append(record) {
    const head = await this.head();
    const recordHash = record.recordHash ?? recordHashOf(record);
    const entry = {
      nodeId: this.nodeId,
      seq: head.seq + 1,
      prevEntryHash: head.lastEntryHash,
      prevRecordHash: head.lastRecordHash,
      recordHash,
      appendedAt: record.executedAt ?? new Date().toISOString(),
    };
    entry.entryHash = entryHashOf(entry);
    entry.chainSignature = toB64u(await sign(this.keyPair, toBytes(entry.entryHash)));
    const stored = { ...record, recordHash, seq: entry.seq, entryHash: entry.entryHash, prevEntryHash: entry.prevEntryHash };
    const hashes = await this.recordHashes();
    hashes.push(recordHash);
    await this.store.putChainEntry(this.nodeId, entry);
    await this.store.putRecord(stored);
    await this.store.putHead(this.nodeId, {
      nodeId: this.nodeId,
      seq: entry.seq,
      lastEntryHash: entry.entryHash,
      lastRecordHash: recordHash,
      root: merkleRoot(hashes),
      updatedAt: new Date().toISOString(),
    });
    return { entry, record: stored, recordHash };
  }

  async recordHashes({ from = 1, to = null } = {}) {
    const head = await this.head();
    const end = to ?? head.seq;
    if (end < from) return [];
    const entries = await this.store.listChainEntries(this.nodeId, from, end);
    return entries.map((entry) => entry.recordHash);
  }

  async verifyEntry(entry) {
    if (entryHashOf(entry) !== entry.entryHash) return false;
    const signature = fromB64u(entry.chainSignature);
    if (this.crossCheck && entry.seq > 0) {
      const cross = await crossVerify(this.keyPair.publicKey, toBytes(entry.entryHash), signature, entry.alg ?? this.keyPair.alg);
      if (!cross.viaJs || cross.viaWasm === false) return false;
      return true;
    }
    return verify(this.keyPair.alg, this.keyPair.publicKey, toBytes(entry.entryHash), signature);
  }

  async get(seq) {
    return this.store.getChainEntry(this.nodeId, seq);
  }

  async inclusionProof(seq) {
    const hashes = await this.recordHashes();
    const head = await this.head();
    if (seq < 1 || seq > hashes.length) throw new Error(`seq ${seq} is outside the chain of length ${hashes.length}`);
    return {
      nodeId: this.nodeId,
      seq,
      recordHash: hashes[seq - 1],
      treeSize: hashes.length,
      root: head.root,
      path: inclusionPath(hashes, seq - 1),
    };
  }

  async audit({ from = 1, to = null } = {}) {
    const head = await this.head();
    const end = to ?? head.seq;
    const entries = await this.store.listChainEntries(this.nodeId, from, end);
    const problems = [];
    const assessments = { verified: 0, invalid: 0, unsigned: 0 };
    let previous = await this.store.getChainEntry(this.nodeId, from - 1);
    for (const entry of entries) {
      const at = entry.seq;
      if (entryHashOf(entry) !== entry.entryHash) {
        problems.push({ seq: at, code: 'ENTRY_HASH_MISMATCH', detail: 'stored entryHash does not match recomputed canonical digest' });
      } else if (!(await this.verifyEntry(entry))) {
        problems.push({ seq: at, code: 'CHAIN_SIGNATURE_INVALID', detail: 'chain signature does not verify under the node key' });
      }
      const expectedPrev = previous ? previous.entryHash : GENESIS_PREV_HASH;
      if (entry.prevEntryHash !== expectedPrev) {
        problems.push({ seq: at, code: 'LINKAGE_BREAK', detail: `prevEntryHash ${short(entry.prevEntryHash)} does not match predecessor ${short(expectedPrev)}` });
      }
      const record = await this.store.getRecord(entry.recordHash);
      if (!record) {
        problems.push({ seq: at, code: 'RECORD_MISSING', detail: `record ${short(entry.recordHash)} is referenced by the chain but absent from the store` });
      } else if (recordHashOf(record) !== entry.recordHash) {
        problems.push({ seq: at, code: 'RECORD_TAMPERED', detail: `record ${short(entry.recordHash)} payload hash no longer matches the chain commitment` });
      } else if (record.assessment) {
        const checked = await verifyAssessment({
          record,
          resolve: async (id) => this.store.getIdentity(id),
          trustAnchors: this.trustAnchors,
          crossCheck: this.crossCheck,
        });
        if (checked.valid) assessments.verified += 1;
        else {
          assessments.invalid += 1;
          for (const issue of checked.problems) {
            problems.push({ seq: at, code: issue.code, detail: `${short(entry.recordHash)}: ${issue.detail}` });
          }
        }
      } else {
        assessments.unsigned += 1;
      }
      previous = entry;
    }
    const hashes = await this.recordHashes({ to: end });
    const recomputedRoot = merkleRoot(hashes);
    let rootChecked = false;
    if (end === head.seq) {
      rootChecked = true;
      if (recomputedRoot.toLowerCase() !== String(head.root).toLowerCase()) {
        problems.push({ seq: head.seq, code: 'ROOT_MISMATCH', detail: `head root ${short(head.root)} does not match recomputed ${short(recomputedRoot)}` });
      }
    }
    return { intact: problems.length === 0, nodeId: this.nodeId, auditedFrom: from, auditedTo: end, root: recomputedRoot, rootChecked, assessments, problems };
  }

  static checkInclusionProof(proof) {
    return verifyInclusion(proof.root, proof.recordHash, proof.seq - 1, proof.path);
  }
}

function headFrom(entry) {
  return {
    nodeId: entry.nodeId,
    seq: entry.seq,
    lastEntryHash: entry.entryHash,
    lastRecordHash: entry.recordHash,
    root: merkleRoot([]),
    updatedAt: entry.appendedAt ?? new Date(0).toISOString(),
  };
}

function short(hash) {
  return String(hash).slice(0, 12);
}

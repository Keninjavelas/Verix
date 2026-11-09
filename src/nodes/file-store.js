import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { MemoryStore } from './memory-store.js';

const COLLECTIONS = ['chain', 'records', 'identities', 'revocations', 'heads', 'meta'];

export class FileStore {
  constructor({ directory, name = 'file' } = {}) {
    if (!directory) throw new Error('FileStore requires a directory');
    this.directory = directory;
    this.name = name;
    if (!existsSync(directory)) mkdirSync(directory, { recursive: true });
    this.memory = new MemoryStore({ name });
    this.loaded = false;
  }

  fileFor(collection) {
    return join(this.directory, `${collection}.jsonl`);
  }

  async load() {
    if (this.loaded) return this;
    for (const collection of COLLECTIONS) {
      const path = this.fileFor(collection);
      if (!existsSync(path)) continue;
      for (const line of readFileSync(path, 'utf8').split('\n')) {
        if (line.trim().length === 0) continue;
        this.apply(collection, JSON.parse(line));
      }
    }
    this.loaded = true;
    return this;
  }

  apply(collection, row) {
    if (collection === 'chain') this.memory.chain.set(`${row.nodeId}:${row.seq}`, row);
    else if (collection === 'records') this.memory.records.set(row.recordHash, row);
    else if (collection === 'identities') this.memory.identities.set(row.id, row);
    else if (collection === 'revocations') this.memory.revocations.push(row);
    else if (collection === 'heads') this.memory.heads.set(row.nodeId, row);
    else if (collection === 'meta') this.memory.meta.set(row.key, row.value);
  }

  persist(collection, row) {
    appendFileSync(this.fileFor(collection), `${JSON.stringify(row)}\n`, 'utf8');
  }

  async getHead(nodeId) {
    await this.load();
    return this.memory.getHead(nodeId);
  }

  async putHead(nodeId, head) {
    await this.load();
    await this.memory.putHead(nodeId, head);
    this.persist('heads', head);
  }

  async putChainEntry(nodeId, entry) {
    await this.load();
    await this.memory.putChainEntry(nodeId, entry);
    this.persist('chain', entry);
  }

  async getChainEntry(nodeId, seq) {
    await this.load();
    return this.memory.getChainEntry(nodeId, seq);
  }

  async listChainEntries(nodeId, from = 1, to = null) {
    await this.load();
    return this.memory.listChainEntries(nodeId, from, to);
  }

  async putRecord(record) {
    await this.load();
    await this.memory.putRecord(record);
    this.persist('records', record);
  }

  async getRecord(recordHash) {
    await this.load();
    return this.memory.getRecord(recordHash);
  }

  async listRecords(filter) {
    await this.load();
    return this.memory.listRecords(filter);
  }

  async countRecords(filter) {
    await this.load();
    return this.memory.countRecords(filter);
  }

  async putIdentity(identity) {
    await this.load();
    await this.memory.putIdentity(identity);
    this.persist('identities', identity);
  }

  async getIdentity(id) {
    await this.load();
    return this.memory.getIdentity(id);
  }

  async listIdentities(filter) {
    await this.load();
    return this.memory.listIdentities(filter);
  }

  async putRevocation(revocation) {
    await this.load();
    await this.memory.putRevocation(revocation);
    this.persist('revocations', revocation);
  }

  async listRevocations(agentId) {
    await this.load();
    return this.memory.listRevocations(agentId);
  }

  async getMeta(key) {
    await this.load();
    return this.memory.getMeta(key);
  }

  async putMeta(key, value) {
    await this.load();
    await this.memory.putMeta(key, value);
    this.persist('meta', { key, value });
  }

  async compact() {
    for (const collection of COLLECTIONS) {
      const path = this.fileFor(collection);
      if (!existsSync(path)) continue;
      const latest = new Map();
      for (const line of readFileSync(path, 'utf8').split('\n')) {
        if (line.trim().length === 0) continue;
        const row = JSON.parse(line);
        const key = collectionKey(collection, row);
        latest.set(key, row);
      }
      writeFileSync(path, `${[...latest.values()].map((row) => JSON.stringify(row)).join('\n')}\n`, 'utf8');
    }
    return this;
  }
}

function collectionKey(collection, row) {
  if (collection === 'chain') return `${row.nodeId}:${row.seq}`;
  if (collection === 'records') return row.recordHash;
  if (collection === 'identities') return row.id;
  if (collection === 'heads') return row.nodeId;
  if (collection === 'meta') return row.key;
  return row.revocationId;
}

import { canonicalize, sha3_256, toHex } from '../crypto/hash.js';

const DIMENSIONS = 512;

const STOPWORDS = new Set([
  'a', 'an', 'and', 'are', 'was', 'were', 'be', 'been', 'is', 'it', 'its', 'of', 'on', 'in', 'to', 'at', 'for',
  'the', 'this', 'that', 'these', 'those', 'with', 'from', 'by', 'as', 'or', 'but', 'not', 'so', 'if', 'then',
  'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'can', 'could', 'should', 'about', 'which', 'who',
  'whom', 'whose', 'me', 'my', 'we', 'our', 'you', 'your', 'they', 'their', 'he', 'she', 'his', 'her', 'there',
  'here', 'when', 'where', 'why', 'how', 'any', 'all', 'some', 'more', 'most', 'other', 'just', 'please', 'show',
  'tell', 'give', 'list', 'many', 'much',
]);

/*
 * Actions and resources are structured identifiers ("deploy:infra", "infra:prod-eu-1").
 * Indexing them only as whole tokens means an operator asking about "deploy"
 * matches nothing, so each identifier is indexed both whole and decomposed.
 */
function tokenize(text) {
  const raw = String(text).toLowerCase().replace(/[^a-z0-9_:.\-]+/g, ' ').split(' ').filter((token) => token.length > 1);
  const tokens = [];
  for (const token of raw) {
    tokens.push(token);
    if (/[:._-]/.test(token)) {
      for (const piece of token.split(/[:._-]+/)) if (piece.length > 1 && piece !== token) tokens.push(piece);
    }
  }
  return tokens;
}

function charGrams(token, n = 4) {
  const padded = `^${token}$`;
  const grams = [];
  for (let i = 0; i + n <= padded.length; i += 1) grams.push(padded.slice(i, i + n));
  if (grams.length === 0) grams.push(padded);
  return grams;
}

function hashIndex(token) {
  const digest = sha3_256(token);
  return (digest[0] << 8 | digest[1]) % DIMENSIONS;
}

function gramsFor(tokens) {
  const grams = [];
  for (const token of tokens) {
    grams.push(token);
    for (const gram of charGrams(token)) grams.push(gram);
  }
  for (let i = 0; i + 1 < tokens.length; i += 1) grams.push(`${tokens[i]} ${tokens[i + 1]}`);
  return grams;
}

function embed(tokens) {
  const vector = new Float64Array(DIMENSIONS);
  for (const gram of gramsFor(tokens)) {
    const at = hashIndex(gram);
    const sign = (gram.charCodeAt(0) + gram.length) % 2 === 0 ? 1 : -1;
    vector[at] += sign;
  }
  let norm = 0;
  for (const value of vector) norm += value * value;
  norm = Math.sqrt(norm);
  if (norm > 0) for (let i = 0; i < DIMENSIONS; i += 1) vector[i] /= norm;
  return vector;
}

function cosine(a, b) {
  let sum = 0;
  for (let i = 0; i < DIMENSIONS; i += 1) sum += a[i] * b[i];
  return sum;
}

function termFrequencies(tokens) {
  const counts = new Map();
  for (const token of tokens) counts.set(token, (counts.get(token) ?? 0) + 1);
  return counts;
}

const STATUS_VOCABULARY = {
  trusted: 'trusted verified clean authorised authorized ok passed',
  flagged: 'flag flagged flags flagging anomaly suspicious attention warn warned untrusted',
  rejected: 'rejected reject rejects denial denied unauthorised unauthorized forbidden refused failed anomaly',
  unattested: 'unattested unverified unsigned quorum absence unattested',
};

function wordsOf(value) {
  return String(value ?? '').toLowerCase().split(/[^a-z0-9]+/).filter((word) => word.length > 1).join(' ');
}

function statusOf(record) {
  return record.trust?.status ?? (record.verification?.authorized === false ? 'rejected' : 'unknown');
}

function documentText(document) {
  return [
    document.agentId,
    document.action,
    wordsOf(document.action),
    document.resource,
    wordsOf(document.resource),
    document.status,
    document.statusWords,
    document.band,
    document.reason,
    document.identityName,
    document.anomalyCodes.join(' '),
    wordsOf(document.anomalyCodes.join(' ')),
    document.anomalySeverities.join(' '),
    document.signals.join(' '),
    document.policyCodes.join(' '),
    wordsOf(document.policyCodes.join(' ')),
    document.cloudCoverage.join(' '),
    document.nodeIds.join(' '),
    document.note ?? '',
  ].filter(Boolean).join(' ');
}

export class ProofIndex {
  constructor({ k1 = 1.4, b = 0.75 } = {}) {
    this.k1 = k1;
    this.b = b;
    this.documents = [];
    this.byId = new Map();
    this.idIndex = new Map();
    this.df = new Map();
    this.totalLength = 0;
  }

  static fromRecord(record, { identity = null, note = '' } = {}) {
    const proofId = record.recordHash ?? record.proofId;
    if (!proofId) throw new Error('ProofIndex.fromRecord requires recordHash or proofId');
    const status = statusOf(record);
    return {
      id: proofId,
      seq: record.seq ?? null,
      agentId: record.agentId,
      identityId: record.agentId,
      action: record.action,
      resource: record.resource,
      executedAt: record.executedAt,
      status,
      statusWords: STATUS_VOCABULARY[status] ?? '',
      band: record.trust?.band ?? null,
      score: record.trust?.score ?? null,
      reason: record.trust?.reason ?? null,
      signals: record.trust?.signals ?? [],
      anomalyCodes: (record.anomalies ?? []).map((anomaly) => anomaly.code),
      anomalySeverities: (record.anomalies ?? []).map((anomaly) => anomaly.severity),
      policyCodes: (record.policy?.reasons ?? []).map((entry) => entry.code),
      nodeIds: (record.witnesses ?? []).map((witness) => witness.nodeId),
      cloudCoverage: [...new Set((record.witnesses ?? []).map((witness) => witness.cloud))].sort(),
      identityName: identity?.subject?.name ?? null,
      note,
      canonical: canonicalize({ seq: record.seq, action: record.action, resource: record.resource, agentId: record.agentId, proofId }),
    };
  }

  add(document) {
    if (this.byId.has(document.id)) this.remove(document.id);
    const tokens = tokenize(documentText(document));
    const enriched = { ...document, tokens, length: tokens.length, vector: embed(tokens) };
    this.documents.push(enriched);
    this.byId.set(enriched.id, enriched);
    this.idIndex.set(String(enriched.id).toLowerCase(), enriched.id);
    this.totalLength += tokens.length;
    for (const term of new Set(tokens)) this.df.set(term, (this.df.get(term) ?? 0) + 1);
    return enriched;
  }

  /*
   * Proof identifiers are opaque hex, so BM25 can never rank them. Callers that
   * quote an identifier get the record by exact or prefix match instead.
   */
  findByIdentifier(needle, { minPrefix = 8 } = {}) {
    const key = String(needle).toLowerCase();
    const exact = this.idIndex.get(key);
    if (exact) return this.byId.get(exact) ?? null;
    if (key.length < minPrefix) return null;
    for (const [id, full] of this.idIndex) {
      if (id.startsWith(key)) return this.byId.get(full) ?? null;
    }
    return null;
  }

  remove(id) {
    const existing = this.byId.get(id);
    if (!existing) return false;
    this.byId.delete(id);
    this.idIndex.delete(String(id).toLowerCase());
    this.documents = this.documents.filter((document) => document.id !== id);
    this.totalLength -= existing.length;
    for (const term of new Set(existing.tokens)) {
      const next = (this.df.get(term) ?? 1) - 1;
      if (next <= 0) this.df.delete(term);
      else this.df.set(term, next);
    }
    return true;
  }

  clear() {
    this.documents = [];
    this.byId.clear();
    this.idIndex.clear();
    this.df.clear();
    this.totalLength = 0;
  }

  get size() {
    return this.documents.length;
  }

  stats() {
    return {
      documents: this.size,
      distinctTerms: this.df.size,
      averageLength: this.size === 0 ? 0 : Number((this.totalLength / this.size).toFixed(2)),
      embeddingDimensions: DIMENSIONS,
    };
  }

  search(query, { k = 8, semanticWeight = 0.45, filters = {} } = {}) {
    const all = tokenize(query);
    const meaningful = all.filter((token) => !STOPWORDS.has(token));
    const tokens = meaningful.length > 0 ? meaningful : all;
    if (tokens.length === 0 || this.size === 0) return [];
    const queryCounts = termFrequencies(tokens);
    const queryVector = embed(tokens);
    const averageLength = this.totalLength / this.size;
    const scored = [];
    for (const document of this.documents) {
      if (filters.agentId && document.agentId !== filters.agentId) continue;
      if (filters.status && document.status !== filters.status) continue;
      if (filters.action && document.action !== filters.action) continue;
      const counts = termFrequencies(document.tokens);
      let lexical = 0;
      for (const term of queryCounts.keys()) {
        const frequency = counts.get(term) ?? 0;
        if (frequency === 0) continue;
        const documentFrequency = this.df.get(term) ?? 1;
        const idf = Math.log(1 + (this.size - documentFrequency + 0.5) / (documentFrequency + 0.5));
        lexical += idf * (frequency * (this.k1 + 1)) / (frequency + this.k1 * (1 - this.b + this.b * document.length / averageLength));
      }
      const semantic = cosine(queryVector, document.vector);
      const score = lexical + semanticWeight * Math.max(0, semantic) * 4;
      if (score <= 0) continue;
      scored.push({ document, score, lexical, semantic, matched: [...queryCounts.keys()].filter((term) => counts.has(term)) });
    }
    scored.sort((a, b) => b.score - a.score || (b.document.seq ?? 0) - (a.document.seq ?? 0));
    return scored.slice(0, k).map((entry) => ({
      id: entry.document.id,
      seq: entry.document.seq,
      agentId: entry.document.agentId,
      action: entry.document.action,
      resource: entry.document.resource,
      status: entry.document.status,
      score: Number(entry.score.toFixed(4)),
      lexical: Number(entry.lexical.toFixed(4)),
      semantic: Number(entry.semantic.toFixed(4)),
      matched: entry.matched,
      document: { ...entry.document, tokens: undefined, vector: undefined },
    }));
  }

  async rebuildFrom(service, { limit = 1000, identities = new Map() } = {}) {
    const records = await service.primary.listRecords({ limit });
    this.clear();
    for (const record of records) {
      const identity = identities.get(record.agentId) ?? null;
      this.add(ProofIndex.fromRecord(record, { identity }));
    }
    return this.stats();
  }

  lookup(id) {
    const document = this.byId.get(id);
    if (!document) return null;
    const { tokens, vector, ...rest } = document;
    return rest;
  }
}

export function fingerprintOfIndex(documents) {
  return toHex(sha3_256(documents.map((document) => document.canonical ?? document.id).join('|')));
}

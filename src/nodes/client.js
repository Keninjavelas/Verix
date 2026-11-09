export class LocalNodeClient {
  constructor(node) {
    this.node = node;
  }

  get nodeId() {
    return this.node.nodeId;
  }

  get trustAnchors() {
    return this.node.trustAnchors;
  }

  async descriptor() {
    return this.node.descriptor();
  }

  async accept(submission) {
    return this.node.accept(submission);
  }

  async certify(payload) {
    return this.node.certify(payload);
  }

  async head() {
    return this.node.head();
  }

  async status() {
    return this.node.status();
  }

  async getRecord(recordHash) {
    return this.node.getRecord(recordHash);
  }

  async listRecords(filter) {
    return this.node.listRecords(filter);
  }

  async inclusionProof(seq) {
    return this.node.inclusionProof(seq);
  }

  async audit(range) {
    return this.node.audit(range);
  }

  async putIdentity(identity) {
    return this.node.putIdentity(identity);
  }

  async getIdentity(id) {
    return this.node.getIdentity(id);
  }

  async listIdentities(filter) {
    return this.node.listIdentities(filter);
  }

  async listRevocations(agentId) {
    return this.node.listRevocations(agentId);
  }

  async putRevocation(entry) {
    return this.node.putRevocation(entry);
  }
}

export class HttpNodeClient {
  constructor({ baseUrl, nodeId = null, fetch = globalThis.fetch, timeoutMs = 15_000, headers = {} }) {
    if (!baseUrl) throw new Error('HttpNodeClient requires baseUrl');
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.nodeId = nodeId;
    this.cloud = null;
    this.fetch = fetch;
    this.timeoutMs = timeoutMs;
    this.headers = headers;
  }

  async refresh() {
    const descriptor = await this.descriptor();
    this.nodeId = descriptor?.nodeId ?? this.nodeId;
    this.cloud = descriptor?.cloud ?? this.cloud;
    return descriptor;
  }

  async call(path, { method = 'GET', body } = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetch(`${this.baseUrl}${path}`, {
        method,
        headers: { 'content-type': 'application/json', ...this.headers },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
      });
      const text = await response.text();
      const payload = text.length > 0 ? JSON.parse(text) : null;
      if (!response.ok) {
        const detail = payload?.error?.message ?? `HTTP ${response.status}`;
        throw new Error(`node ${this.baseUrl}${path} responded ${response.status}: ${detail}`);
      }
      return payload;
    } finally {
      clearTimeout(timer);
    }
  }

  descriptor() {
    return this.call('/nodes/self');
  }

  accept(submission) {
    return this.call('/nodes/accept', { method: 'POST', body: submission });
  }

  certify(payload) {
    return this.call('/nodes/certify', { method: 'POST', body: payload });
  }

  head() {
    return this.call('/nodes/head');
  }

  status() {
    return this.call('/nodes/status');
  }

  async getRecord(recordHash) {
    const payload = await this.call(`/ledger/records/${recordHash}`);
    return payload?.record ?? null;
  }

  inclusionProof(seq) {
    return this.call(`/ledger/inclusion/${seq}`);
  }

  audit(range = {}) {
    return this.call('/ledger/audit', { method: 'POST', body: range });
  }

  putIdentity(identity) {
    return this.call('/identities', { method: 'POST', body: { identity } });
  }

  async getIdentity(id) {
    const payload = await this.call(`/identities/${encodeURIComponent(id)}`);
    return payload?.identity ?? null;
  }

  async listIdentities({ subjectKind = null } = {}) {
    const query = subjectKind ? `?kind=${encodeURIComponent(subjectKind)}` : '';
    const payload = await this.call(`/identities${query}`);
    return payload?.identities ?? [];
  }

  async listRecords({ agentId = null, limit = 200 } = {}) {
    const query = new URLSearchParams({ limit: String(limit) });
    if (agentId) query.set('agentId', agentId);
    const payload = await this.call(`/ledger/records?${query}`);
    return payload?.records ?? [];
  }

  async listRevocations(agentId = null) {
    if (!agentId) {
      const payload = await this.call('/revocations');
      return payload?.revocations ?? [];
    }
    const payload = await this.call(`/identities/${encodeURIComponent(agentId)}/revocations`);
    return payload?.revocations ?? [];
  }

  putRevocation(entry) {
    return this.call('/revocations', { method: 'POST', body: { revocation: entry } });
  }
}

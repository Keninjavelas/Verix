import { assertRecordLayering } from '../ledger/chain.js';
const TABLES = {
  records: 'verix_records',
  chain: 'verix_chain',
  identities: 'verix_identities',
  heads: 'verix_heads',
  revocations: 'verix_revocations',
  meta: 'verix_meta',
};

async function loadDocumentClient(region) {
  try {
    const { DynamoDBClient } = await import('@aws-sdk/client-dynamodb');
    const { DynamoDBDocumentClient } = await import('@aws-sdk/lib-dynamodb');
    const client = new DynamoDBClient(region ? { region } : {});
    return DynamoDBDocumentClient.from(client);
  } catch (error) {
    if (error?.code === 'ERR_MODULE_NOT_FOUND') {
      throw new Error('the AWS node requires the optional SDK: run `npm install @aws-sdk/client-dynamodb @aws-sdk/lib-dynamodb` and configure AWS credentials');
    }
    throw error;
  }
}

export class DynamoStore {
  constructor({ docClient, region = null, tables = TABLES, name = 'aws-dynamodb' } = {}) {
    this.name = name;
    this.region = region;
    this.tables = { ...TABLES, ...tables };
    this.docClient = docClient ?? null;
    this.ready = docClient ? Promise.resolve(docClient) : loadDocumentClient(region);
  }

  async client() {
    if (!this.docClient) this.docClient = await this.ready;
    return this.docClient;
  }

  async put(table, key, item) {
    const client = await this.client();
    await client.put({ TableName: this.tables[table], Item: { ...key, ...item }, ConditionExpression: 'attribute_not_exists(#pk)', ExpressionAttributeNames: { '#pk': Object.keys(key)[0] } });
  }

  async get(table, key) {
    const client = await this.client();
    const result = await client.get({ TableName: this.tables[table], Key: key, ConsistentRead: true });
    return result.Item ?? null;
  }

  async headKey(nodeId) {
    return this.get('heads', { nodeId });
  }

  async getHead(nodeId) {
    const item = await this.headKey(nodeId);
    if (!item) return null;
    const { nodeId: _drop, ...head } = item;
    return head;
  }

  async putHead(nodeId, head) {
    const client = await this.client();
    await client.put({ TableName: this.tables.heads, Item: { nodeId, ...head } });
  }

  async putChainEntry(nodeId, entry) {
    await this.put('chain', { nodeId, seq: entry.seq }, entry);
  }

  async getChainEntry(nodeId, seq) {
    return this.get('chain', { nodeId, seq });
  }

  async listChainEntries(nodeId, from = 1, to = null) {
    const client = await this.client();
    const params = {
      TableName: this.tables.chain,
      KeyConditionExpression: 'nodeId = :node AND #seq >= :from',
      ExpressionAttributeNames: { '#seq': 'seq' },
      ExpressionAttributeValues: { ':node': nodeId, ':from': from },
      ScanIndexForward: true,
    };
    if (to !== null) {
      params.KeyConditionExpression += ' AND #seq <= :to';
      params.ExpressionAttributeValues[':to'] = to;
    }
    const pages = [];
    let ExclusiveStartKey = undefined;
    do {
      const page = await client.query({ ...params, ExclusiveStartKey });
      pages.push(...(page.Items ?? []));
      ExclusiveStartKey = page.LastEvaluatedKey;
    } while (ExclusiveStartKey);
    return pages.sort((a, b) => a.seq - b.seq);
  }

  async putRecord(record) {
    assertRecordLayering(await this.get('records', { recordHash: record.recordHash }), record);
    const client = await this.client();
    await client.put({ TableName: this.tables.records, Item: record });
  }

  async getRecord(recordHash) {
    return this.get('records', { recordHash });
  }

  async listRecords({ limit = 100, offset = 0, agentId = null, from = null, to = null, authorized = null } = {}) {
    const client = await this.client();
    const params = { TableName: this.tables.records };
    if (agentId) {
      params.IndexName = 'agentId-executedAt-index';
      params.KeyConditionExpression = 'agentId = :agent';
      params.ExpressionAttributeValues = { ':agent': agentId };
    }
    const pages = [];
    let ExclusiveStartKey = undefined;
    do {
      const page = agentId ? await client.query({ ...params, ExclusiveStartKey }) : await client.scan({ ...params, ExclusiveStartKey });
      pages.push(...(page.Items ?? []));
      ExclusiveStartKey = page.LastEvaluatedKey;
    } while (ExclusiveStartKey && pages.length < offset + limit);
    let list = pages;
    if (from) list = list.filter((r) => Date.parse(r.executedAt) >= Date.parse(from));
    if (to) list = list.filter((r) => Date.parse(r.executedAt) <= Date.parse(to));
    if (authorized !== null) list = list.filter((r) => Boolean(r.verification?.authorized) === authorized);
    return list.sort((a, b) => a.seq - b.seq).slice(offset, offset + limit);
  }

  async countRecords(filter = {}) {
    return (await this.listRecords({ ...filter, limit: Number.MAX_SAFE_INTEGER })).length;
  }

  async putIdentity(identity) {
    const client = await this.client();
    await client.put({ TableName: this.tables.identities, Item: identity });
  }

  async getIdentity(id) {
    return this.get('identities', { id });
  }

  async listIdentities({ subjectKind = null } = {}) {
    const client = await this.client();
    const pages = [];
    let ExclusiveStartKey = undefined;
    do {
      const page = await client.scan({ TableName: this.tables.identities, ExclusiveStartKey });
      pages.push(...(page.Items ?? []));
      ExclusiveStartKey = page.LastEvaluatedKey;
    } while (ExclusiveStartKey);
    return subjectKind ? pages.filter((i) => i.kind === subjectKind) : pages;
  }

  async putRevocation(revocation) {
    const client = await this.client();
    await client.put({
      TableName: this.tables.revocations,
      Item: revocation,
      ConditionExpression: 'attribute_not_exists(revocationId)',
    });
    const identity = await this.getIdentity(revocation.identityId);
    if (identity) await this.putIdentity({ ...identity, revokedAt: revocation.revokedAt, revocationReason: revocation.reason });
  }

  async listRevocations(agentId = null) {
    const client = await this.client();
    if (agentId) {
      const page = await client.query({
        TableName: this.tables.revocations,
        KeyConditionExpression: 'identityId = :agent',
        ExpressionAttributeValues: { ':agent': agentId },
      });
      return page.Items ?? [];
    }
    const pages = [];
    let ExclusiveStartKey = undefined;
    do {
      const page = await client.scan({ TableName: this.tables.revocations, ExclusiveStartKey });
      pages.push(...(page.Items ?? []));
      ExclusiveStartKey = page.LastEvaluatedKey;
    } while (ExclusiveStartKey);
    return pages;
  }

  async getMeta(key) {
    const item = await this.get('meta', { key });
    if (!item) return null;
    const { key: _drop, value } = item;
    return value;
  }

  async putMeta(key, value) {
    const client = await this.client();
    await client.put({ TableName: this.tables.meta, Item: { key, value } });
  }
}

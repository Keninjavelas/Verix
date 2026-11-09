import test, { describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../src/config.js';
import { createPlatform } from '../src/platform.js';
import { ProofIndex, fingerprintOfIndex } from '../src/intelligence/rag.js';
import { classifyIntent, extractEntities, INTENTS, TrustCopilot } from '../src/intelligence/copilot.js';
import { evidenceBlock, systemPrompt, llmProviderFrom, HttpLlmProvider } from '../src/intelligence/llm.js';

const NODE_PLAN = [
  { nodeId: 'verix-node-aws-1', cloud: 'aws', region: 'us-east-1', backend: 'memory' },
  { nodeId: 'verix-node-gcp-1', cloud: 'gcp', region: 'us-central1', backend: 'memory' },
  { nodeId: 'verix-node-edge-1', cloud: 'local', region: 'local', backend: 'memory' },
];

const settled = () => new Promise((resolve) => setImmediate(resolve));
const head = (value) => String(value).slice(0, 8);
const lines = (answer) => answer.split('\n');

// The synthetic documents below are the ones every retrieval number in this file was
// measured against: fixed identifiers keep BM25 (which reads document lengths and
// document frequencies) and the hash embedding reproducible.
const doc = (overrides = {}) => ({
  id: 'a'.repeat(64),
  seq: 1,
  agentId: 'verix:agent:aaa',
  action: 'read:logs',
  resource: 'logs:app',
  status: 'trusted',
  statusWords: '',
  band: 'high-trust',
  score: 96.4,
  reason: null,
  signals: [],
  anomalyCodes: [],
  anomalySeverities: [],
  policyCodes: [],
  nodeIds: [],
  cloudCoverage: [],
  identityName: null,
  note: '',
  ...overrides,
});

const divergentDoc = doc({
  id: 'b'.repeat(64),
  seq: 2,
  agentId: 'verix:agent:bbb',
  action: 'deploy:infra',
  resource: 'infra:prod-eu-1',
  status: 'flagged',
  anomalyCodes: ['REPLICATION_DIVERGENCE'],
  anomalySeverities: ['critical'],
  policyCodes: ['NO_SCOPE_MATCH'],
  nodeIds: ['n1', 'n2'],
  cloudCoverage: ['aws', 'gcp'],
  identityName: 'Deploy-Bot',
  reason: 'cross-cloud roots disagree',
});

function twoDocIndex() {
  const index = new ProofIndex();
  index.add(doc());
  index.add(divergentDoc);
  return index;
}

test('the copilot routes a question to one intent, in pattern order, and says how sure it is', () => {
  assert.deepEqual(classifyIntent('why was the deploy flagged'), { intent: 'why-flagged', pattern: '/why .*(flag|reject|denied|fail)/i', confidence: 0.9 });
  assert.equal(classifyIntent('why did the verification fail').intent, 'why-flagged');
  assert.equal(classifyIntent('what caused the anomaly here').intent, 'why-flagged');
  assert.equal(classifyIntent('explain the rejection').intent, 'why-flagged');
  assert.equal(classifyIntent('was agent-1 authorized').intent, 'authorization-check');
  assert.equal(classifyIntent('had the runner got permission').intent, 'authorization-check');
  assert.equal(classifyIntent('was it allowed to run deploy:infra').intent, 'authorization-check');
  assert.equal(classifyIntent('trace the sequence for agent-1').intent, 'trace-sequence');
  assert.equal(classifyIntent('what is the lineage of this proof').intent, 'trace-sequence');
  assert.equal(classifyIntent('what happened before the deploy').intent, 'trace-sequence');
  assert.equal(classifyIntent('replay the last hour').intent, 'trace-sequence');
  assert.equal(classifyIntent('explain the trust score').intent, 'score-explain');
  assert.equal(classifyIntent('give me a breakdown of proof x').intent, 'score-explain');
  assert.equal(classifyIntent('how many proofs are there').intent, 'status-summary');
  assert.equal(classifyIntent('current state of the fleet').intent, 'status-summary');
  assert.equal(classifyIntent('overview').intent, 'status-summary');
  assert.equal(classifyIntent('fleet status').intent, 'status-summary');
});

test('an unrecognised question falls back to retrieval, and the first matching pattern wins', () => {
  assert.deepEqual(classifyIntent('which proofs touch infra in prod'), { intent: 'search', pattern: null, confidence: 0.5 });
  // "why … score" also matches the score-explain pattern, but why-flagged is listed first.
  assert.equal(classifyIntent('why was it flagged').intent, INTENTS.WHY_FLAGGED);
  // A question that asks for a summary and a trace gets the earlier intent, not the later one.
  assert.equal(classifyIntent('summary of the trace').intent, INTENTS.TRACE_SEQUENCE);
  assert.deepEqual(Object.values(INTENTS), ['why-flagged', 'authorization-check', 'trace-sequence', 'score-explain', 'status-summary', 'search']);
});

test('entities are lifted out of the question so a quoted proof beats any ranking', () => {
  const proofId = '8867033b994c38b2787e378efdc5d124';
  const second = 'ffffffffffffffffffffffffffffffff';
  const parsed = extractEntities(`why was ${proofId} and ${second} flagged for agent-7 seq 42 running deploy:infra, was it a delete in the last 24h?`);
  assert.deepEqual(parsed.proofIds, [proofId, second]);
  assert.deepEqual(parsed.agentRefs, ['agent-7']);
  assert.equal(parsed.sequence, 42);
  assert.deepEqual(parsed.actions, ['deploy:infra', 'delete']);
  assert.equal(parsed.destructive, true);
  assert.equal(parsed.windowHours, 24);

  const bare = extractEntities('how many proofs are there?');
  assert.deepEqual(bare, { proofIds: [], agentRefs: [], sequence: null, actions: [], destructive: false, windowHours: null });

  assert.equal(extractEntities('sequence 7 of verix:agent:9XRqTF5ybXiW').sequence, 7);
  assert.deepEqual(extractEntities('verix:agent:9XRqTF5ybXiW').agentRefs, ['verix:agent:9XRqTF5ybXiW']);
  // 15 hex characters is below the 16 the identifier pattern requires.
  assert.deepEqual(extractEntities('deadbeefdeadbee').proofIds, []);
  assert.deepEqual(extractEntities('deadbeefdeadbee1').proofIds, ['deadbeefdeadbee1']);
  assert.deepEqual(extractEntities('scale up the cluster').actions, ['scale']);
  assert.equal(extractEntities('read the logs of the refund').destructive, false);
});

test('an empty index reports itself as empty and retrieves nothing', () => {
  const index = new ProofIndex();
  assert.deepEqual(index.stats(), { documents: 0, distinctTerms: 0, averageLength: 0, embeddingDimensions: 512 });
  assert.equal(index.size, 0);
  assert.deepEqual(index.search('read logs'), []);
  assert.equal(index.lookup('nope'), null);
  assert.equal(index.findByIdentifier('nope'), null);
  assert.equal(index.remove('nope'), false);
});

test('indexing keeps per-term document frequencies and reverses them exactly on remove', () => {
  const index = twoDocIndex();
  assert.deepEqual(index.stats(), { documents: 2, distinctTerms: 41, averageLength: 31.5, embeddingDimensions: 512 });
  assert.equal(index.size, 2);
  assert.equal(index.df.get('logs'), 1, 'only the read:logs document holds that term');
  assert.equal(index.df.get('deploy'), 1);
  assert.equal(index.byId.get('a'.repeat(64)).length, 18, 'tokens are counted once per document');

  const replaced = index.add(doc({ score: 50 }));
  assert.equal(index.size, 2, 're-adding an identifier replaces the document instead of duplicating it');
  assert.equal(replaced.score, 50);
  assert.equal(index.df.get('logs'), 1, 'the document frequency did not double');

  assert.equal(index.remove('b'.repeat(64)), true);
  assert.deepEqual(index.stats(), { documents: 1, distinctTerms: 13, averageLength: 18, embeddingDimensions: 512 });
  assert.equal(index.df.get('deploy'), undefined, 'a term that only the removed document carried is dropped');
  assert.equal(index.df.get('logs'), 1);
  assert.equal(index.remove('b'.repeat(64)), false, 'removing twice is a no-op, not a negative count');
  assert.equal(index.findByIdentifier('b'.repeat(64)), null);

  index.clear();
  assert.deepEqual(index.stats(), { documents: 0, distinctTerms: 0, averageLength: 0, embeddingDimensions: 512 });
  assert.deepEqual(index.documents, []);
});

test('structured identifiers are indexed whole and decomposed, so partial words retrieve', () => {
  const index = twoDocIndex();
  const lookups = Object.fromEntries([
    'read logs',
    'logs',
    'deploy',
    'infra',
    'prod',
    'eu',
    'Deploy-Bot',
    'divergence',
    'REPLICATION_DIVERGENCE',
    'aws',
  ].map((query) => [query, index.search(query).map((hit) => [head(hit.id), hit.lexical, hit.matched])]));

  assert.deepEqual(lookups['read logs'], [['aaaaaaaa', 2.4721, ['read', 'logs']]]);
  assert.deepEqual(lookups['logs'], [['aaaaaaaa', 1.3443, ['logs']]]);
  // "prod" and "eu" are never written alone: they come from infra:prod-eu-1.
  assert.deepEqual(lookups['prod'], [['bbbbbbbb', 0.8642, ['prod']]]);
  assert.deepEqual(lookups['eu'], [['bbbbbbbb', 0.8642, ['eu']]]);
  // The identity name is indexed too, and a hyphenated name matches on both halves.
  assert.deepEqual(lookups['Deploy-Bot'], [['bbbbbbbb', 2.1964, ['deploy-bot', 'deploy', 'bot']]]);
  assert.deepEqual(lookups['aws'], [['bbbbbbbb', 0.5837, ['aws']]], 'cloud coverage is searchable');
  assert.deepEqual(lookups['REPLICATION_DIVERGENCE'][0], ['bbbbbbbb', 2.3121, ['replication_divergence', 'replication', 'divergence']]);
  assert.deepEqual(lookups['divergence'].map((hit) => hit[0]), ['bbbbbbbb', 'aaaaaaaa']);
  assert.deepEqual(lookups['divergence'][1][2], [], 'the other document matched on embedding only, so it recorded no lexical term');
});

test('stopwords carry no lexical signal, but an embedding match still retrieves', () => {
  const index = twoDocIndex();
  assert.deepEqual(index.search('the of and'), [], 'every token is a stopword and the fallback embedding points at nothing either');
  assert.deepEqual(index.search('nonsense zzz'), []);
  assert.deepEqual(index.search(''), []);

  const only = index.search('how many proofs are there');
  assert.deepEqual(only.map((hit) => [head(hit.id), hit.lexical, hit.matched]), [['bbbbbbbb', 0, []]], '"proofs" is in no document, so this hit is the embedding alone');
  assert.ok(only[0].semantic > 0);
  assert.deepEqual(index.search('what are the logs').map((hit) => [head(hit.id), hit.lexical]), [['aaaaaaaa', 1.3443]], 'the one content term does all of the lexical work');
});

test('results are ranked, capped by k, and broken by sequence newest first', () => {
  const index = twoDocIndex();
  const hits = index.search('deploy infra divergence', { k: 8 });
  assert.equal(hits[0].id, 'b'.repeat(64), 'the document that matches more query terms ranks first');
  assert.ok(hits[0].lexical > (hits[1]?.lexical ?? 0));
  assert.deepEqual(index.search('logs', { k: 1 }).map((hit) => head(hit.id)), ['aaaaaaaa']);

  // Three documents with identical text can only be ordered by the tie-break.
  const tied = new ProofIndex();
  tied.add(doc({ id: '1'.repeat(64) }));
  tied.add(doc({ id: '2'.repeat(64), seq: 2 }));
  tied.add(doc({ id: '3'.repeat(64), seq: 3 }));
  const results = tied.search('logs');
  assert.deepEqual(results.map((hit) => [head(hit.id), hit.seq]), [['33333333', 3], ['22222222', 2], ['11111111', 1]], 'equal scores fall to descending sequence');
  assert.equal(new Set(results.map((hit) => hit.score)).size, 1, 'the identifier is not part of the document text, so all three score the same');
  assert.deepEqual(tied.search('logs', { k: 2 }).map((hit) => head(hit.id)), ['33333333', '22222222']);

  const hit = index.search('logs')[0];
  assert.deepEqual(Object.keys(hit), ['id', 'seq', 'agentId', 'action', 'resource', 'status', 'score', 'lexical', 'semantic', 'matched', 'document']);
  assert.equal(hit.document.action, 'read:logs');
  assert.equal(hit.document.tokens, undefined, 'a search hit blanks the derived fields rather than handing back the whole index entry');
  assert.equal(hit.document.vector, undefined);
  assert.deepEqual(Object.keys(hit.document).sort(), ['action', 'agentId', 'anomalyCodes', 'anomalySeverities', 'band', 'cloudCoverage', 'id', 'identityName', 'length', 'nodeIds', 'note', 'policyCodes', 'reason', 'resource', 'score', 'seq', 'signals', 'status', 'statusWords', 'tokens', 'vector']);
  assert.deepEqual(Object.keys(index.lookup('a'.repeat(64))).sort(), Object.keys(hit.document).sort().filter((key) => key !== 'tokens' && key !== 'vector'), 'lookup drops the keys instead of blanking them');
  assert.equal(index.lookup('a'.repeat(64)).action, 'read:logs');
  assert.equal(index.lookup('nope'), null);
});

test('filters drop documents before they can be scored', () => {
  const index = twoDocIndex();
  const ids = (query, filters) => index.search(query, { filters }).map((hit) => head(hit.id));
  assert.deepEqual(ids('deploy logs').sort(), ['aaaaaaaa', 'bbbbbbbb']);
  assert.deepEqual(ids('deploy logs', { agentId: 'verix:agent:bbb' }), ['bbbbbbbb']);
  assert.deepEqual(ids('deploy logs', { status: 'trusted' }), ['aaaaaaaa']);
  assert.deepEqual(ids('deploy logs', { action: 'read:logs' }), ['aaaaaaaa']);
  assert.deepEqual(ids('deploy logs', { agentId: 'verix:agent:aaa', status: 'flagged' }), [], 'contradictory filters retrieve nothing');
  assert.deepEqual(ids('deploy logs', { agentId: 'verix:agent:zzz' }), []);
});

test('a quoted proof identifier is looked up exactly or by prefix, never by BM25', () => {
  const index = twoDocIndex();
  assert.equal(head(index.findByIdentifier('b'.repeat(64)).id), 'bbbbbbbb');
  assert.equal(head(index.findByIdentifier('B'.repeat(64)).id), 'bbbbbbbb', 'identifiers are case-insensitive');
  assert.equal(head(index.findByIdentifier('bbbbbbbb').id), 'bbbbbbbb', 'eight characters is the shortest usable prefix');
  assert.equal(index.findByIdentifier('bbbbbbbb1234'), null, 'a prefix that is not one does not resolve');
  assert.equal(index.findByIdentifier('bbbbbbb'), null, 'seven characters is refused rather than guessed');
  assert.equal(index.findByIdentifier('c'.repeat(64)), null);
});

test('fromRecord turns a ledger record into a searchable document', () => {
  const document = ProofIndex.fromRecord({
    recordHash: 'd'.repeat(64),
    seq: 7,
    agentId: 'verix:agent:ddd',
    action: 'scale:cluster',
    resource: 'cluster:eu',
    executedAt: '2026-11-09T00:00:00.000Z',
    trust: { status: 'flagged', band: 'review', score: 35, reason: 'cap', signals: ['s1'] },
    anomalies: [{ code: 'REPLICATION_DIVERGENCE', severity: 'critical', detail: 'x' }],
    policy: { reasons: [{ code: 'SCOPE_OK', severity: 'allow', detail: 'y' }] },
    witnesses: [{ nodeId: 'n2', cloud: 'gcp' }, { nodeId: 'n1', cloud: 'aws' }, { nodeId: 'n3', cloud: 'aws' }],
  }, { identity: { subject: { name: 'Scale-Bot' } }, note: 'from record' });

  assert.deepEqual(document, {
    id: 'd'.repeat(64),
    seq: 7,
    agentId: 'verix:agent:ddd',
    identityId: 'verix:agent:ddd',
    action: 'scale:cluster',
    resource: 'cluster:eu',
    executedAt: '2026-11-09T00:00:00.000Z',
    status: 'flagged',
    statusWords: 'flag flagged flags flagging anomaly suspicious attention warn warned untrusted',
    band: 'review',
    score: 35,
    reason: 'cap',
    signals: ['s1'],
    anomalyCodes: ['REPLICATION_DIVERGENCE'],
    anomalySeverities: ['critical'],
    policyCodes: ['SCOPE_OK'],
    nodeIds: ['n2', 'n1', 'n3'],
    cloudCoverage: ['aws', 'gcp'],
    identityName: 'Scale-Bot',
    note: 'from record',
    canonical: '{"action":"scale:cluster","agentId":"verix:agent:ddd","proofId":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","resource":"cluster:eu","seq":7}',
  });
  assert.deepEqual(document.cloudCoverage, ['aws', 'gcp'], 'clouds are de-duplicated and sorted so coverage is comparable');

  assert.equal(ProofIndex.fromRecord({ recordHash: 'e'.repeat(64), agentId: 'x', verification: { authorized: false } }).status, 'rejected', 'an unsigned authorisation still reads as a rejection');
  assert.equal(ProofIndex.fromRecord({ recordHash: 'f'.repeat(64), agentId: 'x' }).status, 'unknown');
  assert.equal(ProofIndex.fromRecord({ recordHash: 'f'.repeat(64), agentId: 'x' }).anomalyCodes.length, 0, 'absent anomaly lists become empty arrays, not undefined');
  assert.throws(() => ProofIndex.fromRecord({ agentId: 'x' }), /requires recordHash or proofId/);
});

test('rebuildFrom clears the live index and re-indexes what the ledger holds', async () => {
  const asked = [];
  const service = {
    primary: {
      listRecords: async ({ limit }) => {
        asked.push(limit);
        return [
          { recordHash: '1'.repeat(64), seq: 1, agentId: 'verix:agent:aaa', action: 'read:logs', resource: 'logs:app', trust: { status: 'trusted', score: 90, band: 'high-trust' } },
          { recordHash: '2'.repeat(64), seq: 2, agentId: 'verix:agent:bbb', action: 'deploy:infra', resource: 'infra:prod-eu-1', trust: { status: 'flagged', score: 35, band: 'restricted' } },
        ];
      },
    },
  };
  const index = new ProofIndex();
  index.add(doc());
  const stats = await index.rebuildFrom(service, { identities: new Map([['verix:agent:bbb', { subject: { name: 'Deploy-Bot' } }]]) });
  assert.deepEqual(asked, [1000], 'the rebuild asks for a page of records and takes the default limit');
  assert.equal(index.byId.get('a'.repeat(64)), undefined, 'the stale document is gone');
  assert.deepEqual(stats.documents, 2);
  assert.deepEqual(index.documents.map((document) => [head(document.id), document.identityName]), [['11111111', null], ['22222222', 'Deploy-Bot']], 'only identities the registry supplied get a name');
  assert.deepEqual(await index.rebuildFrom(service, { limit: 5, identities: new Map() }) && asked, [1000, 5]);
});

test('the index fingerprint commits to the documents it holds, in order', () => {
  const index = twoDocIndex();
  const fingerprint = fingerprintOfIndex(index.documents);
  assert.equal(fingerprint.length, 64);
  assert.equal(/^[0-9a-f]{64}$/.test(fingerprint), true);
  assert.equal(fingerprintOfIndex(index.documents), fingerprint, 'the same documents fingerprint the same way twice');
  index.remove('b'.repeat(64));
  assert.notEqual(fingerprintOfIndex(index.documents), fingerprint);
  assert.notEqual(fingerprintOfIndex([divergentDoc, doc()]), fingerprintOfIndex([doc(), divergentDoc]), 'the fingerprint covers the index order, not just its contents');
});

test('the evidence block numbers proofs and stops at twelve', () => {
  const many = Array.from({ length: 14 }, (_, i) => ({
    id: `${String(i).padStart(16, '0')}${'x'.repeat(48)}`,
    seq: i,
    agentId: `agent-${i}`,
    action: 'read:logs',
    resource: 'logs:app',
    status: 'trusted',
    document: i === 0 ? { reason: 'because' } : {},
  }));
  const block = evidenceBlock(many);
  assert.equal(lines(block).length, 12, 'a long evidence list is truncated, not summarized');
  assert.equal(lines(block)[0], '1. proof 0000000000000000… seq 0 agent agent-0 action read:logs on logs:app status trusted reason: because');
  assert.equal(lines(block)[11], '12. proof 0000000000000011… seq 11 agent agent-11 action read:logs on logs:app status trusted');
  assert.equal(block.includes('agent-12'), false);
  assert.equal(evidenceBlock([]), '');
});

test('the system prompt forbids the claims the ledger cannot support', () => {
  assert.deepEqual(lines(systemPrompt(['id1', 'id2'])), [
    'You are the Verix Trust Copilot. You answer questions about autonomous AI agent actions using only the verified evidence supplied below.',
    'Every claim you make must be traceable to an evidence item; cite proof identifiers inline in the form [1], [2].',
    'If the evidence does not answer the question, say exactly what is missing instead of speculating.',
    'Never claim a verification passed when the evidence marks it flagged, rejected or unattested.',
    'Citable proof identifiers: id1, id2.',
  ]);
  assert.match(systemPrompt([]), /Citable proof identifiers: none\./);
});

test('no model is wired unless both a key and a base URL are configured', () => {
  assert.equal(llmProviderFrom({}), null);
  assert.equal(llmProviderFrom({ llm: {} }), null);
  assert.equal(llmProviderFrom({ llm: { apiKey: 'k' } }), null, 'a key with no endpoint cannot be called');
  assert.equal(llmProviderFrom({ llm: { baseUrl: 'https://x.test' } }), null, 'an endpoint with no key cannot be authenticated');
  const provider = llmProviderFrom({ llm: { apiKey: 'k', baseUrl: 'https://x.test/v1/', model: 'm' } });
  assert.ok(provider instanceof HttpLlmProvider);
  assert.equal(provider.name, 'openai-compatible:m@https://x.test/v1', 'the trailing slash is normalised away before the path is appended');
  assert.throws(() => new HttpLlmProvider({ baseUrl: 'https://x.test' }), /requires baseUrl and apiKey/);
  assert.throws(() => new HttpLlmProvider({ apiKey: 'k' }), /requires baseUrl and apiKey/);
});

test('the LLM provider speaks the OpenAI chat-completions shape', async () => {
  let seen = null;
  const provider = new HttpLlmProvider({
    baseUrl: 'https://x.test/v1',
    apiKey: 'secret',
    model: 'm',
    fetch: async (url, init) => {
      seen = { url, init };
      return { ok: true, status: 200, json: async () => ({ choices: [{ message: { content: ' model text ' } }], model: 'served-model', usage: { total_tokens: 7 } }) };
    },
  });
  const completion = await provider.complete({
    system: 'SYS',
    prompt: 'USER',
    evidence: [{ id: 'z'.repeat(64), seq: 1, agentId: 'a', action: 'read:logs', resource: 'logs:app', status: 'trusted' }],
  });
  assert.equal(seen.url, 'https://x.test/v1/chat/completions');
  assert.equal(seen.init.method, 'POST');
  assert.deepEqual(seen.init.headers, { 'content-type': 'application/json', authorization: 'Bearer secret' });
  assert.ok(seen.init.signal instanceof AbortSignal);
  assert.deepEqual(JSON.parse(seen.init.body), {
    model: 'm',
    temperature: 0,
    messages: [
      { role: 'system', content: 'SYS\n\nVerified evidence:\n1. proof zzzzzzzzzzzzzzzz… seq 1 agent a action read:logs on logs:app status trusted' },
      { role: 'user', content: 'USER' },
    ],
  });
  assert.deepEqual(completion, { text: ' model text ', model: 'served-model', usage: { total_tokens: 7 } });

  const defaults = await new HttpLlmProvider({ baseUrl: 'https://x.test', apiKey: 'k', model: 'fallback', fetch: async () => ({ ok: true, status: 200, json: async () => ({ choices: [{ message: { content: 'x' } }] }) }) }).complete({ system: 's', prompt: 'p' });
  assert.deepEqual(defaults, { text: 'x', model: 'fallback', usage: null }, 'a response that names no model falls back to the requested one');
});

test('a model that errors or answers nothing fails loudly instead of inventing an answer', async () => {
  await assert.rejects(new HttpLlmProvider({ baseUrl: 'https://x.test', apiKey: 's', fetch: async () => ({ ok: false, status: 503, text: async () => 'upstream down' }) }).complete({ system: 's', prompt: 'p' }), /LLM provider responded 503: upstream down/);
  await assert.rejects(new HttpLlmProvider({ baseUrl: 'https://x.test', apiKey: 's', fetch: async () => ({ ok: true, status: 200, json: async () => ({ choices: [] }) }) }).complete({ system: 's', prompt: 'p' }), /returned no completion content/);

  let aborted = null;
  const hanging = new HttpLlmProvider({
    baseUrl: 'https://x.test',
    apiKey: 's',
    timeoutMs: 20,
    fetch: (_url, init) => new Promise((_resolve, reject) => {
      init.signal.addEventListener('abort', () => {
        aborted = init.signal.reason?.name ?? 'aborted';
        reject(new Error('This operation was aborted'));
      });
    }),
  });
  await assert.rejects(hanging.complete({ system: 's', prompt: 'p' }), /aborted/i);
  assert.notEqual(aborted, null, 'the timeout actually fired rather than leaking the request');
});

describe('the copilot answers questions about a live fleet', () => {
  let fleet;
  let cold;
  let deployer;
  let cleaner;
  let idle;
  let trusted;
  let diverged;
  let denied;

  before(async () => {
    fleet = await createPlatform({ config: loadConfig({}, { nodePlan: NODE_PLAN, backend: 'memory', crossCheck: false, trustFloor: 30, adminToken: 'admin' }) });
    deployer = await fleet.issueAgent({ name: 'Copilot-Deployer', scopes: [{ action: 'deploy:*', resource: 'infra:*' }] });
    cleaner = await fleet.issueAgent({ name: 'Copilot-Cleaner', scopes: [{ action: 'read:*', resource: 'logs:*' }] });
    idle = await fleet.issueAgent({ name: 'Copilot-Idle', scopes: [{ action: 'scale:*', resource: 'cluster:*' }, { action: 'invoke:*', resource: 'api:*' }] });
    trusted = await fleet.service.verifyAction({ identityId: deployer.identity.id, keyPair: deployer.keyPair, action: 'deploy:infra', resource: 'infra:prod-eu-1' });
    const liar = fleet.nodes.find((node) => node.nodeId === 'verix-node-edge-1');
    const entry = await liar.store.chain.get('verix-node-edge-1:1');
    await liar.store.chain.set('verix-node-edge-1:1', { ...entry, recordHash: 'f'.repeat(64) });
    diverged = await fleet.service.verifyAction({ identityId: deployer.identity.id, keyPair: deployer.keyPair, action: 'deploy:infra', resource: 'infra:prod-eu-2' });
    denied = await fleet.service.verifyAction({ identityId: cleaner.identity.id, keyPair: cleaner.keyPair, action: 'terminate:host', resource: 'host:db-prod-1' });
    await settled();
    cold = new TrustCopilot({ index: new ProofIndex(), registry: fleet.registry, service: fleet.service, config: {} });
  });

  after(async () => {
    await fleet?.close();
  });

  test('three proofs are indexed, one per status the ledger can hand back', () => {
    assert.equal(trusted.status, 'trusted');
    assert.equal(diverged.status, 'flagged', 'tampering with one node makes the next proof diverge and flag');
    assert.equal(denied.status, 'rejected');
    assert.equal(fleet.index.size, 3);
    const byId = new Map(fleet.index.documents.map((document) => [document.id, document]));
    assert.deepEqual(byId.get(diverged.proofId).anomalyCodes, ['REPLICATION_DIVERGENCE']);
    assert.deepEqual(byId.get(denied.proofId).policyCodes, ['NO_SCOPE_MATCH']);
  });

  test('why-flagged quotes the policy finding, the anomaly and the lost score, and cites the proof', async () => {
    const asked = await fleet.copilot.ask(`why was ${diverged.proofId} flagged`);
    assert.deepEqual(asked.intent, 'why-flagged');
    assert.equal(asked.intentConfidence, 0.9);
    assert.equal(asked.mode, 'rag-only');
    assert.deepEqual(asked.citations, [diverged.proofId]);
    assert.equal(asked.evidence.length, 1, 'a quoted identifier selects exactly one proof');
    assert.equal(asked.evidence[0].id, diverged.proofId);
    assert.equal(asked.evidence[0].status, 'flagged');
    assert.equal(asked.evidence[0].relevance, null, 'an identifier hit has no retrieval score');

    const text = lines(asked.answer);
    assert.match(text[0], new RegExp(`^Proof ${diverged.proofId.slice(0, 16)}… \\(sequence 2\\) recorded \\d{4}-\\d{2}-\\d{2} [\\d:]+ for agent ${deployer.identity.id} executing deploy:infra on infra:prod-eu-2 carries status flagged\\[1\\]\\.$`));
    assert.equal(text[1], 'No policy finding denied the action, so the flag did not originate from authorization.');
    assert.equal(text[2], 'Behavioural detectors raised 1 finding(s):');
    assert.match(text[3], /^  - \[critical\] REPLICATION_DIVERGENCE: nodes disagree about the ledger root at sequence 2: 2 distinct roots across 3 reporting nodes \(evidence: \{.*"divergent":\["verix-node-edge-1"\].*\}\)$/);
    assert.match(text[4], /^Trust score 35\/100 lost credit in: lineage \(89% of 15\), consistency \(30% of 15\), behaviour \(\d+% of 10\)\.$/);
    assert.match(text[5], /^Attested by 3 independent node\(s\): verix-node-aws-1\/aws, verix-node-gcp-1\/gcp, verix-node-edge-1\/local; median witness time .*\.$/);
    assert.equal(text[6], 'Cross-cloud roots disagree for this sequence, which is the strongest available signal that at least one node copy is not trustworthy.');
    assert.equal(asked.answer.includes('policy (0% of 20)'), false, 'a component that kept full credit is not reported as lost');
  });

  test('without an identifier the answer still targets a proof that went wrong', async () => {
    const asked = await fleet.copilot.ask('why was the deploy:infra proof flagged');
    assert.equal(asked.intent, 'why-flagged');
    assert.ok(asked.retrieved >= 2, `${asked.retrieved} documents matched, including the trusted deploy`);
    assert.deepEqual(asked.evidence.map((item) => item.id), [diverged.proofId], 'a trusted proof that ranked into the evidence is passed over for the flagged one');
    assert.match(asked.answer, /carries status flagged\[1\]\./);
  });

  test('why-flagged reports a policy denial when the rejection came from authorization', async () => {
    const asked = await fleet.copilot.ask(`why was ${denied.proofId} rejected`);
    assert.equal(asked.intent, 'why-flagged');
    assert.deepEqual(asked.citations, [denied.proofId]);
    assert.match(lines(asked.answer)[0], /^Proof [0-9a-f]{16}… \(sequence 3\) recorded .+ for agent verix:agent:\S+ executing terminate:host on host:db-prod-1 carries status rejected\[1\]\.$/);
    assert.ok(asked.answer.includes('Authorization was denied by 1 policy finding(s):'));
    assert.ok(asked.answer.includes('  - NO_SCOPE_MATCH: no scope covers terminate:host on host:db-prod-1'));
    assert.ok(asked.answer.includes('Attested by 3 independent node(s)'));
  });

  test('score-explain breaks the stored components down and names the hard cap', async () => {
    const asked = await fleet.copilot.ask(`explain the trust score for ${diverged.proofId}`);
    assert.equal(asked.intent, 'score-explain');
    const text = lines(asked.answer);
    assert.equal(text[0], `${deployer.identity.id} deploy:infra: trust 35/100, band restricted, status flagged[1].`);
    assert.equal(text[1], 'Contributing signals: critical:REPLICATION_DIVERGENCE, critical:cross-cloud-divergence.');
    assert.equal(text[2], 'Score components as stored on the proof:');
    assert.equal(text[3], `  signature: 20/20 weighted 100% - ${deployer.identity.id} action signature and identity self-binding verify`);
    assert.equal(text[4], '  policy: 20/20 weighted 100% - authorized with no findings');
    assert.equal(text[5], '  lineage: 13.33/15 weighted 89% - delegation chain resolves at depth 1 of 8');
    assert.equal(text[6], '  replication: 20/20 weighted 100% - 3 of 3 independent nodes attest to this proof');
    assert.equal(text[7], '  consistency: 4.5/15 weighted 30% - cross-cloud roots diverge');
    assert.match(text[8], /^  behaviour: 3\.\d+\/10 weighted \d+% - 1\/1 prior actions verified \(smoothed reliability [\d.]+%\)$/);
    assert.match(text[9], /^  anomaly \[critical\] REPLICATION_DIVERGENCE: /);
    assert.equal(text[11], 'Hard cap 35 applied: a core verification check failed, so the weighted total could not raise the score above it.');
    assert.deepEqual(asked.citations, [diverged.proofId]);
  });

  test('trace walks the agent sequence around the queried proof and audits the chain', async () => {
    const asked = await fleet.copilot.ask(`trace agent ${deployer.identity.id}`);
    assert.equal(asked.intent, 'trace-sequence');
    assert.deepEqual(asked.resolvedAgents, [deployer.identity.id], 'an identifier written in the question resolves to the agent');
    assert.deepEqual(asked.unresolvedAgents, []);
    const text = lines(asked.answer);
    assert.equal(text[0], `Tracing agent ${deployer.identity.id} around sequence 2: 2 proof(s) on record, showing 2.`);
    assert.match(text[1], /^  1\. seq 1 .+ deploy:infra on infra:prod-eu-1 status trusted anomaly IDENTITY_FIRST_SIGHTING\[low\] prev [0-9a-f]{8}…$/);
    assert.match(text[2], /^  2\. seq 2 .+ deploy:infra on infra:prod-eu-2 status flagged anomaly REPLICATION_DIVERGENCE\[critical\] prev [0-9a-f]{8}…  <-- queried$/);
    assert.match(text[3], /^Chain audit over that window: intact(\; merkle root [0-9a-f]{16}… recomputed from stored entries)?\.$/);
    assert.deepEqual(asked.evidence.map((item) => item.seq), [2, 1, 2], 'the queried proof leads, then the window in ledger order');
    assert.equal(asked.evidence[0].id, diverged.proofId);
    assert.equal(asked.citations[0], diverged.proofId);
  });

  test('authorization answers with a verdict over the recorded evidence', async () => {
    const allowed = await fleet.copilot.ask(`was ${deployer.identity.id} allowed to run deploy:infra`);
    assert.equal(allowed.intent, 'authorization-check');
    assert.deepEqual(allowed.resolvedAgents, [deployer.identity.id]);
    assert.equal(allowed.retrieved, 2, 'the resolved agent filters retrieval to its own two proofs');
    const text = lines(allowed.answer);
    assert.equal(text[0], 'Verdict for the recorded evidence: PARTIALLY AUTHORIZED.');
    assert.equal(text[1], `${deployer.identity.id} invoking deploy:infra: 2 matching proof(s) in the ledger, 1 trusted, 1 not trusted[1].`);
    // Which of the two proofs is listed first is the retrieval ranking's business, so both
    // numbered lines are matched anywhere in the answer.
    assert.equal(text.slice(2).length, 2);
    assert.match(text[2] + text[3], /sequence 1 .+ status trusted; granted by scope deploy:\*:infra:\*; attested at median .+\[\d\]/);
    assert.match(text[2] + text[3], /sequence 2 .+ status flagged; granted by scope deploy:\*:infra:\*; attested at median .+\[\d\]/);
    assert.deepEqual([...allowed.citations].sort(), [trusted.proofId, diverged.proofId].sort());

    const partial = await fleet.copilot.ask('was agent-9 allowed to run deploy:infra');
    assert.deepEqual(partial.resolvedAgents, [], 'a made-up agent reference is not guessed at');
    assert.deepEqual(partial.unresolvedAgents, ['agent-9']);
    assert.equal(lines(partial.answer)[0], 'Verdict for the recorded evidence: PARTIALLY AUTHORIZED.');
    assert.equal(lines(partial.answer)[1], 'agent-9 invoking deploy:infra: 2 matching proof(s) in the ledger, 1 trusted, 1 not trusted[1].');

    const refused = await fleet.copilot.ask('was agent-9 allowed to run terminate:host');
    assert.equal(lines(refused.answer)[0], 'Verdict for the recorded evidence: NOT AUTHORIZED.');
    assert.equal(lines(refused.answer)[1], 'agent-9 invoking terminate:host: 1 matching proof(s) in the ledger, 0 trusted, 1 not trusted[1].');
    assert.deepEqual(refused.citations, [denied.proofId]);
  });

  test('authorization falls back to the identity registry when the agent has no such proof', async () => {
    const asked = await fleet.copilot.ask(`was ${idle.identity.id} allowed to run scale:cluster`);
    assert.equal(asked.intent, 'authorization-check');
    assert.deepEqual(asked.resolvedAgents, [idle.identity.id]);
    assert.equal(asked.evidence.length, 0, 'the idle agent has no proof whose action the question asks about');
    assert.equal(asked.answer, `${idle.identity.subject.name} (${idle.identity.id}) has no recorded actions matching scale:cluster. Its identity grants 2 scope(s): scale:* on cluster:*; invoke:* on api:*. Whether scale:cluster falls inside them: yes, the scope pattern covers it.`);

    const outside = await fleet.copilot.ask(`was ${idle.identity.id} allowed to run deploy:infra`);
    assert.equal(outside.answer.match(/falls inside them: (.*)\.$/)[1], 'no, no scope pattern covers it');
  });

  test('an agent the registry never heard of gets no answer, not a confident one', async () => {
    // With nothing retrievable, the only branch left is the honest "I cannot confirm".
    const asked = await cold.ask('was agent-424242 allowed to run deploy:infra');
    assert.deepEqual(asked.unresolvedAgents, ['agent-424242']);
    assert.equal(asked.answer, 'No ledger evidence for agent-424242 and action deploy:infra, and the agent is not in the identity registry, so authorization cannot be confirmed either way.');
    assert.deepEqual(asked.evidence, []);
    assert.deepEqual(asked.citations, []);
  });

  test('the summary reports the index, the status mix and what needs attention', async () => {
    const asked = await fleet.copilot.ask('how many proofs are there?');
    assert.equal(asked.intent, 'status-summary');
    const text = lines(asked.answer);
    assert.equal(text[0], 'Indexed proofs: 3. Returned in this answer: 3.');
    assert.equal(text[1].replace(/^Status mix: /, '').replace(/\.$/, '').split(', ').sort().join(','), 'flagged=1,rejected=1,trusted=1');
    assert.equal(text[2], `Most active agents: ${deployer.identity.id}(2), ${cleaner.identity.id}(1).`);
    assert.equal(text[3], `Needing attention: ${head(diverged.proofId)}… seq 2 deploy:infra; ${head(denied.proofId)}… seq 3 terminate:host.`);
    assert.deepEqual(asked.citations, asked.evidence.map((item) => item.id));
  });

  test('a plain search lists what it retrieved with the score that ordered it', async () => {
    const asked = await fleet.copilot.ask('which proofs touch deploy infra');
    assert.equal(asked.intent, 'search');
    assert.equal(asked.intentConfidence, 0.5);
    const text = lines(asked.answer);
    assert.equal(text[0], 'Retrieved 3 evidence item(s) for the query, ranked by combined BM25 and embedding score:');
    assert.match(text[1], /^  1\. seq \d+ verix:agent:\S+ deploy:infra on infra:prod-eu-\d status (flagged|trusted)\[1\] \(relevance \d+\.\d+, matched deploy\/infra\)$/);
    assert.match(text[2], /^  2\. seq \d+ verix:agent:\S+ deploy:infra on infra:prod-eu-\d status (flagged|trusted)\[2\] \(relevance \d+\.\d+, matched deploy\/infra\)$/);
    assert.deepEqual([...new Set(asked.evidence.slice(0, 2).map((item) => item.seq))].sort(), [1, 2], 'the two deploy proofs outrank the terminate proof');
    assert.equal(asked.evidence[2].id, denied.proofId);
    assert.deepEqual(asked.evidence.map((item) => item.relevance).filter(Boolean).length, 3, 'retrieval hits all carry their relevance');
    assert.deepEqual(asked.evidence.slice(0, 2).map((item) => item.relevance.matched), [['deploy', 'infra'], ['deploy', 'infra']]);
    const scores = asked.evidence.map((item) => item.relevance.score);
    assert.deepEqual(scores, [...scores].sort((a, b) => b - a), 'the answer is written in descending relevance');

    const capped = await fleet.copilot.ask('which proofs touch deploy infra', { k: 1 });
    assert.equal(capped.evidence.length, 1);
    assert.equal(capped.retrieved, 1);
  });

  test('citations and evidence carry the whole document, minus the derived index fields', async () => {
    const asked = await fleet.copilot.ask(`why was ${diverged.proofId} flagged`);
    const [item] = asked.evidence;
    assert.deepEqual(Object.keys(item), ['id', 'seq', 'agentId', 'action', 'resource', 'status', 'reason', 'score', 'relevance', 'document']);
    assert.equal(item.document.tokens, undefined);
    assert.equal(item.document.vector, undefined);
    assert.equal(item.document.identityName, 'Copilot-Deployer');
    assert.deepEqual(item.document.cloudCoverage, ['aws', 'gcp', 'local']);
    assert.equal(item.score, 35);
    assert.equal(item.reason, 'critical anomaly critical: REPLICATION_DIVERGENCE');
    assert.deepEqual(Object.keys(asked).sort(), ['answer', 'citations', 'evidence', 'intent', 'intentConfidence', 'mode', 'resolvedAgents', 'retrieved', 'unresolvedAgents']);
  });

  test('evidenceForIdentifiers answers from the index when it can and the ledger when it cannot', async () => {
    const found = await fleet.copilot.evidenceForIdentifiers([diverged.proofId, '2'.repeat(64)]);
    assert.equal(found.length, 1, 'an identifier on no node yields nothing rather than a fabricated row');
    assert.equal(found[0].id, diverged.proofId);
    assert.equal(typeof found[0].document.length, 'number', 'the warm answer is the indexed document');

    // A copilot over a cold index has never seen the proof, so the only way it can
    // answer is by reading it back off the nodes.
    const [rebuilt] = await cold.evidenceForIdentifiers([diverged.proofId]);
    assert.equal(rebuilt.id, diverged.proofId, 'a proof the index has not seen is read straight from the ledger');
    assert.equal(rebuilt.document.length, undefined, 'it is rebuilt from the record, not copied out of the index');
    assert.equal(rebuilt.status, 'flagged');
    assert.equal(rebuilt.score, 35);
    assert.equal(rebuilt.document.identityName, 'Copilot-Deployer', 'the identity behind the proof is resolved through the registry');
    assert.deepEqual(await cold.evidenceForIdentifiers(['2'.repeat(64)]), []);
  });

  test('explainFailure answers about a proof the operator already holds', async () => {
    const explained = await fleet.copilot.explainFailure(diverged.proofId);
    assert.deepEqual(explained.citations, [diverged.proofId]);
    assert.match(explained.answer, new RegExp(`^Proof ${diverged.proofId.slice(0, 16)}…`));
    assert.match(explained.answer, /carries status flagged\[1\]\./);

    const unknown = await fleet.copilot.explainFailure('3'.repeat(64));
    assert.deepEqual(unknown, { answer: `Proof ${'3'.repeat(64)} is not present on any node, so it cannot be explained.`, evidence: [], citations: [] });
  });

  test('a model augments the deterministic answer and never replaces it', async () => {
    const deterministic = await fleet.copilot.ask('how many proofs are there?');
    const calls = [];
    fleet.copilot.provider = { complete: async ({ system, prompt, evidence }) => { calls.push({ system, prompt, evidence }); return { text: 'MODEL SUMMARY', model: 'fake-1' }; } };
    try {
      const asked = await fleet.copilot.ask('how many proofs are there?');
      assert.equal(asked.mode, 'rag+model');
      assert.equal(asked.model, 'fake-1');
      assert.equal(asked.answer, `MODEL SUMMARY\n\n(deterministic grounding)\n${deterministic.answer}`, 'the rewrite is appended to the grounded answer, never swapped for it');
      assert.ok(asked.answer.includes('Indexed proofs: 3.'), 'the grounded answer survives the rewrite');
      assert.equal(calls.length, 1);
      assert.match(calls[0].system, /^You are the Verix Trust Copilot\./);
      assert.match(calls[0].prompt, /Detected intent: status-summary/);
      assert.match(calls[0].prompt, /Rewrite the draft as a concise operator-facing answer\. Keep every citation marker/);
      assert.equal(calls[0].evidence.length, asked.evidence.length, 'the model is shown exactly the evidence the answer cites');
      assert.ok(calls[0].system.includes('Citable proof identifiers:'), 'and told which identifiers it may cite');

      fleet.copilot.provider = { complete: async () => { throw new Error('provider exploded'); } };
      const broken = await fleet.copilot.ask('how many proofs are there?');
      assert.equal(broken.mode, 'rag-only', 'an outage degrades to the deterministic answer, it does not fail the request');
      assert.equal(broken.modelError, 'provider exploded');
      assert.ok(broken.answer.includes('Indexed proofs: 3.'));

      const declined = await fleet.copilot.ask('how many proofs are there?', { useModel: false });
      assert.equal(declined.mode, 'rag-only');
      assert.equal(declined.modelError, undefined, 'opting out is not an error');
    } finally {
      fleet.copilot.provider = null;
    }
  });

  test('a fleet with nothing indexed says so instead of answering from the registry', async () => {
    const copilot = cold;
    assert.equal(copilot.provider, null, 'no model is reached for unless the config names an endpoint and a key');
    const why = await copilot.ask('why was the last deploy flagged?');
    assert.equal(why.answer, 'No proofs matched the question, so nothing can be explained. Ask about a registered agent or a specific proof identifier.');
    assert.deepEqual(why.citations, []);
    assert.equal((await copilot.ask('trace verix:agent:aaaaaa seq 3')).answer, 'Nothing in the ledger matches the sequence you asked about.');
    assert.equal((await copilot.ask(`explain the trust score for ${'4'.repeat(64)}`)).answer, 'No proof matched, so there is no score to break down.');
    const summary = await copilot.ask('how many proofs are there?');
    assert.equal(lines(summary.answer)[0], 'Indexed proofs: 0. Returned in this answer: 0.');
    assert.equal(lines(summary.answer)[1], 'Status mix: none.');
    assert.equal(lines(summary.answer)[2], 'Most active agents: none.');
    assert.equal((await copilot.ask('which proofs touch nothing at all')).answer, 'No indexed proof matched "which proofs touch nothing at all".');
  });
});

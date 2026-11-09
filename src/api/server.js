import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import { createServer } from 'node:http';
import { extname, join, normalize, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { WebSocketServer } from 'ws';
import { plannedBackends } from '../config.js';
import { assertRevocationAuthority, verifyIdentitySelfBinding, verifyRevocation } from '../crypto/identity.js';
import { deserializeKeyPair, serializeKeyPair } from '../crypto/pqc.js';
import { buildActionEnvelope, signActionEnvelope } from '../verification/action.js';
import { verifyAssessment } from '../verification/assessment.js';

const PUBLIC_DIR = resolve(fileURLToPath(new URL('../../public', import.meta.url)));

const CONTENT_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
};

class HttpError extends Error {
  constructor(status, code, message, details = null) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

function readBody(request, limitBytes = 8 * 1024 * 1024) {
  return new Promise((resolveBody, rejectBody) => {
    const chunks = [];
    let size = 0;
    let overflow = false;
    request.on('data', (chunk) => {
      size += chunk.length;
      if (size > limitBytes) {
        if (overflow) return;
        overflow = true;
        // Destroying the socket here would drop the response before it flushes, so
        // the remainder is drained and discarded and the caller replies 413.
        request.resume();
        rejectBody(new HttpError(413, 'BODY_TOO_LARGE', `request body exceeds ${limitBytes} bytes`));
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => {
      if (overflow) return;
      if (chunks.length === 0) resolveBody(null);
      else {
        try {
          resolveBody(JSON.parse(Buffer.concat(chunks).toString('utf8')));
        } catch {
          rejectBody(new HttpError(400, 'INVALID_JSON', 'request body is not valid JSON'));
        }
      }
    });
    request.on('error', rejectBody);
  });
}

/*
 * A keyPair that arrives over JSON has base64url strings where the crypto layer
 * expects bytes, so it must be deserialized before signing. In-process callers
 * (the CLI and the tests) hand the live key pair straight over, which is already
 * in the shape sign() wants.
 */
function normalizeKeyPair(doc) {
  if (doc.privateKey instanceof Uint8Array || Buffer.isBuffer(doc.privateKey)) return doc;
  if (typeof doc.privateKey !== 'string' || typeof doc.publicKey !== 'string') {
    throw new HttpError(400, 'KEYPAIR_MALFORMED', 'a submitted keyPair must be the serialized document returned by /identities/register, with base64url publicKey and privateKey');
  }
  try {
    return deserializeKeyPair(doc);
  } catch (error) {
    throw new HttpError(400, 'KEYPAIR_MALFORMED', String(error.message ?? error));
  }
}

function sendJson(response, status, payload) {
  const body = JSON.stringify(payload, null, 2);
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
  });
  response.end(body);
}

export function createVerixApp({ platform }) {
  const { service, registry, group, index, copilot, eventBus, config, clients, coordinator, nodes = [] } = platform;
  // Inbound replication lands on the stores this process owns; forwarding it to
  // remote peers again would make every peer write echo back to the sender.
  const localTargets = nodes.length > 0 ? nodes : [service.primary];

  const routes = {
    health: { method: 'GET', path: '/health', handler: () => ({
      ok: true,
      service: 'verix',
      version: '0.1.0',
      now: new Date().toISOString(),
      crypto: { signingAlg: platform.signingAlg, standards: ['FIPS 203 ML-KEM', 'FIPS 204 ML-DSA', 'FIPS 205 SLH-DSA', 'SHA3-256/512'], crossImplementationCheck: config.crossCheck },
      security: {
        adminTokenConfigured: Boolean(config.adminToken),
        nodeTokenConfigured: Boolean(config.nodeToken),
        failClosed: ['/identities/register', '/revocations/revoke'].filter((path) => !config.adminToken),
        note: config.adminToken
          ? 'peer replication endpoints require the bearer token in VERIX_NODE_TOKEN (or VERIX_ADMIN_TOKEN); issuing agent keys and issuer-side revocation always require VERIX_ADMIN_TOKEN'
          : 'no tokens configured: this instance accepts anonymous identity and revocation writes and only refuses key handout, which is appropriate for a local development run and not for a shared host',
      },
      endpoints: Object.entries(routes).map(([, route]) => ({ method: route.method, path: route.path, gate: route.gate ?? 'public' })),
      planned: plannedBackends(),
    }) },

    status: { method: 'GET', path: '/status', handler: async () => await platform.status() },

    verifyAction: { method: 'POST', path: '/verify-action', handler: async ({ body }) => {
      const identityId = body?.identityId ?? body?.identity?.id;
      if (!identityId) throw new HttpError(400, 'IDENTITY_REQUIRED', 'verify-action requires identityId (or an inline identity document)');
      if (!body?.action || !body?.resource) throw new HttpError(400, 'ACTION_REQUIRED', 'verify-action requires action and resource');
      const proof = body.keyPair
        ? { identity: body.identity ?? await registry.require(identityId).catch(() => null), keyPair: normalizeKeyPair(body.keyPair) }
        : { identity: body.identity ?? null, signatureDoc: body.signatureDoc ?? null };
      if (!proof.identity) proof.identity = await registry.require(identityId).catch(() => null);
      if (!proof.identity) throw new HttpError(404, 'IDENTITY_UNKNOWN', `identity ${identityId} is not registered`);
      if (!proof.keyPair && !proof.signatureDoc) {
        throw new HttpError(400, 'SIGNATURE_REQUIRED', 'the platform never holds agent private keys: submit either a signatureDoc produced by the agent, or a keyPair for this request only');
      }
      const envelope = body.envelope ?? buildActionEnvelope({
        agentId: proof.identity.id,
        action: body.action,
        resource: body.resource,
        executedAt: body.executedAt,
        context: body.context ?? {},
        executionFingerprint: body.executionFingerprint ?? null,
        payload: body.payload ?? null,
      });
      const signatureDoc = proof.signatureDoc ?? await signActionEnvelope(proof.keyPair, envelope);
      try {
        return await service.verifyAction({
          ...body,
          identity: proof.identity,
          envelope,
          signatureDoc,
          keyPair: proof.keyPair,
        });
      } catch (error) {
        throw new HttpError(500, 'VERIFICATION_FAILED', error.message, { cause: error.constructor.name });
      }
    } },

    getProof: { method: 'GET', path: '/ledger/records/:hash', handler: async ({ params }) => {
      const proof = await service.getProof(params.hash);
      if (!proof) throw new HttpError(404, 'PROOF_NOT_FOUND', `no proof with record hash ${params.hash}`);
      const assessment = await verifyAssessment({
        record: proof.record,
        resolve: async (id) => (await registry.get(id))?.identity ?? null,
        trustAnchors: registry.trustAnchors,
        crossCheck: config.crossCheck,
      });
      return { ...proof, assessment };
    } },

    listRecords: { method: 'GET', path: '/ledger/records', handler: async ({ query }) => {
      const records = await service.primary.listRecords({
        agentId: query.get('agentId') ?? null,
        limit: Number(query.get('limit') ?? 200),
        offset: Number(query.get('offset') ?? 0),
      });
      return { records, count: records.length };
    } },

    inclusion: { method: 'GET', path: '/ledger/inclusion/:seq', handler: async ({ params }) => {
      try {
        return await service.primary.inclusionProof(Number(params.seq));
      } catch (error) {
        throw new HttpError(404, 'SEQUENCE_OUT_OF_RANGE', error.message);
      }
    } },

    audit: { method: 'POST', path: '/ledger/audit', handler: async ({ body }) => {
      const nodeId = body?.nodeId ?? service.primary.nodeId;
      try {
        return await service.auditNode(nodeId, { from: Number(body?.from ?? 1), to: body?.to === undefined ? null : Number(body.to) });
      } catch (error) {
        throw new HttpError(404, 'NODE_UNKNOWN', error.message);
      }
    } },

    crossCloud: { method: 'GET', path: '/ledger/cross-check/:seq', handler: async ({ params }) => await service.crossCloud(Number(params.seq)) },

    listIdentities: { method: 'GET', path: '/identities', handler: async ({ query }) => {
      const listed = await registry.list({ subjectKind: query.get('kind') });
      return {
        identities: listed.identities.map((identity) => ({
          ...identity,
          scopes: identity.scopes,
          subject: identity.subject,
        })),
        nodesReporting: listed.nodesReporting,
        divergent: listed.divergent.length,
        trustAnchors: [...registry.trustAnchors.keys()],
      };
    } },

    getIdentity: { method: 'GET', path: '/identities/:id', handler: async ({ params }) => {
      const resolved = await registry.get(params.id);
      if (!resolved) throw new HttpError(404, 'IDENTITY_UNKNOWN', `identity ${params.id} is not registered`);
      return { identity: resolved.identity, copies: resolved.copies, disagreement: resolved.disagreement };
    } },

    identityRevocations: { method: 'GET', path: '/identities/:id/revocations', handler: async ({ params }) => {
      const result = await registry.revocationsFor(params.id);
      return { revocations: result.revocations, forged: result.forged, nodesReporting: result.nodesReporting };
    } },

    allRevocations: { method: 'GET', path: '/revocations', gate: 'public', handler: async () => {
      const listed = await registry.list();
      const merged = [];
      for (const identity of listed.identities) {
        const result = await registry.revocationsFor(identity.id);
        merged.push(...result.revocations.map((entry) => ({ ...entry, agentName: identity.subject?.name ?? null })));
      }
      return { revocations: merged };
    } },

    putIdentity: { method: 'POST', path: '/identities', gate: 'node', handler: async ({ body }) => {
      const identity = body?.identity ?? body;
      if (!identity?.id || !identity?.publicKey || !identity?.selfSignature) {
        throw new HttpError(400, 'IDENTITY_INCOMPLETE', 'expected a full identity document with id, publicKey and selfSignature');
      }
      if (!(await verifyIdentitySelfBinding(identity))) {
        throw new HttpError(422, 'IDENTITY_SELF_BINDING_INVALID', `identity ${identity.id} does not bind its recorded public key; refusing to store it`);
      }
      for (const target of localTargets) await target.putIdentity(identity);
      return { stored: true, identityId: identity.id, nodes: localTargets.map((target) => target.nodeId) };
    } },

    issueIdentity: { method: 'POST', path: '/identities/register', gate: 'adminRequired', handler: async ({ body }) => {
      const name = body?.name ?? body?.subject?.name;
      if (!name) throw new HttpError(400, 'NAME_REQUIRED', 'registering an agent requires a name');
      const { identity, keyPair } = await platform.issueAgent({
        name,
        scopes: body?.scopes ?? [],
        kind: body?.kind ?? 'agent',
        ttlSeconds: body?.ttlSeconds,
        subject: body?.subject ?? {},
        seedLabel: body?.seedLabel ?? null,
      });
      return {
        identity,
        // The platform never keeps an agent private key: it is returned here once
        // and is not written to any store, so this response is the only copy.
        privateKey: serializeKeyPair(keyPair),
        note: 'the secret key was generated for this request and is not stored by the platform; it will not be recoverable from the ledger later',
      };
    } },

    putRevocation: { method: 'POST', path: '/revocations', gate: 'node', handler: async ({ body }) => {
      const entry = body?.revocation ?? body;
      if (!entry?.identityId || !entry?.signature || !entry?.revokerPublicKey) {
        throw new HttpError(400, 'REVOCATION_INCOMPLETE', 'expected a signed revocation entry with identityId, revokerPublicKey and signature');
      }
      if (!(await verifyRevocation(entry))) {
        throw new HttpError(422, 'REVOCATION_FORGERY', `revocation ${String(entry.revocationId).slice(0, 12)} does not verify; refusing to store it`);
      }
      const resolved = await registry.get(entry.identityId).catch(() => null);
      if (!resolved) throw new HttpError(404, 'IDENTITY_UNKNOWN', `revocation targets ${entry.identityId}, which this registry has never seen`);
      const authority = assertRevocationAuthority(entry, resolved.identity);
      if (!authority.ok) throw new HttpError(403, 'REVOCATION_UNAUTHORIZED', authority.reason);
      for (const target of localTargets) await target.putRevocation(entry);
      return { stored: true, revocationId: entry.revocationId, byIssuer: authority.byIssuer === true, nodes: localTargets.map((target) => target.nodeId) };
    } },

    revokeIdentity: { method: 'POST', path: '/revocations/revoke', gate: 'adminRequired', handler: async ({ body }) => {
      const identityId = body?.identityId;
      if (!identityId) throw new HttpError(400, 'IDENTITY_REQUIRED', 'revoke requires identityId and reason');
      if (!body?.reason) throw new HttpError(400, 'REASON_REQUIRED', 'a revocation must record why the identity is being killed');
      // An unknown id is a 404 here too: registry.revoke reports it as a refusal,
      // which would otherwise blur "nothing to revoke" with "revocation rejected".
      if (!(await registry.get(identityId).catch(() => null))) throw new HttpError(404, 'IDENTITY_UNKNOWN', `identity ${identityId} is not registered`);
      try {
        const entry = await registry.revoke({ keyPair: platform.coordinatorKeyPair, identityId, reason: body.reason, revokedBy: coordinator.id });
        return { revoked: true, revocation: entry };
      } catch (error) {
        throw new HttpError(409, 'REVOCATION_REFUSED', error.message);
      }
    } },

    events: { method: 'GET', path: '/events', handler: ({ query }) => {
      const sinceSeq = Number(query.get('since') ?? 0);
      const topic = query.get('topic');
      return { events: eventBus.replay({ sinceSeq, topic: topic ?? null }), sequence: eventBus.sequence };
    } },

    copilotAsk: { method: 'POST', path: '/copilot/ask', handler: async ({ body }) => {
      const question = body?.question;
      if (!question || typeof question !== 'string') throw new HttpError(400, 'QUESTION_REQUIRED', 'ask requires a question string');
      return await copilot.ask(question, { k: Number(body?.k ?? 8), useModel: body?.useModel ?? null });
    } },

    copilotIndex: { method: 'POST', path: '/copilot/reindex', gate: 'admin', handler: async () => await platform.reindex() },

    trustSummary: { method: 'GET', path: '/trust/summary', handler: async ({ query }) => {
      const limit = Number(query.get('limit') ?? 500);
      const records = await service.primary.listRecords({ limit });
      const byAgent = new Map();
      const byStatus = new Map();
      const timeline = [];
      for (const record of records) {
        const status = record.trust?.status ?? 'unattested';
        byStatus.set(status, (byStatus.get(status) ?? 0) + 1);
        const entry = byAgent.get(record.agentId) ?? { agentId: record.agentId, name: null, proofs: 0, trusted: 0, flagged: 0, rejected: 0, unattested: 0, score: null, anomalies: new Map(), lastSeq: 0 };
        entry.proofs += 1;
        entry[status] = (entry[status] ?? 0) + 1;
        entry.score = record.trust?.score ?? entry.score;
        entry.lastSeq = Math.max(entry.lastSeq, record.seq ?? 0);
        for (const anomaly of record.anomalies ?? []) entry.anomalies.set(anomaly.code, (entry.anomalies.get(anomaly.code) ?? 0) + 1);
        byAgent.set(record.agentId, entry);
        timeline.push({
          seq: record.seq ?? null,
          recordHash: record.recordHash,
          agentId: record.agentId,
          action: record.action,
          resource: record.resource,
          executedAt: record.executedAt,
          status,
          score: record.trust?.score ?? null,
          band: record.trust?.band ?? null,
          anomalies: (record.anomalies ?? []).map((anomaly) => ({ code: anomaly.code, severity: anomaly.severity })),
          clouds: [...new Set((record.witnesses ?? []).map((witness) => witness.cloud))],
          nodes: (record.witnesses ?? []).map((witness) => witness.nodeId),
          certifiedAt: record.timestamp?.certifiedAt ?? null,
          signedBy: record.assessment?.coordinatorId ?? null,
        });
      }
      const listed = await registry.list().catch(() => ({ identities: [] }));
      const names = new Map(listed.identities.map((identity) => [identity.id, identity.subject?.name ?? null]));
      const agents = [...byAgent.values()].map((entry) => ({
        ...entry,
        name: names.get(entry.agentId),
        revoked: listed.identities.some((identity) => identity.id === entry.agentId && identity.revokedAt),
        anomalies: [...entry.anomalies.entries()].map(([code, count]) => ({ code, count })),
      }));
      const perNode = await service.status();
      return {
        generatedAt: new Date().toISOString(),
        totals: { proofs: records.length, agents: agents.length, byStatus: Object.fromEntries(byStatus), indexed: index.size },
        agents,
        timeline,
        nodes: perNode,
        quorum: { required: group.required, of: group.size },
        coordinatorId: coordinator.id,
      };
    } },

    topology: { method: 'GET', path: '/trust/topology', handler: async ({ query }) => {
      const limit = Number(query.get('limit') ?? 120);
      const records = await service.primary.listRecords({ limit });
      const nodes = await service.status();
      const edges = new Map();
      for (const record of records) {
        for (const witness of record.witnesses ?? []) {
          const key = `${record.agentId}->${witness.nodeId}`;
          const edge = edges.get(key) ?? { from: record.agentId, to: witness.nodeId, cloud: witness.cloud, proofs: 0, statuses: new Map(), lastScore: null, lastSeq: 0 };
          edge.proofs += 1;
          const status = record.trust?.status ?? 'unattested';
          edge.statuses.set(status, (edge.statuses.get(status) ?? 0) + 1);
          edge.lastScore = record.trust?.score ?? edge.lastScore;
          edge.lastSeq = Math.max(edge.lastSeq, record.seq ?? 0);
          edges.set(key, edge);
        }
      }
      return {
        coordinatorId: coordinator.id,
        nodes: nodes.map((node) => ({ id: node.nodeId, cloud: node.cloud, region: node.region, chainLength: node.chainLength, intact: node.recentWindowIntact, problems: node.recentProblems?.length ?? 0, root: node.head?.root ?? null })),
        agents: [...new Set(records.map((record) => record.agentId))].map((id) => ({ id })),
        edges: [...edges.values()].map((edge) => ({ ...edge, statuses: Object.fromEntries(edge.statuses) })),
        proofs: records.length,
      };
    } },

    nodeSelf: { method: 'GET', path: '/nodes/self', handler: () => service.primary.descriptor() },
    nodeHead: { method: 'GET', path: '/nodes/head', handler: async () => await service.primary.head() },
    nodeStatus: { method: 'GET', path: '/nodes/status', handler: async () => await service.primary.status() },
    nodeAccept: { method: 'POST', path: '/nodes/accept', gate: 'node', handler: async ({ body }) => {
      // Without this a peer's malformed submission crashes while the node reads
      // submission.actionProof.record and answers 500; a submission that cannot be
      // parsed must be refused, not appended to the chain.
      if (!body?.identity?.id || !body?.actionProof?.record || !body?.actionProof?.recordHash) {
        throw new HttpError(400, 'SUBMISSION_INCOMPLETE', 'a replication submission must carry an identity document and an actionProof with its record and recordHash');
      }
      return await service.primary.accept(body);
    } },
    nodeCertify: { method: 'POST', path: '/nodes/certify', gate: 'node', handler: async ({ body }) => {
      if (!body?.record?.recordHash || !Array.isArray(body?.witnesses)) {
        throw new HttpError(400, 'CERTIFY_INCOMPLETE', 'certification requires the committed record and its witness set');
      }
      return await service.primary.certify(body);
    } },
    eventIngest: { method: 'POST', path: '/events', gate: 'node', handler: async ({ body }) => {
      if (!body?.event?.topic) throw new HttpError(400, 'EVENT_REQUIRED', 'expected { source, event }');
      eventBus.publish(body.event.topic, { ...body.event.payload, originNodeId: body.source ?? 'unknown' });
      return { accepted: true };
    } },
  };

  async function dispatch(method, path) {
    for (const [name, route] of Object.entries(routes)) {
      if (route.method !== method) continue;
      const match = matchPath(route.path, path);
      if (!match) continue;
      return { name, route, params: match.params };
    }
    return null;
  }

  async function handle(request, response) {
    const url = new URL(request.url, `http://${request.headers.host ?? 'localhost'}`);
    const matched = await dispatch(request.method, url.pathname);
    if (!matched) {
      if (request.method === 'GET') return serveStatic(url.pathname, response);
      return sendJson(response, 404, { error: { code: 'ROUTE_NOT_FOUND', message: `no route for ${request.method} ${url.pathname}` } });
    }
    const gate = authGate(matched.route.gate, request, config);
    if (gate) return sendJson(response, gate.status, { error: { code: gate.code, message: gate.message } });
    let body = null;
    if (request.method !== 'GET') {
      try {
        body = await readBody(request);
      } catch (error) {
        if (!(error instanceof HttpError)) throw error;
        return sendJson(response, error.status, { error: { code: error.code, message: error.message, details: error.details } });
      }
    }
    try {
      const result = await matched.route.handler({ body, params: matched.route.path.includes(':') ? matched.params : {}, query: url.searchParams, request });
      sendJson(response, request.method === 'POST' && matched.name === 'verifyAction' ? (result.status === 'trusted' ? 200 : 201) : 200, result);
    } catch (error) {
      if (error instanceof HttpError) return sendJson(response, error.status, { error: { code: error.code, message: error.message, details: error.details } });
      return sendJson(response, 500, { error: { code: 'INTERNAL', message: error.message ?? String(error) } });
    }
  }

  const server = createServer((request, response) => {
    handle(request, response).catch((error) => {
      sendJson(response, 500, { error: { code: 'HANDLER_CRASH', message: String(error?.message ?? error) } });
    });
  });

  const wss = new WebSocketServer({ server, path: '/ws' });
  const unsubscribe = eventBus.subscribe('*', (event) => {
    const payload = JSON.stringify(event);
    for (const client of wss.clients) if (client.readyState === 1) client.send(payload);
  });
  wss.on('connection', (socket) => {
    socket.send(JSON.stringify({ topic: 'stream.hello', payload: { coordinatorId: coordinator.id, sequence: eventBus.sequence, nodes: clients.map((client) => client.nodeId) }, seq: 0, at: new Date().toISOString() }));
    for (const event of eventBus.replay({ sinceSeq: 0 }).slice(-25)) socket.send(JSON.stringify(event));
  });
  server.on('close', () => {
    unsubscribe();
    wss.close();
  });

  function serveStatic(pathname, response) {
    const relative = pathname === '/' ? 'index.html' : normalize(pathname).replace(/^(\.\.[/\\])+/, '').replace(/^[/\\]+/, '');
    const file = join(PUBLIC_DIR, relative);
    if (!file.startsWith(PUBLIC_DIR)) {
      sendJson(response, 403, { error: { code: 'PATH_REJECTED', message: 'requested path escapes the public directory' } });
      return;
    }
    stat(file).then((info) => {
      if (!info.isFile()) throw new Error('not a file');
      response.writeHead(200, { 'content-type': CONTENT_TYPES[extname(file)] ?? 'application/octet-stream', 'content-length': info.size });
      createReadStream(file).pipe(response);
    }).catch(() => {
      sendJson(response, 404, { error: { code: 'NOT_FOUND', message: `no route and no file for ${pathname}`, hint: 'the API surface is listed at /health' } });
    });
  }

  return { server, handle, routes, wss };
}

function authGate(gate, request, config) {
  if (!gate || gate === 'public') return null;
  const token = (request.headers.authorization ?? '').replace(/^Bearer\s+/i, '').trim();
  const adminOk = Boolean(config.adminToken) && token === config.adminToken;
  if (gate === 'adminRequired') {
    if (!config.adminToken) {
      return { status: 503, code: 'ADMIN_TOKEN_NOT_CONFIGURED', message: 'this endpoint hands out signing keys or kills identities, so it is disabled until VERIX_ADMIN_TOKEN is set' };
    }
    return adminOk ? null : { status: 401, code: 'ADMIN_TOKEN_REQUIRED', message: 'this endpoint requires the admin bearer token' };
  }
  if (gate === 'node') {
    if (!config.nodeToken && !config.adminToken) return null;
    if (adminOk || (Boolean(config.nodeToken) && token === config.nodeToken)) return null;
    return { status: 401, code: 'NODE_TOKEN_REQUIRED', message: 'peer replication endpoints require the node bearer token (VERIX_NODE_TOKEN) or the admin token' };
  }
  if (gate === 'admin') {
    if (!config.adminToken) return null;
    return adminOk ? null : { status: 401, code: 'ADMIN_TOKEN_REQUIRED', message: 'this endpoint requires the admin bearer token' };
  }
  return { status: 500, code: 'GATE_MISCONFIGURED', message: `unknown auth gate ${gate} on route` };
}

function matchPath(pattern, pathname) {
  const patternParts = pattern.split('/').filter(Boolean);
  const pathParts = pathname.split('/').filter(Boolean);
  if (patternParts.length !== pathParts.length) return null;
  const params = {};
  for (const [index, part] of patternParts.entries()) {
    if (part.startsWith(':')) params[part.slice(1)] = decodeURIComponent(pathParts[index]);
    else if (part !== pathParts[index]) return null;
  }
  return { params };
}

export { HttpError };

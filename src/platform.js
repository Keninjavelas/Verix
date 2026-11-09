import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { assertBackendAvailable, loadConfig, STORAGE_BACKENDS } from './config.js';
import { hkdfSha3_256 } from './crypto/hash.js';
import { DEFAULT_SIGNING_ALG, deserializeKeyPair, generateSigningKeyPair, serializeKeyPair } from './crypto/pqc.js';
import { createIdentity, issueIdentityUnderIssuer } from './crypto/identity.js';
import { DynamoStore } from './nodes/dynamodb-store.js';
import { FileStore } from './nodes/file-store.js';
import { FirestoreStore } from './nodes/firestore-store.js';
import { MemoryStore } from './nodes/memory-store.js';
import { HttpNodeClient, LocalNodeClient } from './nodes/client.js';
import { VerixNode } from './nodes/node.js';
import { EventBus, RemoteEventForwarder } from './nodes/pubsub.js';
import { IdentityRegistry } from './nodes/registry.js';
import { ReplicationGroup } from './nodes/replication.js';
import { VerificationService } from './verification/service.js';
import { ProofIndex } from './intelligence/rag.js';
import { TrustCopilot } from './intelligence/copilot.js';

const SEED_BYTES = { 'ML-DSA-65': 32, 'ML-DSA-87': 32, 'SLH-DSA-SHA2-128F': 48 };

function deriveSeed(material, label, alg) {
  return hkdfSha3_256(material, `verix:seed:${label}`, 'verix:key-derivation:v1', SEED_BYTES[alg] ?? 32);
}

export function deriveAgentKeyPair({ keyMaterial, signingAlg = DEFAULT_SIGNING_ALG, name, seedLabel = null }) {
  if (!name) throw new Error('deriveAgentKeyPair requires the agent name the key was derived from');
  if (!keyMaterial) throw new Error('deriveAgentKeyPair requires VERIX_NODE_KEY_MATERIAL; without it agent keys are random and only the holder has the copy');
  return generateSigningKeyPair(signingAlg, { seed: deriveSeed(keyMaterial, `agent:${name}:${seedLabel ?? ''}`, signingAlg) });
}

// The coordinator signs every trust assessment in this ledger, so its key has to
// outlive the process that wrote them: derived from key material when configured,
// otherwise kept beside the data directory. Only an in-memory run treats it as
// throwaway, because nothing there survives the process either.
async function coordinatorKey({ config, signingAlg }) {
  if (config.keyMaterial) return generateSigningKeyPair(signingAlg, { seed: deriveSeed(config.keyMaterial, 'coordinator', signingAlg) });
  if (config.backend === STORAGE_BACKENDS.memory) return generateSigningKeyPair(signingAlg);
  const path = join(config.dataDir, 'coordinator-key.json');
  const stored = await readFile(path, 'utf8').then((text) => JSON.parse(text)).catch((error) => {
    if (error.code === 'ENOENT') return null;
    throw new Error(`the coordinator key at ${path} could not be read: ${error.message}`);
  });
  if (stored) {
    if (stored.alg !== signingAlg) {
      throw new Error(`the coordinator key at ${path} is ${stored.alg} but VERIX_SIGNING_ALG is ${signingAlg}; retire that key file deliberately rather than letting the assessment signer change silently`);
    }
    return deserializeKeyPair(stored);
  }
  const generated = await generateSigningKeyPair(signingAlg);
  await mkdir(config.dataDir, { recursive: true });
  await writeFile(path, `${JSON.stringify(serializeKeyPair(generated), null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  return generated;
}

export async function createStore({ backend, nodeId, region = null, config }) {
  assertBackendAvailable(backend);
  if (backend === STORAGE_BACKENDS.memory) return new MemoryStore({ name: nodeId });
  if (backend === STORAGE_BACKENDS.file) {
    const store = new FileStore({ directory: join(config.dataDir, nodeId), name: nodeId });
    return store.load();
  }
  if (backend === STORAGE_BACKENDS.dynamodb) return new DynamoStore({ region, name: nodeId });
  if (backend === STORAGE_BACKENDS.firestore) return new FirestoreStore({ projectId: config.gcpProjectId ?? null, name: nodeId });
  throw new Error(`no store adapter for backend ${backend}`);
}

export async function createPlatform({ config = loadConfig(), eventBus = new EventBus(), signingAlg = config.signingAlg ?? DEFAULT_SIGNING_ALG } = {}) {
  const trustAnchors = new Map();
  const nodes = [];
  const clients = [];
  const remotes = [];

  for (const plan of config.nodePlan) {
    if (plan.baseUrl) {
      const client = new HttpNodeClient({
        baseUrl: plan.baseUrl,
        nodeId: plan.nodeId ?? null,
        headers: config.nodeToken ? { authorization: `Bearer ${config.nodeToken}` } : {},
      });
      remotes.push(client);
      clients.push(client);
      continue;
    }
    const node = await VerixNode.create({
      nodeId: plan.nodeId,
      cloud: plan.cloud,
      region: plan.region ?? null,
      seed: config.keyMaterial ? deriveSeed(config.keyMaterial, plan.nodeId, signingAlg) : undefined,
      // A plan entry that names no backend follows the configured one: falling
      // back to memory here would drop the ledger on every restart unnoticed.
      store: await createStore({ backend: plan.backend ?? config.backend ?? STORAGE_BACKENDS.memory, nodeId: plan.nodeId, region: plan.region, config }),
      // Every node shares one anchor map: registering the coordinator here is
      // what makes it authoritative for lineage checks on all later proofs.
      trustAnchors,
      crossCheck: config.crossCheck,
    });
    nodes.push(node);
    clients.push(new LocalNodeClient(node));
  }
  if (clients.length === 0) throw new Error('platform configuration produced no verix nodes');

  for (const client of remotes) {
    const descriptor = await client.refresh().catch((error) => {
      throw new Error(`remote node ${client.baseUrl} is unreachable or unhealthy: ${error.message}`);
    });
    if (!descriptor?.nodeId) throw new Error(`remote node ${client.baseUrl} did not report a nodeId`);
  }

  const group = new ReplicationGroup({ clients, required: config.quorum });
  const registry = new IdentityRegistry({ clients, eventBus, trustAnchors });
  // Roots and keys have to survive a restart: anchors are rebuilt from the
  // stored identities, then the coordinator key is loaded or created, so an
  // assessment signed before the restart still verifies after it.
  const anchored = await registry.hydrateAnchors().catch(() => ({ anchors: [...trustAnchors.keys()], identities: 0, divergent: 0 }));

  const coordinatorKeyPair = await coordinatorKey({ config, signingAlg });
  const coordinator = await createIdentity({
    keyPair: coordinatorKeyPair,
    subject: { name: 'verix-coordinator', kind: 'platform' },
    scopes: [{ action: '*', resource: '*', constraint: { role: 'coordinator' } }],
    kind: 'coordinator',
  });
  await registry.register(coordinator);

  const service = new VerificationService({
    nodes: clients,
    group,
    registry,
    eventBus,
    config,
    primary: clients[0],
    coordinator: { keyPair: coordinatorKeyPair, identityId: coordinator.id },
  });

  // A multi-process fleet has one EventBus per process; mirroring local events
  // onto each peer's /events is what makes the UI live across nodes. The source
  // stamp is what stops a peer forwarding an event straight back here.
  const forwarder = remotes.length > 0
    ? new RemoteEventForwarder({
      bus: eventBus,
      peers: remotes.map((client) => ({ baseUrl: client.baseUrl, nodeId: client.nodeId })),
      headers: config.nodeToken ? { authorization: `Bearer ${config.nodeToken}` } : {},
      originNodeId: config.publicOrigin,
    })
    : null;

  const index = new ProofIndex();
  const copilot = new TrustCopilot({ index, registry, service, config });
  const indexErrors = [];

  // The proof has already been certified when these events fire, so the index can
  // take it straight away; without this the copilot and UI lag until a reindex.
  const identityMemo = new Map();
  const indexProof = async (event) => {
    try {
      const record = await service.primary.getRecord(event.payload.proofId);
      if (!record) throw new Error(`proof ${event.payload.proofId} was announced but is not readable from the primary node`);
      let identity = identityMemo.get(record.agentId);
      if (identity === undefined) {
        identity = (await registry.get(record.agentId).catch(() => null))?.identity ?? null;
        identityMemo.set(record.agentId, identity);
      }
      index.add(ProofIndex.fromRecord(record, { identity }));
    } catch (error) {
      indexErrors.push({ proofId: event.payload.proofId, error: String(error.message ?? error).slice(0, 200) });
    }
  };
  const indexUnsubscribes = ['action.verified', 'action.flagged'].map((topic) => eventBus.subscribe(topic, indexProof));
  const identityUnsubscribe = eventBus.subscribe('identity.registered', (event) => identityMemo.delete(event.payload.id));

  async function reindex({ limit = 2000 } = {}) {
    const listed = await registry.list().catch(() => ({ identities: [] }));
    const byId = new Map(listed.identities.map((identity) => [identity.id, identity]));
    return index.rebuildFrom(service, { limit, identities: byId });
  }

  async function agentKeyPair(name, seedLabel = null) {
    if (config.keyMaterial) return deriveAgentKeyPair({ keyMaterial: config.keyMaterial, signingAlg, name, seedLabel });
    return generateSigningKeyPair(signingAlg);
  }

  async function issueAgent({ name, scopes = [], kind = 'agent', ttlSeconds = 60 * 60 * 24 * 30, subject = {}, seedLabel = null } = {}) {
    if (!name) throw new Error('issueAgent requires a name');
    const keyPair = await agentKeyPair(name, seedLabel);
    const identity = await issueIdentityUnderIssuer({
      issuerKeyPair: coordinatorKeyPair,
      issuerIdentity: coordinator,
      keyPair,
      subject: { name, ...subject },
      scopes,
      kind,
      ttlSeconds,
    });
    await registry.register(identity);
    return { identity, keyPair };
  }

  async function status() {
    const perNode = await Promise.all(clients.map((client) => client.status()));
    return {
      coordinatorId: coordinator.id,
      nodes: perNode,
      quorumRequired: group.required,
      trustAnchors: [...trustAnchors.keys()],
      anchorHydration: anchored,
      indexedProofs: index.size,
      eventSequence: eventBus.sequence,
      eventForwarding: forwarder ? { peers: forwarder.peers.length, delivered: forwarder.delivered, failed: forwarder.failed, skippedEcho: forwarder.skippedEcho } : null,
    };
  }

  async function close() {
    forwarder?.close();
    for (const node of nodes) await node.store.close?.();
    eventBus.handlers.clear();
  }

  return {
    config,
    eventBus,
    nodes,
    clients,
    group,
    registry,
    service,
    index,
    copilot,
    coordinator,
    coordinatorKeyPair,
    trustAnchors,
    signingAlg,
    forwarder,
    reindex,
    agentKeyPair,
    issueAgent,
    status,
    close,
  };
}

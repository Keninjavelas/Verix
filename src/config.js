import { DEFAULT_SIGNING_ALG } from './crypto/pqc.js';

export const STORAGE_BACKENDS = {
  memory: 'memory',
  file: 'file',
  dynamodb: 'dynamodb',
  firestore: 'firestore',
};

const PLANNED_BACKENDS = {
  azure_table: 'Azure is marked planned in the design: install the optional client with `npm install @azure/data-tables`, then set VERIX_AZURE_TABLE_CREDENTIALS. No Azure store adapter is shipped yet, so enabling this backend is a deliberate configuration error rather than a silent fallback.',
};

export const DEFAULT_NODE_PLAN = [
  { nodeId: 'verix-node-aws-1', cloud: 'aws', region: 'us-east-1' },
  { nodeId: 'verix-node-gcp-1', cloud: 'gcp', region: 'us-central1' },
  { nodeId: 'verix-node-edge-1', cloud: 'local', region: 'local' },
];

export function loadConfig(env = process.env, overrides = {}) {
  const port = Number(env.VERIX_PORT ?? 4317);
  const dataDir = env.VERIX_DATA_DIR ?? '.verix-data';
  const backend = env.VERIX_BACKEND ?? STORAGE_BACKENDS.file;
  const nodePlan = env.VERIX_NODE_PLAN ? JSON.parse(env.VERIX_NODE_PLAN) : DEFAULT_NODE_PLAN.map((node) => ({ ...node, backend }));
  const nodeCount = nodePlan.length;
  return {
    port,
    host: env.VERIX_HOST ?? '127.0.0.1',
    dataDir,
    publicOrigin: env.VERIX_PUBLIC_ORIGIN ?? `http://${env.VERIX_HOST ?? '127.0.0.1'}:${port}`,
    nodePlan,
    keyMaterial: env.VERIX_NODE_KEY_MATERIAL ?? null,
    quorum: Number(env.VERIX_QUORUM ?? Math.floor(nodeCount / 2) + 1),
    signingAlg: env.VERIX_SIGNING_ALG ?? DEFAULT_SIGNING_ALG,
    crossCheck: env.VERIX_CROSS_CHECK !== '0',
    trustFloor: Number(env.VERIX_TRUST_FLOOR ?? 45),
    maxClockSkewSeconds: Number(env.VERIX_MAX_CLOCK_SKEW_SECONDS ?? 120),
    peers: (env.VERIX_PEERS ?? '').split(',').filter(Boolean).map((url) => ({ baseUrl: url })),
    adminToken: env.VERIX_ADMIN_TOKEN ?? null,
    nodeToken: env.VERIX_NODE_TOKEN ?? null,
    llm: {
      baseUrl: env.VERIX_LLM_BASE_URL ?? null,
      apiKey: env.VERIX_LLM_API_KEY ?? null,
      model: env.VERIX_LLM_MODEL ?? null,
    },
    vectorDb: {
      provider: env.VERIX_VECTOR_DB ?? null,
      apiKey: env.VERIX_VECTOR_DB_API_KEY ?? null,
      index: env.VERIX_VECTOR_DB_INDEX ?? 'verix-proofs',
    },
    ...overrides,
  };
}

export function assertBackendAvailable(backend) {
  if (PLANNED_BACKENDS[backend]) throw new Error(PLANNED_BACKENDS[backend]);
  if (!Object.values(STORAGE_BACKENDS).includes(backend)) {
    throw new Error(`unknown storage backend ${backend}, expected one of ${Object.values(STORAGE_BACKENDS).join(', ')} or a planned backend`);
  }
  return true;
}

export function plannedBackends() {
  return { ...PLANNED_BACKENDS };
}

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadConfig } from './config.js';
import { deserializeKeyPair, selfTest, serializeKeyPair } from './crypto/pqc.js';
import { executionFingerprint } from './crypto/identity.js';
import { deriveAgentKeyPair } from './platform.js';
import { buildActionEnvelope, signActionEnvelope } from './verification/action.js';
import { startVerix } from './index.js';

const HELP = `verix - quantum-resilient trust infrastructure for autonomous agents

usage: node src/cli.js <command> [options]

  serve          start the verification API + WebSocket + UI on VERIX_PORT (default 4317)
  demo           seed a three-node fleet with agents, proofs, an anomaly and a revocation
  verify         sign one action and verify it (--url to submit to a running node)
  ask            query the Trust Copilot over the ledger
  status         report nodes, chain heads, quorum and index size
  selftest       run the cryptographic and end-to-end conformance checks

options:
  --url <origin>        submit to a running server instead of an in-process fleet
  --name <name>         agent name as registered (demo/verify)
  --identity <id>       agent identity id (verify, when the name is ambiguous)
  --key <file>          serialized key pair written by demo, default .verix-data/agents/<name>.key.json
  --action <action>     e.g. deploy:infra
  --resource <res>      e.g. infra:prod-eu-1
  --context <json>      action context object, JSON
  --memory              use the in-memory backend so nothing is written to disk
  --quiet               machine-readable output only
`;

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === '--help' || token === '-h') args.help = true;
    else if (token.startsWith('--')) {
      if (i + 1 >= argv.length || argv[i + 1].startsWith('--')) args[token.slice(2)] = true;
      else {
        args[token.slice(2)] = argv[i + 1];
        i += 1;
      }
    } else args._.push(token);
  }
  return args;
}

function configFrom(args) {
  const overrides = {};
  if (args.memory) overrides.VERIX_BACKEND = 'memory';
  return loadConfig(process.env, overrides);
}

function out(args, value, human) {
  if (args.quiet) console.log(typeof value === 'string' ? value : JSON.stringify(value));
  else console.log(human());
}

async function localPlatform(args) {
  const { createPlatform } = await import('./platform.js');
  return await createPlatform({ config: configFrom(args) });
}

async function findIdentity({ registry, args }) {
  const listed = await registry.list();
  if (args.identity) {
    const exact = listed.identities.find((identity) => identity.id === args.identity);
    if (!exact) throw new Error(`identity ${args.identity} is not registered on any node`);
    return exact;
  }
  if (!args.name) throw new Error('verify requires --name or --identity');
  const matches = listed.identities.filter((identity) => identity.subject?.name === args.name);
  if (matches.length === 0) throw new Error(`no registered identity is named "${args.name}"`);
  if (matches.length > 1) throw new Error(`${matches.length} identities are named "${args.name}"; pass --identity <id>`);
  return matches[0];
}

async function keyPairFor({ args, config, identity }) {
  const label = String(args.name ?? identity.id).replace(/[^\w.-]/g, '_');
  const file = typeof args.key === 'string' ? args.key : join(config.dataDir, 'agents', `${label}.key.json`);
  try {
    return deserializeKeyPair(JSON.parse(await readFile(file, 'utf8')));
  } catch (error) {
    const missing = error.code === 'ENOENT' || error instanceof SyntaxError;
    if (!missing) throw error;
    if (!args.name) throw new Error(`no key pair at ${file} and no --name to reproduce one from: the platform never stores agent private keys`);
    return await deriveAgentKeyPair({ keyMaterial: config.keyMaterial, signingAlg: config.signingAlg, name: args.name, seedLabel: args.seedLabel ?? null });
  }
}

async function submitRemote({ args, path, body }) {
  const token = typeof args.adminToken === 'string' ? args.adminToken : process.env.VERIX_ADMIN_TOKEN;
  const response = await fetch(`${String(args.url).replace(/\/$/, '')}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify(body),
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) throw new Error(`${path} responded ${response.status}: ${payload?.error?.message ?? 'no body'}`);
  return payload;
}

async function identityFromRemote({ args, url }) {
  const listed = await fetch(`${url}/identities`).then((r) => r.json());
  const identities = listed.identities ?? [];
  if (args.identity) {
    const exact = identities.find((identity) => identity.id === args.identity);
    if (exact) return exact;
    return await fetch(`${url}/identities/${encodeURIComponent(args.identity)}`).then(async (r) => {
      const payload = await r.json();
      if (!r.ok) throw new Error(`identity ${args.identity} is unknown to ${url}`);
      return payload.identity;
    });
  }
  const matches = identities.filter((identity) => identity.subject?.name === args.name);
  if (matches.length !== 1) throw new Error(`--name "${args.name}" matched ${matches.length} identities on ${url}`);
  return matches[0];
}

async function commandServe(args) {
  const running = await startVerix({ config: configFrom(args) });
  out(args, { origin: running.origin, indexed: running.indexed.documents }, () => [
    `verix listening on ${running.origin}`,
    `nodes: ${running.platform.clients.map((client) => client.nodeId).join(', ')}`,
    `coordinator: ${running.platform.coordinator.id}`,
    `proofs indexed at boot: ${running.indexed.documents}`,
    `ui: ${running.origin}/  |  api: ${running.origin}/health  |  ws: ${running.origin.replace(/^http/, 'ws')}/ws`,
    running.config.adminToken ? '' : 'VERIX_ADMIN_TOKEN is unset: peer replication endpoints are open, which is a local-development posture only.',
  ].filter(Boolean).join('\n'));
  const stop = async () => {
    await running.close();
    process.exit(0);
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
  await new Promise(() => {});
}

const DEMO_AGENTS = [
  { name: 'Agent-7', scopes: [{ action: 'deploy:*', resource: 'infra:*' }, { action: 'read:*', resource: '*' }], role: 'release engineer' },
  { name: 'Agent-Ops', scopes: [{ action: 'read:logs', resource: 'svc:*' }], role: 'observability' },
  { name: 'Agent-Rogue', scopes: [{ action: 'read:*', resource: 'safe:*' }], role: 'undeclared automation' },
];

async function commandDemo(args) {
  const platform = await localPlatform(args);
  const keysDir = join(platform.config.dataDir, 'agents');
  const issued = [];
  for (const spec of DEMO_AGENTS) {
    const { identity, keyPair } = await platform.issueAgent({ name: spec.name, scopes: spec.scopes, subject: { role: spec.role } });
    issued.push({ ...spec, identity, keyPair });
    if (!args.memory) {
      await mkdir(keysDir, { recursive: true });
      await writeFile(join(keysDir, `${spec.name}.key.json`), JSON.stringify(serializeKeyPair(keyPair), null, 2));
    }
  }
  const byName = new Map(issued.map((entry) => [entry.name, entry]));
  const fp = executionFingerprint({ modelVersion: 'verix-demo-1', promptHash: 'a'.repeat(64), codeVersion: 'v1', toolset: ['terraform', 'kubectl'] });
  const actions = [
    ...[1, 2, 3].map(() => ({ who: 'Agent-7', action: 'deploy:infra', resource: 'infra:prod-eu-1', context: { costUsd: 12, destructive: false } })),
    { who: 'Agent-Ops', action: 'read:logs', resource: 'svc:audit', context: {} },
    { who: 'Agent-Rogue', action: 'deploy:infra', resource: 'infra:prod-eu-1', context: { destructive: true } },
    ...[4, 5, 6, 7, 8, 9].map((i) => ({ who: 'Agent-7', action: 'deploy:infra', resource: 'infra:prod-eu-1', context: { costUsd: 9 + i, burst: true } })),
    { who: 'Agent-7', action: 'terminate:infra', resource: 'infra:staging-1', context: { destructive: true } },
  ];
  const proofs = [];
  for (const item of actions) {
    const agent = byName.get(item.who);
    proofs.push(await platform.service.verifyAction({
      identity: agent.identity,
      keyPair: agent.keyPair,
      action: item.action,
      resource: item.resource,
      executionFingerprint: fp,
      context: item.context,
    }));
  }
  await platform.registry.revoke({ keyPair: platform.coordinatorKeyPair, identityId: byName.get('Agent-Ops').identity.id, reason: 'demo key rotation', revokedBy: platform.coordinator.id });
  const indexed = await platform.reindex();
  const status = await platform.status();
  await platform.close();
  out(args, { proofs: proofs.map((p) => ({ id: p.proofId, status: p.status, score: p.trustScore })), indexed }, () => [
    `seeded ${actions.length} proofs across ${status.nodes.length} nodes (${status.nodes.map((node) => `${node.nodeId} len ${node.head.seq}`).join(', ')})`,
    ...proofs.map((proof) => `  ${proof.status.padEnd(9)} ${String(proof.trustScore).padStart(6)}  ${proof.action} on ${proof.resource}  ${proof.proofId.slice(0, 16)}`),
    `index: ${indexed.documents} documents, ${indexed.distinctTerms} terms`,
    args.memory ? 'in-memory run: nothing written' : `agent keys written to ${keysDir}; agent secrets live only there, while each node keeps its own signing key beside the ledger so its chain still verifies after a restart`,
    `then: node src/cli.js serve   # UI and copilot over this data`,
  ].join('\n'));
}

async function commandVerify(args) {
  if (!args.action || !args.resource) throw new Error('verify requires --action and --resource');
  const context = args.context ? JSON.parse(String(args.context)) : {};
  const fingerprint = executionFingerprint({ modelVersion: 'verix-cli', promptHash: '0'.repeat(64), codeVersion: 'v1', toolset: [] });
  if (args.url) {
    const config = configFrom(args);
    const identity = await identityFromRemote({ args, url: String(args.url).replace(/\/$/, '') });
    const keyPair = await keyPairFor({ args, config, identity });
    const envelope = buildActionEnvelope({ agentId: identity.id, action: args.action, resource: args.resource, context, executionFingerprint: fingerprint });
    const signatureDoc = await signActionEnvelope(keyPair, envelope);
    const result = await submitRemote({ args, path: '/verify-action', body: { identityId: identity.id, action: args.action, resource: args.resource, context, executionFingerprint: fingerprint, envelope, signatureDoc } });
    out(args, result, () => proofLines(result).join('\n'));
    return;
  }
  const platform = await localPlatform(args);
  const identity = await findIdentity({ registry: platform.registry, args });
  const keyPair = await keyPairFor({ args, config: platform.config, identity });
  const result = await platform.service.verifyAction({ identity, keyPair, action: args.action, resource: args.resource, context, executionFingerprint: fingerprint });
  await platform.close();
  out(args, result, () => proofLines(result).join('\n'));
}

function proofLines(result) {
  return [
    `status ${result.status} - ${result.reason}`,
    `proof ${result.proofId}`,
    `trust ${result.trustScore}/100 band ${result.band} (floor ${result.scored?.trustFloor ?? '-'}, mode ${result.allowedMode}, meets floor ${result.meetsFloor})`,
    `signature ${result.checks?.actionSignature ? 'valid' : 'INVALID'} | lineage ${result.lineage?.valid ? 'valid' : 'BROKEN'} | quorum ${result.quorum?.agreeingCount}/${result.quorum?.required} of ${result.quorum?.total}`,
    `cross-cloud roots ${result.divergence?.consistent ? 'agree' : 'DIVERGE'} (distinct ${result.divergence?.distinctRoots ?? '-'})`,
    `attested ${result.nodes?.length ?? 0} node(s)${result.nodes?.length ? `: ${result.nodes.map((node) => node.nodeId).join(', ')}` : ''}`,
    ...(result.anomalies?.length ? [`anomalies: ${result.anomalies.map((a) => `${a.code}[${a.severity}]`).join(', ')}`] : []),
    `assessment signed by ${result.assessment?.coordinatorId ?? '-'} and self-verified ${result.assessment?.selfVerified ?? '-'}`,
  ];
}

async function commandAsk(args) {
  const question = args._.slice(1).join(' ') || args.question;
  if (!question) throw new Error('ask requires a question, e.g. node src/cli.js ask "why was the deployment flagged?"');
  if (args.url) {
    const answer = await submitRemote({ args, path: '/copilot/ask', body: { question, k: Number(args.k ?? 8) } });
    out(args, answer, () => `${answer.mode}: ${answer.answer}`);
    return;
  }
  const platform = await localPlatform(args);
  await platform.reindex();
  const answer = await platform.copilot.ask(question, { k: Number(args.k ?? 8) });
  await platform.close();
  out(args, answer, () => `${answer.mode}: ${answer.answer}`);
}

async function commandStatus(args) {
  if (args.url) {
    const base = String(args.url).replace(/\/$/, '');
    const [health, status] = await Promise.all([fetch(`${base}/health`).then((r) => r.json()), fetch(`${base}/status`).then((r) => r.json())]);
    out(args, { health, status }, () => renderStatus(health, status));
    return;
  }
  const platform = await localPlatform(args);
  const status = await platform.status();
  const crypto = await selfTest();
  await platform.close();
  out(args, status, () => renderStatus({ crypto: { signingAlg: platform.signingAlg }, security: {} }, { ...status, crypto: crypto.checks }));
}

function renderStatus(health, status) {
  const lines = [
    `crypto: ${health.crypto?.signingAlg ?? '?'} (selftest ${health.crypto?.crossImplementationCheck ? 'cross-implementation' : 'single-implementation'})`,
    `coordinator: ${status.coordinatorId}`,
    `quorum required: ${status.quorumRequired} | indexed proofs: ${status.indexedProofs} | events: ${status.eventSequence}`,
    ...status.nodes.map((node) => `  ${node.nodeId} [${node.cloud}/${node.region ?? '-'}] head ${node.head.seq} root ${String(node.head.root).slice(0, 16)} intact=${node.recentWindowIntact} records=${node.records} identities=${node.identities} revocations=${node.revocations}`),
    `trust anchors: ${(status.trustAnchors ?? []).length}`,
  ];
  if (status.eventForwarding) lines.push(`event forwarding: ${status.eventForwarding.delivered} delivered, ${status.eventForwarding.failed} failed, ${status.eventForwarding.skippedEcho} echoes refused`);
  return lines.join('\n');
}

async function commandSelftest(args) {
  const crypto = await selfTest();
  const results = [{ name: 'crypto conformance', pass: crypto.passed === true, detail: Object.entries(crypto.checks).filter(([, ok]) => !ok).map(([name]) => name).join(',') || `${Object.keys(crypto.checks).length} checks` }];
  const platform = await localPlatform({ ...args, memory: true });
  const agent = await platform.issueAgent({ name: 'selftest-agent', scopes: [{ action: 'read:*', resource: '*' }] });
  const ok = await platform.service.verifyAction({ identity: agent.identity, keyPair: agent.keyPair, action: 'read:logs', resource: 'svc:audit' });
  results.push({ name: 'authorized action trusted', pass: ok.status === 'trusted', detail: `score ${ok.trustScore}` });
  results.push({ name: 'quorum reached', pass: ok.quorum.reached === true, detail: `${ok.quorum.agreeingCount}/${ok.quorum.required}` });
  results.push({ name: 'assessment signed', pass: ok.assessment?.selfVerified === true, detail: ok.assessment?.coordinatorId });
  const forged = await platform.service.verifyAction({ identity: agent.identity, keyPair: (await platform.issueAgent({ name: 'other' })).keyPair, action: 'read:logs', resource: 'svc:audit' });
  results.push({ name: 'forged signature refused certification', pass: forged.checks.actionSignature === false, detail: `status ${forged.status} quorum ${forged.quorum.agreeingCount}` });
  const stored = await platform.service.getProof(ok.proofId);
  results.push({ name: 'proof readable from every node', pass: stored.present === platform.clients.length, detail: `${stored.present}/${platform.clients.length}` });
  await platform.close();
  const failed = results.filter((entry) => !entry.pass);
  out(args, results, () => results.map((entry) => `${entry.pass ? 'PASS' : 'FAIL'}  ${entry.name} :: ${entry.detail}`).join('\n') + `\n${results.length - failed.length}/${results.length} passed`);
  if (failed.length > 0) process.exitCode = 1;
}

export async function run(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const command = args._[0] ?? 'serve';
  if (args.help) {
    console.log(HELP);
    return;
  }
  switch (command) {
    case 'serve': await commandServe(args); break;
    case 'demo': await commandDemo(args); break;
    case 'verify': await commandVerify(args); break;
    case 'ask': await commandAsk(args); break;
    case 'status': await commandStatus(args); break;
    case 'selftest': await commandSelftest(args); break;
    default: throw new Error(`unknown command "${command}"\n\n${HELP}`);
  }
}

const invokedDirectly = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  run().catch((error) => {
    console.error(`verix ${error.message}`);
    process.exitCode = 1;
  });
}

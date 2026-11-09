import { createPlatform } from './platform.js';
import { loadConfig } from './config.js';
import { createVerixApp } from './api/server.js';

export { createPlatform, createVerixApp, loadConfig };
export { VerixNode } from './nodes/node.js';
export { VerificationService } from './verification/service.js';
export { IdentityRegistry } from './nodes/registry.js';
export { ReplicationGroup } from './nodes/replication.js';
export { EventBus, RemoteEventForwarder, PubSubBridge } from './nodes/pubsub.js';
export { TrustCopilot } from './intelligence/copilot.js';
export { ProofIndex } from './intelligence/rag.js';
export { selfTest } from './crypto/pqc.js';

export function addressOrigin(address) {
  const host = address.address === '::' || address.address === '0.0.0.0' ? '127.0.0.1' : address.address;
  return `http://${host.includes(':') ? `[${host}]` : host}:${address.port}`;
}

export async function startVerix({ config = loadConfig(), port = config.port, host = config.host } = {}) {
  const platform = await createPlatform({ config });
  const app = createVerixApp({ platform });
  await new Promise((resolve, reject) => {
    app.server.once('error', reject);
    app.server.listen(port, host, resolve);
  });
  const origin = addressOrigin(app.server.address());
  // The retrieval index is built from what the nodes already store, so a restarted
  // server answers copilot queries over its ledger instead of an empty index.
  const seeded = await platform.reindex();
  return {
    config,
    platform,
    app,
    origin,
    indexed: seeded,
    async close() {
      await new Promise((resolve) => app.server.close(resolve));
      await platform.close();
    },
  };
}

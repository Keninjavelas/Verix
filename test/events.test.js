import test from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import WebSocket from 'ws';
import { EventBus, RemoteEventForwarder, PubSubBridge } from '../src/nodes/pubsub.js';
import { loadConfig } from '../src/config.js';
import { createPlatform } from '../src/platform.js';
import { createVerixApp } from '../src/api/server.js';

const NODE_PLAN = [
  { nodeId: 'verix-node-aws-1', cloud: 'aws', region: 'us-east-1', backend: 'memory' },
  { nodeId: 'verix-node-gcp-1', cloud: 'gcp', region: 'us-central1', backend: 'memory' },
  { nodeId: 'verix-node-edge-1', cloud: 'local', region: 'local', backend: 'memory' },
];

const tick = () => new Promise((resolve) => setImmediate(resolve));

// Delivery is queued on microtasks and the socket streams frames in, so waiting
// for two identical readings is the only honest way to count what arrived.
async function quiet(readings, ms = 150) {
  let last = -1;
  for (;;) {
    await new Promise((resolve) => setTimeout(resolve, ms));
    if (readings.length === last) return;
    last = readings.length;
  }
}

async function serve(overrides = {}) {
  const config = loadConfig({}, { nodePlan: NODE_PLAN, backend: 'memory', crossCheck: false, ...overrides });
  const platform = await createPlatform({ config });
  const app = createVerixApp({ platform });
  await new Promise((resolve) => app.server.listen(0, '127.0.0.1', resolve));
  const { port } = app.server.address();
  return { port, config, platform, app, close: async () => { app.server.closeAllConnections?.(); await new Promise((resolve) => app.server.close(resolve)); await platform.close(); } };
}

test('the bus delivers on a later microtask and stamps each event with a monotonic sequence', async () => {
  const bus = new EventBus();
  const seen = [];
  bus.subscribe('action.verified', (event) => seen.push(event));
  const returned = bus.publish('action.verified', { proofId: 'a'.repeat(64) });
  assert.deepEqual(seen, [], 'a subscriber never runs inside publish, so the ledger write cannot be blocked by listener work');
  await tick();
  assert.equal(seen.length, 1);
  assert.deepEqual(Object.keys(returned), ['topic', 'payload', 'seq', 'at']);
  assert.equal(returned.seq, 1);
  assert.deepEqual(seen[0], returned);
  assert.equal(new Date(returned.at).toString() !== 'Invalid Date', true);
  bus.publish('action.flagged', { proofId: 'b'.repeat(64) });
  const third = bus.publish('action.flagged', { proofId: 'c'.repeat(64) });
  assert.equal(third.seq, 3, 'the sequence counts every publish, delivered or not');
  assert.equal(bus.history.length, 3);
  assert.deepEqual(bus.history.map((event) => [event.seq, event.topic]), [[1, 'action.verified'], [2, 'action.flagged'], [3, 'action.flagged']]);
});

test('a wildcard listener sees every topic while history rolls at historyLimit', async () => {
  const bus = new EventBus({ historyLimit: 3 });
  const topicHits = [];
  const wildHits = [];
  bus.subscribe('a', (event) => topicHits.push(event.seq));
  bus.subscribe('*', (event) => wildHits.push(event.seq));
  for (const [topic, n] of [['a', 1], ['b', 2], ['a', 3]]) bus.publish(topic, { n });
  await tick();
  assert.deepEqual(topicHits, [1, 3], 'a topic listener only sees its own topic');
  assert.deepEqual(wildHits, [1, 2, 3], 'a wildcard listener sees all of them, in sequence order');
  assert.deepEqual(bus.history.map((event) => event.seq), [1, 2, 3]);
  bus.publish('a', { n: 4 });
  bus.publish('a', { n: 5 });
  assert.deepEqual(bus.history.map((event) => event.seq), [3, 4, 5], 'the oldest event is dropped once historyLimit is passed');
  assert.deepEqual(bus.replay({ sinceSeq: 3 }).map((event) => event.seq), [4, 5], 'replay is strictly after sinceSeq');
  assert.deepEqual(bus.replay({ sinceSeq: 0, topic: 'b' }).map((event) => event.seq), [], 'b fell out of the retained history, so it cannot be replayed');
  assert.equal(new EventBus().historyLimit, 500);
});

test('unsubscribing stops delivery and removes the topic once its last listener leaves', async () => {
  const bus = new EventBus();
  const kept = [];
  const dropped = [];
  const off = bus.subscribe('proof', (event) => dropped.push(event.seq));
  bus.subscribe('proof', (event) => kept.push(event.seq));
  bus.publish('proof', {});
  await tick();
  assert.deepEqual([dropped, kept], [[1], [1]]);
  off();
  bus.publish('proof', {});
  await tick();
  assert.deepEqual(dropped, [1], 'the released handler is not called again');
  assert.deepEqual(kept, [1, 2]);
  const off2 = bus.subscribe('solo', () => {});
  off2();
  assert.equal(bus.handlers.has('solo'), false, 'an empty topic list is deleted rather than left behind');
});

test('a broken listener cannot take the node down or starve the other listeners', async () => {
  const bus = new EventBus();
  const survived = [];
  bus.subscribe('boom', () => { throw new Error('handler exploded'); });
  bus.subscribe('boom', async () => { throw new Error('promise exploded'); });
  bus.subscribe('boom', (event) => survived.push(event.seq));
  bus.publish('boom', {});
  await quiet(survived);
  assert.deepEqual(survived, [1], 'the third listener still gets the event');
  assert.deepEqual(bus.handlerErrors, [
    { topic: 'boom', seq: 1, error: 'handler exploded' },
    { topic: 'boom', seq: 1, error: 'promise exploded' },
  ], 'both a synchronous throw and a rejected promise are recorded, not rethrown');
  for (let i = 0; i < 40; i += 1) bus.publish('boom', { i });
  await quiet(bus.handlerErrors);
  assert.equal(bus.handlerErrors.length, 50, 'the record is bounded so a permanently failing listener cannot grow the heap');
  assert.deepEqual(Object.keys(bus.handlerErrors.at(-1)), ['topic', 'seq', 'error']);
});

test('the forwarder posts every local event to each peer with the node bearer token', async () => {
  const calls = [];
  const bus = new EventBus();
  const forwarder = new RemoteEventForwarder({
    bus,
    peers: [
      { baseUrl: 'http://peer-a.invalid/' },
      { baseUrl: 'http://peer-b.invalid', onFailure: (event, error) => calls.push(['failure', event.topic, event.seq, error.message]) },
    ],
    headers: { authorization: 'Bearer node-token' },
    originNodeId: 'http://127.0.0.1:4317',
    timeoutMs: 40,
    fetch: async (url, init) => {
      calls.push(['post', url, init.method, init.headers, JSON.parse(init.body)]);
      if (url.startsWith('http://peer-b.invalid')) {
        // A peer that never answers must be cut off by the timeout, not awaited forever.
        await new Promise((resolve, reject) => {
          init.signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })));
          setTimeout(resolve, 2_000);
        });
      }
      return { ok: true, status: 200 };
    },
  });
  const event = bus.publish('action.verified', { proofId: 'a'.repeat(64) });
  await quiet(calls);
  const posts = calls.filter((call) => call[0] === 'post');
  assert.deepEqual(posts.map((call) => call[1]), ['http://peer-a.invalid/events', 'http://peer-b.invalid/events'], 'a trailing slash in the peer base url is normalised');
  assert.deepEqual([...new Set(posts.map((call) => call[2]))], ['POST']);
  for (const call of posts) {
    assert.deepEqual(call[3], { 'content-type': 'application/json', authorization: 'Bearer node-token' });
    assert.deepEqual(call[4], { source: 'http://127.0.0.1:4317', event });
  }
  assert.deepEqual(calls.filter((call) => call[0] === 'failure'), [['failure', 'action.verified', 1, 'aborted']]);
  assert.deepEqual({ delivered: forwarder.delivered, failed: forwarder.failed, skippedEcho: forwarder.skippedEcho }, { delivered: 1, failed: 1, skippedEcho: 0 }, 'one slow peer does not stop the other from receiving the event');
  forwarder.close();
  const after = calls.length;
  bus.publish('action.flagged', { proofId: 'b'.repeat(64) });
  await new Promise((resolve) => setTimeout(resolve, 60));
  assert.equal(calls.length, after, 'close() detaches the forwarder from the bus');
});

test('an event that arrived from a peer is never forwarded back', async () => {
  const posts = [];
  const bus = new EventBus();
  const forwarder = new RemoteEventForwarder({
    bus,
    peers: [{ baseUrl: 'http://peer.invalid' }],
    originNodeId: 'http://127.0.0.1:4317',
    fetch: async (url, init) => {
      posts.push(JSON.parse(init.body));
      return { ok: true, status: 200 };
    },
  });
  bus.publish('action.verified', { proofId: 'a'.repeat(64), originNodeId: 'http://peer.invalid' });
  await new Promise((resolve) => setTimeout(resolve, 40));
  assert.deepEqual(posts, [], 'a stamped event is not posted, which is what breaks the echo loop');
  assert.equal(forwarder.skippedEcho, 1);
  assert.equal(forwarder.delivered, 0);
  const local = bus.publish('action.verified', { proofId: 'b'.repeat(64) });
  await new Promise((resolve) => setTimeout(resolve, 40));
  assert.deepEqual(posts.map((post) => post.event.seq), [local.seq]);
});

test('the forwarder refuses to start without a bus or an origin to stamp itself with', () => {
  assert.throws(() => new RemoteEventForwarder({ peers: [], originNodeId: 'http://x' }), /requires a bus/);
  assert.throws(
    () => new RemoteEventForwarder({ bus: new EventBus(), peers: [] }),
    /without a stamped source a peer would forward the event straight back/,
  );
});

test('a failed peer post is counted rather than thrown at the caller', async () => {
  const bus = new EventBus();
  const forwarder = new RemoteEventForwarder({
    bus,
    peers: [{ baseUrl: 'http://peer.invalid' }],
    originNodeId: 'http://127.0.0.1:4317',
    fetch: async () => ({ ok: false, status: 503 }),
  });
  bus.publish('action.verified', { proofId: 'a'.repeat(64) });
  await new Promise((resolve) => setTimeout(resolve, 40));
  assert.deepEqual({ delivered: forwarder.delivered, failed: forwarder.failed }, { delivered: 0, failed: 1 }, 'a non-2xx peer response is a delivery failure');
  bus.publish('action.verified', { proofId: 'b'.repeat(64) });
  await new Promise((resolve) => setTimeout(resolve, 40));
  assert.equal(forwarder.failed, 2, 'the event stays certified locally even while a peer is down');
});

test('PubSubBridge names the missing optional dependency instead of pretending to fan out', async () => {
  const bus = new EventBus();
  const bridge = new PubSubBridge({ bus });
  await assert.rejects(() => bridge.init(), /Google Cloud Pub\/Sub requires the optional dependency: run `npm install @google-cloud\/pubsub`/);

  const published = [];
  const stamped = [];
  const fakeClient = {
    topic: (name) => {
      stamped.push(name);
      return { publishMessage: async ({ data }) => published.push(JSON.parse(Buffer.from(data).toString('utf8'))) };
    },
    subscription: (name) => ({ on: () => {}, close: () => stamped.push(`sub:${name}`) }),
  };
  const wired = await new PubSubBridge({ bus: new EventBus(), pubsub: fakeClient, topic: 'verix-events' }).init();
  assert.deepEqual(stamped, ['verix-events']);
  wired.bus.publish('action.verified', { proofId: 'a'.repeat(64) });
  await tick();
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(published.length, 1, 'a local event crosses the bridge once');
  wired.bus.publish('action.verified', { proofId: 'b'.repeat(64), originNodeId: 'http://elsewhere' });
  await tick();
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(published.length, 1, 'an event that came from a peer is not republished to the topic');
  const acks = [];
  const received = [];
  const subClient = {
    topic: () => ({ publishMessage: async () => {} }),
    subscription: () => ({ on: (_event, handler) => received.push(handler), close: () => {} }),
  };
  const listening = await new PubSubBridge({ bus: new EventBus(), pubsub: subClient }).init();
  const unsubscribe = await listening.onMessage((event) => received.push(event));
  const [handler] = received;
  const message = { data: Buffer.from(JSON.stringify({ topic: 'action.flagged', payload: { proofId: 'c'.repeat(64) }, seq: 9, at: 'now' })), ack: () => acks.push('acked') };
  handler(message);
  assert.deepEqual(received[1], { topic: 'action.flagged', payload: { proofId: 'c'.repeat(64) }, seq: 9, at: 'now' }, 'the incoming message is parsed into the same event shape the bus uses');
  assert.deepEqual(acks, ['acked'], 'the message is acknowledged, so the subscription does not redeliver it forever');
  assert.equal(typeof unsubscribe, 'function');
  listening.close();
});

test('the websocket stream greets a client, replays a bounded history, then pushes live', async () => {
  const s = await serve();
  const messages = [];
  try {
    for (let i = 0; i < 30; i += 1) s.platform.eventBus.publish('tick.test', { i });
    await tick();
    const socket = new WebSocket(`ws://127.0.0.1:${s.port}/ws`);
    await new Promise((resolve, reject) => {
      socket.on('message', (data) => messages.push(JSON.parse(data.toString())));
      socket.on('open', resolve);
      socket.on('error', reject);
    });
    await quiet(messages);
    const [hello, ...replay] = messages;
    assert.equal(hello.topic, 'stream.hello');
    assert.equal(hello.seq, 0, 'the greeting is not an event and never carries a sequence');
    assert.deepEqual(Object.keys(hello.payload), ['coordinatorId', 'sequence', 'nodes']);
    assert.equal(hello.payload.coordinatorId, s.platform.coordinator.id);
    assert.deepEqual(hello.payload.nodes, NODE_PLAN.map((node) => node.nodeId));
    assert.equal(hello.payload.sequence, s.platform.eventBus.sequence);
    assert.equal(replay.length, 25, 'replay is capped at the last 25 events so a reconnect cannot drown the client');
    assert.deepEqual([...new Set(replay.map((event) => event.topic))], ['tick.test']);
    assert.deepEqual(replay.map((event) => event.seq), Array.from({ length: 25 }, (_, index) => hello.payload.sequence - 24 + index));
    s.platform.eventBus.publish('live.push', { value: 7 });
    await quiet(messages);
    assert.deepEqual(messages.at(-1).topic, 'live.push');
    assert.equal(messages.at(-1).payload.value, 7);
    socket.close();
    await new Promise((resolve) => socket.on('close', resolve));
    await quiet(messages);
    const count = messages.length;
    s.platform.eventBus.publish('after.close', { value: 1 });
    await tick();
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(messages.length, count, 'a closed socket receives nothing further');
    assert.equal(s.app.wss.clients.size, 0, 'the server drops the closed client from its set');
  } finally {
    await s.close();
  }
});

test('closing the server detaches the stream listener so a later publish cannot crash it', async () => {
  const s = await serve();
  try {
    assert.equal(s.platform.eventBus.handlers.get('*').length, 1, 'the server holds exactly one wildcard listener');
    const bus = s.platform.eventBus;
    await new Promise((resolve) => {
      s.app.server.closeAllConnections?.();
      s.app.server.close(resolve);
    });
    assert.equal(bus.handlers.has('*'), false, 'the wildcard listener is released on close');
    bus.publish('after.shutdown', { proofId: 'd'.repeat(64) });
    await tick();
    assert.equal(bus.history.at(-1).topic, 'after.shutdown', 'publishing after close is harmless, not fatal');
  } finally {
    await s.platform.close();
  }
});

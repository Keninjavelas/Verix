export class EventBus {
  constructor({ historyLimit = 500 } = {}) {
    this.handlers = new Map();
    this.history = [];
    this.historyLimit = historyLimit;
    this.handlerErrors = [];
    this.sequence = 0;
  }

  subscribe(topic, handler) {
    const list = this.handlers.get(topic) ?? [];
    list.push(handler);
    this.handlers.set(topic, list);
    return () => {
      const remaining = (this.handlers.get(topic) ?? []).filter((candidate) => candidate !== handler);
      if (remaining.length === 0) this.handlers.delete(topic);
      else this.handlers.set(topic, remaining);
    };
  }

  publish(topic, payload) {
    const event = { topic, payload, seq: ++this.sequence, at: new Date().toISOString() };
    this.history.push(event);
    if (this.history.length > this.historyLimit) this.history.shift();
    for (const handler of [...(this.handlers.get(topic) ?? []), ...(this.handlers.get('*') ?? [])]) {
      queueMicrotask(() => this.deliver(handler, event));
    }
    return event;
  }

  replay({ sinceSeq = 0, topic = null } = {}) {
    return topic === null
      ? this.history.filter((event) => event.seq > sinceSeq)
      : this.history.filter((event) => event.seq > sinceSeq && event.topic === topic);
  }

  /*
   * The write that triggered this publish already succeeded, so a broken listener
   * must not take the node down with it nor stop the other listeners from seeing
   * the event. Failures are recorded instead of thrown into the microtask queue.
   */
  deliver(handler, event) {
    try {
      const result = handler(event);
      if (result && typeof result.then === 'function') result.then(undefined, (error) => this.recordHandlerError(event, error));
    } catch (error) {
      this.recordHandlerError(event, error);
    }
  }

  recordHandlerError(event, error) {
    this.handlerErrors.push({ topic: event.topic, seq: event.seq, error: String(error?.message ?? error) });
    if (this.handlerErrors.length > 50) this.handlerErrors.shift();
  }
}

export class RemoteEventForwarder {
  constructor({ bus, peers = [], fetch = globalThis.fetch, timeoutMs = 8000, headers = {}, originNodeId }) {
    if (!bus) throw new Error('RemoteEventForwarder requires a bus');
    if (!originNodeId) {
      throw new Error('RemoteEventForwarder requires originNodeId: without a stamped source a peer would forward the event straight back and the two nodes would echo it forever');
    }
    this.bus = bus;
    this.peers = peers;
    this.fetch = fetch;
    this.timeoutMs = timeoutMs;
    this.headers = headers;
    this.originNodeId = originNodeId;
    this.delivered = 0;
    this.failed = 0;
    this.skippedEcho = 0;
    this.unsubscribe = bus.subscribe('*', (event) => this.broadcast(event));
  }

  async post(peer, event) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetch(`${peer.baseUrl.replace(/\/$/, '')}/events`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...this.headers },
        body: JSON.stringify({ source: this.originNodeId, event }),
        signal: controller.signal,
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      this.delivered += 1;
    } catch (error) {
      this.failed += 1;
      if (peer.onFailure) peer.onFailure(event, error);
    } finally {
      clearTimeout(timer);
    }
  }

  broadcast(event) {
    if (event.payload?.originNodeId) {
      this.skippedEcho += 1;
      return Promise.resolve([]);
    }
    return Promise.all(this.peers.map((peer) => this.post(peer, event)));
  }

  close() {
    this.unsubscribe();
  }
}

async function loadPubSubSdk() {
  try {
    const module = await import('@google-cloud/pubsub');
    return module.PubSub ? new module.PubSub() : null;
  } catch (error) {
    if (error?.code === 'ERR_MODULE_NOT_FOUND') {
      throw new Error('Google Cloud Pub/Sub requires the optional dependency: run `npm install @google-cloud/pubsub` and provide GOOGLE_APPLICATION_CREDENTIALS');
    }
    throw error;
  }
}

export class PubSubBridge {
  constructor({ bus, topic = 'verix-events', projectId = null, pubsub = null }) {
    this.bus = bus;
    this.topic = topic;
    this.projectId = projectId;
    this.client = pubsub;
    this.subcriptions = [];
  }

  async init() {
    if (!this.client) this.client = await loadPubSubSdk();
    this.outgoing = this.client.topic(this.topic);
    this.unsubscribeLocal = this.bus.subscribe('*', (event) => {
      if (event.payload?.originNodeId) return;
      this.outgoing.publishMessage({ data: Buffer.from(JSON.stringify(event)) }).catch(() => {});
    });
    return this;
  }

  async onMessage(handler) {
    if (!this.client) this.client = await loadPubSubSdk();
    const subscription = this.client.subscription(`${this.topic}-sub`);
    subscription.on('message', (message) => {
      try {
        handler(JSON.parse(Buffer.from(message.data).toString('utf8')));
      } finally {
        message.ack();
      }
    });
    this.subcriptions.push(subscription);
    return () => subscription.close();
  }

  close() {
    this.unsubscribeLocal?.();
    for (const subscription of this.subcriptions) subscription.close();
    this.subcriptions = [];
  }
}

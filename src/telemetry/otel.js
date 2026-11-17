// ==============================================================================
// Verix AI-Native Observability — Phase 5 Deliverable 1: OpenTelemetry Bootstrap
// ==============================================================================
// Initializes the OpenTelemetry Trace Provider with OTLP/HTTP export and a
// non-blocking BatchSpanProcessor so Post-Quantum Cryptographic (ML-DSA / ML-KEM)
// verification latency is never degraded by synchronous telemetry I/O.
// Automatically loads @opentelemetry/* packages when installed in the runtime
// image while providing a deterministic W3C-compliant BatchSpanProcessor engine
// for zero-dependency offline execution and conformance testing.
// ==============================================================================

import { randomBytes } from 'node:crypto';

export const DEFAULT_OTLP_ENDPOINT = 'http://127.0.0.1:4318/v1/traces';

/**
 * Asynchronous BatchSpanProcessor that buffers completed spans in memory and
 * flushes them in bounded batches over OTLP/HTTP to prevent telemetry backpressure
 * from affecting PQC signature verification latency.
 */
export class VerixBatchSpanProcessor {
  constructor({
    endpoint = process.env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT ?? process.env.OTEL_EXPORTER_OTLP_ENDPOINT ?? DEFAULT_OTLP_ENDPOINT,
    headers = {},
    maxQueueSize = 2048,
    maxExportBatchSize = 512,
    scheduledDelayMillis = 5000,
    exportTimeoutMillis = 30000,
    serviceName = process.env.OTEL_SERVICE_NAME ?? 'verix-zero-trust-api',
    cloudProvider = process.env.VERIX_CLOUD_PROVIDER ?? 'multi-cloud',
  } = {}) {
    this.endpoint = endpoint;
    this.headers = headers;
    this.maxQueueSize = maxQueueSize;
    this.maxExportBatchSize = maxExportBatchSize;
    this.scheduledDelayMillis = scheduledDelayMillis;
    this.exportTimeoutMillis = exportTimeoutMillis;
    this.serviceName = serviceName;
    this.cloudProvider = cloudProvider;
    this.queue = [];
    this.droppedSpans = 0;
    this.timer = null;
  }

  start() {
    if (this.timer) return;
    this.timer = setInterval(() => {
      this.flush().catch(() => {});
    }, this.scheduledDelayMillis);
    this.timer.unref?.();
  }

  onEnd(span) {
    if (this.queue.length >= this.maxQueueSize) {
      // Drop oldest span when buffer is saturated to preserve API latency SLAs
      this.queue.shift();
      this.droppedSpans += 1;
    }
    this.queue.push(span);
    if (this.queue.length >= this.maxExportBatchSize) {
      this.flush().catch(() => {});
    }
  }

  async flush() {
    if (this.queue.length === 0) return { exported: 0 };
    const batch = this.queue.splice(0, this.maxExportBatchSize);
    if (process.env.OTEL_SDK_DISABLED === 'true') {
      return { exported: 0, skipped: true };
    }

    const payload = {
      resourceSpans: [
        {
          resource: {
            attributes: [
              { key: 'service.name', value: { stringValue: this.serviceName } },
              { key: 'service.namespace', value: { stringValue: 'verix.pqc.audit' } },
              { key: 'cloud.provider', value: { stringValue: this.cloudProvider } },
            ],
          },
          scopeSpans: [
            {
              scope: { name: 'verix.telemetry.otel', version: '0.1.0' },
              spans: batch,
            },
          ],
        },
      ],
    };

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.exportTimeoutMillis);
    timeout.unref?.();

    try {
      await fetch(this.endpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          ...this.headers,
        },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
      return { exported: batch.length };
    } catch {
      return { exported: 0 };
    } finally {
      clearTimeout(timeout);
    }
  }

  async shutdown() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    await this.flush();
  }
}

/**
 * Generates W3C Trace Context identifiers (16-byte traceId hex, 8-byte spanId hex).
 */
export function generateTraceId() {
  return randomBytes(16).toString('hex');
}

export function generateSpanId() {
  return randomBytes(8).toString('hex');
}

/**
 * Bootstraps OpenTelemetry Node SDK with @opentelemetry/exporter-trace-otlp-http,
 * BatchSpanProcessor, and HTTP/Express auto-instrumentation when installed, or
 * falls back seamlessly to VerixBatchSpanProcessor.
 */
export async function bootstrapOpenTelemetry(options = {}) {
  const processor = new VerixBatchSpanProcessor(options);
  processor.start();

  try {
    const [
      { NodeTracerProvider },
      { BatchSpanProcessor },
      { OTLPTraceExporter },
      { registerInstrumentations },
      { HttpInstrumentation },
    ] = await Promise.all([
      import('@opentelemetry/sdk-trace-node'),
      import('@opentelemetry/sdk-trace-base'),
      import('@opentelemetry/exporter-trace-otlp-http'),
      import('@opentelemetry/instrumentation'),
      import('@opentelemetry/instrumentation-http'),
    ]);

    const exporter = new OTLPTraceExporter({
      url: processor.endpoint,
      headers: processor.headers,
    });

    const provider = new NodeTracerProvider();
    provider.addSpanProcessor(
      new BatchSpanProcessor(exporter, {
        maxQueueSize: processor.maxQueueSize,
        maxExportBatchSize: processor.maxExportBatchSize,
        scheduledDelayMillis: processor.scheduledDelayMillis,
        exportTimeoutMillis: processor.exportTimeoutMillis,
      }),
    );
    provider.register();

    registerInstrumentations({
      instrumentations: [
        new HttpInstrumentation({
          ignoreIncomingPaths: ['/health'],
        }),
      ],
    });

    return {
      mode: 'opentelemetry-sdk',
      processor,
      shutdown: async () => {
        await provider.shutdown();
        await processor.shutdown();
      },
    };
  } catch {
    return {
      mode: 'w3c-otlp-native',
      processor,
      shutdown: async () => {
        await processor.shutdown();
      },
    };
  }
}

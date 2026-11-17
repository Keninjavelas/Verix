// ==============================================================================
// Verix AI-Native Observability — Phase 5 Deliverable 3: Cross-Cloud Gossip Propagation
// ==============================================================================
// Combines the Phase 4 TLS 1.3 SPIFFE mTLS peer agent with Phase 5 W3C Trace
// Context (`traceparent` & `tracestate`) header injection so cross-cloud quorum
// replication from AWS Fargate (`verix-node-aws-1`) to GCP Cloud Run
// (`verix-node-gcp-1`) produces a single, cryptographically correlated trace.
// ==============================================================================

import { generateSpanId } from '../telemetry/otel.js';
import { formatTraceparent } from '../api/middleware.js';

/**
 * Injects W3C Trace Context headers (`traceparent`, `tracestate`) and creates
 * a child CLIENT span for outbound cross-cloud mTLS gossip calls.
 */
export function buildCrossCloudGossipHeaders({
  activeSpanContext,
  nodeToken = process.env.VERIX_NODE_TOKEN ?? null,
  sourceNodeId = 'verix-node-aws-1',
} = {}) {
  const childSpanId = generateSpanId();
  const headers = {
    'content-type': 'application/json',
    'x-verix-source-node': sourceNodeId,
  };

  if (nodeToken) {
    headers.authorization = `Bearer ${nodeToken}`;
  }

  if (activeSpanContext?.traceId) {
    headers.traceparent = formatTraceparent({
      traceId: activeSpanContext.traceId,
      spanId: childSpanId,
      traceFlags: activeSpanContext.traceFlags ?? '01',
    });
    if (activeSpanContext.tracestate) {
      headers.tracestate = activeSpanContext.tracestate;
    }
  }

  return { headers, childSpanId };
}

/**
 * Dispatches a signed quorum replication payload to a remote cloud peer over
 * the Phase 4 SPIFFE mTLS agent while propagating the W3C Trace Context.
 */
export async function dispatchTracedPeerGossip({
  peerOrigin,
  path,
  payload,
  activeSpanContext,
  mtlsAgent = null,
  nodeToken = process.env.VERIX_NODE_TOKEN ?? null,
  sourceNodeId = 'verix-node-aws-1',
  processor = null,
}) {
  const { headers, childSpanId } = buildCrossCloudGossipHeaders({
    activeSpanContext,
    nodeToken,
    sourceNodeId,
  });

  const startTimeUnixNano = BigInt(Date.now()) * 1_000_000n;
  const targetUrl = `${String(peerOrigin).replace(/\/$/, '')}${path}`;

  try {
    const response = await fetch(targetUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
      ...(mtlsAgent ? { dispatcher: mtlsAgent, agent: mtlsAgent } : {}),
    });

    const body = await response.json().catch(() => null);
    if (activeSpanContext?.traceId && processor) {
      processor.onEnd({
        traceId: activeSpanContext.traceId,
        spanId: childSpanId,
        parentSpanId: activeSpanContext.spanId,
        name: `verix.gossip.${path.replace(/^\//, '').replace(/\//g, '.')}`,
        kind: 3, // SPAN_KIND_CLIENT
        startTimeUnixNano: startTimeUnixNano.toString(),
        endTimeUnixNano: (BigInt(Date.now()) * 1_000_000n).toString(),
        attributes: [
          { key: 'verix.peer.origin', value: { stringValue: peerOrigin } },
          { key: 'verix.peer.mtls_enforced', value: { boolValue: Boolean(mtlsAgent) } },
          { key: 'http.response.status_code', value: { doubleValue: response.status } },
        ],
        status: { code: response.ok ? 1 : 2 },
      });
    }

    return { ok: response.ok, status: response.status, body, traceparent: headers.traceparent };
  } catch (error) {
    if (activeSpanContext?.traceId && processor) {
      processor.onEnd({
        traceId: activeSpanContext.traceId,
        spanId: childSpanId,
        parentSpanId: activeSpanContext.spanId,
        name: `verix.gossip.${path.replace(/^\//, '').replace(/\//g, '.')}`,
        kind: 3,
        startTimeUnixNano: startTimeUnixNano.toString(),
        endTimeUnixNano: (BigInt(Date.now()) * 1_000_000n).toString(),
        attributes: [
          { key: 'verix.peer.origin', value: { stringValue: peerOrigin } },
          { key: 'error.message', value: { stringValue: error.message } },
        ],
        status: { code: 2 },
      });
    }
    throw error;
  }
}

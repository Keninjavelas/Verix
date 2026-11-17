// ==============================================================================
// Verix AI-Native Observability — Phase 5 Deliverable 2: W3C Trace Context Middleware
// ==============================================================================
// Intercepts incoming verification requests (e.g., POST /verify-action), extracts
// upstream W3C `traceparent` and `tracestate` headers emitted by autonomous AI
// agents, creates a linked verification span, and enriches it with cryptographic
// audit attributes (agentId, action hash, PQC algorithm, and quorum outcome).
// ==============================================================================

import { generateSpanId, generateTraceId } from '../telemetry/otel.js';

const W3C_TRACEPARENT_REGEX = /^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/i;

/**
 * Parses a W3C Trace Context `traceparent` header (`00-<traceId>-<parentSpanId>-<flags>`).
 * If absent or malformed, generates a fresh root trace context.
 */
export function extractW3CTraceContext(headers = {}) {
  const rawTraceparent = String(headers.traceparent ?? headers['traceparent'] ?? '').trim();
  const rawTracestate = String(headers.tracestate ?? headers['tracestate'] ?? '').trim();

  const match = W3C_TRACEPARENT_REGEX.exec(rawTraceparent);
  if (match && match[1] !== '0'.repeat(32) && match[2] !== '0'.repeat(16)) {
    return {
      version: '00',
      traceId: match[1].toLowerCase(),
      parentSpanId: match[2].toLowerCase(),
      traceFlags: match[3].toLowerCase(),
      tracestate: rawTracestate || null,
      inherited: true,
    };
  }

  return {
    version: '00',
    traceId: generateTraceId(),
    parentSpanId: null,
    traceFlags: '01',
    tracestate: rawTracestate || null,
    inherited: false,
  };
}

/**
 * Formats a W3C `traceparent` header string for downstream cross-cloud propagation.
 */
export function formatTraceparent({ traceId, spanId, traceFlags = '01' }) {
  return `00-${traceId}-${spanId}-${traceFlags}`;
}

/**
 * Creates a request-scoped telemetry span for `POST /verify-action` and attaches
 * deterministic cryptographic verification attributes upon completion.
 */
export function createVerificationTraceMiddleware({ processor } = {}) {
  return {
    startVerificationSpan(req, body = {}) {
      const context = extractW3CTraceContext(req?.headers ?? {});
      const spanId = generateSpanId();
      const startTimeUnixNano = BigInt(Date.now()) * 1_000_000n;

      const attributes = {
        'http.request.method': req?.method ?? 'POST',
        'url.path': req?.url ?? '/verify-action',
        'verix.trace.inherited_from_agent': context.inherited,
        'verix.agent.id': body.identityId ?? body.envelope?.agentId ?? 'unknown',
        'verix.action.name': body.action ?? 'unknown',
        'verix.action.resource': body.resource ?? 'unknown',
      };

      return {
        traceId: context.traceId,
        spanId,
        parentSpanId: context.parentSpanId,
        traceFlags: context.traceFlags,
        tracestate: context.tracestate,
        traceparent: formatTraceparent({
          traceId: context.traceId,
          spanId,
          traceFlags: context.traceFlags,
        }),
        attributes,
        recordVerificationOutcome(result = {}) {
          attributes['verix.proof.id'] = result.proofId ?? 'none';
          attributes['verix.action.hash'] = result.record?.recordHash ?? result.record?.payloadDigest ?? 'none';
          attributes['verix.verification.status'] = result.status ?? 'error';
          attributes['verix.verification.trust_score'] = Number(result.trustScore ?? 0);
          attributes['verix.crypto.signature_valid'] = Boolean(result.checks?.actionSignature);
          attributes['verix.quorum.reached'] = Boolean(result.quorum?.reached);
          attributes['verix.quorum.agreeing_count'] = Number(result.quorum?.agreeingCount ?? 0);
          attributes['verix.divergence.consistent'] = Boolean(result.divergence?.consistent);
        },
        end(statusCode = 200) {
          const endTimeUnixNano = BigInt(Date.now()) * 1_000_000n;
          attributes['http.response.status_code'] = statusCode;

          const otlpSpan = {
            traceId: context.traceId,
            spanId,
            parentSpanId: context.parentSpanId ?? undefined,
            name: 'verix.verify_action',
            kind: 2, // SPAN_KIND_SERVER
            startTimeUnixNano: startTimeUnixNano.toString(),
            endTimeUnixNano: endTimeUnixNano.toString(),
            attributes: Object.entries(attributes).map(([key, value]) => ({
              key,
              value:
                typeof value === 'boolean'
                  ? { boolValue: value }
                  : typeof value === 'number'
                    ? { doubleValue: value }
                    : { stringValue: String(value) },
            })),
            status: {
              code: statusCode >= 400 ? 2 : 1,
            },
          };

          processor?.onEnd(otlpSpan);
          return otlpSpan;
        },
      };
    },
  };
}

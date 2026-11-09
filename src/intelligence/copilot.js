import { evidenceBlock, llmProviderFrom, systemPrompt } from './llm.js';
import { ProofIndex } from './rag.js';

export const INTENTS = {
  WHY_FLAGGED: 'why-flagged',
  AUTHORIZATION_CHECK: 'authorization-check',
  TRACE_SEQUENCE: 'trace-sequence',
  SCORE_EXPLAIN: 'score-explain',
  STATUS_SUMMARY: 'status-summary',
  SEARCH: 'search',
};

const INTENT_PATTERNS = [
  { intent: INTENTS.WHY_FLAGGED, patterns: [/why .*(flag|reject|denied|fail)/i, /what caused .*(flag|anomaly)/i, /explain .*(flagged|rejection)/i] },
  { intent: INTENTS.AUTHORIZATION_CHECK, patterns: [/\bwas\b.*\bauthorized\b/i, /\bhad\b.*\bpermission\b/i, /\ballowed (to|to run)\b/i, /authorize.*\bworkflow\b/i] },
  { intent: INTENTS.TRACE_SEQUENCE, patterns: [/trace/i, /sequence leading/i, /lineage/i, /what happened (before|after)/i, /replay/i] },
  { intent: INTENTS.SCORE_EXPLAIN, patterns: [/trust score/i, /why .*score/i, /breakdown/i, /components? of trust/i] },
  { intent: INTENTS.STATUS_SUMMARY, patterns: [/how many/i, /summary/i, /overview/i, /current state/i, /fleet status/i] },
];

const HEX_ID = /\b[0-9a-f]{16,64}\b/gi;
const AGENT_REF = /\b(?:agent[-\s_]?\d+|verix:agent:[a-z0-9_-]{6,})\b/gi;

export function classifyIntent(question) {
  for (const entry of INTENT_PATTERNS) {
    const matched = entry.patterns.find((pattern) => pattern.test(question));
    if (matched) return { intent: entry.intent, pattern: String(matched), confidence: 0.9 };
  }
  return { intent: INTENTS.SEARCH, pattern: null, confidence: 0.5 };
}

export function extractEntities(question) {
  const proofIds = question.match(HEX_ID) ?? [];
  const agentRefs = question.match(AGENT_REF) ?? [];
  const sequence = question.match(/\bseq(?:uence)?\s*#?(\d+)\b/i)?.[1] ?? null;
  return {
    proofIds,
    agentRefs,
    sequence: sequence === null ? null : Number(sequence),
    actions: (question.match(/\b(deploy|terminate|write|read|refund|escalate|invoke|transfer|delete|create|scale|rotate|query|orchestrate)(?::[\w*:.-]+)?\b/gi) ?? []),
    destructive: /\b(destructive|delete|terminate|drop|wipe)\b/i.test(question),
    windowHours: question.match(/last\s+(\d+)\s*h/)?.[1] ? Number(question.match(/last\s+(\d+)\s*h/)[1]) : null,
  };
}

function formatTime(value) {
  return value ? new Date(value).toISOString().replace('T', ' ').slice(0, 19) : 'unknown time';
}

function cite(index) {
  return `[${index + 1}]`;
}

export class TrustCopilot {
  constructor({ index, registry, service, provider = null, config = {} }) {
    this.index = index;
    this.registry = registry;
    this.service = service;
    this.config = config;
    this.provider = provider ?? llmProviderFrom(config);
    this.nameCache = null;
  }

  async agentNames() {
    const cache = { byRef: new Map(), ids: [] };
    try {
      const listed = await this.registry.list();
      this.nameCache = listed.identities;
    } catch {
      this.nameCache = this.nameCache ?? [];
    }
    for (const identity of this.nameCache) {
      const name = identity.subject?.name ?? null;
      cache.ids.push(identity.id);
      if (name) cache.byRef.set(name.toLowerCase(), identity.id);
      const tail = identity.id.split(':').pop();
      cache.byRef.set(tail.toLowerCase(), identity.id);
      if (name) {
        const alias = name.match(/agent[-\s_]?\w+/i)?.[0]?.toLowerCase();
        if (alias) cache.byRef.set(alias, identity.id);
      }
    }
    return cache;
  }

  async resolveAgentIds(refs) {
    const cache = await this.agentNames();
    const ids = new Set();
    for (const raw of refs) {
      const ref = raw.trim().toLowerCase();
      const direct = cache.byRef.get(ref) ?? cache.byRef.get(ref.replace(/^verix:agent:/, ''));
      if (direct) ids.add(direct);
      else if (/^verix:agent:/.test(raw)) ids.add(raw);
    }
    return { ids: [...ids], unresolved: refs.filter((ref) => !cache.byRef.has(ref.trim().toLowerCase()) && !/^verix:agent:/.test(ref)) };
  }

  evidenceFromDocument(document, relevance = null) {
    const { tokens, vector, ...doc } = document;
    return {
      id: doc.id,
      seq: doc.seq ?? null,
      agentId: doc.agentId,
      action: doc.action,
      resource: doc.resource,
      status: doc.status,
      reason: doc.reason ?? null,
      score: doc.score ?? null,
      relevance,
      document: doc,
    };
  }

  async evidenceForIdentifiers(ids) {
    const found = [];
    for (const id of ids) {
      const indexed = this.index.findByIdentifier(id);
      if (indexed) {
        found.push(this.evidenceFromDocument(indexed));
        continue;
      }
      const proof = await this.service.getProof(id).catch(() => null);
      if (proof?.record) {
        const identity = await this.registry.get(proof.record.agentId).catch(() => null);
        found.push(this.evidenceFromDocument(ProofIndex.fromRecord(proof.record, { identity: identity?.identity ?? null })));
      }
    }
    return found;
  }

  async ask(question, { k = 8, useModel = null } = {}) {
    const intent = classifyIntent(question);
    const entities = extractEntities(question);
    const resolved = await this.resolveAgentIds(entities.agentRefs);
    const filters = { agentId: resolved.ids.length === 1 ? resolved.ids[0] : null };
    const hits = this.index.search(question, { k, filters });
    const evidence = [];
    const seen = new Set();
    for (const item of await this.evidenceForIdentifiers(entities.proofIds)) {
      if (seen.has(item.id)) continue;
      seen.add(item.id);
      evidence.push(item);
    }
    for (const hit of hits) {
      if (seen.has(hit.id)) continue;
      seen.add(hit.id);
      evidence.push(this.evidenceFromDocument(hit.document, { score: hit.score, lexical: hit.lexical, semantic: hit.semantic, matched: hit.matched }));
    }
    const deterministic = await this.compose({ intent: intent.intent, entities, resolved, evidence, question });
    const grounding = { intent: intent.intent, intentConfidence: intent.confidence, retrieved: hits.length, resolvedAgents: resolved.ids, unresolvedAgents: resolved.unresolved };
    const modelRequested = useModel ?? Boolean(this.provider);
    if (modelRequested && this.provider) {
      try {
        const completion = await this.provider.complete({
          system: systemPrompt(evidence.map((item) => item.id)),
          prompt: `Question: ${question}\n\nDetected intent: ${intent.intent}\n\nDraft answer built directly from the ledger:\n${deterministic.answer}\n\nRewrite the draft as a concise operator-facing answer. Keep every citation marker and do not introduce any fact absent from the evidence.`,
          evidence,
        });
        return { ...grounding, ...deterministic, answer: `${completion.text}\n\n(deterministic grounding)\n${deterministic.answer}`, mode: 'rag+model', model: completion.model };
      } catch (error) {
        return { ...grounding, ...deterministic, mode: 'rag-only', modelError: String(error.message).slice(0, 240) };
      }
    }
    return { ...grounding, ...deterministic, mode: 'rag-only' };
  }

  async compose({ intent, entities, resolved, evidence, question }) {
    switch (intent) {
      case INTENTS.WHY_FLAGGED:
        return this.answerWhyFlagged({ evidence, entities });
      case INTENTS.AUTHORIZATION_CHECK:
        return this.answerAuthorization({ evidence, entities, resolved });
      case INTENTS.TRACE_SEQUENCE:
        return this.answerTrace({ evidence, entities });
      case INTENTS.SCORE_EXPLAIN:
        return this.answerScore({ evidence });
      case INTENTS.STATUS_SUMMARY:
        return this.answerSummary({ evidence });
      default:
        return this.answerSearch({ evidence, question });
    }
  }

  targetProof({ evidence, entities }) {
    if (entities.proofIds.length > 0) {
      const wanted = entities.proofIds[0].toLowerCase();
      const exact = evidence.find((item) => item.id.toLowerCase().startsWith(wanted));
      if (exact) return exact;
    }
    return evidence.find((item) => item.status === 'flagged' || item.status === 'rejected') ?? evidence[0] ?? null;
  }

  async answerWhyFlagged({ evidence, entities }) {
    const target = this.targetProof({ evidence, entities });
    if (!target) return { answer: 'No proofs matched the question, so nothing can be explained. Ask about a registered agent or a specific proof identifier.', evidence: [], citations: [] };
    const record = await this.service.getProof(target.id);
    const full = record?.record ?? target.document;
    const reasons = (full?.policy?.reasons ?? []).filter((entry) => entry.severity === 'deny');
    const anomalies = (full?.anomalies ?? []).filter((entry) => entry.severity !== 'low');
    const weak = (full?.trust?.components ?? []).filter((component) => component.achieved < 0.999);
    const lines = [];
    lines.push(`Proof ${target.id.slice(0, 16)}… (sequence ${target.seq}) recorded ${formatTime(full?.executedAt)} for agent ${target.agentId} executing ${target.action} on ${target.resource} carries status ${full?.trust?.status ?? target.status}${cite(0)}.`);
    if (reasons.length > 0) {
      lines.push(`Authorization was denied by ${reasons.length} policy finding(s):`);
      for (const entry of reasons) lines.push(`  - ${entry.code}: ${entry.detail}`);
    } else {
      lines.push('No policy finding denied the action, so the flag did not originate from authorization.');
    }
    if (anomalies.length > 0) {
      lines.push(`Behavioural detectors raised ${anomalies.length} finding(s):`);
      for (const anomaly of anomalies) lines.push(`  - [${anomaly.severity}] ${anomaly.code}: ${anomaly.detail}${anomaly.evidence ? ` (evidence: ${JSON.stringify(anomaly.evidence)})` : ''}`);
    }
    if (weak.length > 0) {
      lines.push(`Trust score ${full?.trust?.score ?? target.score}/100 lost credit in: ${weak.map((component) => `${component.key} (${(component.achieved * 100).toFixed(0)}% of ${component.weight})`).join(', ')}.`);
    }
    const nodes = (full?.witnesses ?? []).map((witness) => `${witness.nodeId}/${witness.cloud}`);
    lines.push(`Attested by ${nodes.length} independent node(s)${nodes.length ? `: ${nodes.join(', ')}` : ''}${full?.timestamp?.certifiedAt ? `; median witness time ${full.timestamp.certifiedAt}` : ''}.`);
    if (anomalies.some((a) => a.code === 'REPLICATION_DIVERGENCE')) {
      lines.push('Cross-cloud roots disagree for this sequence, which is the strongest available signal that at least one node copy is not trustworthy.');
    }
    return { answer: lines.join('\n'), evidence: [target], citations: [target.id] };
  }

  async answerAuthorization({ evidence, entities, resolved }) {
    const action = entities.actions[0] ?? null;
    const scope = action ? action.split(':')[0] : null;
    const candidates = evidence.filter((item) => (scope ? String(item.action).startsWith(scope) : true));
    const subjectLabel = resolved.ids[0] ?? (entities.agentRefs[0] ?? 'the referenced agent');
    if (candidates.length === 0) {
      const identities = await this.registry.list().catch(() => ({ identities: [] }));
      const identity = identities.identities.find((entry) => entry.id === resolved.ids[0]);
      if (!identity) return { answer: `No ledger evidence for ${subjectLabel}${action ? ` and action ${action}` : ''}, and the agent is not in the identity registry, so authorization cannot be confirmed either way.`, evidence: [], citations: [] };
      const scopes = (identity.scopes ?? []).map((entry) => `${entry.action} on ${entry.resource}`);
      return {
        answer: `${identity.subject?.name ?? identity.id} (${identity.id}) has no recorded actions${action ? ` matching ${action}` : ''}. Its identity grants ${scopes.length} scope(s): ${scopes.join('; ') || 'none'}. Whether ${action ?? 'the queried action'} falls inside them: ${scopes.some((entry) => !action || new RegExp(`^${entry.split(' on ')[0].replace(/\*/g, '.*')}$`).test(action)) ? 'yes, the scope pattern covers it' : 'no, no scope pattern covers it'}.`,
        evidence: [],
        citations: [],
      };
    }
    const authorized = candidates.filter((item) => item.status === 'trusted');
    const refused = candidates.filter((item) => item.status !== 'trusted');
    const lines = [`${subjectLabel}${action ? ` invoking ${action}` : ''}: ${candidates.length} matching proof(s) in the ledger, ${authorized.length} trusted, ${refused.length} not trusted${cite(0)}.`];
    for (const [i, item] of candidates.slice(0, 6).entries()) {
      const record = await this.service.getProof(item.id);
      const matched = record?.record?.policy?.matchedScopes ?? [];
      lines.push(`  ${i + 1}. sequence ${item.seq} ${formatTime(item.document?.executedAt)} status ${item.status}; ${matched.length ? `granted by scope ${matched.map((entry) => `${entry.action}:${entry.resource}`).join(', ')}` : 'no scope matched'}${record?.record?.timestamp?.certifiedAt ? `; attested at median ${record.record.timestamp.certifiedAt}` : ''}${cite(i)}`);
    }
    const verdict = authorized.length > 0 && refused.length === 0 ? 'AUTHORIZED' : authorized.length > 0 ? 'PARTIALLY AUTHORIZED' : 'NOT AUTHORIZED';
    lines.unshift(`Verdict for the recorded evidence: ${verdict}.`);
    return { answer: lines.join('\n'), evidence: candidates, citations: candidates.map((item) => item.id) };
  }

  async answerTrace({ evidence, entities }) {
    const target = this.targetProof({ evidence, entities });
    if (!target) return { answer: 'Nothing in the ledger matches the sequence you asked about.', evidence: [], citations: [] };
    const agentId = target.agentId;
    const records = await this.service.primary.listRecords({ agentId, limit: 200 });
    const ordered = records.filter((record) => record.seq !== undefined).sort((a, b) => a.seq - b.seq);
    const at = ordered.findIndex((record) => record.recordHash === target.id);
    const window = ordered.slice(Math.max(0, at - 4), Math.max(0, at + 1) + 2);
    const lines = [`Tracing agent ${agentId} around sequence ${target.seq}: ${ordered.length} proof(s) on record, showing ${window.length}.`];
    for (const [i, record] of window.entries()) {
      const marker = record.recordHash === target.id ? '  <-- queried' : '';
      const firstAnomaly = (record.anomalies ?? [])[0];
      lines.push(`  ${i + 1}. seq ${record.seq} ${formatTime(record.executedAt)} ${record.action} on ${record.resource} status ${record.trust?.status ?? '?'}${firstAnomaly ? ` anomaly ${firstAnomaly.code}[${firstAnomaly.severity}]` : ''}${record.prevEntryHash ? ` prev ${String(record.prevEntryHash).slice(0, 8)}…` : ''}${marker}`);
    }
    const audit = await this.service.auditNode(this.service.primary.nodeId, { from: Math.max(1, (target.seq ?? 1) - 6), to: target.seq });
    lines.push(`Chain audit over that window: ${audit.intact ? 'intact' : `FAILED with ${audit.problems.length} problem(s)`}${audit.rootChecked ? `; merkle root ${audit.root.slice(0, 16)}… recomputed from stored entries` : ''}.`);
    if (!audit.intact) for (const problem of audit.problems.slice(0, 5)) lines.push(`  ! sequence ${problem.seq} ${problem.code}: ${problem.detail}`);
    return { answer: lines.join('\n'), evidence: [target, ...window.map((record) => ({ id: record.recordHash, seq: record.seq, agentId, action: record.action, resource: record.resource, status: record.trust?.status ?? 'unknown', document: record }))], citations: [target.id, ...window.map((record) => record.recordHash)] };
  }

  async answerScore({ evidence }) {
    const target = evidence[0];
    if (!target) return { answer: 'No proof matched, so there is no score to break down.', evidence: [], citations: [] };
    const record = (await this.service.getProof(target.id))?.record ?? null;
    const trust = record?.trust ?? {};
    const document = target.document ?? {};
    const score = trust.score ?? document.score ?? target.score ?? 'unrecorded';
    const line = `${target.agentId} ${target.action}: trust ${score}/100, band ${trust.band ?? document.band ?? '?'}, status ${trust.status ?? target.status}${cite(0)}.`;
    const signals = trust.signals ?? document.signals ?? [];
    const detail = signals.length ? `Contributing signals: ${signals.join(', ')}.` : 'No signals were recorded for this proof.';
    const components = trust.components ?? [];
    const breakdown = components.length
      ? components.map((entry) => `  ${entry.key}: ${entry.points}/${entry.weight} weighted ${(entry.achieved * 100).toFixed(0)}% - ${entry.detail}`).join('\n')
      : '  (the stored proof carries no per-component breakdown; the score predates component recording)';
    const cap = trust.cappedAt ?? null;
    const capLine = cap === null ? '' : `\nHard cap ${cap} applied: a core verification check failed, so the weighted total could not raise the score above it.`;
    const anomalies = (record?.anomalies ?? []).map((anomaly) => `  anomaly [${anomaly.severity}] ${anomaly.code}: ${anomaly.detail}`);
    return {
      answer: [line, detail, 'Score components as stored on the proof:', breakdown, ...anomalies, capLine].filter(Boolean).join('\n'),
      evidence: [target],
      citations: [target.id],
    };
  }

  answerSummary({ evidence }) {
    const byStatus = new Map();
    const byAgent = new Map();
    for (const item of evidence) {
      byStatus.set(item.status, (byStatus.get(item.status) ?? 0) + 1);
      byAgent.set(item.agentId, (byAgent.get(item.agentId) ?? 0) + 1);
    }
    const lines = [`Indexed proofs: ${this.index.size}. Returned in this answer: ${evidence.length}.`];
    lines.push(`Status mix: ${[...byStatus].map(([status, count]) => `${status}=${count}`).join(', ') || 'none'}.`);
    lines.push(`Most active agents: ${[...byAgent].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([id, count]) => `${id}(${count})`).join(', ') || 'none'}.`);
    const worst = evidence.filter((item) => item.status === 'flagged' || item.status === 'rejected').slice(0, 3);
    if (worst.length > 0) lines.push(`Needing attention: ${worst.map((item) => `${item.id.slice(0, 8)}… seq ${item.seq} ${item.action}`).join('; ')}.`);
    return { answer: lines.join('\n'), evidence, citations: evidence.map((item) => item.id) };
  }

  answerSearch({ evidence, question }) {
    if (evidence.length === 0) return { answer: `No indexed proof matched "${question.slice(0, 80)}".`, evidence: [], citations: [] };
    const lines = [`Retrieved ${evidence.length} evidence item(s) for the query, ranked by combined BM25 and embedding score:`];
    for (const [index, item] of evidence.slice(0, 6).entries()) {
      const relevance = item.relevance ? ` (relevance ${item.relevance.score}${item.relevance.matched?.length ? `, matched ${item.relevance.matched.slice(0, 4).join('/')}` : ''})` : '';
      lines.push(`  ${index + 1}. seq ${item.seq} ${item.agentId} ${item.action} on ${item.resource} status ${item.status}${cite(index)}${relevance}`);
    }
    return { answer: lines.join('\n'), evidence: evidence.slice(0, 6), citations: evidence.slice(0, 6).map((item) => item.id) };
  }

  async explainFailure(proofId) {
    const evidence = await this.evidenceForIdentifiers([proofId]);
    if (evidence.length === 0) return { answer: `Proof ${proofId} is not present on any node, so it cannot be explained.`, evidence: [], citations: [] };
    return this.answerWhyFlagged({ evidence, entities: { proofIds: [proofId] } });
  }

  evidenceBlock(evidence) {
    return evidenceBlock(evidence);
  }
}

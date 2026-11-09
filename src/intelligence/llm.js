const MAX_EVIDENCE_ITEMS = 12;

function evidenceBlock(evidence) {
  return evidence.slice(0, MAX_EVIDENCE_ITEMS).map((item, index) => `${index + 1}. proof ${item.id.slice(0, 16)}… seq ${item.seq} agent ${item.agentId} action ${item.action} on ${item.resource} status ${item.status}${item.document?.reason ? ` reason: ${item.document.reason}` : ''}`).join('\n');
}

function systemPrompt(citationIds) {
  return [
    'You are the Verix Trust Copilot. You answer questions about autonomous AI agent actions using only the verified evidence supplied below.',
    'Every claim you make must be traceable to an evidence item; cite proof identifiers inline in the form [1], [2].',
    'If the evidence does not answer the question, say exactly what is missing instead of speculating.',
    'Never claim a verification passed when the evidence marks it flagged, rejected or unattested.',
    `Citable proof identifiers: ${citationIds.join(', ') || 'none'}.`,
  ].join('\n');
}

export class HttpLlmProvider {
  constructor({ baseUrl, apiKey, model, fetch = globalThis.fetch, timeoutMs = 30_000 }) {
    if (!baseUrl || !apiKey) throw new Error('HttpLlmProvider requires baseUrl and apiKey');
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.apiKey = apiKey;
    this.model = model ?? 'gpt-4o-mini';
    this.fetch = fetch;
    this.timeoutMs = timeoutMs;
  }

  get name() {
    return `openai-compatible:${this.model}@${this.baseUrl}`;
  }

  async complete({ system, prompt, evidence = [] }) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetch(`${this.baseUrl}/chat/completions`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${this.apiKey}` },
        body: JSON.stringify({
          model: this.model,
          temperature: 0,
          messages: [
            { role: 'system', content: `${system}\n\nVerified evidence:\n${evidenceBlock(evidence)}` },
            { role: 'user', content: prompt },
          ],
        }),
        signal: controller.signal,
      });
      if (!response.ok) {
        const detail = await response.text().catch(() => '');
        throw new Error(`LLM provider responded ${response.status}: ${detail.slice(0, 240)}`);
      }
      const payload = await response.json();
      const text = payload?.choices?.[0]?.message?.content;
      if (!text) throw new Error('LLM provider returned no completion content');
      return { text, model: payload.model ?? this.model, usage: payload.usage ?? null };
    } finally {
      clearTimeout(timer);
    }
  }
}

export function llmProviderFrom(config) {
  if (!config?.llm?.apiKey || !config?.llm?.baseUrl) return null;
  return new HttpLlmProvider({ baseUrl: config.llm.baseUrl, apiKey: config.llm.apiKey, model: config.llm.model });
}

export { evidenceBlock, systemPrompt };

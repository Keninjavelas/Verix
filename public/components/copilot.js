import { api, fmtClock, h, head, statusVar } from '../lib/format.js';

// The server writes citation markers as [1], [2]… keyed to its own evidence
// list; the UI turns each marker into a link to the exact proof it cites.
function withCitations(text, citations, onCite) {
  const parts = String(text).split(/(\[\d{1,2}\])/g);
  return parts.map((part) => {
    const match = /^\[(\d{1,2})\]$/.exec(part);
    if (!match) return part;
    const index = Number(match[1]) - 1;
    const id = citations[index];
    if (!id) return part;
    return h('a', {
      class: 'cite',
      href: `#${id}`,
      title: `open ${id}`,
      onclick: (event) => {
        event.preventDefault();
        onCite?.(id);
      },
    }, part);
  });
}

export function initCopilot({ logEl, formEl, inputEl, suggestEl, names, onCite, onAnswer }) {
  const asked = [];

  function bubble(role, nodes, meta = null) {
    const node = h('div', { class: `msg msg-${role}` }, ...nodes);
    if (meta) node.appendChild(h('span', { class: 'msg-meta' }, meta));
    logEl.appendChild(node);
    const body = logEl.closest('.rail-body');
    if (body) body.scrollTop = body.scrollHeight;
    return node;
  }

  async function ask(question) {
    const text = String(question ?? '').trim();
    if (!text) return;
    asked.push(text);
    bubble('user', [h('span', null, text)]);
    const pending = bubble('bot', [h('p', null, 'Consulting the ledger…')], 'retrieval in progress');
    pending.dataset.pending = 'true';
    const started = performance.now();

    let answer;
    try {
      answer = await api('/copilot/ask', { method: 'POST', body: { question: text, k: 8 } });
    } catch (error) {
      pending.textContent = '';
      pending.dataset.pending = 'false';
      pending.appendChild(h('p', { style: 'color: var(--crimson);' },
        `${error.code ?? 'ERROR'} · ${error.message}`));
      pending.appendChild(h('span', { class: 'msg-meta' }, 'no answer — the copilot refuses to invent one'));
      return;
    }

    const elapsed = Math.round(performance.now() - started);
    pending.textContent = '';
    delete pending.dataset.pending;
    pending.appendChild(h('p', null, ...withCitations(answer.answer, answer.citations ?? [], onCite)));

    const evidence = answer.evidence ?? [];
    if (evidence.length) {
      pending.appendChild(h('div', { class: 'evidence-row' }, ...evidence.slice(0, 6).map((item) => h('button', {
        class: 'pill',
        type: 'button',
        title: `${item.id}\n${item.reason ?? ''}`.trim(),
        onclick: () => onCite?.(item.id),
      },
      h('i', { class: 'dot', style: `color: var(--${statusVar(item.status)});` }),
      h('b', null, item.seq === null || item.seq === undefined ? '—' : `seq ${item.seq}`),
      names.get(item.agentId) ?? head(item.agentId, 14)))));
    }

    pending.appendChild(h('span', { class: 'msg-meta' },
      `${answer.intent ?? 'search'} · ${answer.mode}${answer.model ? ` · ${answer.model}` : ''}${answer.modelError ? ` · model unavailable (${head(answer.modelError, 48)})` : ''} · ${evidence.length} of ${answer.retrieved ?? 0} retrieved · ${elapsed}ms · ${fmtClock(new Date().toISOString())}Z`));

    onAnswer?.(answer);
    renderSuggestions();
  }

  function renderSuggestions() {
    suggestEl.textContent = '';
    const recent = asked.at(-1);
    for (const question of suggestionPool()) {
      if (question === recent) continue;
      suggestEl.appendChild(h('button', { class: 'pill', type: 'button', onclick: () => ask(question) }, question));
    }
  }

  function suggestionPool() {
    const named = [...names.values()];
    const who = named[0] ?? 'the first agent';
    const risky = named.find((name) => /rogue|ops|deploy/i.test(name)) ?? who;
    return [
      `Why was the most recent ${risky} action flagged?`,
      `Was ${who} authorized to run everything in the last hour?`,
      'Explain the trust score components of the newest proof.',
      'Summarise the current fleet state.',
      'Which proofs show cross-cloud divergence?',
    ];
  }

  formEl.addEventListener('submit', (event) => {
    event.preventDefault();
    const question = inputEl.value;
    inputEl.value = '';
    ask(question);
  });

  renderSuggestions();
  bubble('bot', [
    h('p', null, 'Ask about authorisation, anomalies or sequence. Every answer is grounded in a proof this instance can re-read; the bracketed markers link to the exact record hash.'),
  ], 'rag over the local ledger index · answers only from what is stored');

  return { ask, refreshSuggestions: renderSuggestions, asked };
}

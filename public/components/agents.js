import { chip, h, head, mixBar, relTime, statusVar } from '../lib/format.js';

function latestAt(timeline, agentId) {
  const forAgent = (timeline ?? []).filter((entry) => entry.agentId === agentId);
  if (forAgent.length === 0) return null;
  return forAgent.map((entry) => entry.executedAt).sort().at(-1);
}

export function renderAgents(target, { summary, selectedAgent, onSelectAgent }) {
  target.textContent = '';
  const agents = [...(summary.agents ?? [])].sort((a, b) => {
    if (Boolean(a.revoked) !== Boolean(b.revoked)) return a.revoked ? -1 : 1;
    return (b.score ?? -1) - (a.score ?? -1);
  });

  const note = document.getElementById('agentsNote');
  if (note) note.textContent = `${agents.length} with proofs · ${summary.totals?.proofs ?? 0} indexed`;

  if (agents.length === 0) {
    target.appendChild(h('div', { class: 'empty' },
      h('strong', null, 'Nothing to rank yet'),
      h('span', null, 'The ledger holds no proofs, so no agent has standing.'),
      h('code', null, 'npm run seed')));
    return;
  }

  const rows = agents.map((agent) => {
    const mix = { trusted: agent.trusted ?? 0, flagged: agent.flagged ?? 0, rejected: agent.rejected ?? 0, unattested: agent.unattested ?? 0 };
    const dominant = Object.entries(mix).sort((a, b) => b[1] - a[1])[0][0];
    const anomalies = agent.anomalies ?? [];
    return h('tr', {
      dataset: { agent: agent.agentId, selected: String(agent.agentId === selectedAgent) },
      tabindex: '0',
      onclick: () => onSelectAgent?.(agent.agentId),
      onkeydown: (event) => {
        if (event.key === 'Enter' || event.key === ' ') onSelectAgent?.(agent.agentId);
      },
    },
    h('td', { title: agent.agentId },
      h('span', { class: 't-name' }, agent.name ?? head(agent.agentId, 22), agent.revoked ? ' ' : null, agent.revoked ? chip('revoked') : null),
      h('span', { class: 't-sub mono' }, head(String(agent.agentId ?? '').split(':').pop(), 12))),
    h('td', { class: 'nowrap w-stand' },
      h('span', { class: 't-state' }, h('i', { style: `color: var(--${statusVar(dominant)});` }), chip(dominant)),
      h('span', { class: 't-sub' }, `${agent.proofs} proof(s) · seq ${agent.lastSeq}`)),
    h('td', { class: 'col-optional w-mix' }, mixBar(mix, agent.proofs)),
    h('td', { class: 'align-right w-score', title: agent.score === null || agent.score === undefined ? 'no score yet' : 'last score' },
      h('span', { class: 't-num' }, agent.score === null || agent.score === undefined ? '—' : agent.score.toFixed(1))),
    h('td', { class: 'align-right nowrap w-last', title: anomalies.length ? `${anomalies.reduce((sum, entry) => sum + entry.count, 0)} anomaly flag(s)` : 'no anomalies' },
      h('span', null, relTime(latestAt(summary.timeline, agent.agentId))),
      anomalies.length
        ? h('span', { class: 't-sub', style: 'color: var(--amber);' }, `×${anomalies.reduce((sum, entry) => sum + entry.count, 0)}`)
        : h('span', { class: 't-sub muted' }, '\u2014')));
  });

  target.appendChild(h('table', { class: 'table table-fixed' },
    h('thead', null, h('tr', null,
      h('th', null, 'Agent'),
      h('th', { class: 'w-stand' }, 'Standing'),
      h('th', { class: 'col-optional w-mix' }, 'Status mix'),
      h('th', { class: 'align-right w-score' }, 'Score'),
      h('th', { class: 'align-right w-last', title: 'Last proof' }, 'Latest'))),
    h('tbody', null, ...rows)));
}

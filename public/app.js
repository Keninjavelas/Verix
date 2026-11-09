import { api, chip, connectFeed, dash, emptyBlock, errorRow, fmtClock, h, head, hideTip, isBlank, plural, relTime, short, statusVar, toastMsg } from './lib/format.js';
import { fleetFacts, renderAnchors, renderFleet, renderSecurity, securityPanel } from './components/fleet.js';
import { renderAgents } from './components/agents.js';
import { focusAgent, pulse, renderTopology } from './components/topology.js';
import { renderTimeline } from './components/timeline.js';
import { createDossier } from './components/dossier.js';
import { initCopilot } from './components/copilot.js';

// First, and independently of everything else: content starts hidden for the
// scroll-in animation, so this must run even if a later render throws.
const revealables = [...document.querySelectorAll('.reveal')];
if ('IntersectionObserver' in window) {
  const seen = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      entry.target.dataset.shown = 'true';
      seen.unobserve(entry.target);
    }
  }, { rootMargin: '0px 0px -8% 0px' });
  for (const node of revealables) seen.observe(node);
} else {
  for (const node of revealables) node.dataset.shown = 'true';
}

const els = {
  feed: document.getElementById('feed'),
  feedText: document.getElementById('factFeed'),
  vitals: {
    trust: document.getElementById('vitalTrust'),
    proofs: document.getElementById('vitalProofs'),
    quorum: document.getElementById('vitalQuorum'),
    root: document.getElementById('vitalRoot'),
    crypto: document.getElementById('vitalCrypto'),
  },
  canvasTitle: document.getElementById('canvasTitle'),
  canvasHint: document.getElementById('canvasHint'),
  canvasTools: document.getElementById('canvasTools'),
  views: {
    topology: document.getElementById('viewTopology'),
    timeline: document.getElementById('viewTimeline'),
    records: document.getElementById('viewRecords'),
  },
  records: document.getElementById('recordsBody'),
  panes: {
    dossier: document.getElementById('paneDossier'),
    copilot: document.getElementById('paneCopilot'),
  },
  railTabs: [...document.querySelectorAll('.rail-tab')],
  topology: document.getElementById('topology'),
  timeline: document.getElementById('timeline'),
  dossier: document.getElementById('dossierBody'),
  agents: document.getElementById('agentsBody'),
  fleet: document.getElementById('fleetBody'),
  anchors: document.getElementById('anchorBody'),
  colophon: document.getElementById('colophonSecurity'),
  securityBtn: document.getElementById('securityBtn'),
  chatInput: document.getElementById('chatInput'),
};

const VIEW_TEXT = {
  topology: ['Trust topology', 'Each proof must be attested by a quorum that agrees on the same ledger root.'],
  timeline: ['Trust over sequence', 'One bar per proof in ledger order; height is the score the coordinator awarded it.'],
  records: ['Ledger records', 'Every proof this instance has indexed, newest first. Select a row for full forensics.'],
};

const STATUS_FILTERS = ['trusted', 'flagged', 'rejected', 'unattested'];

const state = {
  view: 'topology',
  pane: 'dossier',
  health: null,
  status: null,
  summary: null,
  topology: null,
  identities: null,
  selectedHash: null,
  selectedAgent: null,
  lastProofId: null,
  names: new Map(),
  revoked: new Set(),
  events: 0,
  unread: 0,
  booted: false,
  filter: { q: '', status: null },
};

const dossier = createDossier(els.dossier, {
  names: state.names,
  onSelectProof: (hash) => selectProof(hash),
  onSelectAgent: (id) => selectAgent(id),
});

/* ------------------------------------------------------------------ vitals */

function setVital(el, { value, sub, color = null, bar = null, title = null }) {
  if (!el) return;
  const valueEl = el.querySelector('.vital-v');
  const subEl = el.querySelector('.vital-sub');
  const before = valueEl.textContent;
  valueEl.textContent = String(value);
  valueEl.style.color = color ? `var(--${color})` : '';
  if (subEl) {
    subEl.textContent = dash(sub);
    if (title) subEl.title = title;
  }
  if (bar) {
    let track = el.querySelector('.vital-bar');
    if (!track) {
      track = h('span', { class: 'vital-bar', 'aria-hidden': 'true' });
      el.appendChild(track);
    }
    track.textContent = '';
    for (const seg of bar) track.appendChild(h('i', { style: `flex:${seg.weight}; background: var(--${seg.color});` }));
  }
  if (state.booted && before !== String(value)) {
    el.dataset.flash = 'true';
    setTimeout(() => { el.dataset.flash = 'false'; }, 900);
  }
}

function tone(share) {
  if (share >= 0.9) return 'jade';
  if (share >= 0.6) return 'amber';
  return 'crimson';
}

function renderVitals(facts) {
  const totals = state.summary?.totals ?? { proofs: 0, agents: 0, byStatus: {} };
  const mix = totals.byStatus ?? {};
  const share = totals.proofs ? (mix.trusted ?? 0) / totals.proofs : 0;
  const timeline = state.summary?.timeline ?? [];
  const seqs = timeline.map((entry) => entry.seq).filter((seq) => !isBlank(seq));
  const quorum = state.summary?.quorum ?? { required: facts?.quorum.required, of: facts?.quorum.of };
  const newest = timeline.map((entry) => entry.executedAt).filter(Boolean).sort().at(-1);

  setVital(els.vitals.trust, {
    value: totals.proofs ? `${Math.round(share * 100)}%` : '—',
    color: totals.proofs ? tone(share) : null,
    sub: totals.proofs
      ? `${mix.trusted ?? 0} of ${totals.proofs} trusted`
      : 'no proofs indexed yet',
    bar: STATUS_FILTERS.filter((status) => (mix[status] ?? 0) > 0)
      .map((status) => ({ weight: mix[status], color: statusVar(status) })),
    title: STATUS_FILTERS.map((status) => `${status} ${mix[status] ?? 0}`).join(' · '),
  });

  setVital(els.vitals.proofs, {
    value: totals.proofs ?? 0,
    sub: totals.proofs
      ? `newest ${newest ? relTime(newest) : 'unknown'}`
      : 'the ledger is empty',
    title: totals.proofs
      ? `${totals.agents} ${plural(totals.agents ?? 0, 'agent')} · seq ${Math.min(...seqs)}→${Math.max(...seqs)}${newest ? ` · newest ${fmtClock(newest)}Z` : ''}`
      : null,
  });

  setVital(els.vitals.quorum, {
    value: `${dash(quorum?.required, '?')} of ${dash(quorum?.of, 0)}`,
    sub: quorum?.of ? 'to certify one root' : 'no witnesses joined',
    color: quorum?.of ? null : 'amber',
    title: state.summary?.generatedAt ? `summary generated ${fmtClock(state.summary.generatedAt)}Z` : null,
  });

  setVital(els.vitals.root, {
    value: facts?.root.text ?? '—',
    color: facts?.root.divergent ? 'crimson' : null,
    sub: facts?.root.divergent
      ? 'nodes disagree — recent scores suspect'
      : `${state.status?.nodes?.length ?? 0} node(s) agree`,
    title: facts?.root.full ?? null,
  });

  setVital(els.vitals.crypto, {
    value: facts?.signingAlg ?? '—',
    sub: state.health?.crypto?.crossImplementationCheck ? 'cross-impl verified' : 'cross-check off',
    title: facts?.crypto ?? null,
  });
}

/* -------------------------------------------------------------------- views */

function setView(name) {
  if (!VIEW_TEXT[name]) return;
  state.view = name;
  for (const tab of document.querySelectorAll('.view-tab')) {
    const selected = tab.dataset.view === name;
    tab.setAttribute('aria-selected', String(selected));
    tab.tabIndex = selected ? 0 : -1;
  }
  for (const [key, panel] of Object.entries(els.views)) panel.hidden = key !== name;
  const [title, hint] = VIEW_TEXT[name];
  els.canvasTitle.textContent = title;
  els.canvasHint.textContent = hint;
  renderTools();
  if (name === 'timeline') drawTimeline();
  if (name === 'records') renderRecords();
}

function setPane(name) {
  state.pane = name;
  for (const tab of els.railTabs) {
    const selected = tab.dataset.pane === name;
    tab.setAttribute('aria-selected', String(selected));
    els.panes[tab.dataset.pane].hidden = !selected;
  }
  if (name === 'copilot') {
    state.unread = 0;
    updateBadge();
  }
}

function updateBadge() {
  const tab = document.getElementById('paneTabCopilot');
  if (!tab) return;
  tab.querySelector('.badge')?.remove();
  if (state.unread > 0 && state.pane !== 'copilot') {
    tab.appendChild(h('span', { class: 'badge' }, String(state.unread)));
  }
}

function renderTools() {
  els.canvasTools.textContent = '';
  if (state.view === 'records') {
    els.canvasTools.appendChild(h('input', {
      class: 'input',
      type: 'search',
      value: state.filter.q,
      placeholder: 'filter agent, action, resource or seq',
      'aria-label': 'Filter ledger records',
      oninput: (event) => {
        state.filter.q = event.target.value;
        renderRecords();
      },
    }));
    const all = h('button', {
      class: 'pill',
      type: 'button',
      dataset: { active: String(!state.filter.status) },
      onclick: () => { state.filter.status = null; renderTools(); renderRecords(); },
    }, `all ${state.summary?.totals?.proofs ?? 0}`);
    els.canvasTools.appendChild(all);
    for (const status of STATUS_FILTERS) {
      const count = state.summary?.totals?.byStatus?.[status] ?? 0;
      if (!count) continue;
      els.canvasTools.appendChild(h('button', {
        class: 'pill',
        type: 'button',
        dataset: { active: String(state.filter.status === status) },
        onclick: () => { state.filter.status = state.filter.status === status ? null : status; renderTools(); renderRecords(); },
      }, h('i', { class: 'dot', style: `color: var(--${statusVar(status)});` }), `${status} ${count}`));
    }
    return;
  }
  if (state.selectedAgent) {
    els.canvasTools.appendChild(h('button', {
      class: 'pill',
      type: 'button',
      onclick: () => selectAgent(state.selectedAgent),
    }, `focus: ${state.names.get(state.selectedAgent) ?? head(state.selectedAgent, 18)} — clear`));
  }
}

/* ------------------------------------------------------------------ records */

const RECORD_CAP = 200;

function matches(entry) {
  if (state.filter.status && entry.status !== state.filter.status) return false;
  const q = state.filter.q.trim().toLowerCase();
  if (!q) return true;
  const name = state.names.get(entry.agentId) ?? '';
  return [entry.seq, entry.agentId, name, entry.action, entry.resource, entry.status, entry.band, short(entry.recordHash, 64)]
    .some((field) => String(field ?? '').toLowerCase().includes(q));
}

function renderRecords() {
  if (!els.records) return;
  els.records.textContent = '';
  const all = state.summary?.timeline ?? [];
  if (all.length === 0) {
    els.records.appendChild(emptyBlock('No proofs indexed',
      h('span', null, 'Nothing has been verified against this ledger yet.'),
      h('code', null, 'npm run seed')));
    return;
  }
  const rows = all.filter(matches).sort((a, b) => (b.seq ?? 0) - (a.seq ?? 0));
  if (rows.length === 0) {
    els.records.appendChild(emptyBlock('No match', h('span', null, 'No proof matches this filter.')));
    return;
  }
  const shown = rows.slice(0, RECORD_CAP);

  els.records.appendChild(h('table', { class: 'table table-fixed' },
    h('thead', null, h('tr', null,
      h('th', { class: 'align-right w-seq' }, 'Seq'),
      h('th', { class: 'w-time', title: 'Executed at' }, 'Time'),
      h('th', { class: 'w-agent' }, 'Agent'),
      h('th', { title: 'Action on resource' }, 'Action'),
      h('th', { class: 'w-status' }, 'Status'),
      h('th', { class: 'align-right w-score' }, 'Score'),
      h('th', { class: 'col-optional w-wit' }, 'Witnesses'),
      h('th', { class: 'align-right w-flags', title: 'Anomalies' }, 'Flags'))),
    h('tbody', null, ...shown.map((entry) => h('tr', {
      dataset: { hash: entry.recordHash, selected: String(entry.recordHash === state.selectedHash) },
      tabindex: '0',
      onclick: () => selectProof(entry.recordHash),
      onkeydown: (event) => {
        if (event.key === 'Enter' || event.key === ' ') selectProof(entry.recordHash);
      },
    },
    h('td', { class: 'align-right nowrap w-seq' }, h('span', { class: 't-num' }, String(dash(entry.seq, '—')))),
    h('td', { class: 'nowrap w-time' }, h('span', { class: 't-sub', style: 'color: var(--fg-2);' }, fmtClock(entry.executedAt)),
      h('span', { class: 't-sub' }, relTime(entry.executedAt))),
    h('td', { class: 'w-agent', title: entry.agentId }, h('span', { class: 't-name' }, state.names.get(entry.agentId) ?? head(entry.agentId, 18)),
      h('span', { class: 't-sub mono' }, head(String(entry.agentId ?? '').split(':').pop(), 8))),
    h('td', { title: `${entry.action} ${entry.resource}` }, h('span', { class: 't-name' }, entry.action),
      h('span', { class: 't-sub mono' }, head(entry.resource, 40))),
    h('td', { class: 'w-status' }, chip(entry.status)),
    h('td', { class: 'align-right w-score', title: entry.band ?? null }, h('span', { class: 't-num' }, isBlank(entry.score) ? '—' : entry.score.toFixed(1))),
    h('td', { class: 'nowrap col-optional w-wit' }, h('span', { class: 't-sub' }, `${entry.clouds?.length ?? 0} cloud(s)`),
      h('span', { class: 't-sub mono' }, head((entry.clouds ?? []).join(','), 26))),
    h('td', {
      class: 'align-right nowrap w-flags',
      title: (entry.anomalies ?? []).length ? `${entry.anomalies.length} anomaly flag(s)` : 'no anomalies',
    }, (entry.anomalies ?? []).length
      ? h('span', { class: 't-sub', style: 'color: var(--crimson);' }, `×${entry.anomalies.length}`)
      : h('span', { class: 't-sub muted' }, '\u2014')))))));

  els.records.appendChild(h('p', { class: 't-sub', style: 'margin-top: var(--s-3);' },
    rows.length > shown.length
      ? `showing ${shown.length} of ${rows.length} matching proof(s) — narrow the filter for the rest`
      : `${rows.length} matching proof(s) · newest first`));
}

/* ------------------------------------------------------------------ loading */

async function load() {
  const [health, status, summary, topology, identities] = await Promise.all([
    api('/health').catch((error) => ({ error })),
    api('/status').catch((error) => ({ error })),
    api('/trust/summary?limit=500').catch((error) => ({ error })),
    api('/trust/topology?limit=200').catch((error) => ({ error })),
    api('/identities').catch((error) => ({ error })),
  ]);
  if ([health, status, summary, topology, identities].every((entry) => entry?.error)) {
    throw health.error;
  }
  state.health = health.error ? null : health;
  state.status = status.error ? null : status;
  state.summary = summary.error ? null : summary;
  state.topology = topology.error ? null : topology;
  state.identities = identities.error ? null : identities;

  state.names.clear();
  state.revoked.clear();
  for (const identity of state.identities?.identities ?? []) {
    if (identity.subject?.name) state.names.set(identity.id, identity.subject.name);
    if (identity.revokedAt) state.revoked.add(identity.id);
  }
  for (const agent of state.summary?.agents ?? []) {
    if (agent.name) state.names.set(agent.agentId, agent.name);
    if (agent.revoked) state.revoked.add(agent.agentId);
  }
  state.booted = true;
  document.getElementById('fatalBanner')?.remove();
  render();
}

function render() {
  const facts = state.status ? fleetFacts({ status: state.status, health: state.health }) : null;
  if (facts) {
    renderVitals(facts);
    els.securityBtn.dataset.alert = String(Boolean(facts.root.divergent
      || (state.health?.security && !state.health.security.adminTokenConfigured)));
    renderFleet(els.fleet, { status: state.status, onSelectNode: (id) => selectNode(id) });
    renderAnchors(els.anchors, {
      status: state.status,
      identities: state.identities,
      coordinatorId: state.status.coordinatorId,
      onSelectAgent: (id) => selectAgent(id),
    });
    if (state.health) renderSecurity(els.colophon, state.health);
  }
  if (state.summary) {
    renderAgents(els.agents, {
      summary: state.summary,
      selectedAgent: state.selectedAgent,
      onSelectAgent: (id) => selectAgent(id),
    });
    drawTimeline();
    renderRecords();
  }
  if (state.topology) {
    renderTopology(els.topology, {
      topology: state.topology,
      names: state.names,
      revoked: state.revoked,
      quorum: state.summary?.quorum ?? null,
      onSelectAgent: (id) => selectAgent(id),
      onSelectNode: (id) => selectNode(id),
    });
    focusAgent(els.topology, state.selectedAgent);
  }
  renderTools();
  if (els.feedText) els.feedText.title = state.summary ? `summary generated ${state.summary.generatedAt}` : '';
  copilot.refreshSuggestions();
}

/* -------------------------------------------------------------- selections */

function focusSeq() {
  if (!state.lastProofId) return null;
  return (state.summary?.timeline ?? []).find((entry) => entry.recordHash === state.lastProofId)?.seq ?? null;
}

function drawTimeline() {
  renderTimeline(els.timeline, {
    timeline: state.summary?.timeline ?? [],
    names: state.names,
    selectedHash: state.selectedHash,
    selectedAgent: state.selectedAgent,
    focusSeq: focusSeq(),
    onSelectProof: (hash) => selectProof(hash),
    onClearAgent: () => selectAgent(state.selectedAgent),
  });
}

function selectProof(hash) {
  state.selectedHash = hash;
  setPane('dossier');
  dossier.proof(hash);
  drawTimeline();
  renderRecords();
}

function selectAgent(id) {
  const clearing = state.selectedAgent === id;
  state.selectedAgent = clearing ? null : id;
  if (state.selectedAgent) {
    setPane('dossier');
    dossier.agent(state.selectedAgent);
  } else {
    dossier.clear('Select a proof, agent or node to open what the ledger actually says.');
  }
  focusAgent(els.topology, state.selectedAgent);
  renderAgents(els.agents, {
    summary: state.summary ?? { agents: [], totals: { proofs: 0 }, timeline: [], quorum: {} },
    selectedAgent: state.selectedAgent,
    onSelectAgent: (next) => selectAgent(next),
  });
  renderTools();
  drawTimeline();
  renderRecords();
}

function selectNode(nodeId) {
  const descriptor = (state.status?.nodes ?? []).find((node) => node.nodeId === nodeId) ?? null;
  setPane('dossier');
  dossier.node(nodeId, descriptor);
}

function showSecurity() {
  if (!state.health) {
    toastMsg('instance health unavailable — nothing to show');
    return;
  }
  dossier.cancel();
  setPane('dossier');
  const panel = securityPanel(state.health);
  if (!panel) {
    els.dossier.appendChild(errorRow({ code: 'NO_SECURITY', message: 'this build reports no security posture' }));
    return;
  }
  els.dossier.appendChild(panel);
  els.dossier.appendChild(h('button', {
    class: 'pill',
    type: 'button',
    onclick: () => dossier.clear('Select a proof, agent or node to open what the ledger actually says.'),
  }, 'close'));
}

/* --------------------------------------------------------------- lifecycle */

let refreshTimer = null;
function scheduleRefresh() {
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(() => load().catch(showFatal), 700);
}

function showFatal(error) {
  if (document.getElementById('fatalBanner')) return;
  els.views[state.view].prepend(h('div', { id: 'fatalBanner' }, emptyBlock('Instance unreachable',
    h('span', null, 'This page cannot read the ledger endpoints, so every figure above is stale.'),
    errorRow(error))));
  if (els.feed) els.feed.dataset.state = 'error';
  if (els.feedText) els.feedText.textContent = 'unreachable';
}

const copilot = initCopilot({
  logEl: document.getElementById('chatLog'),
  formEl: document.getElementById('chatForm'),
  inputEl: els.chatInput,
  suggestEl: document.getElementById('chatSuggest'),
  names: state.names,
  onCite: (hash) => {
    state.selectedAgent = null;
    focusAgent(els.topology, null);
    selectProof(hash);
    els.dossier.closest('.rail')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  },
  onAnswer: () => {
    if (state.pane !== 'copilot') {
      state.unread += 1;
      updateBadge();
    }
  },
});

for (const tab of document.querySelectorAll('.view-tab')) {
  tab.addEventListener('click', () => setView(tab.dataset.view));
}
for (const tab of els.railTabs) {
  tab.addEventListener('click', () => setPane(tab.dataset.pane));
}
els.securityBtn.addEventListener('click', showSecurity);

document.addEventListener('keydown', (event) => {
  if (event.metaKey || event.ctrlKey || event.altKey) return;
  const typing = ['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName);
  if (event.key === 'Escape') {
    if (typing) {
      document.activeElement.blur();
      return;
    }
    state.selectedAgent = null;
    state.selectedHash = null;
    state.filter = { q: '', status: null };
    focusAgent(els.topology, null);
    hideTip();
    dossier.clear('Select a proof, agent or node to open what the ledger actually says.');
    render();
    return;
  }
  if (typing) return;
  if (event.key === '/') {
    event.preventDefault();
    setPane('copilot');
    els.chatInput.focus();
    return;
  }
  const view = { 1: 'topology', 2: 'timeline', 3: 'records' }[event.key];
  if (view) {
    setView(view);
    return;
  }
  if (document.activeElement?.classList.contains('view-tab') && ['ArrowLeft', 'ArrowRight'].includes(event.key)) {
    event.preventDefault();
    const order = ['topology', 'timeline', 'records'];
    const step = event.key === 'ArrowRight' ? 1 : order.length - 1;
    const next = order[(order.indexOf(state.view) + step) % order.length];
    setView(next);
    document.getElementById(`tab${next[0].toUpperCase()}${next.slice(1)}`).focus();
  }
});

window.addEventListener('scroll', hideTip, { passive: true });

connectFeed({
  onState: (status, attempt) => {
    if (!els.feed || !els.feedText) return;
    els.feed.dataset.state = status;
    els.feedText.textContent = status === 'live'
      ? `live${state.events ? ` · ${state.events} ${plural(state.events, 'event')}` : ''}`
      : status === 'offline' ? `reconnecting (${attempt})` : status;
  },
  onEvent: (event) => {
    state.events += 1;
    if (els.feedText && els.feed?.dataset.state === 'live') {
      els.feedText.textContent = `live · ${state.events} ${plural(state.events, 'event')}`;
    }
    if (event.topic === 'identity.revoked') {
      state.revoked.add(event.payload.identityId);
      setVital(els.vitals.quorum, { value: `${dash(state.summary?.quorum?.required, '?')} of ${dash(state.summary?.quorum?.of, 0)}`, sub: 'identity revoked — re-reading' });
      scheduleRefresh();
      return;
    }
    if (event.topic === 'action.verified' || event.topic === 'action.flagged') {
      state.lastProofId = event.payload.proofId ?? state.lastProofId;
      pulse(els.topology, event.payload.agentId);
      setVital(els.vitals.proofs, {
        value: (state.summary?.totals?.proofs ?? 0) + 1,
        sub: `newest ${fmtClock(event.payload.executedAt ?? new Date().toISOString())}Z`,
      });
      if (event.payload.status && event.payload.status !== 'trusted') {
        setVital(els.vitals.trust, { value: '—', sub: 'recalculating fleet trust' });
      }
      scheduleRefresh();
    }
  },
});

setInterval(() => {
  if (!state.status) return;
  renderVitals(fleetFacts({ status: state.status, health: state.health }));
}, 15_000);

let resizeTimer = null;
new ResizeObserver(() => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => {
    if (state.summary && state.view === 'timeline') drawTimeline();
  }, 250);
}).observe(els.timeline);

setView('topology');
setPane('dossier');
dossier.clear('Select a proof, agent or node to open what the ledger actually says.');
load().catch(showFatal);

import { chip, dash, fmtTime, h, hashChip, head, plural, relTime, short, statusVar } from '../lib/format.js';

function rootFingerprint(nodes) {
  const roots = [...new Set(nodes.map((node) => String(node.head?.root ?? '').toLowerCase()).filter(Boolean))];
  if (roots.length === 0) return { text: 'no root yet', divergent: false, full: null };
  if (roots.length === 1) return { text: short(roots[0], 14), divergent: false, full: roots[0] };
  return { text: `${roots.length} distinct roots`, divergent: true, full: null };
}

export function fleetFacts({ status, health }) {
  const nodes = status.nodes ?? [];
  return {
    coordinator: head(status.coordinatorId, 22),
    coordinatorId: status.coordinatorId ?? null,
    quorum: { required: dash(status.quorumRequired, '?'), of: nodes.length },
    root: rootFingerprint(nodes),
    crypto: health?.crypto ? `${health.crypto.signingAlg}${health.crypto.crossImplementationCheck ? ' · cross-impl verified' : ''}` : '—',
    signingAlg: health?.crypto?.signingAlg ?? null,
    generatedAt: status.generatedAt ?? null,
  };
}

export function renderFleet(target, { status, onSelectNode }) {
  target.textContent = '';
  const nodes = status.nodes ?? [];
  const note = document.getElementById('fleetNote');
  if (note) note.textContent = `${nodes.length} independent ledgers`;

  if (nodes.length === 0) {
    target.appendChild(h('div', { class: 'empty' },
      h('strong', null, 'No witnesses reported'),
      h('span', null, 'This coordinator has not been joined by any node yet.')));
    return;
  }

  target.appendChild(h('table', { class: 'table table-fixed' },
    h('thead', null, h('tr', null,
      h('th', null, 'Node'),
      h('th', { class: 'w-chain' }, 'Chain'),
      h('th', { class: 'align-right col-optional w-cont' }, 'Contents'),
      h('th', { class: 'w-root' }, 'Root'),
      h('th', { class: 'align-right col-optional w-upd' }, 'Updated'))),
    h('tbody', null, ...nodes.map((node) => {
      const intact = node.recentWindowIntact !== false;
      const problems = node.recentProblems?.length ?? 0;
      return h('tr', {
        dataset: { node: node.nodeId },
        tabindex: '0',
        onclick: () => onSelectNode?.(node.nodeId),
        onkeydown: (event) => {
          if (event.key === 'Enter' || event.key === ' ') onSelectNode?.(node.nodeId);
        },
      },
      h('td', { title: node.nodeId },
        h('span', { class: 't-state' }, h('i', { style: `color: var(--${intact ? 'jade' : 'crimson'});` }), h('span', { class: 't-name' }, head(String(node.nodeId ?? '').split('-').slice(-2).join('-'), 12))),
        h('span', { class: 't-sub' }, `${dash(node.cloud, 'unknown')}${node.region ? ` · ${node.region}` : ''}`)),
      h('td', { class: 'nowrap w-chain' },
        h('span', { class: 't-num' }, String(dash(node.chainLength, 0))),
        h('span', { class: 't-sub', style: `color: var(--${intact ? 'fg-4' : 'crimson'});` },
          intact ? 'window intact' : `${problems} problem(s) in window`)),
      h('td', { class: 'align-right nowrap col-optional w-cont' },
        h('span', null, `${dash(node.records, 0)} ${plural(node.records ?? 0, 'record')}`),
        h('span', { class: 't-sub' }, `${dash(node.identities, 0)} identities · ${dash(node.revocations, 0)} revocation(s)`)),
      h('td', { class: 'w-root' }, hashChip(short(node.head?.root, 8), { full: node.head?.root, toast: 'root' })),
      h('td', { class: 'align-right nowrap col-optional w-upd' }, h('span', { class: 't-sub', style: 'color: var(--fg-2);' }, relTime(node.head?.updatedAt))));
    }))));

  const forwarding = status.eventForwarding;
  target.appendChild(h('p', { class: 't-sub', style: 'margin-top: var(--s-3);' },
    forwarding
      ? `Cross-process feed: ${forwarding.peers} peer(s) · ${forwarding.delivered} delivered · ${forwarding.failed} failed · ${forwarding.skippedEcho} echo(s) refused.`
      : 'Single process: no peer forwarding configured.'));
}

export function renderAnchors(target, { status, identities, coordinatorId, onSelectAgent }) {
  target.textContent = '';
  const anchors = status.trustAnchors ?? [];
  const byId = new Map((identities?.identities ?? []).map((identity) => [identity.id, identity]));

  if (anchors.length === 0) {
    target.appendChild(h('div', { class: 'empty' },
      h('strong', null, 'No trust anchors'),
      h('span', null, 'Delegated identities cannot be anchored until a root is configured.')));
    return;
  }

  const rows = anchors.map((anchorId) => {
    const identity = byId.get(anchorId);
    return h('tr', {
      tabindex: '0',
      onclick: () => onSelectAgent?.(anchorId),
      onkeydown: (event) => {
        if (event.key === 'Enter') onSelectAgent?.(anchorId);
      },
    },
    h('td', null,
      h('span', { class: 't-name' }, identity?.subject?.name ?? head(anchorId, 24)),
      h('span', { class: 't-sub mono' }, head(String(anchorId ?? '').split(':').pop(), 12))),
    h('td', { class: 'nowrap col-optional w-alg' }, identity ? h('span', { class: 't-sub' }, identity.alg) : h('span', { class: 't-sub muted' }, 'document not in registry')),
    h('td', { class: 'align-right nowrap w-valid' }, identity
      ? h('span', { class: 't-sub', style: `color: var(--${new Date(identity.expiresAt) < new Date() ? 'crimson' : 'fg-2'});` }, `valid to ${fmtTime(identity.expiresAt).slice(0, 10)}`)
      : null));
  });

  const coordinator = byId.get(coordinatorId);
  rows.push(h('tr', {
    tabindex: '0',
    onclick: () => coordinatorId && onSelectAgent?.(coordinatorId),
  },
  h('td', null,
    h('span', { class: 't-state' }, h('i', { style: 'color: var(--violet);' }), h('span', { class: 't-name' }, 'Coordinator')),
    h('span', { class: 't-sub' }, 'signs every trust assessment')),
  h('td', { class: 'nowrap col-optional w-alg' }, h('span', { class: 't-sub' }, coordinator ? `${coordinator.alg} · ${coordinator.parent ? 'delegated' : 'self-issued root'}` : 'document not in registry')),
  h('td', { class: 'align-right w-valid' }, hashChip(head(String(coordinatorId ?? '').split(':').pop(), 12), { full: coordinatorId, toast: 'coordinator id' }))));

  target.appendChild(h('table', { class: 'table table-fixed' }, h('tbody', null, ...rows)));
}

export function renderSecurity(target, health) {
  target.textContent = '';
  const security = health?.security;
  if (!security) return;
  const flags = [
    { label: `admin token ${security.adminTokenConfigured ? 'configured' : 'absent'}`, status: security.adminTokenConfigured ? 'trusted' : 'flagged' },
    { label: `node token ${security.nodeTokenConfigured ? 'configured' : 'absent'}`, status: security.nodeTokenConfigured ? 'trusted' : 'unattested' },
  ];
  for (const flag of flags) {
    target.appendChild(h('span', { class: `chip chip-${flag.status}` }, h('i', { class: 'dot' }), flag.label));
  }
  for (const endpoint of security.failClosed ?? []) {
    target.appendChild(h('span', { class: 'chip' }, h('span', { class: 'mono' }, endpoint), 'closed'));
  }
  if (security.note) target.appendChild(h('span', { class: 'muted' }, security.note));
}

export function securityPanel(health) {
  const security = health?.security;
  if (!security) return null;
  const rows = [
    ['admin token', security.adminTokenConfigured, 'configured'],
    ['node token', security.nodeTokenConfigured, 'configured'],
  ];
  return h('div', { class: 'dzr' },
    h('div', { class: 'dzr-head' },
      h('h2', { class: 'dzr-title' }, 'Security posture'),
      h('div', { class: 'dzr-tags' }, ...rows.map(([label, ok, text]) => h('span', { class: `chip chip-${ok ? 'trusted' : 'flagged'}` },
        h('i', { class: 'dot' }), `${label} ${ok ? text : 'absent'}`)))),
    h('div', { class: 'dzr-section' },
      h('h3', { class: 'eyebrow' }, 'Fail-closed endpoints'),
      h('div', { class: 'sources' }, ...(security.failClosed ?? []).map((endpoint) => h('span', { class: 'source' }, endpoint)))),
    h('p', { class: 'finding-detail' }, security.note ?? ''),
    h('p', { class: 't-sub', style: `color: var(--${statusVar('unattested')});` },
      'Endpoints listed above refuse writes when no token is configured, rather than falling open.'));
}

import { h, head, plural, s, short, showTip, hideTip, statusVar } from '../lib/format.js';

const W = 760;
const H = 430;
const LEFT = 176;
const RIGHT = 596;
const TOP = 74;

const COLORS = { trusted: 'var(--jade)', flagged: 'var(--amber)', rejected: 'var(--crimson)', unattested: 'var(--slate)' };
const STATUS_RANK = ['trusted', 'flagged', 'rejected', 'unattested'];

function dominantStatus(statuses) {
  const entries = Object.entries(statuses ?? {});
  if (entries.length === 0) return 'unattested';
  return entries.sort((a, b) => (b[1] - a[1]) || (STATUS_RANK.indexOf(a[0]) - STATUS_RANK.indexOf(b[0])))[0][0];
}

function column(count, top, bottom) {
  if (count === 0) return [];
  if (count === 1) return [(top + bottom) / 2];
  const step = (bottom - top) / (count - 1);
  return Array.from({ length: count }, (_, index) => top + index * step);
}

function tip(html) {
  return (event) => showTip(html, event.clientX, event.clientY);
}

export function renderTopology(svg, { topology, names, revoked, quorum, onSelectAgent, onSelectNode }) {
  while (svg.firstChild) svg.removeChild(svg.firstChild);
  const glyphs = new Map();

  const agents = (topology.agents ?? []).map((agent) => ({
    id: agent.id,
    name: names.get(agent.id) ?? head(agent.id, 20),
    revoked: revoked?.has(agent.id) === true,
  }));
  const nodes = [...(topology.nodes ?? [])].sort((a, b) => String(a.cloud).localeCompare(String(b.cloud)));
  const edges = topology.edges ?? [];

  if (nodes.length === 0) {
    svg.appendChild(s('text', { x: W / 2, y: H / 2, 'text-anchor': 'middle', class: 'graph-title', text: 'no witness nodes reported' }));
    return;
  }

  const agentY = new Map(agents.map((agent, index) => [agent.id, column(agents.length, TOP + 26, H - 44)[index]]));
  const nodeY = new Map(nodes.map((node, index) => [node.id, column(nodes.length, TOP + 40, H - 56)[index]]));
  const coordinatorY = 40;

  for (const [x, label] of [[LEFT, 'AGENTS'], [W / 2, 'COORDINATOR'], [RIGHT, 'WITNESS NODES']]) {
    svg.appendChild(s('text', { x, y: 24, 'text-anchor': 'middle', class: 'graph-title', text: label }));
  }
  svg.appendChild(s('line', { x1: LEFT, y1: 34, x2: LEFT, y2: H - 20, class: 'col-rule', opacity: 0.5 }));
  svg.appendChild(s('line', { x1: RIGHT, y1: 34, x2: RIGHT, y2: H - 20, class: 'col-rule', opacity: 0.5 }));

  // Every dashed line is a real accept/certify target from the replication group,
  // not an inferred relationship — the coordinator reports exactly these nodes.
  for (const node of nodes) {
    svg.appendChild(s('line', {
      x1: W / 2, y1: coordinatorY + 13, x2: RIGHT, y2: nodeY.get(node.id),
      style: 'stroke: var(--violet); stroke-width: 0.7; stroke-dasharray: 2 7;', opacity: 0.26,
    }));
  }

  const edgeGroup = s('g', { class: 'edges' });
  for (const edge of edges) {
    const fromY = agentY.get(edge.from);
    const toY = nodeY.get(edge.to);
    if (fromY === undefined || toY === undefined) continue;
    const status = dominantStatus(edge.statuses);
    const width = Math.min(5, 1 + Math.sqrt(edge.proofs) * 0.8);
    const opacity = status === 'trusted' ? 0.34 : 0.58;
    const path = s('path', {
      class: 'edge',
      d: `M ${LEFT + 15} ${fromY} C ${(LEFT + RIGHT) / 2} ${fromY}, ${(LEFT + RIGHT) / 2} ${toY}, ${RIGHT - 15} ${toY}`,
      style: `stroke: ${COLORS[status]}; stroke-width: ${width.toFixed(2)};`,
      opacity,
      dataset: { from: edge.from, to: edge.to, base: String(opacity) },
      onmousemove: tip(`<b>${names.get(edge.from) ?? head(edge.from, 18)}</b> → ${head(edge.to, 20)}
        <div class="tip-k">${edge.proofs} proof(s) · last score ${edge.lastScore ?? '—'} · seq ${edge.lastSeq}</div>
        <div class="tip-k">${Object.entries(edge.statuses).map(([key, value]) => `${key} ${value}`).join(' · ')}</div>`),
      onmouseleave: hideTip,
      onclick: () => onSelectAgent?.(edge.from),
    });
    edgeGroup.appendChild(path);
  }
  svg.appendChild(edgeGroup);

  svg.appendChild(s('g', { class: 'coordinator-glyph' },
    s('circle', { cx: W / 2, cy: coordinatorY, r: 12, fill: 'rgba(11, 15, 19, 0.9)', style: 'stroke: var(--violet); stroke-width: 1.3;' }),
    s('circle', { cx: W / 2, cy: coordinatorY, r: 3.4, style: 'fill: var(--violet);' }),
    s('text', { x: W / 2, y: coordinatorY + 30, 'text-anchor': 'middle', class: 'glyph-sub', text: `quorum ${quorum?.required ?? '?'} of ${quorum?.of ?? nodes.length}` }),
  ));

  for (const node of nodes) {
    const y = nodeY.get(node.id);
    const intact = node.intact !== false;
    const color = intact ? 'jade' : 'crimson';
    const radius = Math.min(17, 11 + Math.log10(Math.max(1, node.chainLength)) * 3.4);
    const group = s('g', { class: 'node-glyph', dataset: { node: node.id } });
    group.appendChild(s('circle', {
      cx: RIGHT, cy: y, r: radius, fill: 'rgba(11, 15, 19, 0.92)',
      style: `stroke: var(--${color}); stroke-width: ${intact ? 1.1 : 2};`,
    }));
    group.appendChild(s('text', {
      x: RIGHT, y: y + 3.5, 'text-anchor': 'middle', class: 'glyph-sub',
      style: `fill: var(--${color}); font-size: 10px;`, text: String(node.chainLength ?? 0),
    }));
    group.appendChild(s('text', { x: RIGHT + radius + 12, y: y - 3, class: 'glyph-label', text: head(node.id.replace('verix-node-', ''), 20) }));
    group.appendChild(s('text', {
      x: RIGHT + radius + 12, y: y + 10, class: 'glyph-sub',
      text: `${node.cloud ?? 'unknown'}${node.region ? `/${node.region}` : ''} · ${node.chainLength ?? 0} ${plural(node.chainLength ?? 0, 'entry', 'entries')}`,
    }));
    if (!intact || (node.problems ?? 0) > 0) {
      group.appendChild(s('text', {
        x: RIGHT + radius + 12, y: y + 23, class: 'glyph-sub', style: 'fill: var(--crimson);',
        text: `${node.problems ?? 0} problem(s) in the audited window`,
      }));
    }
    const hit = s('circle', {
      cx: RIGHT, cy: y, r: radius + 8, fill: 'transparent', class: 'glyph-hit',
      onmousemove: tip(`<b>${head(node.id, 26)}</b>
        <div class="tip-k">root ${short(node.root, 18)}</div>
        <div class="tip-k">${node.chainLength ?? 0} ${plural(node.chainLength ?? 0, 'entry', 'entries')} · ${intact ? 'window intact' : 'window broken'}</div>`),
      onmouseleave: hideTip,
      onclick: () => onSelectNode?.(node.id),
    });
    group.appendChild(hit);
    svg.appendChild(group);
    glyphs.set(node.id, { group, y, x: RIGHT, kind: 'node' });
  }

  for (const agent of agents) {
    const y = agentY.get(agent.id);
    const incoming = edges.filter((edge) => edge.from === agent.id);
    const attestations = incoming.reduce((sum, edge) => sum + edge.proofs, 0);
    const worst = ['rejected', 'flagged'].find((status) => incoming.some((edge) => dominantStatus(edge.statuses) === status));
    const color = agent.revoked ? 'violet' : worst ?? 'jade';
    const group = s('g', {
      class: 'agent-glyph',
      dataset: { agent: agent.id },
      onmousemove: tip(`<b>${agent.name}</b>
        <div class="tip-k">${short(agent.id, 22)}</div>
        <div class="tip-k">${incoming.length} node(s) · ${attestations} attestation(s)${agent.revoked ? ' · revoked' : ''}</div>`),
      onmouseleave: hideTip,
    });
    group.appendChild(s('rect', {
      x: LEFT - 9, y: y - 9, width: 18, height: 18, rx: 3,
      transform: `rotate(45 ${LEFT} ${y})`,
      fill: 'rgba(11, 15, 19, 0.92)',
      style: `stroke: var(--${color}); stroke-width: 1.2;`,
    }));
    group.appendChild(s('circle', { cx: LEFT, cy: y, r: 2.4, style: `fill: var(--${color});` }));
    group.appendChild(s('text', { x: LEFT - 24, y: y - 2, 'text-anchor': 'end', class: 'glyph-label', text: head(agent.name, 20) }));
    group.appendChild(s('text', { x: LEFT - 24, y: y + 11, 'text-anchor': 'end', class: 'glyph-sub', text: `${attestations} attested` }));
    const hit = s('circle', { cx: LEFT, cy: y, r: 20, fill: 'transparent', class: 'glyph-hit', onclick: () => onSelectAgent?.(agent.id) });
    group.appendChild(hit);
    svg.appendChild(group);
    glyphs.set(agent.id, { group, y, x: LEFT, kind: 'agent' });
  }

  svg.__glyphs = glyphs;
  renderLegend(svg, edges);
}

function renderLegend(svg, edges) {
  const legend = document.getElementById('topologyLegend');
  if (!legend) return;
  legend.textContent = '';
  const counts = new Map();
  for (const edge of edges) {
    const status = dominantStatus(edge.statuses);
    counts.set(status, (counts.get(status) ?? 0) + 1);
  }
  for (const [status, color] of Object.entries(COLORS)) {
    legend.appendChild(h('span', { class: 'legend-item' },
      h('i', { class: 'legend-swatch', style: `color: ${color};` }),
      `${status} `, h('b', null, String(counts.get(status) ?? 0))));
  }
  legend.appendChild(h('span', { class: 'legend-item' },
    h('i', { class: 'legend-swatch', style: `color: var(--${statusVar('revoked')});` }), 'coordinator fan-out'));
  legend.appendChild(h('span', { class: 'legend-item muted' }, 'edge width = attestations'));
}

// A live event adds a ring to the glyph that produced it; the ring is removed
// after one cycle so the diagram never accumulates stale highlights.
export function pulse(svg, id) {
  const entry = svg.__glyphs?.get(id);
  if (!entry) return;
  const ring = s('circle', { cx: entry.x, cy: entry.y, r: 26, fill: 'none', class: 'pulse', style: `stroke: var(--${entry.kind === 'node' ? 'jade' : 'violet'}); stroke-width: 1.1;` });
  svg.appendChild(ring);
  setTimeout(() => ring.remove(), 2400);
}

export function focusAgent(svg, agentId) {
  for (const path of svg.querySelectorAll('.edge')) {
    const hot = agentId !== null && path.dataset.from === agentId;
    path.setAttribute('data-hot', String(hot));
    path.setAttribute('opacity', agentId === null ? path.dataset.base : hot ? '0.95' : '0.06');
  }
}

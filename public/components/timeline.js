import { fmtClock, fmtTime, h, head, hideTip, isBlank, s, showTip, statusVar } from '../lib/format.js';

const HEIGHT = 260;
const AXIS = 208;
const PLOT_TOP = 34;
const COLORS = { trusted: 'var(--jade)', flagged: 'var(--amber)', rejected: 'var(--crimson)', unattested: 'var(--slate)' };

export function renderTimeline(svg, { timeline, names, selectedHash, selectedAgent, focusSeq, onSelectProof, onClearAgent }) {
  const width = Math.max(560, svg.clientWidth || 760);
  svg.setAttribute('viewBox', `0 0 ${width} ${HEIGHT}`);
  while (svg.firstChild) svg.removeChild(svg.firstChild);

  const entries = (timeline ?? []).filter((entry) => !selectedAgent || entry.agentId === selectedAgent);
  const meta = document.getElementById('timelineMeta');

  if (entries.length === 0) {
    svg.appendChild(s('text', { x: width / 2, y: HEIGHT / 2, 'text-anchor': 'middle', class: 'graph-title', text: 'no proofs in this selection' }));
    if (meta) meta.textContent = '';
    return;
  }

  const ordered = [...entries].sort((a, b) => (a.seq ?? 0) - (b.seq ?? 0));
  const left = 44;
  const right = width - 18;
  const gap = ordered.length > 1 ? (right - left) / (ordered.length - 1) : 0;
  const barWidth = Math.max(5, Math.min(18, (gap || 18) * 0.58));

  for (const value of [0, 25, 50, 75, 100]) {
    const y = AXIS - (value / 100) * (AXIS - PLOT_TOP);
    svg.appendChild(s('line', { x1: 34, y1: y, x2: right + 8, y2: y, class: value === 0 ? 'tl-axis' : 'tl-grid' }));
    svg.appendChild(s('text', { x: 28, y: y + 3.5, 'text-anchor': 'end', class: 'tl-tick', text: String(value) }));
  }

  const seenSeq = new Set();
  ordered.forEach((entry, index) => {
    const x = ordered.length === 1 ? (left + right) / 2 : left + index * gap;
    const score = isBlank(entry.score) ? 0 : entry.score;
    const barHeight = Math.max(4, (score / 100) * (AXIS - PLOT_TOP));
    const y = AXIS - barHeight;
    const color = COLORS[entry.status] ?? COLORS.unattested;
    const isSelected = selectedHash === entry.recordHash;
    const mark = s('g', { class: `tl-mark${entry.seq === focusSeq ? ' tl-flag' : ''}`, dataset: { hash: entry.recordHash } });

    if (isSelected) {
      mark.appendChild(s('line', { x1: x, y1: PLOT_TOP - 12, x2: x, y2: AXIS, class: 'tl-guide' }));
    }
    mark.appendChild(s('rect', {
      x: x - barWidth / 2, y, width: barWidth, height: barHeight, rx: 2,
      style: `fill: ${color}; opacity: ${isSelected ? 1 : 0.55};`,
      stroke: isSelected ? 'var(--fg)' : 'transparent', 'stroke-width': isSelected ? 1 : 0,
    }));

    if (entry.anomalies?.length) {
      const worst = entry.anomalies.some((a) => a.severity === 'critical') ? 'critical' : entry.anomalies[0].severity;
      const flagY = Math.max(PLOT_TOP - 8, y - 13);
      mark.appendChild(s('path', {
        d: `M ${x} ${flagY - 5} L ${x + 4.5} ${flagY} L ${x} ${flagY + 5} L ${x - 4.5} ${flagY} Z`,
        style: `fill: var(--${statusVar(worst === 'critical' ? 'rejected' : worst === 'high' ? 'flagged' : 'unattested')});`,
      }));
    }

    if (entry.seq !== null && !seenSeq.has(entry.seq)) {
      seenSeq.add(entry.seq);
      if (gap >= 30 || index % Math.ceil(ordered.length / 14) === 0) {
        mark.appendChild(s('text', { x, y: AXIS + 17, 'text-anchor': 'middle', class: 'tl-tick', text: String(entry.seq) }));
      }
    }

    mark.addEventListener('mousemove', (event) => showTip(
      `<b>seq ${entry.seq} · ${entry.status}</b>
       <div>${names.get(entry.agentId) ?? head(entry.agentId, 22)} — ${entry.action} on ${entry.resource}</div>
       <div class="tip-k">${fmtTime(entry.executedAt)} · score ${entry.score ?? '—'} · ${entry.clouds?.length ?? 0} witness(es)</div>
       ${(entry.anomalies ?? []).map((a) => `<div class="tip-k">${a.severity} ${a.code}</div>`).join('')}`,
      event.clientX, event.clientY));
    mark.addEventListener('mouseleave', hideTip);
    mark.addEventListener('click', () => onSelectProof?.(entry.recordHash));
    svg.appendChild(mark);
  });

  if (meta) {
    meta.textContent = '';
    const first = ordered[0];
    const last = ordered.at(-1);
    const anomalies = new Map();
    for (const entry of ordered) for (const anomaly of entry.anomalies ?? []) anomalies.set(anomaly.code, (anomalies.get(anomaly.code) ?? 0) + 1);
    const notTrusted = ordered.filter((entry) => entry.status !== 'trusted').length;

    meta.appendChild(h('span', null, h('b', null, String(ordered.length)), ' proofs · seq ', h('b', null, `${first.seq}→${last.seq}`)));
    meta.appendChild(h('span', null, `${fmtTime(first.executedAt)} → ${fmtClock(last.executedAt)} UTC`));
    meta.appendChild(h('span', { style: notTrusted ? 'color: var(--amber);' : null }, h('b', null, String(notTrusted)), ' not trusted'));
    meta.appendChild(h('span', { class: 'muted' }, 'bar height = trust score · diamond = worst anomaly · click for forensics'));
    if (selectedAgent) {
      meta.appendChild(h('button', { class: 'pill', onclick: () => onClearAgent?.() }, `filtered: ${names.get(selectedAgent) ?? head(selectedAgent, 20)} — clear`));
    }
    for (const [code, count] of [...anomalies].sort((a, b) => b[1] - a[1]).slice(0, 4)) {
      meta.appendChild(h('span', { style: 'color: var(--crimson);' }, `${code}×`, h('b', null, String(count))));
    }
  }
}

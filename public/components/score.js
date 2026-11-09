import { h, isBlank } from '../lib/format.js';

function shade(achieved) {
  if (achieved >= 0.999) return 'jade';
  if (achieved >= 0.75) return 'amber';
  return 'crimson';
}

export function scoreValue(score, band) {
  return h('span', {
    class: 'verdict-value num',
    dataset: { band: band ?? undefined },
    style: isBlank(score) ? 'color: var(--fg-4);' : null,
  }, isBlank(score) ? '—' : Number(score).toFixed(2));
}

/* One bar per weighted component, exactly as the proof stores it: the track is
   the component's weight, the fill is the share of that weight earned. */
export function scoreBar({ components = [], caption = null }) {
  if (components.length === 0) return null;
  return h('div', { class: 'compbars' },
    ...components.map((entry) => h('div', { class: 'compbar' },
      h('span', { class: 'compbar-k' }, entry.key),
      h('span', { class: 'compbar-track' }, h('span', {
        class: 'compbar-fill',
        style: `width: ${Math.max(0, Math.min(1, entry.achieved ?? 0)) * 100}%; background: var(--${shade(entry.achieved ?? 0)});`,
      })),
      h('span', { class: 'compbar-v', title: entry.detail ?? null }, `${Number(entry.points ?? 0).toFixed(1)}/${entry.weight ?? 0}`))),
    caption ? h('span', { class: 't-sub' }, caption) : null);
}

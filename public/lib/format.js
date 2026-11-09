export const STATUS_ORDER = ['trusted', 'flagged', 'rejected', 'unattested'];

export const STATUS_LABEL = {
  trusted: 'trusted',
  flagged: 'flagged',
  rejected: 'rejected',
  unattested: 'unattested',
  revoked: 'revoked',
};

export const SEVERITY_LABEL = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  deny: 'deny',
  warn: 'warn',
  info: 'info',
};

function className(base, extra) {
  return extra ? `${base} ${extra}` : base;
}

export function h(tag, props = null, ...children) {
  const node = document.createElement(tag);
  if (props) {
    for (const [key, value] of Object.entries(props)) {
      if (value === null || value === undefined || value === false) continue;
      if (key === 'class') node.className = value;
      else if (key === 'style') node.setAttribute('style', value);
      else if (key === 'dataset') Object.assign(node.dataset, value);
      else if (key.startsWith('on') && typeof value === 'function') node.addEventListener(key.slice(2), value);
      else if (key === 'html') node.innerHTML = value;
      else node.setAttribute(key, value === true ? '' : String(value));
    }
  }
  append(node, children);
  return node;
}

export const SVG_NS = 'http://www.w3.org/2000/svg';

export function s(tag, props = null, ...children) {
  const node = document.createElementNS(SVG_NS, tag);
  if (props) {
    for (const [key, value] of Object.entries(props)) {
      if (value === null || value === undefined || value === false) continue;
      if (key === 'style') node.setAttribute('style', value);
      else if (key === 'dataset') Object.assign(node.dataset, value);
      else if (key === 'text') node.textContent = String(value);
      else if (key.startsWith('on') && typeof value === 'function') node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, value === true ? '' : String(value));
    }
  }
  append(node, children);
  return node;
}

function append(node, children) {
  for (const child of children.flat(4)) {
    if (child === null || child === undefined || child === false) continue;
    node.appendChild(typeof child === 'object' ? child : document.createTextNode(String(child)));
  }
}

export function chip(status, extraClass = null) {
  return h('span', { class: className('chip', `chip-${status} ${extraClass ?? ''}`.trim()) }, h('i', { class: 'dot' }), STATUS_LABEL[status] ?? status);
}

export function short(value, length = 12) {
  const text = String(value ?? '');
  if (!text) return '—';
  return text.length <= length * 2 ? text : `${text.slice(0, length)}…${text.slice(-6)}`;
}

export function head(value, length = 16) {
  const text = String(value ?? '');
  if (!text) return '—';
  return text.length <= length ? text : `${text.slice(0, length)}…`;
}

export function fmtTime(value) {
  if (!value) return '—';
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) return String(value);
  const d = new Date(ms);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}Z`;
}

export function fmtClock(value) {
  if (!value) return '—';
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) return String(value);
  const d = new Date(ms);
  const p = (n) => String(n).padStart(2, '0');
  return `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
}

export function relTime(value) {
  if (!value) return 'never';
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) return 'unknown';
  const delta = (Date.now() - ms) / 1000;
  const abs = Math.abs(delta);
  if (abs < 45) return 'just now';
  const label = abs < 3600 ? `${Math.round(abs / 60)}m`
    : abs < 86400 ? `${Math.round(abs / 3600)}h`
      : `${Math.round(abs / 86400)}d`;
  return delta < 0 ? `in ${label}` : `${label} ago`;
}

export function plural(count, singular, pluralForm = null) {
  return count === 1 ? singular : pluralForm ?? `${singular}s`;
}

export function isBlank(value) {
  return value === null || value === undefined || value === '';
}

export function dash(value, fallback = '—') {
  return isBlank(value) ? fallback : value;
}

export async function api(path, { method = 'GET', body = null, token = null } = {}) {
  const headers = { accept: 'application/json' };
  if (body !== null) headers['content-type'] = 'application/json';
  if (token) headers.authorization = `Bearer ${token}`;
  const response = await fetch(path, { method, headers, body: body === null ? undefined : JSON.stringify(body) });
  let payload = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  if (!response.ok) {
    const error = new Error(payload?.error?.message ?? `${method} ${path} failed with HTTP ${response.status}`);
    error.status = response.status;
    error.code = payload?.error?.code ?? 'HTTP_ERROR';
    throw error;
  }
  return payload;
}

export function errorRow(error) {
  return h('p', { class: 'empty' }, `${error.code ? `${error.code}: ` : ''}${error.message}`);
}

export function wsUrl() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  return `${proto}://${location.host}/ws`;
}

export function connectFeed({ onEvent, onState } = {}) {
  let socket = null;
  let attempt = 0;
  let timer = null;
  let closed = false;

  function open() {
    if (closed) return;
    onState?.('connecting', attempt);
    socket = new WebSocket(wsUrl());
    socket.addEventListener('open', () => {
      attempt = 0;
      onState?.('live', 0);
    });
    socket.addEventListener('message', (message) => {
      let event = null;
      try {
        event = JSON.parse(message.data);
      } catch {
        return;
      }
      onEvent?.(event);
    });
    socket.addEventListener('close', () => {
      if (closed) return;
      attempt += 1;
      onState?.('offline', attempt);
      timer = setTimeout(open, Math.min(12_000, 800 * 2 ** Math.min(attempt, 4)));
    });
    socket.addEventListener('error', () => onState?.('error', attempt));
  }

  open();
  return {
    close() {
      closed = true;
      clearTimeout(timer);
      socket?.close();
    },
  };
}

/* ------------------------------------------------------------------ palette */

export const STATUS_VAR = { trusted: 'jade', flagged: 'amber', rejected: 'crimson', unattested: 'slate', revoked: 'violet' };
export const SEVERITY_VAR = { critical: 'crimson', high: 'crimson', medium: 'amber', low: 'slate', deny: 'crimson', warn: 'amber', info: 'jade' };

export function statusVar(status) {
  return STATUS_VAR[status] ?? 'slate';
}

export function severityVar(severity) {
  return SEVERITY_VAR[severity] ?? 'slate';
}

/* ------------------------------------------------------------------ clipboard */

export async function copyText(value) {
  const text = String(value ?? '');
  if (!text) return false;
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    /* the page may be served over an insecure origin; fall through */
  }
  const holder = h('textarea', { readonly: true, style: 'position:fixed;top:-40px;opacity:0;' });
  holder.value = text;
  document.body.appendChild(holder);
  holder.select();
  let ok = false;
  try {
    ok = document.execCommand('copy');
  } catch {
    ok = false;
  }
  holder.remove();
  return ok;
}

const COPY_GLYPH = '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 012-2h10"/></svg>';

export function hashChip(value, { label = null, full = null, toast = 'copied' } = {}) {
  const text = String(value ?? '—');
  return h('button', {
    class: 'hash',
    type: 'button',
    title: text,
    'aria-label': `${label ?? 'value'} ${text} — copy`,
    onclick: async () => toastMsg((await copyText(full ?? text)) ? `${toast} · ${short(text, 10)}` : 'clipboard unavailable'),
  }, label ? h('span', { class: 'muted' }, label) : null, h('b', null, text), h('span', { html: COPY_GLYPH }));
}

/* -------------------------------------------------------------------- toast */

let toastTimer = null;
export function toastMsg(message) {
  const node = document.getElementById('toast');
  if (!node) return;
  node.textContent = message;
  node.dataset.open = 'true';
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { node.dataset.open = 'false'; }, 1600);
}

/* ------------------------------------------------------------------ tooltip */

let tipEl = null;
export function showTip(html, x, y) {
  tipEl ??= document.getElementById('tip');
  if (!tipEl) return;
  tipEl.innerHTML = html;
  tipEl.dataset.open = 'true';
  tipEl.setAttribute('aria-hidden', 'false');
  const box = tipEl.getBoundingClientRect();
  const left = Math.max(8, Math.min(x + 14, window.innerWidth - box.width - 8));
  const top = y - box.height - 12 < 8 ? y + 18 : y - box.height - 12;
  tipEl.style.left = `${left}px`;
  tipEl.style.top = `${Math.max(8, top)}px`;
}

export function hideTip() {
  if (!tipEl) return;
  tipEl.dataset.open = 'false';
  tipEl.setAttribute('aria-hidden', 'true');
}

/* ---------------------------------------------------------------- structures */

export function section(eyebrow, ...children) {
  return h('div', { class: 'dzr-section' }, h('h3', { class: 'eyebrow' }, eyebrow), ...children.filter(Boolean));
}

export function cells(items) {
  return h('div', { class: 'cells' }, ...items.filter(Boolean).map(([key, value, opts = {}]) => h('div', { class: 'cell' },
    h('span', { class: 'cell-k' }, key),
    opts.copy
      ? h('span', { class: 'cell-v' }, hashChip(opts.full ?? value, { toast: key.toLowerCase() }))
      : h('span', { class: `cell-v${opts.mono ? ' mono' : ''}`, style: opts.color ? `color: var(--${opts.color});` : null }, String(value)))));
}

export function mixBar(mix, total) {
  const order = ['trusted', 'flagged', 'rejected', 'unattested'];
  const safe = total || 0;
  const segs = order.filter((status) => (mix?.[status] ?? 0) > 0);
  return h('span', { class: 'mixbar', title: segs.length ? segs.map((status) => `${status} ${mix[status]}`).join(' · ') : 'no proofs' },
    ...(!segs.length
      ? [h('i', { style: 'flex:1; background: var(--line-2);' })]
      : segs.map((status) => h('i', { style: `flex:${(mix[status] / safe) * 100}; background: var(--${statusVar(status)});` }))));
}

export function emptyBlock(title, body, action = null) {
  return h('div', { class: 'empty' }, h('strong', null, title), body, action);
}

export function skeleton(target, rows = 3) {
  target.textContent = '';
  for (let i = 0; i < rows; i += 1) target.appendChild(h('div', { class: `skeleton${i === 0 ? ' tall' : ''}` }));
}

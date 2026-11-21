/* ASI core: safe DOM builder, API client, formatting, widgets, charts.
 * All scanned data is hostile input – it is only ever inserted via textContent. */
'use strict';

const ASI = { me: null, perms: new Set(), meta: null, route: null, timers: [], scope: 'real' };
/* dataset shown in the UI: real (scans/imports/manual) | demo (simulator) | all */
try { const sc = localStorage.getItem('asi-scope'); if (['real', 'demo', 'all'].includes(sc)) ASI.scope = sc; } catch (e) {}
function setScope(sc) { ASI.scope = sc; try { localStorage.setItem('asi-scope', sc); } catch (e) {} }

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
      else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
      else if (k === 'value') el.value = v;
      else if (k === 'checked') el.checked = !!v;
      else el.setAttribute(k, v === true ? '' : String(v));
    }
  }
  for (const k of kids.flat(Infinity)) {
    if (k === null || k === undefined || k === false) continue;
    el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return el;
}
const svgNS = 'http://www.w3.org/2000/svg';
function s(tag, attrs, ...kids) {
  const el = document.createElementNS(svgNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === 'text') el.textContent = v; else el.setAttribute(k, v);
  }
  for (const k of kids.flat()) if (k) el.append(k);
  return el;
}
const can = p => ASI.perms.has(p);
const clear = el => { while (el.firstChild) el.removeChild(el.firstChild); return el; };

/* ---------- API ---------- */
async function api(method, path, body, opts = {}) {
  const init = { method, headers: { 'X-ASI-CSRF': '1', 'X-ASI-Scope': ASI.scope }, credentials: 'same-origin' };
  if (body instanceof FormData) init.body = body;
  else if (body !== undefined) { init.headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(body); }
  const res = await fetch(path, init);
  if (res.status === 401 && !opts.noAuthRedirect) { ASI.me = null; renderLogin(); throw new Error('Sesja wygasła'); }
  if (opts.raw) { if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || res.statusText); return res; }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}
const GET = (p) => api('GET', p);
const POST = (p, b) => api('POST', p, b ?? {});
const PUT = (p, b) => api('PUT', p, b);
const PATCH = (p, b) => api('PATCH', p, b);
const DEL = (p) => api('DELETE', p);
function qs(o) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(o)) if (v !== '' && v !== null && v !== undefined && v !== false) p.set(k, v === true ? '1' : v);
  const s = p.toString(); return s ? '?' + s : '';
}
async function download(path, fallbackName) {
  try {
    const res = await api('GET', path, undefined, { raw: true });
    const blob = await res.blob();
    const cd = res.headers.get('Content-Disposition') || '';
    const m = /filename="([^"]+)"/.exec(cd);
    const a = h('a', { href: URL.createObjectURL(blob), download: m ? m[1] : fallbackName });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 4000);
  } catch (e) { toast(e.message, true); }
}
async function downloadPost(path, body, name) {
  try {
    const res = await fetch(path, { method: 'POST', headers: { 'X-ASI-CSRF': '1', 'X-ASI-Scope': ASI.scope, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || res.statusText);
    const a = h('a', { href: URL.createObjectURL(await res.blob()), download: name });
    document.body.append(a); a.click(); a.remove();
  } catch (e) { toast(e.message, true); }
}

/* ---------- feedback ---------- */
function toast(msg, err) {
  const t = h('div', { class: 'toast' + (err ? ' err' : '') }, msg);
  document.getElementById('toasts').append(t);
  setTimeout(() => t.remove(), err ? 7000 : 3500);
}
async function act(fn, okMsg) {
  try { const r = await fn(); if (okMsg) toast(okMsg); return r; } catch (e) { toast(e.message, true); throw e; }
}
function modal(title, body, actions = [], wide = false) {
  const close = () => ov.remove();
  const foot = h('div', { class: 'mf' }, actions.map(a => h('button', { class: a.cls || '', onclick: async () => {
    if (a.run) { try { const keep = await a.run(close); if (keep !== true) close(); } catch (e) { toast(e.message, true); } } else close();
  } }, a.label)));
  const ov = h('div', { class: 'overlay', onmousedown: e => { if (e.target === ov) close(); } },
    h('div', { class: 'modal' + (wide ? ' wide' : ''), role: 'dialog', 'aria-label': title },
      h('div', { class: 'mh' }, h('h2', { text: title }), h('button', { class: 'ghost', onclick: close, 'aria-label': 'Zamknij' }, '✕')),
      h('div', { class: 'mb' }, body), actions.length ? foot : null));
  document.body.append(ov);
  const f = ov.querySelector('input,select,textarea'); if (f) f.focus();
  return close;
}
function confirmBox(msg, label = 'Usuń') {
  return new Promise(res => modal('Potwierdzenie', h('p', { text: msg }), [
    { label: 'Anuluj', run: () => res(false) }, { label, cls: 'danger', run: () => res(true) }]));
}

/* ---------- formatting ---------- */
const PL = {
  priority: { critical: 'Krytyczny', high: 'Wysoki', medium: 'Średni', low: 'Niski', info: 'Info' },
  state: { active: 'aktywny', unstable: 'niestabilny', suspect: 'oczekuje potwierdzenia', inactive: 'nieaktywny', '': '—' },
  status: { open: 'otwarta', gone: 'zniknęła', queued: 'w kolejce', running: 'w toku', paused: 'wstrzymany', completed: 'zakończony', cancelled: 'anulowany', failed: 'błąd' },
  reason: { window_closed: 'okno czasowe zamknięte – wznowienie w kolejnym oknie', manual_pause: 'wstrzymany ręcznie', waiting_window: 'czeka na otwarcie okna',
    shutdown: 'zatrzymanie serwera – wznowi się po starcie', 'recovered after restart': 'odzyskany po restarcie (checkpoint)' },
  kind: { service_new: 'nowa usługa', service_gone: 'usługa zniknęła', service_changed: 'zmiana usługi', host_new: 'nowy host', host_returned: 'host powrócił',
    host_suspect: 'brak odpowiedzi', host_inactive: 'host nieaktywny', host_unstable: 'host niestabilny', host_stable: 'host stabilny', manual: 'wpis ręczny', vuln_found: 'znane podatności' },
  triage: { '': '—', new: 'nowe', in_progress: 'w analizie', confirmed: 'potwierdzone', false_positive: 'fałszywy alarm', accepted_risk: 'ryzyko zaakceptowane', resolved: 'rozwiązane' },
  cat: { cms: 'CMS', framework: 'framework', language: 'język', server: 'serwer', devops: 'DevOps/CI', monitoring: 'monitoring', 'admin-panel': 'panel admina',
    staging: 'staging/test', iot: 'IoT', 'network-device': 'urządzenie sieciowe', vpn: 'VPN', mail: 'poczta', database: 'baza danych', 'remote-access': 'zdalny dostęp',
    exposure: 'ekspozycja', debug: 'debug', api: 'API', 'waf-cdn': 'WAF/CDN', collaboration: 'współpraca', auth: 'logowanie', info: 'informacja', app: 'aplikacja', cookie: 'ciasteczko', custom: 'własna', 'cms-plugin': 'wtyczka CMS', messaging: 'kolejka komunikatów' },
};
const fmtN = n => (n ?? 0).toLocaleString('pl-PL');
function fmtT(ts, withDate = true) {
  if (!ts) return '—';
  const d = new Date(ts * 1000);
  return withDate ? d.toLocaleString('pl-PL', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) : d.toLocaleTimeString('pl-PL', { hour: '2-digit', minute: '2-digit' });
}
function ago(ts) {
  if (!ts) return '—';
  const d = Math.round(Date.now() / 1000 - ts);
  if (d < 0) return 'za ' + dur(-d);
  if (d < 60) return 'przed chwilą';
  return dur(d) + ' temu';
}
function dur(sec) {
  sec = Math.round(sec || 0);
  if (sec < 60) return sec + ' s';
  if (sec < 3600) return Math.round(sec / 60) + ' min';
  if (sec < 86400) { const hh = Math.floor(sec / 3600), mm = Math.round((sec % 3600) / 60); return hh + ' h' + (mm ? ' ' + mm + ' min' : ''); }
  return Math.round(sec / 86400 * 10) / 10 + ' d';
}
const prioChip = p => h('span', { class: 'chip ' + (p === 'critical' ? 'crit' : p) }, PL.priority[p] || p || '—');
/* priority + curiosity score in one compact element (tables) */
const prioScore = (p, score) => h('span', { class: 'prio', title: `Ocena ciekawości ${score}/100` }, prioChip(p), h('span', { class: 'num' }, score));
const stateChip = st => h('span', { class: 'chip ' + st }, PL.state[st] ?? st);
const statusChip = st => h('span', { class: 'chip ' + st }, PL.status[st] || st);
const tags = (list) => (list || []).map(t => h('span', { class: 'tag' }, t));
const cats = (list) => (list || []).map(c => h('span', { class: 'cat' }, PL.cat[c] || c));
function scoreEl(v) { return h('span', { class: 'score' }, h('span', { class: 'bar' }, h('i', { style: { width: Math.min(100, v) + '%' } })), h('span', { class: 'small' }, v)); }
function confEl(v) { return h('span', { class: 'conf', title: v + '% pewności' }, h('i', { style: { width: v + '%' } })); }
function histEl(hist, max = 24) {
  const s = (hist || '').slice(-max);
  return h('span', { class: 'hist', title: 'Ostatnie obserwacje (od najstarszej): ' + s }, [...s].map(c => h('i', { class: c === '1' ? 'u' : 'd' })));
}
function techList(tech, max = 3) {
  return (tech || []).filter(t => !['info', 'auth'].includes(t.category)).slice(0, max).map(t =>
    h('span', { class: 'chip outline', title: `${t.category} · ${t.confidence}% pewności` }, t.name + (t.version ? ' ' + t.version : '')));
}
function withOverride(value, field, observed) {
  if (observed && field in observed) return h('span', { class: 'ovr', title: 'Wartość zmieniona ręcznie. Wartość ze skanu: ' + (observed[field] || '∅') }, value || '∅');
  return value || '';
}
function kindIcon(k) {
  if (k === 'service_new' || k === 'host_new' || k === 'host_returned') return h('span', { class: 'ic k-new' }, '+');
  if (k === 'service_gone' || k === 'host_inactive') return h('span', { class: 'ic k-gone' }, '−');
  if (k === 'service_changed') return h('span', { class: 'ic k-chg' }, '~');
  if (k === 'manual') return h('span', { class: 'ic' }, '✎');
  if (k === 'vuln_found') return h('span', { class: 'ic k-gone' }, '!');
  return h('span', { class: 'ic k-host' }, '◐');
}
function changeLink(c) {
  if (c.service_id) return '#/services/' + c.service_id;
  if (c.host_id) return '#/hosts/' + c.host_id;
  return null;
}
function feed(changes, empty = 'Brak zmian') {
  if (!changes || !changes.length) return h('div', { class: 'empty' }, empty);
  return h('ul', { class: 'feed' }, changes.map(c => {
    const l = changeLink(c);
    return h('li', null, kindIcon(c.kind),
      h('div', null, l ? h('a', { href: l }, c.summary) : c.summary, ' ', c.severity !== 'info' && c.severity !== 'low' ? prioChip(c.severity) : null),
      h('span', { class: 't', title: fmtT(c.created_at) }, ago(c.created_at)));
  }));
}

/* ---------- table helper ---------- */
function table(cols, rows, onClick) {
  const tb = h('tbody');
  for (const r of rows) {
    const tr = h('tr', { class: onClick ? 'click' : '' }, cols.map(c => h('td', { class: c.cls || '' }, c.render ? c.render(r) : r[c.key])));
    if (onClick) tr.addEventListener('click', e => { if (!e.target.closest('a,button,input,select')) onClick(r, e); });
    tb.append(tr);
  }
  return h('div', { class: 'tblwrap' }, h('table', { class: 'tbl' }, h('thead', null, h('tr', null, cols.map(c => h('th', { class: c.cls || '' }, c.title)))), tb));
}
function pager(total, offset, limit, go) {
  const from = total ? offset + 1 : 0, to = Math.min(total, offset + limit);
  return h('div', { class: 'pager' }, `${fmtN(from)}–${fmtN(to)} z ${fmtN(total)}`,
    h('button', { class: 'sm', disabled: offset <= 0, onclick: () => go(Math.max(0, offset - limit)) }, '‹ Poprzednie'),
    h('button', { class: 'sm', disabled: to >= total, onclick: () => go(offset + limit) }, 'Następne ›'));
}
function field(label, input, hint) { return h('div', { class: 'field' }, h('label', null, label), input, hint ? h('div', { class: 'hint' }, hint) : null); }
function select(opts, value, attrs = {}) {
  return h('select', attrs, opts.map(o => Array.isArray(o) ? h('option', { value: o[0], selected: String(o[0]) === String(value) }, o[1]) : h('option', { value: o, selected: o === value }, o)));
}
function seg(options, value, onChange) {
  const el = h('div', { class: 'seg' });
  for (const [v, l] of options) el.append(h('button', { class: v === value ? 'on' : '', onclick: () => onChange(v) }, l));
  return el;
}

/* ---------- charts (SVG) ---------- */
function trendChart(points) {
  const W = 640, H = 190, P = { l: 34, r: 34, t: 10, b: 26 };
  if (!points || !points.length) return h('div', { class: 'empty' }, 'Brak zakończonych przebiegów');
  const n = points.length, bw = (W - P.l - P.r) / n;
  const maxC = Math.max(1, ...points.map(p => p.new + p.gone + p.changed));
  const maxH = Math.max(1, ...points.map(p => p.hosts_up));
  const y = v => H - P.b - v / maxC * (H - P.t - P.b);
  const yh = v => H - P.b - v / maxH * (H - P.t - P.b);
  const svg = s('svg', { viewBox: `0 0 ${W} ${H}`, class: 'chart', role: 'img', 'aria-label': 'Zmiany w kolejnych przebiegach' });
  const g = s('g', { class: 'grid' });
  for (let i = 0; i <= 4; i++) { const yy = P.t + i * (H - P.t - P.b) / 4; g.append(s('line', { x1: P.l, x2: W - P.r, y1: yy, y2: yy })); }
  svg.append(g);
  points.forEach((p, i) => {
    const x = P.l + i * bw + bw * .18, w = bw * .64;
    let base = H - P.b;
    for (const [v, c] of [[p.new, 'var(--new)'], [p.changed, 'var(--chg)'], [p.gone, 'var(--gone)']]) {
      if (!v) continue;
      const hh = (H - P.t - P.b) * v / maxC;
      base -= hh;
      svg.append(s('rect', { x, y: base, width: w, height: Math.max(1, hh), fill: c, rx: 1.5 }, s('title', { text: `Przebieg #${p.run_id} (${p.job_name}) ${fmtT(p.at)}: +${p.new} nowe, ~${p.changed} zmienione, −${p.gone} zniknięte; ${p.hosts_up} hostów aktywnych` })));
    }
    if (n <= 14 || i % Math.ceil(n / 12) === 0) svg.append(s('text', { x: x + w / 2, y: H - 8, 'text-anchor': 'middle', text: fmtT(p.at, false) }));
  });
  const path = points.map((p, i) => `${i ? 'L' : 'M'}${P.l + i * bw + bw / 2},${yh(p.hosts_up)}`).join(' ');
  svg.append(s('path', { d: path, fill: 'none', stroke: 'var(--accent)', 'stroke-width': 2 }));
  points.forEach((p, i) => svg.append(s('circle', { cx: P.l + i * bw + bw / 2, cy: yh(p.hosts_up), r: 2.5, fill: 'var(--accent)' })));
  svg.append(s('text', { x: 4, y: P.t + 8, text: fmtN(maxC) }));
  svg.append(s('text', { x: W - 4, y: P.t + 8, 'text-anchor': 'end', text: fmtN(maxH) }));
  return h('div', null, svg, h('div', { class: 'legend' },
    h('span', null, h('i', { style: { background: 'var(--new)' } }), 'nowe'), h('span', null, h('i', { style: { background: 'var(--chg)' } }), 'zmienione'),
    h('span', null, h('i', { style: { background: 'var(--gone)' } }), 'zniknięte'), h('span', null, h('i', { style: { background: 'var(--accent)' } }), 'hosty aktywne (oś prawa)')));
}
function hoursStrip(values, title) {
  // values: 24 numbers 0..1 or -1 (no data)
  const strip = h('div', { class: 'hours', title: title || '' });
  values.forEach((v, i) => {
    const c = v < 0 ? 'var(--line)' : `color-mix(in srgb, var(--ok) ${Math.round(15 + v * 85)}%, var(--crit) ${Math.round(85 - v * 85)}%)`;
    strip.append(h('div', { style: { background: c }, title: `${i}:00–${i + 1}:00 — ${v < 0 ? 'brak pomiarów' : Math.round(v * 100) + '% odpowiedzi'}` }));
  });
  const lbl = h('div', { class: 'hours lbl' });
  for (let i = 0; i < 24; i++) lbl.append(h('div', null, i % 3 === 0 ? String(i) : ''));
  return h('div', null, strip, lbl);
}
function hostHours(hu, hp) { return hoursStrip(hp.map((p, i) => p ? hu[i] / p : -1), 'Dostępność wg godziny'); }
function hbars(items, onClick, labeler) {
  const max = Math.max(1, ...items.map(i => i.value));
  return h('div', null, items.map(i => h('div', { class: 'hbar' },
    h('span', { class: 't', title: i.key }, onClick ? h('a', { onclick: () => onClick(i) }, labeler ? labeler(i.key) : i.key) : (labeler ? labeler(i.key) : i.key)),
    h('span', { class: 'b' }, h('i', { style: { width: (i.value / max * 100) + '%' } })), h('span', { class: 'right small' }, fmtN(i.value)))));
}
function chunkChart(chunks) {
  const main = chunks.filter(c => c.kind === 'main' && c.status === 'done');
  if (main.length < 2) return null;
  const W = 640, H = 120, P = 24;
  const maxD = Math.max(1, ...main.map(c => c.duration_ms)), maxS = Math.max(1, ...main.map(c => c.end - c.start));
  const bw = (W - 2 * P) / main.length;
  const svg = s('svg', { viewBox: `0 0 ${W} ${H}`, class: 'chart' });
  main.forEach((c, i) => {
    const hh = (H - 2 * P) * (c.end - c.start) / maxS;
    svg.append(s('rect', { x: P + i * bw + 1, y: H - P - hh, width: Math.max(1, bw - 2), height: hh, fill: 'var(--accent-2)', opacity: .55 },
      s('title', { text: `chunk ${c.seq}: ${c.end - c.start} celów, ${(c.duration_ms / 1000).toFixed(1)} s` })));
  });
  svg.append(s('path', { d: main.map((c, i) => `${i ? 'L' : 'M'}${P + i * bw + bw / 2},${H - P - (H - 2 * P) * c.duration_ms / maxD}`).join(' '), fill: 'none', stroke: 'var(--high)', 'stroke-width': 1.5 }));
  return h('div', null, svg, h('div', { class: 'legend' }, h('span', null, h('i', { style: { background: 'var(--accent-2)' } }), 'rozmiar chunku (adaptacyjny)'),
    h('span', null, h('i', { style: { background: 'var(--high)' } }), 'czas trwania chunku')));
}

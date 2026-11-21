/* ASI pages: dashboard, findings, hosts, changes/compare, groups */
'use strict';

function pageHead(title, sub, ...actions) {
  return h('div', { class: 'topbar' }, h('div', null, sub ? h('div', { class: 'crumbs' }, sub) : null, h('h1', { text: title })), h('div', { class: 'sp' }), ...actions);
}

/* ---------------- Dashboard ---------------- */
async function pageDashboard(root) {
  const d = await GET('/api/dashboard');
  const t = d.totals;
  const kpi = (v, l, sub, cls, href) => h('div', { class: 'kpi ' + (cls || ''), 'data-href': href || null, onclick: href ? () => location.hash = href : null },
    h('div', { class: 'v' }, fmtN(v)), h('div', { class: 'l' }, l), sub ? h('div', { class: 's' }, sub) : null);
  root.append(pageHead('Pulpit', null,
    can('scans:run') ? h('a', { class: 'btn primary', href: '#/quick' }, 'Szybki skan') : null,
    can('scans:run') && d.active_runs.length ? h('button', { class: 'danger', title: 'Natychmiast wstrzymuje wszystkie trwające skany', onclick: async () => {
      if (await confirmBox('Wstrzymać WSZYSTKIE trwające skany?', 'Wstrzymaj')) { const r = await act(() => POST('/api/scans/stop-all')); toast(`Wstrzymano: ${r.paused}`); render(); }
    } }, 'Wstrzymaj wszystkie skany') : null));

  // one short line about which dataset is shown – only when it matters
  const scopeNote = !ASI.meta.has_demo_data ? null
    : ASI.scope === 'demo' ? 'Widok „Demo”: dane z symulowanej sieci demonstracyjnej.'
    : ASI.scope === 'all' ? 'Widok „Wszystkie”: dane prawdziwe i demonstracyjne razem.'
    : !t.hosts ? 'Brak prawdziwych danych. Przeskanuj cel Szybkim skanem albo wybierz widok „Demo” w menu po lewej.' : null;
  if (scopeNote) root.append(h('div', { class: 'notice' }, scopeNote));

  // KISS: six numbers that answer "what needs attention", the rest as one line of links
  const hostSub = [t.unstable && `${fmtN(t.unstable)} niestabilnych`, t.suspect && `${fmtN(t.suspect)} do potwierdzenia`, t.inactive && `${fmtN(t.inactive)} nieaktywnych`]
    .filter(Boolean).join(' · ') || `z ${fmtN(t.hosts)} znanych`;
  root.append(h('div', { class: 'kpis' },
    kpi(t.critical, 'Krytyczne', 'priorytet analityczny', 'crit', '#/services?priority=critical'),
    kpi(t.high, 'Wysokie', '', 'high', '#/services?priority=high'),
    kpi(t.staging, 'Środowiska testowe', 'staging, dev, UAT', '', '#/services?category=staging'),
    kpi(t.admin_panels, 'Panele administracyjne', '', '', '#/services?category=admin-panel'),
    kpi(t.changes_24h, 'Zmiany w 24 h', `${fmtN(t.new_services_7d)} nowych usług w 7 dni`, '', '#/changes'),
    kpi(t.active, 'Hosty aktywne', hostSub, '', '#/hosts')));
  const also = [
    [t.services, 'otwartych usług', '#/services'], [t.web, 'aplikacji WWW', '#/services?web=1'], [t.cert_problems, 'problemów z TLS', '#/services?sort=last_changed'],
    [t.vuln_services, 'usług ze znanymi CVE', '#/quick'], [t.manual, 'wpisów ręcznych', '#/services?origin=manual']];
  root.append(h('div', { class: 'also' }, also.map(([v, l, href]) => h('a', { href }, h('b', null, fmtN(v)), ' ' + l))));

  if (d.active_runs.length) {
    root.append(h('div', { class: 'panel', style: { marginBottom: '14px' } }, h('h2', null, 'Trwające i wstrzymane skany'),
      d.active_runs.map(r => h('div', { style: { display: 'grid', gridTemplateColumns: '1fr 220px 160px', gap: '12px', alignItems: 'center', padding: '6px 0' } },
        h('div', null, h('a', { href: '#/runs/' + r.id }, `#${r.id} ${r.job_name}`), ' ', statusChip(r.status), r.status_reason ? h('span', { class: 'small muted' }, ' ' + (PL.reason[r.status_reason] || r.status_reason)) : null),
        h('div', { class: 'progress' }, h('i', { style: { width: (r.progress * 100).toFixed(1) + '%' } })),
        h('div', { class: 'small muted right' }, `${fmtN(r.done_targets)}/${fmtN(r.total_targets)}` + (r.eta_sec ? ` · ETA ${dur(r.eta_sec)}` : ''))))));
  }

  const top = h('div', { class: 'panel flush' }, h('div', { class: 'ph' }, h('h2', null, 'Najważniejsze znaleziska'), h('div', { class: 'sp' }), h('a', { href: '#/services' }, 'Wszystkie')),
    d.top_findings.length ? table([
      { title: 'Priorytet', render: r => prioScore(r.priority, r.curiosity) },
      { title: 'Usługa', render: r => h('div', null, h('span', { class: 'addr' }, `${r.address}:${r.port}`), r.hostname ? h('div', { class: 'sub' }, r.hostname) : null) },
      { title: 'Co wykryto', render: r => h('div', null, h('div', { class: 'trunc' }, withOverride(r.title, 'title', r.observed) || withOverride(r.product, 'product', r.observed) || r.name),
        h('div', { class: 'sub' }, techList(r.tech, 3), r.triage ? h('span', { class: 'chip outline' }, PL.triage[r.triage]) : null)) },
    ], d.top_findings, r => location.hash = '#/services/' + r.id) : h('div', { class: 'empty' }, 'Brak znalezisk. Uruchom skan lub zaimportuj wyniki.'));

  const changes = h('div', { class: 'panel' }, h('div', { style: { display: 'flex' } }, h('h2', { style: { flex: 1 } }, 'Ostatnie istotne zmiany'), h('a', { href: '#/changes' }, 'Wszystkie')), feed(d.recent_changes.slice(0, 10)));
  root.append(h('div', { class: 'grid g-main' }, top, changes));

  const unstable = h('div', { class: 'panel' }, h('div', { style: { display: 'flex' } }, h('h2', { style: { flex: 1 } }, 'Dostępność wg pory dnia'), h('a', { href: '#/hosts?state=unstable' }, 'Hosty niestabilne')),
    hoursStrip(d.hourly_up),
    h('p', { class: 'small muted' }, 'Odsetek hostów odpowiadających w danej godzinie. Host, który zwykle nie odpowiada o tej porze, jest oznaczany jako okresowy, a nie jako zniknięty.'),
    d.unstable.length ? d.unstable.slice(0, 5).map(x => h('div', { style: { display: 'flex', gap: '10px', alignItems: 'center', padding: '6px 0', borderTop: '1px solid var(--line)' } },
      h('a', { class: 'addr', href: '#/hosts/' + x.id }, x.address), h('span', { class: 'small muted', style: { flex: 1 } }, x.pattern), histEl(x.history, 16)))
      : h('div', { class: 'muted small' }, 'Brak hostów niestabilnych.'));
  root.append(h('div', { class: 'grid g2', style: { marginTop: '14px' } },
    h('div', { class: 'panel' }, h('h2', null, 'Zmiany w kolejnych przebiegach'), trendChart(d.trend)), unstable));
  root.append(h('p', { class: 'small muted', style: { marginTop: '14px' } }, 'Technologie, kategorie, favicony i wystawców certyfikatów znajdziesz w zakładce ', h('a', { href: '#/groups' }, 'Grupowanie'), '.'));
}
function groupMini(groups, by) {
  if (!groups || !groups.length) return h('div', { class: 'empty' }, 'Brak danych');
  return h('div', null, groups.map(g => h('div', { class: 'hbar', style: { gridTemplateColumns: '1fr 70px' } },
    h('a', { class: 't', title: g.key, onclick: () => location.hash = `#/services?${by}=` + encodeURIComponent(g.key) }, g.label),
    h('span', { class: 'small muted right' }, `${g.services} usł. / ${g.hosts} h.`))));
}

/* ---------------- Findings (services) ---------------- */
function routeParams() {
  const q = location.hash.split('?')[1] || '';
  return Object.fromEntries(new URLSearchParams(q));
}
function setParams(base, p) {
  const clean = Object.fromEntries(Object.entries(p).filter(([, v]) => v !== '' && v !== undefined && v !== null && v !== false));
  const s = new URLSearchParams(clean).toString();
  location.hash = base + (s ? '?' + s : '');
}

async function pageServices(root) {
  const p = Object.assign({ status: 'open', limit: 50, offset: 0 }, routeParams());
  const data = await GET('/api/services' + qs(p));
  const selected = new Set();
  const upd = (k, v) => setParams('#/services', Object.assign({}, p, { [k]: v, offset: 0 }));
  const search = h('input', { type: 'search', placeholder: 'Szukaj: IP, nazwa, tytuł, technologia, port…', value: p.q || '', onkeydown: e => { if (e.key === 'Enter') upd('q', e.target.value); } });
  root.append(pageHead('Znaleziska', 'Usługi wykryte skanem, z importu i dodane ręcznie',
    can('assets:create') ? h('button', { onclick: () => manualServiceForm() }, 'Dodaj ręcznie') : null,
    can('data:export') ? h('button', { onclick: () => download('/api/export/results' + qs(Object.assign({}, p, { format: 'csv', limit: '', offset: '' }))) }, 'Eksport CSV') : null,
    can('data:export') ? h('button', { onclick: () => download('/api/export/results' + qs(Object.assign({}, p, { format: 'json', limit: '', offset: '' }))) }, 'Eksport JSON') : null));
  const active = [];
  for (const k of ['category', 'tech', 'tag', 'favicon', 'cert_issuer', 'title', 'product', 'server', 'origin', 'host']) if (p[k]) active.push(h('span', { class: 'chip outline' }, `${k}: ${PL.cat[p[k]] || p[k]} `, h('a', { onclick: () => upd(k, ''), 'aria-label': 'Usuń filtr', title: 'Usuń filtr' }, '✕')));
  root.append(h('div', { class: 'filters' }, search,
    seg([['', 'Wszystkie'], ['critical', 'Krytyczne'], ['high', 'Wysokie'], ['medium', 'Średnie'], ['low', 'Niskie']], p.priority || '', v => upd('priority', v)),
    select([['open', 'Otwarte'], ['gone', 'Zniknięte'], ['all', 'Wszystkie']], p.status, { onchange: e => upd('status', e.target.value) }),
    select([['', 'Triage: dowolny'], ...Object.entries(PL.triage).filter(([k]) => k)], p.triage || '', { onchange: e => upd('triage', e.target.value) }),
    select([['', 'Kategoria: dowolna'], ...Object.entries(PL.cat)], p.category || '', { onchange: e => upd('category', e.target.value) }),
    h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: p.web === '1', onchange: e => upd('web', e.target.checked ? '1' : '') }), 'tylko WWW'),
    select([['', 'Sortuj: priorytet'], ['last_changed', 'ostatnia zmiana'], ['first_seen', 'najnowsze'], ['address', 'adres'], ['port', 'port']], p.sort || '', { onchange: e => upd('sort', e.target.value) }),
    active));
  const bulk = h('div', { class: 'filters hidden' });
  const refreshBulk = () => { bulk.classList.toggle('hidden', selected.size === 0); clear(bulk).append(h('b', null, `Zaznaczono: ${selected.size}`),
    can('assets:update') ? h('button', { class: 'sm', onclick: () => bulkTag([...selected]) }, 'Dodaj tag / triage') : null,
    can('dojo:export') ? h('button', { class: 'sm', onclick: () => dojoDialog([...selected], []) }, 'Wyślij do DefectDojo') : null); };
  root.append(bulk);
  const cols = [
    { title: '', render: r => h('input', { type: 'checkbox', onchange: e => { e.target.checked ? selected.add(r.id) : selected.delete(r.id); refreshBulk(); } }) },
    { title: 'Priorytet', render: r => prioScore(r.priority, r.curiosity) },
    { title: 'Adres', render: r => h('div', null, h('span', { class: 'addr' }, `${r.address}:${r.port}/${r.proto}`), h('div', { class: 'sub' }, r.hostname || ''), r.host_state !== 'active' ? stateChip(r.host_state) : null) },
    { title: 'Usługa', render: r => h('div', null, withOverride(r.name, 'name', r.observed), ' ', h('span', { class: 'muted' }, withOverride([r.product, r.version].filter(Boolean).join(' '), 'product', r.observed)), r.origin !== 'scan' ? h('span', null, ' ', h('span', { class: 'chip manual' }, r.origin === 'manual' ? 'ręczny' : 'import')) : null) },
    { title: 'Aplikacja WWW', render: r => r.is_web ? h('div', null, h('div', { class: 'trunc' }, h('span', { class: 'muted' }, r.http_status + ' '), withOverride(r.title, 'title', r.observed) || h('span', { class: 'faint' }, '(brak tytułu)')), h('div', { class: 'sub' }, r.server)) : h('span', { class: 'faint' }, '—') },
    { title: 'Technologie', render: r => h('div', null, techList(r.tech, 3)) },
    { title: 'Analityk', render: r => h('div', null, r.triage ? h('span', { class: 'chip outline' }, PL.triage[r.triage]) : null, ' ', tags(r.tags), r.has_note ? h('span', { class: 'small muted' }, ' notatka') : null) },
    { title: 'Ostatnio', cls: 'nowrap', render: r => h('div', { class: 'small' }, r.status === 'gone' ? h('span', { class: 'chip gone' }, 'zniknęła ' + ago(r.gone_at)) : ago(r.last_seen)) },
  ];
  root.append(h('div', { class: 'panel flush' }, data.items.length ? table(cols, data.items, r => location.hash = '#/services/' + r.id) : h('div', { class: 'empty' }, 'Brak wyników dla wybranych filtrów'),
    pager(data.total, +p.offset, +p.limit, o => setParams('#/services', Object.assign({}, p, { offset: o })))));
}

function bulkTag(ids) {
  const tagIn = h('input', { placeholder: 'np. do-weryfikacji, wydział-x' });
  const tri = select([['', '(bez zmiany)'], ...Object.entries(PL.triage).filter(([k]) => k)], '');
  modal(`Edycja zbiorcza (${ids.length})`, h('div', null, field('Dodaj tagi (rozdzielone przecinkami)', tagIn), field('Ustaw triage', tri)), [
    { label: 'Anuluj' },
    { label: 'Zapisz', cls: 'primary', run: async () => {
      const body = { ids, add_tags: tagIn.value.split(',').map(x => x.trim()).filter(Boolean) };
      if (tri.value) body.triage = tri.value;
      const r = await POST('/api/services/bulk', body); toast(`Zaktualizowano ${r.updated}`); render();
    } }]);
}

async function pageService(root, id) {
  const sv = await GET('/api/services/' + id);
  const a = sv.annotation || { tags: [], overrides: {} };
  root.append(pageHead(`${sv.address}:${sv.port}/${sv.proto}`, h('span', null, h('a', { href: '#/services' }, 'Znaleziska'), ' / ', h('a', { href: '#/hosts/' + sv.host_id }, sv.hostname || sv.address)),
    prioChip(sv.priority), statusChip(sv.status),
    can('dojo:export') ? h('button', { onclick: () => dojoDialog([sv.id], []) }, 'Wyślij do DefectDojo') : null,
    can('assets:delete') ? h('button', { class: 'danger', onclick: async () => { if (await confirmBox('Usunąć tę usługę? (zostanie ponownie wykryta przy kolejnym skanie, jeśli nadal istnieje)')) { await act(() => DEL('/api/services/' + id), 'Usunięto'); location.hash = '#/services'; } } }, 'Usuń') : null));

  const ov = sv.observed || {};
  const info = h('div', { class: 'panel' }, h('h2', null, 'Podsumowanie'), h('dl', { class: 'kv' },
    h('dt', null, 'Usługa'), h('dd', null, withOverride(sv.name, 'name', ov), ' ', withOverride([sv.product, sv.version].filter(Boolean).join(' '), 'product', ov)),
    h('dt', null, 'Host'), h('dd', null, h('a', { href: '#/hosts/' + sv.host_id }, sv.address), sv.hostname ? ' · ' + sv.hostname : '', ' ', stateChip(sv.host_state)),
    sv.is_web ? [h('dt', null, 'URL'), h('dd', { class: 'mono' }, withOverride(sv.url, 'url', ov))] : null,
    sv.is_web ? [h('dt', null, 'Tytuł / kod'), h('dd', null, withOverride(sv.title, 'title', ov) || '—', ` (HTTP ${sv.http_status})`)] : null,
    sv.server ? [h('dt', null, 'Server'), h('dd', null, sv.server)] : null,
    h('dt', null, 'Pochodzenie'), h('dd', null, { scan: 'skan', manual: 'wpis ręczny (przetwarzany jak skan)', import: 'import' }[sv.origin] || sv.origin),
    h('dt', null, 'Pierwsze wykrycie'), h('dd', null, fmtT(sv.first_seen)), h('dt', null, 'Ostatnio widziana'), h('dd', null, fmtT(sv.last_seen)),
    h('dt', null, 'Ostatnia zmiana'), h('dd', null, fmtT(sv.last_changed)),
    sv.banner ? [h('dt', null, 'Baner'), h('dd', { class: 'mono' }, sv.banner)] : null,
    h('dt', null, 'Kategorie'), h('dd', null, cats(sv.categories)), h('dt', null, 'Tagi'), h('dd', null, tags(sv.tags))));

  const why = h('div', { class: 'panel' }, h('h2', null, `Ocena ciekawości: ${sv.curiosity}/100`),
    sv.priority !== sv.scan_priority ? h('div', { class: 'notice' }, `Priorytet ustawiony ręcznie (${PL.priority[sv.priority]}); wyliczony: ${PL.priority[sv.scan_priority]}`) : null,
    (sv.reasons || []).length ? sv.reasons.map(r => h('div', { class: 'reason' }, h('b', null, '+' + r.points), h('span', null, r.text))) : h('div', { class: 'muted' }, 'Brak czynników podnoszących priorytet.'),
    h('h3', null, 'Wykryte technologie (pewność ważona)'),
    (sv.tech || []).length ? table([
      { title: 'Technologia', render: t => h('div', null, h('b', null, t.name), t.version ? ' ' + t.version : '') },
      { title: 'Kategoria', render: t => PL.cat[t.category] || t.category },
      { title: 'Pewność', render: t => h('span', { class: 'nowrap' }, t.confidence + '%', confEl(t.confidence)) },
      { title: 'Dowody', render: t => h('div', { class: 'small' }, (t.evidence || []).map(e => h('div', null, '• ' + e))) },
    ], sv.tech) : h('div', { class: 'muted' }, 'Brak dopasowanych sygnatur.'));

  const tabsEl = h('div', { class: 'tabs' });
  const body = h('div');
  const tabs = { http: 'HTTP', tls: 'Certyfikat TLS', vulns: `Podatności (${(sv.vulns || []).length})`, history: 'Historia zmian', edit: 'Edycja analityka' };
  const show = (k) => { [...tabsEl.children].forEach(b => b.classList.toggle('on', b.dataset.k === k)); clear(body).append(renderTab(k)); };
  for (const [k, l] of Object.entries(tabs)) tabsEl.append(h('button', { 'data-k': k, onclick: () => show(k) }, l));

  function renderTab(k) {
    if (k === 'http') {
      const x = sv.http;
      if (!x) return h('div', { class: 'empty' }, 'Usługa nie jest aplikacją WWW lub nie odpowiedziała na żądanie HTTP.');
      return h('div', { class: 'grid g2' },
        h('div', { class: 'panel' }, h('h2', null, 'Odpowiedź'), h('dl', { class: 'kv' },
          h('dt', null, 'Żądanie'), h('dd', { class: 'mono' }, 'GET ' + x.url), h('dt', null, 'Końcowy URL'), h('dd', { class: 'mono' }, x.final_url),
          h('dt', null, 'Status'), h('dd', null, x.status), h('dt', null, 'Tytuł'), h('dd', null, x.title || '—'),
          x.generator ? [h('dt', null, 'Generator'), h('dd', null, x.generator)] : null,
          h('dt', null, 'Treść'), h('dd', null, `${fmtN(x.body_len)} B`, h('div', { class: 'small faint mono' }, x.body_sha256 || '')),
          x.favicon_hash ? [h('dt', null, 'Favicon mmh3'), h('dd', null, h('a', { href: '#/services?favicon=' + encodeURIComponent(x.favicon_hash) }, x.favicon_hash), h('span', { class: 'small muted' }, ' (zgodny z Shodan)'))] : null,
          h('dt', null, 'Czas odpowiedzi'), h('dd', null, x.response_ms ? `${fmtN(x.response_ms)} ms` : '—',
            h('span', { class: 'small muted' }, ` (cały fingerprint: ${fmtN(x.duration_ms)} ms, ${x.requests} żądań)`))),
          x.redirects && x.redirects.length ? [h('h3', null, 'Przekierowania'), ...x.redirects.map(r => h('div', { class: 'small mono' }, `${r.status}: ${r.from} → ${r.to}`))] : null,
          h('h3', null, 'Ciasteczka'),
          (x.cookies || []).length ? table([{ title: 'Nazwa', render: c => h('b', null, c.name) }, { title: 'Flagi', render: c => h('span', null, c.secure ? h('span', { class: 'chip ok' }, 'Secure') : h('span', { class: 'chip high' }, 'bez Secure'), ' ', c.httponly ? h('span', { class: 'chip ok' }, 'HttpOnly') : h('span', { class: 'chip high' }, 'bez HttpOnly'), c.samesite ? ' SameSite=' + c.samesite : '') },
            { title: 'Wartość', render: c => h('span', { class: 'mono small faint' }, `${c.value_prefix || ''} (${c.value_len} zn.)`) }], x.cookies) : h('div', { class: 'muted small' }, 'brak')),
        h('div', { class: 'panel' }, h('h2', null, 'Nagłówki'), table([{ title: 'Nagłówek', render: r => h('b', { class: 'small' }, r[0]) }, { title: 'Wartość', render: r => h('span', { class: 'small mono' }, r[1].join(', ')) }],
          Object.entries(x.headers || {}).sort((a, b) => a[0].localeCompare(b[0]))),
          h('h3', null, 'Pasywne sprawdzenie ścieżek (tylko GET, bez logowania)'),
          (x.paths || []).length ? table([{ title: 'Ścieżka', render: r => h('span', { class: 'mono' }, r.path) }, { title: 'Kod', render: r => h('span', { class: r.status === 200 ? 'k-new' : 'muted' }, r.status) },
            { title: 'Tytuł / rozmiar', render: r => h('span', { class: 'small' }, (r.title || '') + ` (${r.length} B)` + (r.location ? ' → ' + r.location : '')) }], x.paths.filter(p => p.status !== 404)) : h('div', { class: 'muted small' }, 'nie wykonywano'),
          x.body_excerpt ? [h('h3', null, 'Fragment treści'), h('pre', { class: 'code' }, x.body_excerpt)] : null));
    }
    if (k === 'tls') {
      const t = sv.tls;
      if (!t) return h('div', { class: 'empty' }, 'Brak certyfikatu TLS.');
      return h('div', { class: 'panel' }, h('dl', { class: 'kv' },
        h('dt', null, 'Podmiot'), h('dd', null, t.subject), h('dt', null, 'Wystawca'), h('dd', null, h('a', { href: '#/services?cert_issuer=' + encodeURIComponent(t.issuer_cn) }, t.issuer)),
        h('dt', null, 'SAN'), h('dd', { class: 'mono' }, (t.sans || []).join(', ') || '—'),
        h('dt', null, 'Ważny'), h('dd', null, `${fmtT(Date.parse(t.not_before) / 1000)} → ${fmtT(Date.parse(t.not_after) / 1000)} `,
          t.expired ? h('span', { class: 'chip crit' }, 'WYGASŁ') : t.days_left <= 14 ? h('span', { class: 'chip high' }, `wygasa za ${t.days_left} dni`) : h('span', { class: 'chip ok' }, `${t.days_left} dni`)),
        h('dt', null, 'Samopodpisany'), h('dd', null, t.self_signed ? h('span', { class: 'chip medium' }, 'tak') : 'nie'),
        h('dt', null, 'Zgodność nazwy'), h('dd', null, t.hostname_match ? 'tak' : h('span', { class: 'chip medium' }, 'nie')),
        h('dt', null, 'Protokół / szyfr'), h('dd', null, `${t.version} · ${t.cipher}`), h('dt', null, 'Klucz / podpis'), h('dd', null, `${t.key_type} · ${t.sig_alg}`),
        h('dt', null, 'Numer seryjny'), h('dd', { class: 'mono' }, t.serial), h('dt', null, 'SHA-256'), h('dd', { class: 'mono small' }, t.sha256)));
    }
    if (k === 'vulns') {
      if (!(sv.vulns || []).length) return h('div', { class: 'empty' }, 'Brak znanych CVE dla wykrytych wersji (lub sprawdzanie podatności nie było włączone – użyj „Szybkiego skanu”).');
      return h('div', { class: 'panel flush' }, h('div', { class: 'pb' }, h('div', { class: 'notice' }, 'Dopasowanie po wersji (NIST NVD) – do weryfikacji; łatki dystrybucji (backport) mogą nie zmieniać numeru wersji.')), vulnTable(sv.vulns, false));
    }
    if (k === 'history') {
      return h('div', { class: 'grid g2' }, h('div', { class: 'panel' }, h('h2', null, 'Zdarzenia'), feed(sv.changes, 'Brak zarejestrowanych zmian')),
        h('div', { class: 'panel' }, h('h2', null, 'Odcisk stanu w kolejnych przebiegach'), h('p', { class: 'small muted' }, 'Zmiana skrótu oznacza zmianę istotnych cech usługi (wersja, tytuł, technologie, certyfikat…).'),
          table([{ title: 'Przebieg', render: r => h('a', { href: '#/runs/' + r.run_id }, '#' + r.run_id) }, { title: 'Czas', render: r => fmtT(r.at) }, { title: 'Skrót stanu', render: r => h('span', { class: 'mono' }, r.digest) }], sv.history || [])));
    }
    return editForm('service', sv.id, a, ['name', 'product', 'version', 'title', 'url'], { name: sv.name, product: sv.product, version: sv.version, title: sv.title, url: sv.url }, ov);
  }
  root.append(h('div', { class: 'grid g2' }, info, why), tabsEl, body);
  show((sv.vulns || []).length ? 'vulns' : sv.is_web ? 'http' : 'history');
}

/* analyst edit form (shared by hosts and services) */
function editForm(type, id, a, fields, current, observed) {
  if (!can('assets:update')) return h('div', { class: 'panel' }, h('div', { class: 'notice' }, 'Twoja rola nie pozwala na edycję. Aktualne adnotacje:'),
    h('dl', { class: 'kv' }, h('dt', null, 'Tagi'), h('dd', null, tags(a.tags)), h('dt', null, 'Triage'), h('dd', null, PL.triage[a.triage || '']), h('dt', null, 'Notatka'), h('dd', null, a.note || '—')));
  const tagsIn = h('input', { value: (a.tags || []).join(', ') });
  const tri = select(Object.entries(PL.triage), a.triage || '');
  const owner = h('input', { value: a.owner || '' });
  const prio = select([['', '(wyliczany automatycznie)'], ...Object.entries(PL.priority)], a.priority_override || '');
  const crit = h('input', { value: a.criticality || '', placeholder: 'np. wysoka – system rekrutacji' });
  const note = h('textarea', { rows: 5 }, a.note || '');
  const ovIn = {};
  const ovFields = fields.map(f => {
    const obs = observed && f in observed ? observed[f] : current[f];
    ovIn[f] = h('input', { value: (a.overrides || {})[f] || '', placeholder: 'ze skanu: ' + (obs || '∅') });
    return field(`Korekta: ${f}`, ovIn[f]);
  });
  return h('div', { class: 'panel' },
    h('div', { class: 'notice' }, 'Zmiany analityka są przechowywane w osobnej warstwie i NIGDY nie są nadpisywane przez kolejne skany. Puste pole korekty = wartość ze skanu. Notatki są szyfrowane w bazie.'),
    h('div', { class: 'frow' }, field('Tagi (przecinki)', tagsIn), field('Triage', tri), type === 'service' ? field('Priorytet (ręcznie)', prio) : field('Krytyczność biznesowa', crit), field('Właściciel', owner)),
    h('h3', null, 'Korekty wartości'), h('div', { class: 'frow' }, ovFields),
    field('Notatka', note),
    h('button', { class: 'primary', onclick: async () => {
      const overrides = {};
      for (const f of fields) overrides[f] = ovIn[f].value.trim();
      const body = { tags: tagsIn.value.split(',').map(x => x.trim()).filter(Boolean), triage: tri.value, owner: owner.value, note: note.value, overrides };
      if (type === 'service') body.priority_override = prio.value; else body.criticality = crit.value;
      await act(() => PATCH(`/api/${type}s/${id}`, body), 'Zapisano');
      render();
    } }, 'Zapisz'));
}

function manualServiceForm(host) {
  const addr = h('input', { value: host ? host.address : '', placeholder: '10.0.0.5', disabled: !!host });
  const hn = h('input', { value: host ? host.hostname : '', placeholder: 'opcjonalnie' });
  const port = h('input', { type: 'number', min: 1, max: 65535, placeholder: '443' });
  const proto = select(['tcp', 'udp'], 'tcp');
  const name = h('input', { placeholder: 'https' }), product = h('input', { placeholder: 'nginx' }), version = h('input', { placeholder: '1.24' });
  const title = h('input', { placeholder: 'Tytuł strony' }), url = h('input', { placeholder: 'https://…' });
  const tagsIn = h('input', { placeholder: 'tagi' }), note = h('textarea', { rows: 3 });
  let jobSel = null;
  const jobWrap = h('div');
  if (!host && can('jobs:create')) GET('/api/jobs').then(js => { jobSel = select([['', '(nie dodawaj do skanu)'], ...js.map(j => [j.id, j.name])], ''); jobWrap.append(field('Dodaj adres do zadania skanowania (będzie skanowany cyklicznie)', jobSel)); }).catch(() => {});
  modal(host ? 'Dodaj usługę ręcznie' : 'Dodaj host / usługę ręcznie', h('div', null,
    h('div', { class: 'notice' }, 'Dane wprowadzone ręcznie przechodzą przez te same sygnatury, scoring i analizę zmian co wyniki skanu. Wartości opisowe zapisywane są jako korekty analityka (nie zostaną nadpisane).'),
    h('div', { class: 'frow' }, field('Adres IP', addr), field('Nazwa hosta', hn)),
    h('div', { class: 'frow' }, field('Port', port), field('Protokół', proto), field('Usługa', name)),
    h('div', { class: 'frow' }, field('Produkt', product), field('Wersja', version)),
    h('div', { class: 'frow' }, field('Tytuł', title), field('URL', url)), field('Tagi', tagsIn), field('Notatka', note), jobWrap), [
    { label: 'Anuluj' },
    { label: 'Dodaj', cls: 'primary', run: async () => {
      const svc = { port: +port.value, proto: proto.value, name: name.value, product: product.value, version: version.value, title: title.value, url: url.value, note: note.value, tags: tagsIn.value.split(',').map(x => x.trim()).filter(Boolean) };
      const body = { address: addr.value.trim(), hostname: hn.value.trim(), services: svc.port ? [svc] : [] };
      if (jobSel && jobSel.value) body.add_to_job = +jobSel.value;
      const r = await POST('/api/hosts', body);
      toast('Dodano'); location.hash = r.service_ids && r.service_ids.length ? '#/services/' + r.service_ids[0] : '#/hosts/' + r.host_id;
    } }]);
}

/* ---------------- Hosts ---------------- */
async function pageHosts(root) {
  const p = Object.assign({ limit: 50, offset: 0 }, routeParams());
  const data = await GET('/api/hosts' + qs(p));
  const upd = (k, v) => setParams('#/hosts', Object.assign({}, p, { [k]: v, offset: 0 }));
  root.append(pageHead('Hosty', 'Dostępność hostów w kolejnych skanach',
    can('assets:create') ? h('button', { onclick: () => manualServiceForm() }, 'Dodaj host') : null));
  root.append(h('div', { class: 'filters' },
    h('input', { type: 'search', placeholder: 'IP, nazwa, system…', value: p.q || '', onkeydown: e => { if (e.key === 'Enter') upd('q', e.target.value); } }),
    seg([['', 'Wszystkie'], ['active', 'Aktywne'], ['unstable', 'Niestabilne'], ['suspect', 'Oczekujące'], ['inactive', 'Nieaktywne']], p.state || '', v => upd('state', v)),
    p.tag ? h('span', { class: 'chip outline' }, 'tag: ' + p.tag + ' ', h('a', { onclick: () => upd('tag', ''), 'aria-label': 'Usuń filtr', title: 'Usuń filtr' }, '✕')) : null,
    select([['', 'Sortuj: ciekawość'], ['last_seen', 'ostatnio widziane'], ['first_seen', 'najnowsze'], ['state', 'stan']], p.sort || '', { onchange: e => upd('sort', e.target.value) })));
  root.append(h('div', { class: 'panel flush' }, data.items.length ? table([
    { title: 'Stan', render: r => stateChip(r.state) },
    { title: 'Adres', render: r => h('div', null, h('span', { class: 'addr' }, r.address), h('div', { class: 'sub' }, withOverride(r.hostname, 'hostname', r.observed))) },
    { title: 'Usługi', cls: 'num', render: r => r.open_services },
    { title: 'Najwyższy priorytet', render: r => r.top_priority ? prioChip(r.top_priority) : '—' },
    { title: 'Historia odpowiedzi', render: r => h('div', null, histEl(r.history), h('div', { class: 'sub' }, r.pattern)) },
    { title: 'Ostatnio widziany', render: r => h('div', { class: 'small' }, ago(r.last_seen), r.misses ? h('div', { class: 'sub' }, `brak odp.: ${r.misses}×`) : null) },
    { title: 'Analityk', render: r => h('div', null, r.triage ? h('span', { class: 'chip outline' }, PL.triage[r.triage]) : null, tags(r.tags), r.origin === 'manual' ? h('span', { class: 'chip manual' }, 'ręczny') : null) },
  ], data.items, r => location.hash = '#/hosts/' + r.id) : h('div', { class: 'empty' }, 'Brak hostów'),
    pager(data.total, +p.offset, +p.limit, o => setParams('#/hosts', Object.assign({}, p, { offset: o })))));
}

async function pageHost(root, id) {
  const x = await GET('/api/hosts/' + id);
  const a = x.annotation || { tags: [], overrides: {} };
  root.append(pageHead(x.address, h('span', null, h('a', { href: '#/hosts' }, 'Hosty'), ' / ', x.hostname || ''), stateChip(x.state),
    can('assets:create') ? h('button', { onclick: () => manualServiceForm(x) }, 'Dodaj usługę') : null,
    can('assets:delete') ? h('button', { class: 'danger', onclick: async () => { if (await confirmBox('Usunąć host wraz z usługami i adnotacjami?')) { await act(() => DEL('/api/hosts/' + id), 'Usunięto'); location.hash = '#/hosts'; } } }, 'Usuń') : null));
  const avail = x.probes ? Math.round(x.ups / x.probes * 100) : 0;
  root.append(h('div', { class: 'grid g2' },
    h('div', { class: 'panel' }, h('h2', null, 'Host'), h('dl', { class: 'kv' },
      h('dt', null, 'Nazwa'), h('dd', null, withOverride(x.hostname, 'hostname', x.observed) || '—'),
      h('dt', null, 'System'), h('dd', null, withOverride(x.os, 'os', x.observed) || '—'),
      h('dt', null, 'Stan'), h('dd', null, stateChip(x.state), x.misses ? ` (kolejne skany bez odpowiedzi: ${x.misses})` : ''),
      h('dt', null, 'Wzorzec dostępności'), h('dd', null, x.pattern || '—'),
      h('dt', null, 'Dostępność'), h('dd', null, `${avail}% (${x.ups}/${x.probes} pomiarów)`),
      h('dt', null, 'Pierwsze wykrycie'), h('dd', null, fmtT(x.first_seen)), h('dt', null, 'Ostatnio widziany'), h('dd', null, fmtT(x.last_seen)),
      h('dt', null, 'Pochodzenie'), h('dd', null, x.origin), h('dt', null, 'Tagi'), h('dd', null, tags(x.tags)))),
    h('div', { class: 'panel' }, h('h2', null, 'Profil godzinowy odpowiedzi'), hostHours(x.hour_up, x.hour_probe),
      h('h3', null, 'Ostatnie przebiegi (od najnowszego)'),
      h('div', { style: { display: 'flex', gap: '3px', flexWrap: 'wrap' } }, (x.timeline || []).map(t => h('a', { href: '#/runs/' + t.run_id, title: `#${t.run_id} ${fmtT(t.at)}: ${t.up ? 'odpowiada' : 'brak odpowiedzi'}`,
        style: { width: '14px', height: '14px', borderRadius: '2px', display: 'block', background: t.up ? 'var(--ok)' : 'var(--crit)', opacity: t.up ? 1 : .6 } }))),
      h('p', { class: 'small muted' }, 'Host, który nie odpowiada, jest ponownie sprawdzany (re-probe) w tym samym przebiegu. Za nieaktywny uznawany jest dopiero po N kolejnych skanach bez odpowiedzi; dla hostów okresowych brak odpowiedzi w ich typowych godzinach „wyłączenia” nie jest liczony.'))));
  const tabsEl = h('div', { class: 'tabs' }), body = h('div');
  const tabs = { svc: `Usługi (${x.services.length})`, ch: 'Zmiany', edit: 'Edycja analityka' };
  const show = k => { [...tabsEl.children].forEach(b => b.classList.toggle('on', b.dataset.k === k)); clear(body).append(
    k === 'svc' ? h('div', { class: 'panel flush' }, table([
      { title: 'Port', render: r => h('span', { class: 'addr' }, `${r.port}/${r.proto}`) }, { title: 'Status', render: r => statusChip(r.status) },
      { title: 'Usługa', render: r => h('div', null, withOverride(r.name, 'name', r.observed), ' ', h('span', { class: 'muted' }, [r.product, r.version].filter(Boolean).join(' '))) },
      { title: 'WWW', render: r => r.is_web ? h('span', { class: 'trunc' }, `${r.http_status} ${r.title}`) : '—' },
      { title: 'Technologie', render: r => techList(r.tech, 4) }, { title: 'Priorytet', render: r => prioChip(r.priority) }], x.services, r => location.hash = '#/services/' + r.id))
    : k === 'ch' ? h('div', { class: 'panel' }, feed(x.changes)) : editForm('host', x.id, a, ['hostname', 'os'], { hostname: x.hostname, os: x.os }, x.observed || {})); };
  for (const [k, l] of Object.entries(tabs)) tabsEl.append(h('button', { 'data-k': k, onclick: () => show(k) }, l));
  root.append(tabsEl, body); show('svc');
}

/* ---------------- Changes & compare ---------------- */
async function pageChanges(root) {
  const p = Object.assign({ limit: 200 }, routeParams());
  const [rows, runs] = await Promise.all([GET('/api/changes' + qs(p)), GET('/api/runs?limit=100')]);
  const upd = (k, v) => setParams('#/changes', Object.assign({}, p, { [k]: v }));
  const done = runs.filter(r => r.status === 'completed');
  root.append(pageHead('Zmiany w czasie', 'Nowe, znikające i zmienione usługi oraz zmiany stanu hostów',
    can('data:export') ? h('button', { onclick: () => download('/api/export/changes' + qs(Object.assign({}, p, { format: 'csv' }))) }, 'Eksport CSV') : null,
    can('data:export') ? h('button', { onclick: () => download('/api/export/changes' + qs(Object.assign({}, p, { format: 'json' }))) }, 'Eksport JSON') : null));
  // default: the latest run and the previous run OF THE SAME JOB (comparing two different jobs is meaningless)
  const prevOf = x => done.find(r => r.id < x.id && r.job_id === x.job_id);
  const latest = done.find(r => prevOf(r)) || done[0], prev = latest ? prevOf(latest) : null;
  const a = select(done.map(r => [r.id, `#${r.id} ${r.job_name} · ${fmtT(r.finished_at)}`]), prev ? prev.id : '');
  const b = select(done.map(r => [r.id, `#${r.id} ${r.job_name} · ${fmtT(r.finished_at)}`]), latest ? latest.id : '');
  const out = h('div');
  root.append(h('div', { class: 'panel', style: { marginBottom: '14px' } }, h('h2', null, 'Porównanie dwóch przebiegów'),
    h('div', { class: 'filters' }, h('span', null, 'Bazowy (A):'), a, h('span', null, 'Nowszy (B):'), b,
      h('button', { class: 'primary', onclick: async () => { clear(out).append(h('div', { class: 'muted' }, 'Porównywanie…')); renderCompare(out, await GET(`/api/compare?a=${a.value}&b=${b.value}`)); } }, 'Porównaj')), out));
  root.append(h('div', { class: 'filters' },
    h('input', { type: 'search', placeholder: 'Szukaj w opisie…', value: p.q || '', onkeydown: e => { if (e.key === 'Enter') upd('q', e.target.value); } }),
    select([['', 'Wszystkie typy'], ['service_new', 'nowe usługi'], ['service_gone', 'zniknięte usługi'], ['service_changed', 'zmienione usługi'],
      ['host_new,host_returned', 'nowe / powracające hosty'], ['host_suspect,host_inactive', 'brak odpowiedzi / nieaktywne'], ['host_unstable,host_stable', 'niestabilność hostów'], ['manual', 'wpisy ręczne']],
      p.kind || '', { onchange: e => upd('kind', e.target.value) }),
    select([['', 'Każda ważność'], ['critical,high', 'krytyczne + wysokie'], ['critical,high,medium', '≥ średnie'], ['info', 'informacyjne']], p.severity || '', { onchange: e => upd('severity', e.target.value) }),
    select([['', 'Wszystkie przebiegi'], ...runs.map(r => [r.id, `#${r.id} ${r.job_name}`])], p.run || '', { onchange: e => upd('run', e.target.value) })));
  root.append(h('div', { class: 'panel flush' }, rows.length ? table([
    { title: '', render: c => kindIcon(c.kind) },
    { title: 'Typ', render: c => h('span', { class: 'small nowrap' }, PL.kind[c.kind] || c.kind) },
    { title: 'Opis', render: c => { const l = changeLink(c); return l ? h('a', { href: l }, c.summary) : c.summary; } },
    { title: 'Ważność', render: c => prioChip(c.severity) },
    { title: 'Przebieg', render: c => c.run_id ? h('a', { href: '#/runs/' + c.run_id }, '#' + c.run_id) : '—' },
    { title: 'Czas', cls: 'nowrap', render: c => fmtT(c.created_at) },
    { title: '', render: c => can('dojo:export') ? h('button', { class: 'sm ghost', title: 'Wyślij do DefectDojo', onclick: () => dojoDialog([], [c.id]) }, 'DefectDojo') : null },
  ], rows) : h('div', { class: 'empty' }, 'Brak zmian')));
  if (a.value && b.value && a.value !== b.value) renderCompare(out, await GET(`/api/compare?a=${a.value}&b=${b.value}`));
}
function renderCompare(el, r) {
  clear(el);
  const item = (x, extra) => h('tr', { class: 'click', onclick: () => location.hash = '#/services/' + x.service_id }, h('td', { class: 'addr' }, `${x.address}:${x.port}`),
    h('td', null, x.name, x.title ? h('div', { class: 'sub' }, x.title) : null), h('td', { class: 'small' }, extra || (x.tech || []).join(', ')));
  const sec = (title, cls, list, ex) => h('div', { class: 'panel flush' }, h('div', { class: 'ph' }, h('h2', { class: cls }, `${title} (${list.length})`)),
    list.length ? h('div', { class: 'tblwrap', style: { maxHeight: '320px', overflowY: 'auto' } }, h('table', { class: 'tbl' }, h('tbody', null, list.slice(0, 300).map(x => item(x, ex ? ex(x) : null))))) : h('div', { class: 'empty' }, '—'));
  el.append(h('div', { class: 'kpis' },
    h('div', { class: 'kpi' }, h('div', { class: 'v' }, `${r.hosts_a} → ${r.hosts_b}`), h('div', { class: 'l' }, 'hosty aktywne A → B')),
    h('div', { class: 'kpi' }, h('div', { class: 'v k-new' }, '+' + r.new.length), h('div', { class: 'l' }, 'nowe usługi')),
    h('div', { class: 'kpi' }, h('div', { class: 'v k-gone' }, '−' + r.gone.length), h('div', { class: 'l' }, 'zniknęły (host odpowiadał)')),
    h('div', { class: 'kpi' }, h('div', { class: 'v k-chg' }, '~' + r.changed.length), h('div', { class: 'l' }, 'zmienione')),
    h('div', { class: 'kpi' }, h('div', { class: 'v' }, r.unreachable.length), h('div', { class: 'l' }, 'niepotwierdzone (host nie odpowiadał)')),
    h('div', { class: 'kpi' }, h('div', { class: 'v' }, r.same), h('div', { class: 'l' }, 'bez zmian'))));
  el.append(h('div', { class: 'grid g2' }, sec('Nowe', 'k-new', r.new), sec('Zmienione', 'k-chg', r.changed, x => (x.fields || []).map(f => `${f.field}: ${f.old || '∅'} → ${f.new || '∅'}`).join('; ')),
    sec('Zniknięte', 'k-gone', r.gone), sec('Niepotwierdzone (host offline w B)', '', r.unreachable)));
}

/* ---------------- Groups ---------------- */
async function pageGroups(root) {
  const p = Object.assign({ by: 'tech' }, routeParams());
  const groups = await GET('/api/groups' + qs({ by: p.by, limit: 60 }));
  const labels = { tech: 'Technologia', category: 'Kategoria', favicon: 'Favicon (mmh3)', cert_issuer: 'Wystawca certyfikatu', title: 'Tytuł strony', server: 'Nagłówek Server', product: 'Produkt / wersja' };
  root.append(pageHead('Grupowanie podobnych usług', 'Przy tysiącach hostów – przeglądaj klastry zamiast pojedynczych wpisów'));
  root.append(h('div', { class: 'filters' }, seg(Object.entries(labels), p.by, v => setParams('#/groups', { by: v }))));
  const param = { tech: 'tech', category: 'category', favicon: 'favicon', cert_issuer: 'cert_issuer', title: 'title', server: 'server', product: 'product' }[p.by];
  root.append(groups.length ? h('div', { class: 'cards' }, groups.map(g => h('div', { class: 'card click', onclick: () => location.hash = `#/services?${param}=` + encodeURIComponent(g.key) },
    h('div', { class: 'hd' }, h('b', null, p.by === 'category' ? (PL.cat[g.label] || g.label) : g.label), g.max_curiosity >= 40 ? prioChip(g.max_curiosity >= 60 ? 'critical' : 'high') : null),
    h('div', { class: 'meta' }, h('span', null, `${fmtN(g.services)} usług`), h('span', null, `${fmtN(g.hosts)} hostów`), h('span', null, `max. ciekawość ${g.max_curiosity}`)),
    h('div', { class: 'small mono faint', style: { marginTop: '6px' } }, (g.sample || []).join(', '), g.hosts > (g.sample || []).length ? ' …' : '')))) : h('div', { class: 'empty' }, 'Brak danych'));
}

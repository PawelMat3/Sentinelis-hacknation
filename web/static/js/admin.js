/* ASI pages: scan jobs, runs, signatures, import/export, administration, DefectDojo */
'use strict';

/* ---------------- Jobs ---------------- */
async function pageJobs(root) {
  const jobs = await GET('/api/jobs');
  root.append(pageHead('Zadania skanowania', 'Cykliczne skany z oknami czasowymi, limitem tempa i adaptacyjnym podziałem na podgrupy',
    can('jobs:create') ? h('button', { class: 'primary', onclick: () => jobEditor() }, 'Nowe zadanie') : null));
  if (!jobs.length) { root.append(h('div', { class: 'panel empty' }, 'Brak zadań. Utwórz zadanie i dodaj cele (IP, CIDR, zakresy, domeny).')); return; }
  root.append(h('div', { class: 'cards' }, jobs.map(j => {
    const r = j.active_run;
    return h('div', { class: 'card click', onclick: () => location.hash = '#/jobs/' + j.id },
      h('div', { class: 'hd' }, h('b', null, j.name), j.enabled ? null : h('span', { class: 'chip inactive' }, 'wyłączone'), h('span', { class: 'chip outline' }, j.engine)),
      h('div', { class: 'small muted', style: { marginBottom: '8px' } }, j.description),
      h('div', { class: 'meta' }, h('span', null, `${fmtN(j.address_count)} adresów`), h('span', null, `porty ${j.ports}`), h('span', null, `${j.rate_pps} pps`)),
      h('div', { class: 'meta' }, h('span', null, 'Okno: ' + j.window_text), h('span', { class: j.window_open ? 'k-new' : 'muted' }, j.window_open ? 'okno otwarte' : 'okno zamknięte')),
      h('div', { class: 'meta' }, h('span', null, j.interval_minutes ? `co ${dur(j.interval_minutes * 60)}` : 'tylko ręcznie'), h('span', null, 'ostatni: ' + ago(j.last_run_at)),
        j.next_run_at && j.interval_minutes ? h('span', null, 'następny: ' + fmtT(j.next_run_at)) : null),
      r ? h('div', { style: { marginTop: '10px' } }, h('div', { class: 'small' }, h('a', { href: '#/runs/' + r.id }, `Przebieg #${r.id}`), ' ', statusChip(r.status), ' ', h('span', { class: 'muted' }, PL.reason[r.status_reason] || '')),
        h('div', { class: 'progress', style: { marginTop: '4px' } }, h('i', { style: { width: (r.progress * 100).toFixed(1) + '%' } }))) : null);
  })));
}

const jobDefaults = { name: '', description: '', enabled: true, engine: 'nmap', ports: 'top:100', exclusions: '', rate_pps: 300, http_rps: 10, concurrency: 4, chunk_size: 0,
  chunk_target_sec: 60, timing: 'T3', service_detection: true, http_fingerprint: true, path_probes: true, nmap_extra: '', window_always: false, window_days: '1111100',
  window_start: '22:00', window_end: '06:00', timezone: 'Europe/Warsaw', interval_minutes: 1440, inactive_after: 3, reprobe_attempts: 2, reprobe_delay_sec: 30 };

function jobEditor(job) {
  const j = Object.assign({}, jobDefaults, job || {});
  const I = (k, attrs = {}) => h('input', Object.assign({ value: j[k] ?? '' }, attrs));
  const C = (k, label) => { const c = h('input', { type: 'checkbox', checked: j[k] }); c.dataset.k = k; return h('label', { class: 'check' }, c, label); };
  const f = {
    name: I('name'), description: I('description'), engine: select([['nmap', 'nmap (zalecany)'], ['native', 'natywny TCP connect'], ['sim', 'symulacja (demo)']], j.engine),
    ports: I('ports'), exclusions: h('textarea', { rows: 2, placeholder: 'np. 10.0.0.1, 10.0.5.0/24 – adresy NIGDY nieskanowane' }, j.exclusions),
    rate_pps: I('rate_pps', { type: 'number', min: 1 }), http_rps: I('http_rps', { type: 'number', min: 1 }), concurrency: I('concurrency', { type: 'number', min: 1, max: 32 }),
    chunk_size: I('chunk_size', { type: 'number', min: 0 }), chunk_target_sec: I('chunk_target_sec', { type: 'number', min: 10 }),
    timing: select(['T1', 'T2', 'T3', 'T4'], j.timing), nmap_extra: I('nmap_extra', { placeholder: '--version-light --script http-title,ssl-cert' }),
    window_start: I('window_start', { type: 'time' }), window_end: I('window_end', { type: 'time' }), timezone: I('timezone'),
    interval_minutes: I('interval_minutes', { type: 'number', min: 0 }), inactive_after: I('inactive_after', { type: 'number', min: 1 }),
    reprobe_attempts: I('reprobe_attempts', { type: 'number', min: 0, max: 5 }), reprobe_delay_sec: I('reprobe_delay_sec', { type: 'number', min: 1 }),
  };
  const days = ['Pn', 'Wt', 'Śr', 'Cz', 'Pt', 'So', 'Nd'].map((d, i) => h('input', { type: 'checkbox', checked: (j.window_days || '1111111')[i] === '1', title: d }));
  const always = h('input', { type: 'checkbox', checked: j.window_always });
  const checks = [C('enabled', 'aktywne'), C('service_detection', 'wykrywanie wersji (-sV)'), C('http_fingerprint', 'fingerprinting HTTP/TLS'), C('path_probes', 'pasywne ścieżki (/login, /version…)')];
  const body = h('div', null,
    h('div', { class: 'frow' }, field('Nazwa', f.name), field('Silnik', f.engine)), field('Opis', f.description),
    h('h3', null, 'Zakres i bezpieczeństwo'),
    h('div', { class: 'frow' }, field('Porty', f.ports, 'top:100, top:1000 lub lista 22,80,443,8000-8100'), field('Timing nmap', f.timing, 'T5 zablokowany')),
    field('Wykluczenia', f.exclusions),
    h('div', { class: 'frow' }, field('Limit pakietów/s (całe zadanie)', f.rate_pps, `maks. ${ASI.meta.max_rate} (ASI_MAX_RATE)`), field('Limit żądań HTTP/s', f.http_rps), field('Równoległe podgrupy', f.concurrency)),
    h('div', { class: 'frow' }, field('Rozmiar podgrupy', f.chunk_size, '0 = adaptacyjnie wg zmierzonego tempa'), field('Docelowy czas podgrupy [s]', f.chunk_target_sec)),
    field('Dodatkowe flagi nmap', f.nmap_extra, 'Tylko z listy bezpiecznych: --version-light/-intensity, --max-retries, -Pn, -n, --script (banner, http-title, ssl-cert…)'),
    h('div', null, checks),
    h('h3', null, 'Harmonogram i okno czasowe'),
    h('label', { class: 'check' }, always, 'bez ograniczeń (24/7)'),
    h('div', { style: { margin: '8px 0' } }, days.map((d, i) => h('label', { class: 'check' }, d, ['Pn', 'Wt', 'Śr', 'Cz', 'Pt', 'So', 'Nd'][i]))),
    h('div', { class: 'frow' }, field('Okno od', f.window_start), field('Okno do', f.window_end, 'może przechodzić przez północ'), field('Strefa czasowa', f.timezone), field('Częstotliwość [min]', f.interval_minutes, '0 = tylko ręcznie')),
    h('div', { class: 'notice' }, 'Gdy skan nie zmieści się w oknie, bieżące podgrupy są przerywane, postęp zapisywany (checkpoint), a skan wznawia się automatycznie w kolejnym oknie.'),
    h('h3', null, 'Hosty niestabilne'),
    h('div', { class: 'frow' }, field('Nieaktywny po N skanach', f.inactive_after), field('Ponowne próby (re-probe)', f.reprobe_attempts), field('Odstęp re-probe [s]', f.reprobe_delay_sec)));
  modal(job ? 'Edycja zadania' : 'Nowe zadanie skanowania', body, [{ label: 'Anuluj' }, { label: 'Zapisz', cls: 'primary', run: async () => {
    const out = Object.assign({}, j);
    for (const [k, el] of Object.entries(f)) out[k] = el.type === 'number' ? +el.value : el.value;
    for (const c of body.querySelectorAll('input[type=checkbox][data-k]')) out[c.dataset.k] = c.checked;
    out.window_always = always.checked;
    out.window_days = days.map(d => d.checked ? '1' : '0').join('');
    const r = job ? await PUT('/api/jobs/' + job.id, out) : await POST('/api/jobs', out);
    toast('Zapisano zadanie'); location.hash = '#/jobs/' + r.id; render();
  } }], true);
}

async function pageJob(root, id) {
  const [j, tg, runs, pv] = await Promise.all([GET('/api/jobs/' + id), GET(`/api/jobs/${id}/targets`), GET('/api/runs?job=' + id), GET(`/api/jobs/${id}/preview`)]);
  root.append(pageHead(j.name, h('a', { href: '#/jobs' }, 'Zadania skanowania'),
    can('scans:run') ? h('button', { class: 'primary', onclick: async () => { const r = await act(() => POST(`/api/jobs/${id}/run`, {}), 'Uruchomiono / zakolejkowano'); location.hash = '#/runs/' + r.id; } }, 'Uruchom w oknie') : null,
    can('scans:run') ? h('button', { title: 'Ignoruje okno czasowe', onclick: async () => { const r = await act(() => POST(`/api/jobs/${id}/run`, { force: true }), 'Uruchomiono natychmiast'); location.hash = '#/runs/' + r.id; } }, 'Uruchom teraz') : null,
    can('jobs:update') ? h('button', { onclick: () => jobEditor(j) }, 'Edytuj') : null,
    can('jobs:delete') ? h('button', { class: 'danger', onclick: async () => { if (await confirmBox('Usunąć zadanie (wyniki pozostaną)?')) { await act(() => DEL('/api/jobs/' + id), 'Usunięto'); location.hash = '#/jobs'; } } }, 'Usuń') : null));
  root.append(h('div', { class: 'grid g2' },
    h('div', { class: 'panel' }, h('h2', null, 'Konfiguracja'), h('dl', { class: 'kv' },
      h('dt', null, 'Silnik'), h('dd', null, j.engine), h('dt', null, 'Porty'), h('dd', { class: 'mono' }, j.ports),
      h('dt', null, 'Tempo'), h('dd', null, `${j.rate_pps} pps · ${j.http_rps} HTTP/s · ${j.concurrency} równoległe podgrupy · ${j.timing}`),
      h('dt', null, 'Okno'), h('dd', null, j.window_text, ' ', j.window_open ? h('span', { class: 'chip ok' }, 'otwarte') : h('span', { class: 'chip inactive' }, 'zamknięte')),
      h('dt', null, 'Częstotliwość'), h('dd', null, j.interval_minutes ? 'co ' + dur(j.interval_minutes * 60) : 'tylko ręcznie'),
      h('dt', null, 'Następny skan'), h('dd', null, j.interval_minutes ? fmtT(j.next_run_at) : '—'),
      h('dt', null, 'Polityka hostów'), h('dd', null, `nieaktywny po ${j.inactive_after} skanach, re-probe ${j.reprobe_attempts}× co ${j.reprobe_delay_sec}s`),
      j.exclusions ? [h('dt', null, 'Wykluczenia'), h('dd', { class: 'mono small' }, j.exclusions)] : null)),
    h('div', { class: 'panel' }, h('h2', null, 'Plan skanu (szacunek)'),
      pv.error ? h('div', { class: 'notice warn' }, pv.error) : h('dl', { class: 'kv' },
        h('dt', null, 'Zakres'), h('dd', null, `${fmtN(pv.addresses)} celów – ${pv.summary}`),
        h('dt', null, 'Podgrupa'), h('dd', null, `~${fmtN(pv.chunk_size)} celów (adaptacyjnie)`),
        h('dt', null, 'Szacowany czas'), h('dd', null, dur(pv.estimate_sec), pv.estimate_measured ? ' (na podstawie zmierzonego tempa)' : ' (wstępnie, z limitu pps)'),
        h('dt', null, 'Potrzebne okna'), h('dd', null, `${pv.windows_needed} × (${pv.window})`),
        h('dt', null, 'Następne otwarcie'), h('dd', null, fmtT(pv.next_open))),
      pv.nmap_command && j.engine === 'nmap' ? [h('h3', null, 'Polecenie nmap (na podgrupę)'), h('pre', { class: 'code' }, pv.nmap_command)] : null)));

  // targets
  const tbox = h('div', { class: 'panel flush', style: { marginTop: '14px' } });
  const addTa = h('textarea', { rows: 3, placeholder: 'IP, CIDR (10.0.0.0/16), zakres (10.0.0.1-50), domena – oddzielone nową linią lub przecinkiem' });
  const file = h('input', { type: 'file', accept: '.csv,.json,.txt' });
  tbox.append(h('div', { class: 'ph' }, h('h2', null, `Cele (${tg.length} wpisów, ${fmtN(j.address_count)} adresów)`), h('div', { class: 'sp' }),
    can('data:export') ? h('button', { class: 'sm', onclick: () => download(`/api/jobs/${id}/targets/export?format=csv`) }, 'Eksport CSV') : null,
    can('data:export') ? h('button', { class: 'sm', onclick: () => download(`/api/jobs/${id}/targets/export?format=json`) }, 'Eksport JSON') : null,
    can('jobs:delete') && tg.length ? h('button', { class: 'sm danger', onclick: async () => { if (await confirmBox('Usunąć wszystkie cele?')) { await act(() => DEL(`/api/jobs/${id}/targets`)); render(); } } }, 'Usuń wszystkie') : null));
  if (can('jobs:create')) tbox.append(h('div', { class: 'pb' }, addTa, h('div', { class: 'filters', style: { marginTop: '8px' } },
    h('button', { class: 'primary', onclick: async () => {
      const fd = new FormData(); fd.append('text', addTa.value);
      const r = await act(() => api('POST', `/api/jobs/${id}/targets?format=text`, fd));
      toast(`Dodano ${r.added}; łącznie ${fmtN(r.total_addresses)} adresów` + (r.errors ? `; błędy: ${r.errors.length}` : ''), !!r.errors);
      if (r.errors) modal('Odrzucone wpisy', h('pre', { class: 'code' }, r.errors.join('\n')));
      render();
    } }, 'Dodaj cele'),
    h('span', { class: 'muted small' }, 'lub import pliku CSV/JSON:'), file,
    h('button', { onclick: async () => {
      if (!file.files[0]) return toast('Wybierz plik', true);
      const fd = new FormData(); fd.append('file', file.files[0]);
      const r = await act(() => api('POST', `/api/jobs/${id}/targets`, fd));
      toast(`Zaimportowano ${r.added}; łącznie ${fmtN(r.total_addresses)} adresów`); render();
    } }, 'Importuj'))));
  tbox.append(tg.length ? h('div', { style: { maxHeight: '340px', overflowY: 'auto' } }, table([
    { title: 'Cel', render: t => h('span', { class: 'mono' }, t.value) }, { title: 'Typ', render: t => t.kind }, { title: 'Adresy', cls: 'num', render: t => fmtN(t.addr_count) },
    { title: 'Tagi', render: t => tags(t.tags) }, { title: 'Notatka', render: t => h('span', { class: 'small' }, t.note) }, { title: 'Źródło', render: t => h('span', { class: 'small muted' }, t.source) },
    { title: '', render: t => h('span', null,
      can('jobs:update') ? h('button', { class: 'sm ghost', onclick: () => targetEdit(id, t) }, 'edytuj') : null,
      can('jobs:delete') ? h('button', { class: 'sm ghost', onclick: async () => { await act(() => DEL(`/api/jobs/${id}/targets/${t.id}`)); render(); } }, 'Usuń') : null) }], tg)) : h('div', { class: 'empty' }, 'Brak celów'));
  root.append(tbox);
  root.append(h('div', { class: 'panel flush', style: { marginTop: '14px' } }, h('div', { class: 'ph' }, h('h2', null, 'Przebiegi')), runsTable(runs)));
}
function targetEdit(jobId, t) {
  const tg = h('input', { value: (t.tags || []).join(', ') }), note = h('textarea', { rows: 3 }, t.note || '');
  modal('Cel ' + t.value, h('div', null, field('Tagi', tg), field('Notatka (szyfrowana)', note)), [{ label: 'Anuluj' }, { label: 'Zapisz', cls: 'primary', run: async () => {
    await PATCH(`/api/jobs/${jobId}/targets/${t.id}`, { tags: tg.value.split(',').map(x => x.trim()).filter(Boolean), note: note.value }); toast('Zapisano'); render();
  } }]);
}
function runsTable(runs) {
  if (!runs.length) return h('div', { class: 'empty' }, 'Brak przebiegów');
  return table([
    { title: '#', render: r => h('a', { href: '#/runs/' + r.id }, '#' + r.id) }, { title: 'Zadanie', render: r => r.job_name || 'import' },
    { title: 'Status', render: r => h('div', null, statusChip(r.status), r.status_reason ? h('div', { class: 'sub' }, PL.reason[r.status_reason] || r.status_reason) : null) },
    { title: 'Postęp', render: r => h('div', { style: { minWidth: '120px' } }, h('div', { class: 'progress' }, h('i', { style: { width: (r.progress * 100).toFixed(0) + '%' } })), h('div', { class: 'sub' }, `${fmtN(r.done_targets)}/${fmtN(r.total_targets)}`)) },
    { title: 'Wyniki', render: r => h('span', { class: 'small' }, `${fmtN(r.hosts_up)} hostów · ${fmtN(r.open_ports)} usług`) },
    { title: 'Zmiany', render: r => h('span', { class: 'small nowrap' }, h('span', { class: 'k-new' }, '+' + r.changes_new), ' ', h('span', { class: 'k-gone' }, '−' + r.changes_gone), ' ', h('span', { class: 'k-chg' }, '~' + r.changes_changed)) },
    { title: 'Czas skanu', render: r => h('span', { class: 'small' }, dur(r.active_ms / 1000), r.windows_used > 1 ? h('div', { class: 'sub' }, `${r.windows_used} okna`) : null) },
    { title: 'Start', cls: 'nowrap', render: r => h('span', { class: 'small' }, fmtT(r.started_at || r.created_at)) },
  ], runs, r => location.hash = '#/runs/' + r.id);
}

async function pageRuns(root) {
  const runs = await GET('/api/runs?limit=200');
  root.append(pageHead('Przebiegi skanów', 'Historia wykonania, czasy trwania i wykorzystanie okien'));
  root.append(h('div', { class: 'panel flush' }, runsTable(runs)));
}

async function pageRun(root, id) {
  const d = await GET('/api/runs/' + id);
  const r = d.run, cs = d.chunk_stats;
  const live = ['running', 'queued', 'paused'].includes(r.status);
  root.append(pageHead(`Przebieg #${r.id}`, h('span', null, h('a', { href: '#/runs' }, 'Przebiegi'), ' / ', r.job_id ? h('a', { href: '#/jobs/' + r.job_id }, r.job_name) : 'import'),
    statusChip(r.status),
    can('scans:run') && r.status === 'running' ? h('button', { onclick: async () => { await act(() => POST(`/api/runs/${id}/pause`), 'Wstrzymano (checkpoint)'); render(); } }, '❚❚ Wstrzymaj') : null,
    can('scans:run') && ['paused', 'queued'].includes(r.status) ? h('button', { onclick: async () => { await act(() => POST(`/api/runs/${id}/resume`), 'Wznowiono / czeka na okno'); render(); } }, '▶ Wznów') : null,
    can('scans:run') && ['paused', 'queued'].includes(r.status) ? h('button', { onclick: async () => { await act(() => POST(`/api/runs/${id}/force-resume`), 'Wznowiono poza oknem'); render(); } }, '▶ Wznów teraz') : null,
    can('scans:run') && live ? h('button', { class: 'danger', onclick: async () => { if (await confirmBox('Anulować przebieg?', 'Anuluj przebieg')) { await act(() => POST(`/api/runs/${id}/cancel`)); render(); } } }, 'Anuluj') : null,
    can('assets:read') && r.status === 'completed' ? h('a', { class: 'btn', href: `#/changes?run=${id}` }, 'Zmiany w przebiegu →') : null));
  if (r.status_reason) root.append(h('div', { class: 'notice' + (r.status === 'paused' ? ' warn' : '') }, PL.reason[r.status_reason] || r.status_reason));
  root.append(h('div', { class: 'kpis' },
    h('div', { class: 'kpi' }, h('div', { class: 'v' }, (r.progress * 100).toFixed(1) + '%'), h('div', { class: 'l' }, `${fmtN(r.done_targets)} / ${fmtN(r.total_targets)} celów`)),
    h('div', { class: 'kpi' }, h('div', { class: 'v' }, dur(r.active_ms / 1000)), h('div', { class: 'l' }, 'czas aktywnego skanowania'), h('div', { class: 's' }, `${r.windows_used} okno(a) czasowe`)),
    h('div', { class: 'kpi' }, h('div', { class: 'v' }, r.throughput_hps ? r.throughput_hps.toFixed(1) : '—'), h('div', { class: 'l' }, 'celów / s'), h('div', { class: 's' }, r.eta_sec ? 'ETA ' + dur(r.eta_sec) : '')),
    h('div', { class: 'kpi' }, h('div', { class: 'v' }, fmtN(r.hosts_up)), h('div', { class: 'l' }, 'hostów aktywnych')),
    h('div', { class: 'kpi' }, h('div', { class: 'v' }, fmtN(r.open_ports)), h('div', { class: 'l' }, 'otwartych usług')),
    h('div', { class: 'kpi' }, h('div', { class: 'v' }, `${cs.done}/${cs.done + cs.pending + cs.running + cs.failed}`), h('div', { class: 's' }, `w toku ${cs.running} · czeka ${cs.pending} · błędy ${cs.failed}`), h('div', { class: 'l' }, 'podgrupy (chunki)')),
    h('div', { class: 'kpi' }, h('div', { class: 'v' }, h('span', { class: 'k-new' }, '+' + r.changes_new), ' ', h('span', { class: 'k-gone' }, '−' + r.changes_gone), ' ', h('span', { class: 'k-chg' }, '~' + r.changes_changed)), h('div', { class: 'l' }, 'zmiany'))));
  const chart = chunkChart(d.chunks);
  root.append(h('div', { class: 'grid g2' },
    h('div', { class: 'panel' }, h('h2', null, 'Adaptacyjny podział na podgrupy'), chart || h('div', { class: 'empty' }, 'Za mało danych'),
      h('p', { class: 'small muted' }, `Rozmiar podgrupy = docelowy czas / zmierzony czas na cel (EWMA: ${r.sec_per_host ? r.sec_per_host.toFixed(3) + ' s/cel' : '—'}), ograniczony pozostałym czasem okna.`)),
    h('div', { class: 'panel' }, h('h2', null, 'Parametry przebiegu (zamrożone)'), h('dl', { class: 'kv' },
      h('dt', null, 'Silnik'), h('dd', null, d.spec.engine), h('dt', null, 'Porty'), h('dd', { class: 'mono' }, d.spec.ports || '—'),
      h('dt', null, 'Tempo'), h('dd', null, `${d.spec.rate_pps || '—'} pps, ${d.spec.concurrency || 1} podgrup równolegle`),
      h('dt', null, 'Cele'), h('dd', { class: 'mono small' }, (d.spec.targets || []).slice(0, 8).join(', ') + ((d.spec.targets || []).length > 8 ? ' …' : '')),
      h('dt', null, 'Utworzony'), h('dd', null, `${fmtT(r.created_at)} przez ${r.created_by} (${r.trigger})`),
      h('dt', null, 'Zakończony'), h('dd', null, fmtT(r.finished_at))))));
  root.append(h('div', { class: 'panel flush', style: { marginTop: '14px' } }, h('div', { class: 'ph' }, h('h2', null, `Podgrupy (${d.chunks.length})`)),
    h('div', { style: { maxHeight: '420px', overflowY: 'auto' } }, table([
      { title: '#', render: c => c.seq }, { title: 'Typ', render: c => c.kind === 'reprobe' ? h('span', { class: 'chip suspect' }, 're-probe') : 'główny' },
      { title: 'Zakres', render: c => h('span', { class: 'mono small' }, c.kind === 'reprobe' ? (c.targets || []).join(', ') : `[${c.start}, ${c.end})`) },
      { title: 'Celów', cls: 'num', render: c => c.kind === 'reprobe' ? (c.targets || []).length : c.end - c.start },
      { title: 'Status', render: c => h('span', null, statusChip(c.status === 'done' ? 'completed' : c.status === 'pending' ? 'queued' : c.status), c.attempts > 1 ? ` (próba ${c.attempts})` : '') },
      { title: 'Czas', cls: 'num', render: c => c.duration_ms ? (c.duration_ms / 1000).toFixed(1) + ' s' : '—' },
      { title: 'Hosty / usługi', cls: 'num', render: c => `${c.hosts_up} / ${c.open_ports}` },
      { title: 'Błąd', render: c => h('span', { class: 'small k-gone' }, c.error) }], d.chunks))));
  if (live) ASI.timers.push(setTimeout(() => { if (location.hash === '#/runs/' + id) render(true); }, 2500));
}

/* ---------------- Signatures ---------------- */
async function pageSignatures(root) {
  const { items, matcher_types } = await GET('/api/signatures');
  const p = routeParams();
  const q = (p.q || '').toLowerCase();
  const list = items.filter(sg => !q || sg.name.toLowerCase().includes(q) || sg.category.includes(q));
  root.append(pageHead('Sygnatury detekcyjne', 'Bezpieczne, pasywne cechy: nagłówki, ciasteczka, favicon, fragmenty HTML, ścieżki GET – bez prób logowania i eksploitacji',
    can('signatures:create') ? h('button', { class: 'primary', onclick: () => sigEditor(null, matcher_types) }, 'Nowa sygnatura') : null,
    can('data:export') ? h('button', { onclick: () => download('/api/signatures/export') }, '⇩ Eksport własnych') : null,
    can('signatures:create') ? h('button', { onclick: () => { const fi = h('input', { type: 'file', accept: '.json' }); modal('Import sygnatur (JSON)', fi, [{ label: 'Anuluj' }, { label: 'Importuj', cls: 'primary', run: async () => {
      const fd = new FormData(); fd.append('file', fi.files[0]); const r = await api('POST', '/api/signatures/import', fd); toast(`Dodano ${r.added}` + (r.errors.length ? `, błędy: ${r.errors.join('; ')}` : ''), r.errors.length > 0); render();
    } }]); } }, '⇧ Import') : null));
  root.append(h('div', { class: 'filters' }, h('input', { type: 'search', placeholder: 'Szukaj sygnatury…', value: p.q || '', onkeydown: e => { if (e.key === 'Enter') setParams('#/signatures', { q: e.target.value }); } }),
    h('span', { class: 'muted small' }, `${items.length} sygnatur (${items.filter(x => !x.builtin).length} własnych, ${items.filter(x => x.enabled).length} aktywnych)`)));
  root.append(h('div', { class: 'panel flush' }, table([
    { title: 'Aktywna', render: sg => h('input', { type: 'checkbox', checked: sg.enabled, disabled: !can('signatures:update'), onchange: async e => {
      await act(() => PUT('/api/signatures/' + sg.id, Object.assign({}, sg, { enabled: e.target.checked })), e.target.checked ? 'Włączono' : 'Wyłączono'); } }) },
    { title: 'Nazwa', render: sg => h('div', null, h('b', null, sg.name), sg.builtin ? h('span', { class: 'chip outline', style: { marginLeft: '6px' } }, 'wbudowana') : h('span', { class: 'chip manual', style: { marginLeft: '6px' } }, 'własna'), h('div', { class: 'sub' }, sg.description)) },
    { title: 'Kategoria', render: sg => PL.cat[sg.category] || sg.category },
    { title: 'Dopasowania', render: sg => h('div', { class: 'small' }, sg.definition.matchers.map(m => h('div', null, `${m.type}${m.name ? ' ' + m.name : ''}${m.path ? ' ' + m.path : ''}${m.pattern ? ' /' + m.pattern + '/' : ''}${m.value ? ' = ' + m.value : ''} · w=${m.weight}`))) },
    { title: 'Ciekawość', cls: 'num', render: sg => sg.definition.curiosity ? '+' + sg.definition.curiosity : '' },
    { title: '', render: sg => h('span', { class: 'nowrap' }, h('button', { class: 'sm ghost', onclick: () => sigEditor(sg, matcher_types) }, sg.builtin ? 'podgląd / test' : 'edytuj'),
      !sg.builtin && can('signatures:delete') ? h('button', { class: 'sm ghost', onclick: async () => { if (await confirmBox('Usunąć sygnaturę ' + sg.name + '?')) { await act(() => DEL('/api/signatures/' + sg.id)); render(); } } }, 'Usuń') : null) },
  ], list)));
}

function sigEditor(sg, types) {
  const ex = { name: 'Moja aplikacja', category: 'app', description: '', enabled: true, definition: { condition: 'any', min_confidence: 40, curiosity: 10,
    matchers: [{ type: 'header', name: 'X-App-Name', pattern: 'portal', weight: 0.7 }, { type: 'path', path: '/version', status: [200], pattern: '"version"', weight: 0.5 }, { type: 'favicon', value: '-1234567890', weight: 0.9 }] } };
  const cur = sg || ex;
  const name = h('input', { value: cur.name }), cat = h('input', { value: cur.category }), desc = h('input', { value: cur.description });
  const def = h('textarea', { rows: 14 }, JSON.stringify(cur.definition, null, 2));
  const res = h('div');
  const ro = sg && sg.builtin;
  const build = () => ({ name: name.value, category: cat.value, description: desc.value, enabled: cur.enabled !== false, definition: JSON.parse(def.value) });
  modal(sg ? 'Sygnatura: ' + sg.name : 'Nowa sygnatura', h('div', null,
    ro ? h('div', { class: 'notice' }, 'Sygnatura wbudowana – można ją wyłączyć lub przetestować; aby zmodyfikować, utwórz kopię jako własną.') : null,
    h('div', { class: 'frow' }, field('Nazwa', name), field('Kategoria', cat)), field('Opis', desc),
    field('Definicja (JSON)', def, `Typy: ${types.join(', ')}. Wzorce to wyrażenia regularne (bez rozróżniania wielkości liter); grupa (?P<version>…) wyciąga wersję. Pewność = 1 − Π(1 − waga). Ścieżki tylko w postaci /ścieżka (bez parametrów).`),
    res), [
    { label: 'Zamknij' },
    { label: 'Testuj na zebranych danych', run: async () => {
      clear(res).append(h('div', { class: 'muted' }, 'Testowanie…'));
      const r = await POST('/api/signatures/test', { signature: build(), sample: 1500 });
      clear(res).append(h('h3', null, `Dopasowania: ${r.matches.length} z ${r.tested} usług`), h('div', { class: 'small muted' }, r.note),
        r.matches.length ? table([{ title: 'Usługa', render: m => h('a', { href: '#/services/' + m.service_id }, `${m.address}:${m.port}`) }, { title: 'Tytuł', render: m => m.title },
          { title: 'Pewność', render: m => m.confidence + '%' + (m.version ? ' · v' + m.version : '') }, { title: 'Dowody', render: m => h('span', { class: 'small' }, m.evidence.join('; ')) }], r.matches.slice(0, 50)) : null);
      return true;
    } },
    ro ? { label: 'Zapisz jako własną kopię', cls: 'primary', run: async () => { if (!can('signatures:create')) throw new Error('brak uprawnień'); const b = build(); b.name += ' (kopia)'; await POST('/api/signatures', b); toast('Utworzono kopię'); render(); } }
      : { label: 'Zapisz', cls: 'primary', run: async () => { const b = build(); sg ? await PUT('/api/signatures/' + sg.id, b) : await POST('/api/signatures', b); toast('Zapisano – aktywna od następnego skanu'); render(); } },
  ], true);
}

/* ---------------- Import / Export ---------------- */
async function pageIO(root) {
  root.append(pageHead('Import i eksport', 'CSV, JSON, nmap XML; DefectDojo'));
  const file = h('input', { type: 'file', accept: '.json,.csv,.xml' });
  const out = h('div');
  root.append(h('div', { class: 'grid g2' },
    can('data:import') ? h('div', { class: 'panel' }, h('h2', null, 'Import wyników skanu'),
      h('p', { class: 'small muted' }, 'Obsługiwane: format Sentinelis JSON (asi-results/v1), płaska tablica JSON wierszy, CSV (adres, port, usługa, produkt, wersja, tytuł, tagi, notatka…) oraz XML z nmap (-oX). Import przechodzi przez ten sam potok co skan: sygnatury, scoring, diff i maszyna stanów hostów. Tagi i notatki z pliku trafiają do warstwy analityka.'),
      file, h('div', { style: { marginTop: '10px' } }, h('button', { class: 'primary', onclick: async () => {
        if (!file.files[0]) return toast('Wybierz plik', true);
        const fd = new FormData(); fd.append('file', file.files[0]);
        const r = await act(() => api('POST', '/api/import/results', fd));
        clear(out).append(h('div', { class: 'notice' }, `Zaimportowano ${r.hosts} hostów (${r.format}) jako przebieg `, h('a', { href: '#/runs/' + r.run.id }, '#' + r.run.id),
          ` – nowe: ${r.run.changes_new}, zmienione: ${r.run.changes_changed}.`));
      } }, '⇧ Importuj')), out) : h('div', { class: 'panel' }, h('div', { class: 'notice' }, 'Import wymaga uprawnienia data:import.')),
    h('div', { class: 'panel' }, h('h2', null, 'Eksport'),
      can('data:export') ? h('div', null,
        h('p', { class: 'small muted' }, 'Eksport zawiera widok efektywny (dane skanu + korekty analityka). Dane są odszyfrowywane wyłącznie dla uprawnionego użytkownika; operacja trafia do audytu.'),
        h('div', { class: 'filters' }, h('button', { onclick: () => download('/api/export/results?format=json&status=all') }, '⇩ Wyniki JSON'),
          h('button', { onclick: () => download('/api/export/results?format=json&status=all&detail=1') }, '⇩ JSON + nagłówki/TLS'),
          h('button', { onclick: () => download('/api/export/results?format=csv&status=all') }, '⇩ Wyniki CSV')),
        h('div', { class: 'filters' }, h('button', { onclick: () => download('/api/export/changes?format=csv') }, '⇩ Zmiany CSV'), h('button', { onclick: () => download('/api/export/changes?format=json') }, '⇩ Zmiany JSON')),
        h('h3', null, 'Przykładowe formaty'),
        h('pre', { class: 'code' }, 'targets.csv\nvalue,tags,note\n10.20.0.0/16,kampus;siec-glowna,Sieć główna\nstaging.example.edu.pl,staging,\n\nresults.csv\naddress,hostname,port,proto,name,product,version,title,tags,note\n10.0.0.5,www.example.edu.pl,443,tcp,https,nginx,1.24.0,Strona główna,www,Serwis główny')) : h('div', { class: 'notice' }, 'Brak uprawnienia data:export.'))));
}

/* ---------------- DefectDojo dialog ---------------- */
function dojoDialog(serviceIds, changeIds) {
  const info = h('input', { type: 'checkbox', checked: true });
  modal('Eksport do DefectDojo', h('div', null,
    h('p', null, `Wybrano: ${serviceIds.length} usług, ${changeIds.length} zmian. Każda obserwacja trafi jako finding (Generic Findings Import) z endpointem i plikami evidence (nagłówki HTTP, certyfikat TLS, dowody detekcji).`),
    h('label', { class: 'check' }, info, 'jako finding informacyjny (Severity: Info)'),
    h('p', { class: 'small muted' }, 'Bez zaznaczenia severity wynika z priorytetu Sentinelis (krytyczny→High, wysoki→Medium, średni→Low).')), [
    { label: 'Anuluj' },
    { label: '⇩ Pobierz JSON (import ręczny)', run: () => downloadPost('/api/dojo/export', { service_ids: serviceIds, change_ids: changeIds, informational: info.checked, dry_run: true }, 'asi-defectdojo-generic.json') },
    { label: 'Wyślij do DefectDojo', cls: 'primary', run: async () => {
      const r = await POST('/api/dojo/export', { service_ids: serviceIds, change_ids: changeIds, informational: info.checked });
      toast(`Wysłano ${r.exported} obserwacji (test #${r.test_id})`);
    } }]);
}

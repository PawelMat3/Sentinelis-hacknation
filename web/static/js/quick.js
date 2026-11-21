/* ASI: "Szybki skan" – one target in, the whole pipeline out (KISS) */
'use strict';

const QUICK_STEPS = [
  ['1', 'Subdomeny', 'Pasywnie z logów Certificate Transparency (crt.sh) + DNS. Do celu nie jest wysyłany żaden pakiet.'],
  ['2', 'Porty i usługi', 'nmap: wykrywa działające hosty, otwarte porty i wersje usług (z limitem tempa).'],
  ['3', 'Aplikacje WWW', 'Strona, nagłówki, ciasteczka, certyfikat TLS, CMS i jego wersja, wtyczki WordPress, panele admina, staging.'],
  ['4', 'Znane podatności', 'Dla każdej wykrytej wersji: lista CVE z bazy NIST NVD. Bez exploitów i prób logowania.'],
];

async function pageQuick(root) {
  const data = await GET('/api/quickscan');
  root.append(pageHead('Szybki skan', 'Wpisz cel i kliknij „Skanuj” – reszta dzieje się automatycznie'));
  root.append(h('div', { class: 'cards', style: { marginBottom: '14px' } }, QUICK_STEPS.map(([n, t, d]) =>
    h('div', { class: 'card' }, h('div', { class: 'hd' }, h('span', { class: 'chip running' }, n), h('b', null, t)), h('div', { class: 'small muted' }, d)))));

  if (can('scans:run') && can('jobs:create')) {
    const target = h('input', { placeholder: 'np. example.edu.pl  ·  10.0.0.5  ·  10.0.0.0/24', style: { fontSize: '16px', padding: '10px 12px' } });
    const subs = h('input', { type: 'checkbox', checked: true });
    const vul = h('input', { type: 'checkbox', checked: data.vuln_lookup, disabled: !data.vuln_lookup });
    const auth = h('input', { type: 'checkbox' });
    let profile = 'auto';
    const profSeg = h('div');
    const profHint = { auto: 'Do 16 adresów (np. localhost, pojedynczy serwer): wszystkie 65535 portów. Większe zakresy: profil Standard.',
      fast: '100 najpopularniejszych portów – szybki przegląd, pomija usługi na niestandardowych portach.',
      standard: '~1500 portów: popularne + typowe usługi dev/admin/baz/kolejek (3000–3010, 5672, 8000–8100, 9000–9100, 15672…).',
      full: 'Wszystkie 65535 portów (maks. 256 adresów).' };
    const drawSeg = () => clear(profSeg).append(seg([['auto', 'Automatyczny'], ['fast', 'Szybki – 100'], ['standard', 'Standard – ~1500'], ['full', 'Pełny – 65535']], profile, v => { profile = v; drawSeg(); }),
      h('div', { class: 'small muted', style: { marginTop: '6px' } }, profHint[profile]));
    drawSeg();
    const status = h('div');
    const btn = h('button', { class: 'primary', style: { fontSize: '15px', padding: '9px 22px' } }, '▶ Skanuj');
    btn.addEventListener('click', async () => {
      if (!target.value.trim()) return toast('Wpisz cel', true);
      if (!auth.checked) return toast('Zaznacz potwierdzenie zgody właściciela celu', true);
      btn.disabled = true;
      clear(status).append(h('div', { class: 'notice' }, subs.checked ? 'Szukam subdomen w logach certyfikatów (może potrwać do ~30 s)…' : 'Uruchamiam skan…'));
      try {
        const r = await POST('/api/quickscan', { target: target.value, subdomains: subs.checked, vulns: vul.checked, profile, authorized: true });
        if (r.warning) toast(r.warning, true);
        location.hash = '#/quick/' + r.run.id;
      } catch (e) { clear(status).append(h('div', { class: 'notice warn' }, e.message)); btn.disabled = false; }
    });
    target.addEventListener('keydown', e => { if (e.key === 'Enter') btn.click(); });
    root.append(h('div', { class: 'panel', style: { marginBottom: '14px' } },
      field('Cel (domena, adres IP, zakres lub CIDR – maks. 4096 adresów)', target),
      h('div', { class: 'filters' }, h('label', { class: 'check' }, subs, 'szukaj subdomen (dla domeny)'),
        h('label', { class: 'check', title: data.vuln_lookup ? '' : 'Wyłączone w konfiguracji (ASI_NVD_DISABLE)' }, vul, 'sprawdź znane podatności (CVE)')),
      h('div', { style: { margin: '6px 0 12px' } }, profSeg),
      h('label', { class: 'check', style: { marginBottom: '12px' } }, auth, 'Potwierdzam, że mam zgodę właściciela na skanowanie tego celu (skan jest zapisywany w audycie).'),
      h('div', null, btn), status));
  } else {
    root.append(h('div', { class: 'notice' }, 'Twoja rola pozwala przeglądać wyniki szybkich skanów, ale nie uruchamiać nowych.'));
  }

  root.append(h('div', { class: 'panel flush' }, h('div', { class: 'ph' }, h('h2', null, 'Poprzednie szybkie skany')),
    data.items.length ? table([
      { title: 'Cel', render: x => h('b', null, x.job.name.replace('Szybki skan: ', '')) },
      { title: 'Celów', cls: 'num', render: x => fmtN(x.job.address_count) },
      { title: 'Status', render: x => x.run ? statusChip(x.run.status) : '—' },
      { title: 'Wyniki', render: x => x.run ? h('span', { class: 'small' }, `${fmtN(x.run.hosts_up)} hostów · ${fmtN(x.run.open_ports)} usług`) : '' },
      { title: 'Start', render: x => x.run ? fmtT(x.run.created_at) : '' },
    ], data.items, x => { if (x.run) location.hash = '#/quick/' + x.run.id; }) : h('div', { class: 'empty' }, 'Jeszcze nic nie skanowano.')));
}

function stepState(i, r, vulnOn) {
  const mainDone = r.phase !== 'main' || r.status === 'completed';
  if (i === 0) return 'done';
  if (i === 1 || i === 2) return mainDone ? 'done' : (r.status === 'running' ? 'active' : 'wait');
  if (!vulnOn) return 'skip';
  if (r.status === 'completed') return 'done';
  return r.phase === 'vulns' ? 'active' : 'wait';
}

async function pageQuickResult(root, runId) {
  const d = await GET('/api/runs/' + runId);
  const r = d.run;
  const [svc, vul, tg] = await Promise.all([GET(`/api/services?run=${runId}&status=all&limit=1000&sort=address`), GET('/api/vulns?run=' + runId),
    r.job_id ? GET(`/api/jobs/${r.job_id}/targets`) : Promise.resolve([])]);
  const vulnOn = d.spec.vuln_lookup;
  const live = ['running', 'queued'].includes(r.status);
  root.append(pageHead(r.job_name.replace('Szybki skan: ', ''), h('span', null, h('a', { href: '#/quick' }, 'Szybki skan'), ' / przebieg ', h('a', { href: '#/runs/' + r.id }, '#' + r.id)),
    statusChip(r.status), live && can('scans:run') ? h('button', { class: 'danger', onclick: async () => { await act(() => POST(`/api/runs/${r.id}/cancel`)); render(); } }, 'Zatrzymaj') : null));

  const subCount = tg.filter(t => (t.tags || []).includes('subdomena')).length;
  const stepInfo = [
    subCount ? `${subCount} subdomen` : 'tylko podany cel',
    r.status === 'completed' || r.phase !== 'main' ? `${fmtN(r.hosts_up)} hostów, ${fmtN(r.open_ports)} portów` : `${(r.progress * 100).toFixed(0)}% · ${fmtN(r.done_targets)}/${fmtN(r.total_targets)} celów`,
    `${svc.items.filter(s => s.is_web).length} aplikacji WWW`,
    vulnOn ? (vul.length ? `${vul.length} CVE` : (r.status === 'completed' ? 'brak znanych CVE' : '…')) : 'wyłączone',
  ];
  root.append(h('div', { class: 'cards', style: { marginBottom: '14px' } }, QUICK_STEPS.map(([n, t], i) => {
    const st = stepState(i, r, vulnOn);
    const chip = { done: h('span', { class: 'chip ok' }, '✓'), active: h('span', { class: 'chip running' }, '… trwa'), wait: h('span', { class: 'chip outline' }, 'czeka'), skip: h('span', { class: 'chip inactive' }, 'pominięto') }[st];
    return h('div', { class: 'card' }, h('div', { class: 'hd' }, h('span', { class: 'chip outline' }, n), h('b', null, t), chip), h('div', { class: 'small muted' }, stepInfo[i]),
      i === 1 && st === 'active' ? h('div', { class: 'progress', style: { marginTop: '6px' } }, h('i', { style: { width: (r.progress * 100) + '%' } })) : null);
  })));

  const crit = vul.filter(v => v.cvss >= 9).length, high = vul.filter(v => v.cvss >= 7 && v.cvss < 9).length;
  const techs = new Set(); svc.items.forEach(s => (s.tech || []).forEach(t => { if (t.version) techs.add(t.name + ' ' + t.version); }));
  root.append(h('div', { class: 'kpis' },
    h('div', { class: 'kpi' }, h('div', { class: 'v' }, fmtN(new Set(svc.items.map(s => s.host_id)).size)), h('div', { class: 'l' }, 'hosty')),
    h('div', { class: 'kpi' }, h('div', { class: 'v' }, fmtN(svc.items.length)), h('div', { class: 'l' }, 'otwarte porty / usługi')),
    h('div', { class: 'kpi' }, h('div', { class: 'v' }, fmtN(techs.size)), h('div', { class: 'l' }, 'technologie z wersją')),
    h('div', { class: 'kpi crit' }, h('div', { class: 'v' }, fmtN(crit)), h('div', { class: 'l' }, 'CVE krytyczne (CVSS ≥ 9)')),
    h('div', { class: 'kpi high' }, h('div', { class: 'v' }, fmtN(high)), h('div', { class: 'l' }, 'CVE wysokie (7–8.9)')),
    h('div', { class: 'kpi' }, h('div', { class: 'v' }, dur(r.active_ms / 1000)), h('div', { class: 'l' }, 'czas skanu'))));

  const cveByService = {};
  vul.forEach(v => { (cveByService[v.service_id] = cveByService[v.service_id] || []).push(v); });
  root.append(h('div', { class: 'panel flush', style: { marginBottom: '14px' } }, h('div', { class: 'ph' }, h('h2', null, 'Co znaleziono'), h('div', { class: 'sp' }),
    h('span', { class: 'small muted' }, 'kliknij wiersz, aby zobaczyć nagłówki, certyfikat, dowody wykrycia')),
    svc.items.length ? table([
      { title: 'Adres', render: s => h('div', null, h('span', { class: 'addr' }, `${s.address}:${s.port}`), s.hostname ? h('div', { class: 'sub' }, s.hostname) : null) },
      { title: 'Usługa', render: s => h('div', null, s.name, ' ', h('span', { class: 'muted' }, [s.product, s.version].filter(Boolean).join(' '))) },
      { title: 'Strona WWW', render: s => s.is_web ? h('div', { class: 'trunc' }, h('span', { class: 'muted' }, s.http_status + ' '), s.title || h('span', { class: 'faint' }, '(brak tytułu)')) : h('span', { class: 'faint' }, '—') },
      { title: 'Technologie', render: s => h('div', null, techList(s.tech, 6)) },
      { title: 'CVE', render: s => { const c = cveByService[s.id] || []; if (!c.length) return h('span', { class: 'faint' }, '—'); const m = Math.max(...c.map(x => x.cvss));
        return h('span', { class: 'chip ' + (m >= 9 ? 'crit' : m >= 7 ? 'high' : m >= 4 ? 'medium' : 'low') }, `${c.length} · max ${m.toFixed(1)}`); } },
      { title: 'Priorytet', render: s => prioChip(s.priority) },
    ], svc.items, s => location.hash = '#/services/' + s.id) : h('div', { class: 'empty' }, live ? 'Skanowanie trwa – wyniki pojawią się tutaj…' : 'Nie znaleziono otwartych usług.')));

  root.append(h('div', { class: 'panel flush' }, h('div', { class: 'ph' }, h('h2', null, `Znane podatności (${vul.length})`)),
    h('div', { class: 'pb' }, h('div', { class: 'notice' }, 'Dopasowanie na podstawie wykrytej wersji (NIST NVD). Dystrybucje Linuksa często łatają usługi bez zmiany numeru wersji (backport), więc wyniki należy traktować jako „do weryfikacji”. Skaner nie próbuje wykorzystywać podatności.')),
    vul.length ? vulnTable(vul, true) : h('div', { class: 'empty' }, !vulnOn ? 'Sprawdzanie podatności było wyłączone.' : r.status === 'completed' ? 'Nie znaleziono znanych CVE dla wykrytych wersji.' : 'Sprawdzanie podatności nastąpi po zakończeniu skanu portów…')));

  if (live) ASI.timers.push(setTimeout(() => { if (location.hash === '#/quick/' + runId) render(true); }, 3000));
}

function vulnTable(list, withWhere) {
  return table([
    { title: 'CVE', render: v => h('a', { href: 'https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(v.cve), target: '_blank', rel: 'noopener noreferrer' }, v.cve) },
    { title: 'CVSS', render: v => h('span', { class: 'chip ' + (v.cvss >= 9 ? 'crit' : v.cvss >= 7 ? 'high' : v.cvss >= 4 ? 'medium' : 'low') }, v.cvss ? v.cvss.toFixed(1) : '?') },
    { title: 'Komponent', render: v => h('span', { class: 'nowrap' }, `${v.product} ${v.version}`) },
    withWhere ? { title: 'Gdzie', render: v => h('a', { class: 'addr', href: '#/services/' + v.service_id }, `${v.address}:${v.port}`) } : null,
    { title: 'Opis', render: v => h('div', { class: 'small', style: { maxWidth: '520px' } }, v.summary) },
    { title: 'Opublikowano', cls: 'nowrap', render: v => h('span', { class: 'small' }, v.published) },
  ].filter(Boolean), list.slice(0, 500));
}

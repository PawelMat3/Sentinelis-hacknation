/* ASI: administration pages, login, shell and router */
'use strict';

async function pageUsers(root) {
  const [users, roles] = await Promise.all([GET('/api/users'), GET('/api/roles')]);
  root.append(pageHead('Użytkownicy', 'Administracja', h('button', { class: 'primary', onclick: () => userForm(null, roles) }, 'Nowy użytkownik')));
  root.append(h('div', { class: 'panel flush' }, table([
    { title: 'Login', render: u => h('b', null, u.username) }, { title: 'Nazwa', render: u => u.display_name },
    { title: 'Rola', render: u => h('span', { class: 'chip outline' }, u.role_name) },
    { title: 'Status', render: u => u.disabled ? h('span', { class: 'chip inactive' }, 'zablokowany') : h('span', { class: 'chip ok' }, 'aktywny') },
    { title: 'Ostatnie logowanie', render: u => fmtT(u.last_login) },
    { title: '', render: u => h('span', null, h('button', { class: 'sm ghost', onclick: () => userForm(u, roles) }, 'edytuj'),
      u.id !== ASI.me.id ? h('button', { class: 'sm ghost', onclick: async () => { if (await confirmBox('Usunąć użytkownika ' + u.username + '?')) { await act(() => DEL('/api/users/' + u.id)); render(); } } }, 'Usuń') : null) }], users)));
}
function userForm(u, roles) {
  const login = h('input', { value: u ? u.username : '', disabled: !!u }), name = h('input', { value: u ? u.display_name : '' });
  const pw = h('input', { type: 'password', placeholder: u ? '(bez zmiany)' : 'min. 10 znaków', autocomplete: 'new-password' });
  const role = select(roles.map(r => [r.id, r.name]), u ? u.role_id : roles[roles.length - 1].id);
  const dis = h('input', { type: 'checkbox', checked: u && u.disabled });
  modal(u ? 'Edycja użytkownika' : 'Nowy użytkownik', h('div', null, h('div', { class: 'frow' }, field('Login', login), field('Nazwa wyświetlana', name)),
    h('div', { class: 'frow' }, field('Hasło', pw), field('Rola', role)), u ? h('label', { class: 'check' }, dis, 'konto zablokowane') : null), [
    { label: 'Anuluj' }, { label: 'Zapisz', cls: 'primary', run: async () => {
      if (u) { const b = { display_name: name.value, role_id: +role.value, disabled: dis.checked }; if (pw.value) b.password = pw.value; await PATCH('/api/users/' + u.id, b); }
      else await POST('/api/users', { username: login.value, display_name: name.value, password: pw.value, role_id: +role.value });
      toast('Zapisano'); render();
    } }]);
}

async function pageRoles(root) {
  const [roles, perms] = await Promise.all([GET('/api/roles'), GET('/api/permissions')]);
  root.append(pageHead('Role i uprawnienia (RBAC)', 'Administracja', can('admin:roles') ? h('button', { class: 'primary', onclick: () => roleForm(null, perms) }, 'Nowa rola') : null));
  const groups = [...new Set(perms.map(p => p.group))];
  const has = (r, p) => r.permissions.includes('*') || r.permissions.includes(p);
  const thead = h('tr', null, h('th', null, 'Uprawnienie'), roles.map(r => h('th', { class: 'right', title: r.description },
    h('div', null, r.name), h('div', { class: 'small', style: { textTransform: 'none', fontWeight: 400 } }, `${r.users} użytk.`, r.builtin ? ' · wbudowana' : '',
      !r.builtin && can('admin:roles') ? h('span', null, ' · ', h('a', { onclick: () => roleForm(r, perms) }, 'edytuj'), ' · ', h('a', { onclick: async () => { if (await confirmBox('Usunąć rolę ' + r.name + '?')) { await act(() => DEL('/api/roles/' + r.id)); render(); } } }, 'usuń')) : null))));
  const tb = h('tbody');
  for (const g of groups) {
    tb.append(h('tr', null, h('td', { colspan: roles.length + 1, style: { background: 'var(--panel-2)', fontWeight: 600 } }, g)));
    for (const p of perms.filter(x => x.group === g)) tb.append(h('tr', null, h('td', null, p.label, h('div', { class: 'sub mono' }, p.key)),
      roles.map(r => h('td', { class: 'right' }, has(r, p.key) ? h('span', { class: 'k-new' }, '✓') : h('span', { class: 'faint' }, '·')))));
  }
  root.append(h('div', { class: 'notice' }, 'Cztery role wymagane specyfikacją są wbudowane i niemodyfikowalne. Własne role tworzysz z dowolnego zestawu uprawnień. Uprawnienia egzekwuje serwer dla każdego endpointu API; interfejs jedynie ukrywa niedostępne akcje.'));
  root.append(h('div', { class: 'panel flush' }, h('div', { class: 'tblwrap' }, h('table', { class: 'tbl' }, h('thead', null, thead), tb))));
}
function roleForm(r, perms) {
  const name = h('input', { value: r ? r.name : '' }), desc = h('input', { value: r ? r.description : '' });
  const boxes = perms.map(p => { const c = h('input', { type: 'checkbox', checked: r && r.permissions.includes(p.key) }); c.dataset.p = p.key; return h('label', { class: 'check', style: { display: 'flex', margin: '3px 0' } }, c, `${p.label} `, h('span', { class: 'faint mono small' }, p.key)); });
  modal(r ? 'Edycja roli' : 'Nowa rola', h('div', null, h('div', { class: 'frow' }, field('Nazwa', name), field('Opis', desc)), h('h3', null, 'Uprawnienia'), boxes), [
    { label: 'Anuluj' }, { label: 'Zapisz', cls: 'primary', run: async () => {
      const permissions = boxes.map(b => b.querySelector('input')).filter(c => c.checked).map(c => c.dataset.p);
      r ? await PUT('/api/roles/' + r.id, { name: name.value, description: desc.value, permissions }) : await POST('/api/roles', { name: name.value, description: desc.value, permissions });
      toast('Zapisano'); render();
    } }], true);
}

async function pageSettings(root) {
  const [c, hist] = await Promise.all([GET('/api/settings/dojo'), can('dojo:export') ? GET('/api/dojo/history') : Promise.resolve([])]);
  const I = (k, a = {}) => h('input', Object.assign({ value: c[k] ?? '' }, a));
  const f = { url: I('url', { placeholder: 'https://defectdojo.example.org' }), api_key: I('api_key', { type: 'password', placeholder: 'Token API v2' }), product_name: I('product_name'),
    product_type_name: I('product_type_name', { placeholder: 'Attack Surface' }), engagement_name: I('engagement_name'), engagement_id: I('engagement_id', { type: 'number' }),
    test_title: I('test_title'), minimum_severity: select(['Info', 'Low', 'Medium', 'High', 'Critical'], c.minimum_severity || 'Info') };
  const verify = h('input', { type: 'checkbox', checked: c.verify_tls });
  root.append(pageHead('Ustawienia i integracje', 'Administracja'));
  root.append(h('div', { class: 'grid g2' },
    h('div', { class: 'panel' }, h('h2', null, 'DefectDojo'),
      h('p', { class: 'small muted' }, 'Klucz API jest przechowywany zaszyfrowany (AES-256-GCM) i nigdy nie jest zwracany w całości. Podaj ID engagementu albo nazwy produktu i engagementu (zostaną utworzone automatycznie).'),
      h('div', { class: 'frow' }, field('URL', f.url), field('Klucz API', f.api_key)),
      h('div', { class: 'frow' }, field('Produkt', f.product_name), field('Typ produktu', f.product_type_name)),
      h('div', { class: 'frow' }, field('Engagement', f.engagement_name), field('lub ID engagementu', f.engagement_id)),
      h('div', { class: 'frow' }, field('Tytuł testu', f.test_title), field('Minimalna ważność', f.minimum_severity)),
      h('label', { class: 'check' }, verify, 'weryfikuj certyfikat TLS'),
      h('div', { class: 'filters', style: { marginTop: '12px' } },
        h('button', { class: 'primary', onclick: async () => {
          const b = {}; for (const [k, el] of Object.entries(f)) b[k] = el.type === 'number' ? +el.value : el.value; b.verify_tls = verify.checked;
          await act(() => PUT('/api/settings/dojo', b), 'Zapisano'); } }, 'Zapisz'),
        h('button', { onclick: async () => { const r = await act(() => POST('/api/settings/dojo/test')); toast('Połączenie OK – użytkownik ' + r.user); } }, 'Test połączenia'))),
    h('div', { class: 'panel' }, h('h2', null, 'Historia eksportów do DefectDojo'), hist.length ? table([{ title: 'Czas', render: x => fmtT(x.ts) }, { title: 'Użytkownik', render: x => x.username },
      { title: 'Obserwacje', cls: 'num', render: x => x.items }, { title: 'Test', render: x => x.test_id || '—' }, { title: 'Status', render: x => statusChip(x.status === 'ok' ? 'completed' : 'failed') }], hist) : h('div', { class: 'empty' }, 'Brak eksportów'),
      h('h3', null, 'System'), h('dl', { class: 'kv' }, h('dt', null, 'Wersja'), h('dd', null, ASI.meta.version), h('dt', null, 'nmap'), h('dd', null, ASI.meta.nmap),
        h('dt', null, 'Silniki'), h('dd', null, ASI.meta.engines.join(', ')), h('dt', null, 'Globalny limit'), h('dd', null, `${ASI.meta.max_rate} pps, ${fmtN(ASI.meta.max_targets)} celów/zadanie`),
        h('dt', null, 'Klucz danych'), h('dd', { class: 'mono' }, ASI.meta.key_fingerprint + ' (odcisk, nie klucz)')))));
}

async function pageAudit(root) {
  const rows = await GET('/api/audit?limit=300');
  root.append(pageHead('Dziennik audytu', 'Administracja'));
  root.append(h('div', { class: 'panel flush' }, table([{ title: 'Czas', cls: 'nowrap', render: a => fmtT(a.ts) }, { title: 'Użytkownik', render: a => a.username },
    { title: 'Akcja', render: a => h('span', { class: a.action === 'denied' || a.action === 'login_failed' ? 'k-gone' : '' }, a.action) }, { title: 'Obiekt', render: a => `${a.entity}${a.entity_id ? ' #' + a.entity_id : ''}` },
    { title: 'Szczegóły', render: a => h('span', { class: 'small' }, a.detail) }, { title: 'IP', render: a => h('span', { class: 'mono small' }, a.ip) }], rows)));
}

function passwordForm() {
  const o = h('input', { type: 'password', autocomplete: 'current-password' }), n = h('input', { type: 'password', autocomplete: 'new-password' });
  modal('Zmiana hasła', h('div', null, field('Obecne hasło', o), field('Nowe hasło (min. 10 znaków)', n)), [{ label: 'Anuluj' }, { label: 'Zmień', cls: 'primary', run: async () => {
    await POST('/api/auth/password', { old: o.value, new: n.value }); toast('Hasło zmienione – zaloguj się ponownie'); renderLogin(); } }]);
}

/* ---------------- shell ---------------- */
const logo = () => s('svg', { width: 26, height: 26, viewBox: '0 0 32 32' }, s('rect', { width: 32, height: 32, rx: 7, fill: '#0f1a2b' }),
  s('circle', { cx: 16, cy: 16, r: 10, fill: 'none', stroke: '#14b8a6', 'stroke-width': 2 }), s('circle', { cx: 16, cy: 16, r: 5, fill: 'none', stroke: '#14b8a6', 'stroke-width': 2, opacity: .6 }),
  s('path', { d: 'M16 16 L24 9', stroke: '#5eead4', 'stroke-width': 2.4, 'stroke-linecap': 'round' }), s('circle', { cx: 22, cy: 20, r: 2, fill: '#f97316' }));

function renderLogin(msg) {
  ASI.timers.forEach(clearTimeout); ASI.timers = [];
  const root = clear(document.getElementById('root'));
  const u = h('input', { autocomplete: 'username', autofocus: true }), p = h('input', { type: 'password', autocomplete: 'current-password' });
  const err = h('div', { class: 'notice warn hidden' });
  const submit = async e => {
    e.preventDefault();
    try {
      await api('POST', '/api/auth/login', { username: u.value, password: p.value }, { noAuthRedirect: true });
      await boot();
    } catch (x) { err.textContent = x.message; err.classList.remove('hidden'); }
  };
  root.append(h('div', { class: 'login' }, h('form', { class: 'box', onsubmit: submit },
    h('div', { class: 'brand' }, logo(), h('div', null, 'Sentinelis', h('small', null, 'Attack Surface Intelligence · CBI AGH'))),
    msg ? h('div', { class: 'notice' }, msg) : null, err, field('Użytkownik', u), field('Hasło', p),
    h('button', { class: 'primary', type: 'submit', style: { width: '100%', justifyContent: 'center' } }, 'Zaloguj'))));
}

const NAV = [
  ['Start', null],
  ['#/quick', 'Szybki skan', 'jobs:read'],
  ['Analiza', null],
  ['#/dashboard', 'Pulpit', 'assets:read'], ['#/services', 'Znaleziska', 'assets:read'], ['#/hosts', 'Hosty', 'assets:read'],
  ['#/changes', 'Zmiany i porównania', 'assets:read'], ['#/groups', 'Grupowanie', 'assets:read'],
  ['Skanowanie', null],
  ['#/jobs', 'Zadania i cele', 'jobs:read'], ['#/runs', 'Przebiegi', 'jobs:read'], ['#/signatures', 'Sygnatury', 'signatures:read'], ['#/io', 'Import / eksport', 'data:export'],
  ['Administracja', null],
  ['#/admin/users', 'Użytkownicy', 'admin:users'], ['#/admin/roles', 'Role (RBAC)', 'admin:roles'], ['#/admin/settings', 'Integracje', 'admin:settings'], ['#/admin/audit', 'Audyt', 'admin:audit'],
];

/* Dataset switch: real scans vs. the simulated demo network. */
const SCOPES = [['real', 'Prawdziwe'], ['demo', 'Demo'], ['all', 'Wszystkie']];
function scopeSwitch() {
  const box = h('div', { class: 'scope', role: 'radiogroup', 'aria-label': 'Wyświetlane dane' }, h('div', { class: 'sec' }, 'Wyświetlane dane'));
  const row = h('div', { class: 'seg' });
  for (const [v, label] of SCOPES) {
    row.append(h('button', { class: ASI.scope === v ? 'on' : '', role: 'radio', 'aria-checked': ASI.scope === v ? 'true' : 'false',
      title: v === 'real' ? 'Tylko prawdziwe skany, importy i wpisy ręczne' : v === 'demo' ? 'Tylko symulowana sieć demonstracyjna' : 'Prawdziwe i demonstracyjne razem',
      onclick: () => { if (ASI.scope === v) return; setScope(v); row.querySelectorAll('button').forEach(b => { const on = b.textContent === label; b.classList.toggle('on', on); b.setAttribute('aria-checked', on ? 'true' : 'false'); }); render(); } }, label));
  }
  box.append(row);
  return box;
}

function shell() {
  const root = clear(document.getElementById('root'));
  const nav = h('nav', { class: 'nav' });
  let pendingSec = null;
  for (const [href, label, perm] of NAV) {
    if (!label) { pendingSec = href; continue; }
    if (perm && !can(perm)) continue;
    if (pendingSec) { nav.append(h('div', { class: 'sec' }, pendingSec)); pendingSec = null; }
    nav.append(h('a', { href, 'data-nav': href }, label));
  }
  const theme = () => { const cur = document.documentElement.dataset.theme; const next = cur === 'dark' ? 'light' : 'dark'; document.documentElement.dataset.theme = next; try { localStorage.setItem('asi-theme', next); } catch (e) {} };
  const side = h('aside', { class: 'side' }, h('div', { class: 'brand' }, logo(), h('div', null, 'Sentinelis', h('small', null, 'Attack Surface Intelligence'))), nav,
    ASI.meta.has_demo_data ? scopeSwitch() : null,
    h('div', { class: 'who' }, h('b', null, ASI.me.display_name || ASI.me.username), ASI.me.role_name,
      h('div', { class: 'row' }, h('button', { class: 'sm', onclick: passwordForm }, 'Hasło'), h('button', { class: 'sm', onclick: theme, title: 'Przełącz jasny lub ciemny motyw' }, 'Motyw'),
        h('button', { class: 'sm', onclick: async () => { await api('POST', '/api/auth/logout', {}, { noAuthRedirect: true }).catch(() => {}); renderLogin('Wylogowano.'); } }, 'Wyloguj'))));
  root.append(h('div', { class: 'app' }, side, h('main', { class: 'main', id: 'page' })));
}

const ROUTES = [
  [/^#\/dashboard$/, pageDashboard], [/^#\/quick$/, pageQuick], [/^#\/quick\/(\d+)$/, pageQuickResult], [/^#\/services$/, pageServices], [/^#\/services\/(\d+)$/, pageService], [/^#\/hosts$/, pageHosts], [/^#\/hosts\/(\d+)$/, pageHost],
  [/^#\/changes$/, pageChanges], [/^#\/groups$/, pageGroups], [/^#\/jobs$/, pageJobs], [/^#\/jobs\/(\d+)$/, pageJob], [/^#\/runs$/, pageRuns], [/^#\/runs\/(\d+)$/, pageRun],
  [/^#\/signatures$/, pageSignatures], [/^#\/io$/, pageIO], [/^#\/admin\/users$/, pageUsers], [/^#\/admin\/roles$/, pageRoles], [/^#\/admin\/settings$/, pageSettings], [/^#\/admin\/audit$/, pageAudit],
];

let renderSeq = 0;
async function render(keepScroll) {
  ASI.timers.forEach(clearTimeout); ASI.timers = [];
  if (!ASI.me) return;
  if (!document.getElementById('page')) shell();
  let hash = location.hash || '#/dashboard';
  const path = hash.split('?')[0];
  document.querySelectorAll('[data-nav]').forEach(a => a.classList.toggle('active', path === a.dataset.nav || path.startsWith(a.dataset.nav + '/')));
  const page = document.getElementById('page');
  const y = window.scrollY;
  const seq = ++renderSeq;
  for (const [re, fn] of ROUTES) {
    const m = re.exec(path);
    if (!m) continue;
    const tmp = h('div');
    // show a loading state instead of a blank (or stale) page when data takes a moment
    const slow = keepScroll ? null : setTimeout(() => { if (seq === renderSeq) clear(page).append(h('div', { class: 'loading', role: 'status' }, 'Wczytywanie…')); }, 200);
    try {
      await fn(tmp, m[1]);
    } catch (e) {
      if (e.message === 'Sesja wygasła') return;
      tmp.append(h('div', { class: 'panel' }, h('div', { class: 'notice warn' }, 'Błąd: ' + e.message)));
    }
    clearTimeout(slow);
    if (seq !== renderSeq) return; // a newer navigation already started
    clear(page).append(...tmp.childNodes);
    if (keepScroll) window.scrollTo(0, y); else window.scrollTo(0, 0);
    return;
  }
  location.hash = can('assets:read') ? '#/dashboard' : '#/jobs';
}

async function boot() {
  try {
    const me = await api('GET', '/api/auth/me', undefined, { noAuthRedirect: true });
    ASI.me = me.user; ASI.perms = new Set(me.permissions);
    ASI.meta = await GET('/api/meta');
  } catch (e) { renderLogin(); return; }
  shell();
  render();
}

try { const t = localStorage.getItem('asi-theme'); if (t) document.documentElement.dataset.theme = t; } catch (e) {}
window.addEventListener('hashchange', () => render());
boot();

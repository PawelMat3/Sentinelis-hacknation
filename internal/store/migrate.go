package store

// Schema migrations. Columns suffixed _enc hold AES-256-GCM envelopes
// (crypto.Keyring) - see docs/ARCHITEKTURA.md "Klasyfikacja danych".
//
// Layering principle: tables hosts/services/service_tech/run_* are written
// ONLY by the scan pipeline; annotations is written ONLY by analysts. The API
// merges both into an "effective" view, so a rescan can never overwrite a
// manual correction, tag, note or triage decision.
var migrations = []string{
	// v1
	`
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE roles(
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  permissions TEXT NOT NULL DEFAULT '[]',
  builtin INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL);

CREATE TABLE users(
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  display_name TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL,
  role_id INTEGER NOT NULL REFERENCES roles(id),
  disabled INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  last_login INTEGER NOT NULL DEFAULT 0);

CREATE TABLE sessions(
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  ip TEXT NOT NULL DEFAULT '');

CREATE TABLE settings(key TEXT PRIMARY KEY, value_enc TEXT NOT NULL, updated_at INTEGER NOT NULL);

CREATE TABLE jobs(
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  engine TEXT NOT NULL DEFAULT 'nmap',
  ports TEXT NOT NULL DEFAULT 'top:100',
  exclusions TEXT NOT NULL DEFAULT '',
  rate_pps INTEGER NOT NULL DEFAULT 300,
  http_rps INTEGER NOT NULL DEFAULT 10,
  concurrency INTEGER NOT NULL DEFAULT 4,
  chunk_size INTEGER NOT NULL DEFAULT 0,
  chunk_target_sec INTEGER NOT NULL DEFAULT 60,
  timing TEXT NOT NULL DEFAULT 'T3',
  service_detection INTEGER NOT NULL DEFAULT 1,
  http_fingerprint INTEGER NOT NULL DEFAULT 1,
  path_probes INTEGER NOT NULL DEFAULT 1,
  nmap_extra TEXT NOT NULL DEFAULT '',
  window_always INTEGER NOT NULL DEFAULT 1,
  window_days TEXT NOT NULL DEFAULT '1111111',
  window_start TEXT NOT NULL DEFAULT '22:00',
  window_end TEXT NOT NULL DEFAULT '06:00',
  timezone TEXT NOT NULL DEFAULT 'Europe/Warsaw',
  interval_minutes INTEGER NOT NULL DEFAULT 1440,
  inactive_after INTEGER NOT NULL DEFAULT 3,
  reprobe_attempts INTEGER NOT NULL DEFAULT 2,
  reprobe_delay_sec INTEGER NOT NULL DEFAULT 30,
  next_run_at INTEGER NOT NULL DEFAULT 0,
  last_run_at INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL);

CREATE TABLE targets(
  id INTEGER PRIMARY KEY,
  job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  value TEXT NOT NULL,
  kind TEXT NOT NULL,
  addr_count INTEGER NOT NULL DEFAULT 1,
  tags TEXT NOT NULL DEFAULT '[]',
  note_enc TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT 'manual',
  created_at INTEGER NOT NULL,
  UNIQUE(job_id, value));

CREATE TABLE runs(
  id INTEGER PRIMARY KEY,
  job_id INTEGER REFERENCES jobs(id) ON DELETE SET NULL,
  seq INTEGER NOT NULL DEFAULT 0,
  trigger TEXT NOT NULL,
  status TEXT NOT NULL,
  status_reason TEXT NOT NULL DEFAULT '',
  ignore_window INTEGER NOT NULL DEFAULT 0,
  spec TEXT NOT NULL DEFAULT '{}',
  engine TEXT NOT NULL DEFAULT '',
  total_targets INTEGER NOT NULL DEFAULT 0,
  cursor INTEGER NOT NULL DEFAULT 0,
  done_targets INTEGER NOT NULL DEFAULT 0,
  hosts_up INTEGER NOT NULL DEFAULT 0,
  open_ports INTEGER NOT NULL DEFAULT 0,
  sec_per_host REAL NOT NULL DEFAULT 0,
  active_ms INTEGER NOT NULL DEFAULT 0,
  windows_used INTEGER NOT NULL DEFAULT 0,
  reprobe_round INTEGER NOT NULL DEFAULT 0,
  phase TEXT NOT NULL DEFAULT 'main',
  changes_new INTEGER NOT NULL DEFAULT 0,
  changes_gone INTEGER NOT NULL DEFAULT 0,
  changes_changed INTEGER NOT NULL DEFAULT 0,
  changes_hosts INTEGER NOT NULL DEFAULT 0,
  created_by TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  started_at INTEGER NOT NULL DEFAULT 0,
  last_resumed_at INTEGER NOT NULL DEFAULT 0,
  finished_at INTEGER NOT NULL DEFAULT 0);
CREATE INDEX runs_job ON runs(job_id, id);
CREATE INDEX runs_status ON runs(status);

CREATE TABLE chunks(
  id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  seq INTEGER NOT NULL,
  kind TEXT NOT NULL DEFAULT 'main',
  start_idx INTEGER NOT NULL DEFAULT 0,
  end_idx INTEGER NOT NULL DEFAULT 0,
  targets TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  hosts_up INTEGER NOT NULL DEFAULT 0,
  open_ports INTEGER NOT NULL DEFAULT 0,
  duration_ms INTEGER NOT NULL DEFAULT 0,
  started_at INTEGER NOT NULL DEFAULT 0,
  finished_at INTEGER NOT NULL DEFAULT 0,
  error TEXT NOT NULL DEFAULT '');
CREATE INDEX chunks_run ON chunks(run_id, status);

CREATE TABLE hosts(
  id INTEGER PRIMARY KEY,
  address TEXT NOT NULL UNIQUE,
  hostname TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL DEFAULT 'active',
  origin TEXT NOT NULL DEFAULT 'scan',
  job_id INTEGER,
  os_guess TEXT NOT NULL DEFAULT '',
  first_seen INTEGER NOT NULL DEFAULT 0,
  last_seen INTEGER NOT NULL DEFAULT 0,
  last_probed INTEGER NOT NULL DEFAULT 0,
  misses INTEGER NOT NULL DEFAULT 0,
  probes INTEGER NOT NULL DEFAULT 0,
  ups INTEGER NOT NULL DEFAULT 0,
  history TEXT NOT NULL DEFAULT '',
  hour_up TEXT NOT NULL DEFAULT '[]',
  hour_probe TEXT NOT NULL DEFAULT '[]',
  pattern TEXT NOT NULL DEFAULT '',
  curiosity INTEGER NOT NULL DEFAULT 0,
  last_run_id INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL DEFAULT 0);
CREATE INDEX hosts_hostname ON hosts(hostname);
CREATE INDEX hosts_state ON hosts(state);

CREATE TABLE services(
  id INTEGER PRIMARY KEY,
  host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  port INTEGER NOT NULL,
  proto TEXT NOT NULL DEFAULT 'tcp',
  status TEXT NOT NULL DEFAULT 'open',
  origin TEXT NOT NULL DEFAULT 'scan',
  name TEXT NOT NULL DEFAULT '',
  product TEXT NOT NULL DEFAULT '',
  version TEXT NOT NULL DEFAULT '',
  tunnel TEXT NOT NULL DEFAULT '',
  banner_enc TEXT NOT NULL DEFAULT '',
  is_web INTEGER NOT NULL DEFAULT 0,
  url TEXT NOT NULL DEFAULT '',
  http_status INTEGER NOT NULL DEFAULT 0,
  title TEXT NOT NULL DEFAULT '',
  server TEXT NOT NULL DEFAULT '',
  http_enc TEXT NOT NULL DEFAULT '',
  tls_enc TEXT NOT NULL DEFAULT '',
  snap_enc TEXT NOT NULL DEFAULT '',
  cert_issuer TEXT NOT NULL DEFAULT '',
  cert_subject TEXT NOT NULL DEFAULT '',
  cert_not_after INTEGER NOT NULL DEFAULT 0,
  cert_self_signed INTEGER NOT NULL DEFAULT 0,
  favicon_hash TEXT NOT NULL DEFAULT '',
  categories TEXT NOT NULL DEFAULT '[]',
  curiosity INTEGER NOT NULL DEFAULT 0,
  priority TEXT NOT NULL DEFAULT 'info',
  reasons TEXT NOT NULL DEFAULT '[]',
  digest TEXT NOT NULL DEFAULT '',
  first_seen INTEGER NOT NULL DEFAULT 0,
  last_seen INTEGER NOT NULL DEFAULT 0,
  last_changed INTEGER NOT NULL DEFAULT 0,
  gone_at INTEGER NOT NULL DEFAULT 0,
  last_run_id INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL DEFAULT 0,
  UNIQUE(host_id, port, proto));
CREATE INDEX services_prio ON services(status, curiosity DESC);
CREATE INDEX services_fav ON services(favicon_hash);

CREATE TABLE service_tech(
  service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  version TEXT NOT NULL DEFAULT '',
  confidence INTEGER NOT NULL,
  signature_id INTEGER NOT NULL DEFAULT 0,
  evidence TEXT NOT NULL DEFAULT '[]',
  PRIMARY KEY(service_id, name));
CREATE INDEX service_tech_name ON service_tech(name);

CREATE TABLE run_hosts(
  run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  up INTEGER NOT NULL,
  pending INTEGER NOT NULL DEFAULT 0,
  at INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(run_id, host_id));
CREATE INDEX run_hosts_pending ON run_hosts(run_id, pending);

CREATE TABLE run_services(
  run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  host_id INTEGER NOT NULL,
  digest TEXT NOT NULL,
  snap_enc TEXT NOT NULL DEFAULT '',
  PRIMARY KEY(run_id, service_id));

CREATE TABLE changes(
  id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL DEFAULT 0,
  job_id INTEGER NOT NULL DEFAULT 0,
  host_id INTEGER NOT NULL DEFAULT 0,
  service_id INTEGER NOT NULL DEFAULT 0,
  kind TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'low',
  summary TEXT NOT NULL DEFAULT '',
  detail_enc TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL);
CREATE INDEX changes_run ON changes(run_id);
CREATE INDEX changes_time ON changes(created_at DESC);
CREATE INDEX changes_host ON changes(host_id);

CREATE TABLE annotations(
  entity_type TEXT NOT NULL,
  entity_id INTEGER NOT NULL,
  tags TEXT NOT NULL DEFAULT '[]',
  triage TEXT NOT NULL DEFAULT '',
  owner TEXT NOT NULL DEFAULT '',
  criticality TEXT NOT NULL DEFAULT '',
  priority_override TEXT NOT NULL DEFAULT '',
  note_enc TEXT NOT NULL DEFAULT '',
  overrides_enc TEXT NOT NULL DEFAULT '',
  updated_by TEXT NOT NULL DEFAULT '',
  updated_at INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(entity_type, entity_id));

CREATE TABLE signatures(
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  category TEXT NOT NULL DEFAULT 'custom',
  description TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  builtin INTEGER NOT NULL DEFAULT 0,
  definition TEXT NOT NULL,
  created_by TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL);

CREATE TABLE audit_log(
  id INTEGER PRIMARY KEY,
  ts INTEGER NOT NULL,
  username TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL,
  entity TEXT NOT NULL DEFAULT '',
  entity_id INTEGER NOT NULL DEFAULT 0,
  detail TEXT NOT NULL DEFAULT '',
  ip TEXT NOT NULL DEFAULT '');
CREATE INDEX audit_ts ON audit_log(ts DESC);

CREATE TABLE dojo_exports(
  id INTEGER PRIMARY KEY,
  ts INTEGER NOT NULL,
  username TEXT NOT NULL,
  items INTEGER NOT NULL,
  test_id INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL,
  detail_enc TEXT NOT NULL DEFAULT '');
`,
	// v2: quick scans + known vulnerabilities (CVE) matched by detected versions
	`
ALTER TABLE jobs ADD COLUMN quick INTEGER NOT NULL DEFAULT 0;
ALTER TABLE jobs ADD COLUMN vuln_lookup INTEGER NOT NULL DEFAULT 0;
CREATE TABLE service_vulns(
  service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  cve TEXT NOT NULL,
  cvss REAL NOT NULL DEFAULT 0,
  severity TEXT NOT NULL DEFAULT '',
  product TEXT NOT NULL DEFAULT '',
  version TEXT NOT NULL DEFAULT '',
  cpe TEXT NOT NULL DEFAULT '',
  published TEXT NOT NULL DEFAULT '',
  summary TEXT NOT NULL DEFAULT '',
  found_at INTEGER NOT NULL,
  PRIMARY KEY(service_id, cve));
CREATE INDEX service_vulns_cvss ON service_vulns(cvss DESC);
CREATE TABLE cve_cache(cpe TEXT PRIMARY KEY, fetched_at INTEGER NOT NULL, data TEXT NOT NULL);
`,
}

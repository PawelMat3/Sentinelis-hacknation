# Sentinelis – dokumentacja techniczna

## 1. Architektura

```
                ┌──────────────────────── asi (jeden proces, Go) ────────────────────────┐
 przeglądarka ─▶│ api: REST + sesje + RBAC + CSRF + CSP │ web: dashboard (go:embed, bez buildu) │
                │──────────────────────────────────────────────────────────────────────────│
                │ orchestrator: scheduler (tick 10 s) → executor (pula workerów, chunki)  │
                │   ├─ scanner: nmap (-oX) │ native (TCP connect) │ sim (model laboratorium)│
                │   ├─ fingerprint: prober HTTP/TLS + favicon mmh3 + sygnatury + insights   │
                │   └─ ratelimit: token bucket (HTTP req/s), nmap --max-rate (pps)         │
                │ analysis: maszyna stanów hosta, scoring, snapshot/diff (czysta logika)   │
                │ store: SQLite WAL (modernc, bez CGO) + crypto.Keyring (AES-256-GCM)      │
                │ dojo: DefectDojo API v2 │ iox: CSV/JSON/nmap XML │ lab: symulator+lab TCP │
                └──────────────────────────────────────────────────────────────────────────┘
```

Decyzje: Go (niskie zużycie zasobów, statyczna binarka, łatwe `scp`), SQLite (zero administracji, WAL, transakcja na chunk = checkpoint),
frontend bez frameworka (brak łańcucha budowania, ścisły CSP `script-src 'self'`, cała treść ze skanów wstawiana wyłącznie przez `textContent`).

## 2. Model danych

| Tabela | Warstwa | Opis |
|---|---|---|
| `jobs`, `targets` | konfiguracja | zadania (porty, tempo, okno, częstotliwość, polityka hostów), cele z tagami/notatką |
| `runs` | wykonanie | przebieg: zamrożona specyfikacja, kursor, postęp, EWMA s/cel, czas aktywny, liczba okien, faza (`main`/`reprobe`) |
| `chunks` | checkpoint | podgrupa `[start,end)` lub lista re-probe; status, próby, czas, wyniki |
| `hosts` | obserwacja | stan maszyny stanów, historia 32 obserwacji, `hour_up/hour_probe[24]`, wzorzec |
| `services` | obserwacja | dane ze skanu + zaszyfrowane `http_enc/tls_enc/banner_enc/snap_enc/reasons`, scoring, `digest` |
| `service_tech` | obserwacja | wykryte technologie z pewnością i (zaszyfrowanymi) dowodami |
| `run_hosts`, `run_services` | historia | stan każdego hosta/usługi w każdym przebiegu → porównanie dowolnych przebiegów |
| `changes` | zdarzenia | nowe/zniknięte/zmienione usługi, zdarzenia hostów; szczegóły zaszyfrowane |
| `annotations` | **analityk** | tagi, triage, właściciel, krytyczność, priorytet ręczny, notatka (enc), korekty pól (enc) |
| `signatures` | konfiguracja | wbudowane + własne (definicja JSON) |
| `users`, `roles`, `sessions`, `audit_log`, `settings`, `dojo_exports`, `meta` | system | `meta.dek` = zaszyfrowany klucz danych |

**Separacja danych skanera od decyzji analityka.** Skaner zapisuje wyłącznie tabele obserwacji, a analityk wyłącznie `annotations`. API składa „widok efektywny”: wartość korekty wygrywa, a oryginał ze skanu jest zwracany w polu `observed` (UI pokazuje go w podpowiedzi).
Kolejne skany aktualizują obserwacje i generują diffy, ale nie mają ścieżki zapisu do adnotacji (test `TestWindowCheckpointResumeAndChangeDetection`).
Wpisy ręczne (`origin=manual`) przechodzą przez te same sygnatury, scoring i diff. Wartości podane przez użytkownika trafiają też do warstwy analityka.

## 3. Discovery dużych sieci

1. **Przestrzeń celów** (`internal/targets`): CIDR, zakresy i IP są scalane w posortowane przedziały, wykluczenia odejmowane. `At(i)` działa w O(log n), więc /16 nie jest rozwijane w pamięci. Domeny trafiają na koniec. Obowiązuje limit `ASI_MAX_TARGETS`, a wpisy są walidowane (brak wstrzyknięć).
2. **Specyfikacja przebiegu jest zamrażana** przy jego tworzeniu, więc wznowienie po kilku dniach skanuje identyczny zakres z identycznymi parametrami.
3. **Adaptacyjne podgrupy.** Rozmiar = `chunk_target_sec / EWMA(s/cel)` w granicach [8, 4096]. Wartość startowa pochodzi z poprzedniego przebiegu zadania albo z szacunku `(porty+10)/(pps/workerów)`. Chunk jest wycinany z kursora dopiero w chwili pobrania, a jeśli w oknie zostało mniej czasu, jest przycinany do `0.8 × pozostały czas / s_na_cel`. Chunki oczekujące są w razie potrzeby dzielone.
4. **Workery**: `concurrency` równoległych procesów nmap, każdy z `--max-rate = rate_pps / concurrency`, `--max-retries 2`, `--host-timeout`, `-T0..T4` (T5 zablokowane). Cele trafiają przez stdin (`-iL -`), nigdy przez argv. Dodatkowe flagi tylko z allowlisty.
5. **Fingerprinting** usług WWW działa w puli 8 wątków ze wspólnym limiterem HTTP req/s. Wynik każdego chunku jest zapisywany w jednej transakcji, co stanowi checkpoint.

### Okna czasowe, checkpoint i wznowienie
- Okno: maska dni + `HH:MM–HH:MM` w strefie czasowej (może przechodzić przez północ) albo 24/7. Częstotliwość w minutach (`next_run_at`).
- Executor ustawia timer na koniec okna. Po jego zamknięciu kontekst jest anulowany, `exec.CommandContext` zabija nmap, przerwane chunki wracają do `pending` (bez kary za próbę), a przebieg dostaje status `paused/window_closed` z zapisanym czasem aktywnym.
- Gdy w oknie zostało mniej niż `MinChunkTime`, nowy chunk nie startuje (łagodne zakończenie).
- Scheduler wznawia przebiegi w stanie `paused/queued`, gdy okno się otwiera. Pauza ręczna wymaga ręcznego wznowienia. Po awarii lub restarcie `RecoverInterrupted` przywraca stan z checkpointu.
- Test potwierdza: start o 05:50, pauza przed 06:00 (58% postępu), brak skanowania w południe, wznowienie o 22:00, 100% pokrycia **bez podwójnego skanowania żadnego indeksu**.

### Pomiar czasu
Czas każdego chunku, `active_ms` przebiegu (suma segmentów), przepustowość, ETA, `windows_used` oraz podgląd zadania („szacowany czas”, „potrzebne okna”, polecenie nmap).

## 4. Hosty niestabilne – maszyna stanów

```
            odpowiada                 brak odp. (po re-probe)          brak odp. × N
 (nowy) ──────────────▶ ACTIVE ─────────────────────────▶ SUSPECT ─────────────────▶ INACTIVE
                          ▲  ◀──────── odpowiada (cicho) ────┘                         │
                          │                                                            │ odpowiada
                          └────────── ≥8 kolejnych odpowiedzi ◀── UNSTABLE ◀── ≥3 zmiany w 12 obs.
                                                                   │ brak odp. w godzinach „off” – nie liczony
                                                                   └─ brak odp. × 2N (w godzinach „on”) → INACTIVE
```
- **Re-probe**: znane hosty, które nie odpowiedziały, są skanowane ponownie (`reprobe_attempts` razy co `reprobe_delay_sec`), zanim brak odpowiedzi zostanie zapisany.
- **Profil godzinowy**: `hour_up/hour_probe[24]` daje wzorzec, np. „okresowa: odpowiada w godz. 7–19”. Brak odpowiedzi w godzinie z dostępnością ≤20% jest uznawany za oczekiwany.
- **Usługi „zniknęły”** tylko wtedy, gdy host odpowiadał, a port był w zakresie skanu (potwierdzone), albo gdy host przeszedł do `inactive`. Przy hostach w stanie `suspect` usługi nie są oznaczane jako zniknięte, co eliminuje szum. W porównaniu przebiegów takie przypadki trafiają do kategorii „niepotwierdzone”.
- Przebieg bazowy (pierwszy dla zadania) nie zalewa kanału zmian zdarzeniami „nowy”.

## 5. Fingerprinting, sygnatury, pewność, ciekawość

- Prober: tylko GET, bez poświadczeń i parametrów, body ≤512 KB, przekierowania w obrębie tego samego originu (pozostałe są tylko rejestrowane), SNI/Host dla domen, `InsecureSkipVerify` z własną analizą certyfikatu (wygasły, self-signed, zgodność nazwy, protokół, algorytm podpisu). Identyfikujący User-Agent.
- Ścieżki sprawdzane pasywnie wynikają z włączonych sygnatur (np. `/login`, `/admin`, `/version`, `/.git/HEAD`, `/actuator`, `/server-status`), maks. 32 na usługę. Walidator dopuszcza tylko postać `^/[A-Za-z0-9._~-/]+$` (bez `..`, query i payloadów).
- **Pewność** detekcji = `1 − Π(1 − wᵢ)` po dopasowanych markerach; niezależne sygnatury tej samej technologii łączone są tym samym wzorem. `condition: all`, `negate`, `min_confidence`.
- **Insights** (ciekawe nagłówki i ciasteczka): ujawnianie wersji, nagłówki infrastruktury (`X-Backend-Server`…), CORS `*` z credentials, brak nagłówków bezpieczeństwa, ciasteczka sesyjne bez `Secure`/`HttpOnly`, problemy TLS.
- **Ciekawość (0–100)**: suma ważonych czynników (ciekawość sygnatury × pewność, porty wysokiego ryzyka, insights, nowość, zmiana, niestabilność) z malejącym przyrostem. Wynik dzielony jest na progi critical/high/medium/low/info, a każdy czynnik ma tekstowe uzasadnienie w UI.

## 6. Bezpieczeństwo

**Encryption at Rest**: KEK (`ASI_MASTER_KEY` lub plik 0600 poza katalogiem danych) zabezpiecza losowy DEK przechowywany w `meta`. Pola szyfrowane są AES-256-GCM z losowym nonce, a AAD = `tabela.kolumna` uniemożliwia przenoszenie szyfrogramów między kolumnami. Szyfrowane są: nagłówki/ciasteczka/body/ścieżki (`services.http`), certyfikaty, banery, snapshoty, uzasadnienia, dowody detekcji, notatki i korekty analityka, notatki celów, szczegóły zmian, ustawienia (klucz API DefectDojo). Jawne pozostają adresy, porty, tytuły, nazwy produktów i wystawcy certyfikatów, bo są potrzebne do wyszukiwania i grupowania. Rotacja KEK: `asi rotate-key`. Weryfikację umożliwia `asi crypto-check`, a test sprawdza brak tekstu jawnego w pliku DB i WAL.

**RBAC**: uprawnienia `zasób:akcja` (20), deklarowane przy każdej trasie API. Wbudowane role:

| Uprawnienie | Administracja | Dodawanie, usuwanie, modyfikacja | Modyfikacja i odczyt | Odczyt |
|---|---|---|---|---|
| odczyt zasobów/skanów/sygnatur, eksport | ✓ | ✓ | ✓ | ✓ |
| edycja znalezisk, zadań, sygnatur | ✓ | ✓ | ✓ | |
| dodawanie / usuwanie, import, uruchamianie skanów, DefectDojo | ✓ | ✓ | | |
| użytkownicy, role, ustawienia, audyt | ✓ | | | |

Role własne tworzy się z dowolnego zestawu uprawnień. Role wbudowane są niemodyfikowalne.

**Aplikacja**: bcrypt (koszt 12) z wyrównaniem czasu dla nieistniejących kont, sesje jako losowe tokeny (w bazie wyłącznie SHA-256), ciasteczko HttpOnly + SameSite=Strict (+Secure), wymagany nagłówek `X-ASI-CSRF`, throttling logowań (5 prób / 5 min), CSP bez inline, `X-Frame-Options`, audyt (także odmowy dostępu), neutralizacja formula injection w eksporcie CSV, limity rozmiaru żądań.

**Ostrożność skanera**: globalny limit pps, limit HTTP req/s, wykluczenia, limit rozmiaru zakresu, allowlista flag nmap (bez NSE poza `banner/http-title/ssl-cert/…`), brak T5, przycisk „Stop wszystkich skanów”. Usługa systemd działa jako nieuprzywilejowany użytkownik z `CAP_NET_RAW` oraz `ProtectSystem=strict` i `MemoryDenyWriteExecute`.

## 7. Integracje i formaty

**DefectDojo** (`internal/dojo`): konfiguracja w UI (URL, zaszyfrowany token, `engagement_id` albo produkt+engagement z `auto_create_context`) i test połączenia (`/api/v2/user_profile/`). Eksport wybranych usług lub zmian idzie przez `POST /api/v2/import-scan/` z `scan_type=Generic Findings Import`. Każda obserwacja to finding z `unique_id_from_tool` (deduplikacja), endpointami, tagami, komponentem i wersją oraz plikami evidence (`http-response.txt`, `tls-certificate.json`, `detection-evidence.txt`). Domyślnie Severity=Info („finding informacyjny”), opcjonalnie mapowanie z priorytetu. Gotowy JSON można też pobrać do ręcznego importu.

**Formaty**: `examples/` – cele (CSV/JSON/tekst), wyniki (`asi-results/v1` JSON, płaski JSON, CSV, nmap XML), sygnatury JSON. Import wyników tworzy przebieg `import` i przechodzi przez pełny potok (sygnatury, scoring, diff, maszyna stanów). Tagi i notatki z pliku trafiają do warstwy analityka.

## 8. API (skrót)

Wszystkie ścieżki pod `/api`, sesja w ciasteczku albo `Authorization: Bearer <token>` (token zwracany przez `/api/auth/login`).

| Metoda i ścieżka | Uprawnienie |
|---|---|
| `POST /auth/login`, `POST /auth/logout`, `GET /auth/me`, `POST /auth/password`, `GET /meta` | – |
| `GET /dashboard`, `GET /hosts`, `GET /hosts/{id}`, `GET /services`, `GET /services/{id}`, `GET /groups?by=tech\|category\|favicon\|cert_issuer\|title\|server\|product`, `GET /changes`, `GET /compare?a=&b=` | assets:read |
| `POST /hosts`, `POST /services` (wpisy ręczne) | assets:create |
| `PATCH /hosts/{id}`, `PATCH /services/{id}`, `POST /services/bulk` (adnotacje/korekty) | assets:update |
| `DELETE /hosts/{id}`, `DELETE /services/{id}` | assets:delete |
| `GET /jobs`, `GET /jobs/{id}`, `GET /jobs/{id}/targets`, `GET /jobs/{id}/preview`, `GET /runs`, `GET /runs/{id}` | jobs:read |
| `POST /jobs`, `POST /jobs/{id}/targets` (tekst/CSV/JSON/multipart) | jobs:create |
| `PUT /jobs/{id}`, `PATCH /jobs/{id}/targets/{tid}` | jobs:update |
| `DELETE /jobs/{id}`, `DELETE /jobs/{id}/targets[/{tid}]` | jobs:delete |
| `POST /jobs/{id}/run {force}`, `POST /runs/{id}/pause\|resume\|force-resume\|cancel`, `POST /scans/stop-all` | scans:run |
| `GET /export/results?format=json\|csv&detail=1`, `GET /export/changes`, `GET /jobs/{id}/targets/export`, `GET /signatures/export` | data:export |
| `POST /import/results` | data:import |
| `GET /signatures`, `POST /signatures/test` · `POST /signatures`, `POST /signatures/import` · `PUT` · `DELETE /signatures/{id}` | signatures:* |
| `POST /dojo/export {service_ids, change_ids, informational, dry_run}`, `GET /dojo/history` | dojo:export |
| `/users`, `/roles`, `/settings/dojo[/test]`, `/audit` | admin:* |

## 9. Testowanie

`go test ./...` – testy jednostkowe i integracyjne (sieć 4097 celów na symulatorze z wirtualnym zegarem, 5 przebiegów w ok. 10 s), test HTTP na prawdziwych serwerach `httptest`, test API (RBAC, CSRF, throttling, walidacja zadań), test DefectDojo z mockiem multipart.
Wynik na żywo: `asi lab` daje 10 hostów i 20 usług na loopbacku, a prawdziwy nmap wykrywa wszystkie artefakty (WordPress 6.4.2, Jenkins 2.401.3, staging + `.git`, phpMyAdmin, Werkzeug debug, listowanie katalogów, OWA z wygasłym certyfikatem, kamera IP, Grafana, Actuator, własna sygnatura favicony).

## 10. Ograniczenia i dalszy rozwój
- UDP nie jest skanowane domyślnie (możliwe przez `-sU` po dodaniu do allowlisty).
- Domena skanowana po pierwszym adresie A (nmap). Pasywne źródła (CT logs, passive DNS) to naturalne rozszerzenie modułu `targets`.
- Dla bardzo dużych instalacji SQLite można zastąpić PostgreSQL (warstwa `store`), a orkiestrator rozproszyć na wiele sond.

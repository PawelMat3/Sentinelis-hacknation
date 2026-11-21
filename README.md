# Sentinelis – Attack Surface Intelligence

Prototyp systemu do cyklicznego, bezpiecznego discovery dużej infrastruktury (>10 000 adresów IP) dla Centrum Bezpieczeństwa Informacji AGH.
Wykrywa aktywne hosty i usługi (nmap), robi pasywny fingerprinting HTTP/HTTPS/TLS, rozpoznaje technologie, CMS-y, panele administracyjne i środowiska testowe,
śledzi zmiany w czasie z obsługą hostów niestabilnych, priorytetyzuje znaleziska i eksportuje je do DefectDojo.

**Jeden statyczny plik binarny (Go, bez CGO) + SQLite z szyfrowaniem pól + osadzony dashboard.** ~30 MB RAM w spoczynku.

## Laboratorium organizatorów (Docker)

Sentinelis jest dostosowany do szablonów środowisk testowych udostępnionych przez organizatorów (stacki `custom-network`, `modern`, `modern-proxy`, `vulnerable`):

- **Cel:** `localhost` lub `127.0.0.1` (albo adres maszyny z labem). W **Szybkim skanie** profil *Automatyczny* skanuje dla małych celów (≤16 adresów) **wszystkie 65535 portów**, więc wykrywa usługi na niestandardowych portach (8787, 5673, 15672, 15432, 2223, 8474…), których nie ma w top‑1000 nmapa. Profil *Standard* obejmuje ok. 1500 portów, w tym typowe porty usług dev, admin, baz danych i kolejek.
- **Rozpoznawane aplikacje:** WordPress (z wersją, także 4.7), phpMyAdmin, Adminer, DVWA, Gitea (wersja), RabbitMQ (panel i AMQP), Traefik (panel i API, wersja), Toxiproxy (API bez uwierzytelnienia), Nginx Proxy Manager, httpbin, nginx (strona domyślna), Redis, PostgreSQL, vsftpd, OpenSSH.
- **Scenariusz „quickstart”:** zatrzymanie usługi na porcie 8787 daje zdarzenie „usługa zniknęła”, a ponowne uruchomienie „usługa ponownie wykryta”. Kolejne szybkie skany tego samego celu porównują się z poprzednim przebiegiem.
- **Toxiproxy (opóźnienia):** Sentinelis mierzy czas odpowiedzi strony głównej. Wartość ≥400 ms jest zgłaszana jako obserwacja „wolna odpowiedź HTTP”, a skok czasu odpowiedzi między skanami (≥3× i ≥250 ms) jako zmiana „czas odpowiedzi: 3 ms → 540 ms”.
- **Port panelu:** domyślnie `7780`, więc nie koliduje z portami labu (80/81/443/8080/8081/8088–8090).
- **Docker:** Sentinelis uruchomiony w kontenerze w sieci bridge nie widzi portów opublikowanych na hoście (`localhost` oznacza wtedy sam kontener). Do skanowania labu na tej samej maszynie służy wariant z siecią hosta: `docker compose --profile hostnet up -d asi-hostnet`. Można też uruchomić samą binarkę na hoście.

## Najważniejsze cechy

| Obszar | Co zostało zrobione |
|---|---|
| Discovery dużych sieci | Przestrzeń celów jako zbiór przedziałów (CIDR/zakresy/domeny, scalanie, wykluczenia), adaptacyjne podgrupy (chunki) dobierane do zmierzonego tempa, równoległe skany nmap z `--max-rate`, limit HTTP req/s, globalne limity bezpieczeństwa |
| Okna czasowe | Harmonogram (częstotliwość + okno dni/godzin, także przez północ). Gdy okno się kończy: przerwanie podgrup, checkpoint w bazie, automatyczne wznowienie w kolejnym oknie bez ponownego skanowania zrobionych celów |
| Pomiar czasu | Czas każdej podgrupy, aktywny czas skanu, przepustowość, ETA, liczba wykorzystanych okien, szacunek „ile okien potrzeba” przed startem |
| Fingerprinting | Status, przekierowania (off-origin tylko rejestrowane), tytuł, nagłówki, ciasteczka (flagi), certyfikat TLS, favicon mmh3 (zgodny z Shodan), pasywne ścieżki GET |
| Sygnatury | 101 wbudowanych + własne (UI/JSON): nagłówek, ciasteczko, favicon, HTML, tytuł, generator, ścieżka, certyfikat, hostname, baner, produkt, port; ważona pewność `1−Π(1−w)`, ekstrakcja wersji, tester na zebranych danych |
| Zmiany w czasie | Nowe / zniknięte / zmienione usługi (diff istotnych cech), porównanie dowolnych dwóch przebiegów, wykres trendu |
| Hosty niestabilne | Maszyna stanów `active → suspect → inactive` + `unstable`, re-probe przed zapisaniem braku odpowiedzi, profil godzinowy (24 h), wzorzec „okresowa: odpowiada 8–19” – brak odpowiedzi w typowych godzinach „off” nie jest alarmem |
| Priorytety | Ocena ciekawości 0–100 z uzasadnieniem (staging, panel admina, debug, .git, wygasły TLS, bazy danych, nowość, zmiana…) |
| RBAC | 4 wymagane role + role własne z 20 uprawnień; egzekwowane na serwerze dla każdego endpointu; audyt |
| Dane analityka | Osobna warstwa (tagi, notatki, triage, korekty pól, priorytet ręczny) – skany jej nigdy nie nadpisują. Wpisy ręczne przechodzą przez ten sam potok co skan |
| Szyfrowanie | AES-256-GCM per pole (nagłówki, ciasteczka, certyfikaty, banery, notatki, korekty, dowody, klucz API DefectDojo), klucz w kopercie (KEK poza bazą) |
| Import / eksport | Cele: CSV/JSON/tekst. Wyniki: JSON, CSV, nmap XML (import przez pełny potok). Zmiany: CSV/JSON. Sygnatury: JSON |
| DefectDojo | Wysyłka wybranych usług/zmian jako findingi (Generic Findings Import, `/api/v2/import-scan/`) z plikami evidence; tryb informacyjny; pobranie JSON do ręcznego importu |

## Szybki skan – najprostszy sposób użycia

Menu **Szybki skan** → wpisz cel (domena, IP, zakres, CIDR do 4096 adresów) → zaznacz zgodę właściciela → **Skanuj**. Aplikacja sama wykonuje kolejne kroki:

1. **Subdomeny** (dla domeny): pasywnie z logów Certificate Transparency (crt.sh) + DNS, maks. 64 nazwy.
2. **Porty i usługi**: nmap z wykrywaniem wersji (profil: 100 / 1000 / wszystkie porty).
3. **Aplikacje WWW**: nagłówki, ciasteczka, TLS, CMS i wersja, wtyczki i motywy WordPress z wersjami (z kodu strony, `/feed/`), panele admina, staging, ekspozycje.
4. **Znane podatności**: każda wykryta wersja → CPE → lista CVE z NIST NVD (z cache, z limitem zapytań; `ASI_NVD_API_KEY` przyspiesza, `ASI_NVD_DISABLE=1` wyłącza). To dopasowanie po wersji do weryfikacji, a nie eksploitacja.

Wynik to jedna strona z postępem kroków, tabelą „co znaleziono” i listą CVE posortowaną po CVSS. Znalezione podatności podnoszą priorytet usług i trafiają do kanału zmian, pulpitu i eksportu do DefectDojo.

## Szybki start

```bash
make build && ASI_DEMO=1 ./bin/asi serve          # http://localhost:7780, login admin / Demo-ASI-2026! (tylko tryb demo)
```

Tryb demo generuje w ok. 45 s trzy dni symulowanych skanów sieci 16 384 adresów (hosty zależne od pory dnia, aktualizacje, nowe i znikające usługi),
skan DMZ przerwany o 06:00 i wznowiony następnej nocy, użytkowników dla każdej roli (`operator`, `analityk`, `audytor`, `soc`), własne sygnatury i adnotacje.

### Prawdziwy skan na żywo (laboratorium)

```bash
sudo ./bin/asi lab                                 # 10 hostów 127.0.1.1–10, ~20 usług (WordPress, Jenkins, staging, kamera…)
./bin/asi lab --port-offset 8000                   # gdy porty <1024 są zajęte lub bez roota
```
Następnie w UI: *Zadania → „Laboratorium – prawdziwy skan” → Teraz*. Host .9 odpowiada tylko w parzystych minutach (demo hosta niestabilnego).

## Wdrożenie na Ubuntu 26.04 (VPS)

```bash
make release                                       # asi-1.0.0-linux-amd64.tar.gz
scp asi-1.0.0-linux-amd64.tar.gz root@serwer:/opt/ && ssh root@serwer
cd /opt && mkdir asi-release && tar xzf asi-*.tar.gz -C asi-release && cd asi-release
./deploy/install.sh --demo --listen 127.0.0.1:8090   # nmap + użytkownik asi + systemd + klucz + hasła
```
Instalator jest idempotentny (ponowne uruchomienie = aktualizacja). Usługa działa jako użytkownik `asi` z `CAP_NET_RAW` (SYN scan bez roota) i utwardzeniem systemd.
Dostęp: tunel `ssh -L 8090:127.0.0.1:8090 root@serwer` albo reverse proxy z TLS (wtedy `ASI_SECURE_COOKIE=1`).

Docker: `docker compose up -d` (opcjonalnie `--profile lab`).

## Konfiguracja (zmienne środowiskowe)

| Zmienna | Domyślnie | Opis |
|---|---|---|
| `ASI_LISTEN` | `0.0.0.0:7780` | adres nasłuchu (poza portami typowych usług – nie koliduje z labem: 80/81/443/8080/8081…) |
| `ASI_DATA_DIR` | `./data` | baza SQLite |
| `ASI_MASTER_KEY` / `ASI_MASTER_KEY_FILE` | `<data>/master.key` | klucz główny (base64, 32 B); `asi gen-key` |
| `ASI_ADMIN_PASSWORD` | losowe | hasło pierwszego admina |
| `ASI_DEMO`, `ASI_DEMO_PASSWORD` | `0` | dane demonstracyjne |
| `ASI_NMAP_PATH`, `ASI_NMAP_PRIVILEGED` | `nmap`, `auto` | SYN scan gdy uprawnienia |
| `ASI_MAX_RATE`, `ASI_MAX_TARGETS` | `2000`, `1048576` | globalne limity bezpieczeństwa |
| `ASI_TLS_CERT`, `ASI_TLS_KEY` | – | HTTPS bez proxy |
| `ASI_SECURE_COOKIE`, `ASI_TRUST_PROXY`, `ASI_SESSION_HOURS` | | sesje |

## Narzędzia CLI

`asi serve | lab | gen-key | crypto-check | rotate-key --new-key-file f | user add <login> <rola> | user passwd <login> | healthcheck | version`

`asi crypto-check` pokazuje surową zawartość zaszyfrowanych kolumn i weryfikuje, że żadna nie zawiera tekstu jawnego.

## Testy

`go test ./...` – m.in.: szyfrowanie (AAD, manipulacja, zły klucz), przestrzeń celów >10k, okna przez północ, **pauza na końcu okna i wznowienie z checkpointu bez nakładania**, adaptacyjne chunki, diff przebiegów, **przetrwanie korekt analityka po kolejnych skanach**, suspect→inactive, re-probe, **brak tekstu jawnego w pliku bazy**, macierz RBAC + CSRF + throttling, odrzucanie niebezpiecznych flag nmap, multipart DefectDojo.

Dokumentacja techniczna: [docs/ARCHITEKTURA.md](docs/ARCHITEKTURA.md) · Prezentacja: [docs/PREZENTACJA.md](docs/PREZENTACJA.md)

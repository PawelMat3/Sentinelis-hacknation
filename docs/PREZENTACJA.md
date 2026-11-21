# Sentinelis – konspekt prezentacji (10 slajdów, ~8 min + demo)

**1. Problem.** Kilkadziesiąt tysięcy adresów; część hostów odpowiada tylko o niektórych porach; jednorazowy skan daje fałszywy obraz. Potrzebne jest: *co* tam działa, *co się zmieniło*, *co jest ciekawe* – i to bezpiecznie.

**2. Rozwiązanie w jednym zdaniu.** Jedna binarka (Go) + SQLite z szyfrowaniem pól + dashboard; nmap do discovery, pasywny fingerprinting HTTP/TLS, analiza zmian, priorytety, RBAC, DefectDojo. Instalacja jednym skryptem na Ubuntu 26.04, ~30 MB RAM.

**3. Skala i bezpieczeństwo skanu.** Przestrzeń celów jako przedziały (CIDR/zakresy/domeny, wykluczenia). Adaptacyjne podgrupy (rozmiar = docelowy czas / zmierzone tempo), równoległe nmapy z `--max-rate`, limit HTTP req/s, allowlista flag, brak T5, kill-switch. *Demo: podgląd zadania – szacowany czas, liczba okien, polecenie nmap; wykres rozmiarów chunków.*

**4. Okna czasowe i checkpoint.** Skan DMZ 22:00–06:00: przerwany o 06:00 przy 58%, wznowiony o 22:00 bez ponownego skanowania. Czas aktywny, ETA, liczba okien. *Demo: przebieg DMZ (2 okna), przycisk Wstrzymaj/Wznów na żywym przebiegu.*

**5. Hosty niestabilne.** Maszyna stanów aktywny → oczekuje potwierdzenia → nieaktywny (po N skanach), stan „niestabilny/okresowy”, re-probe przed zapisaniem braku odpowiedzi, profil 24 h. Brak odpowiedzi „w nocy” hosta biurowego nie jest alarmem. *Demo: pulpit – heatmapa godzinowa, host „okresowa: odpowiada w godz. 7–19”.*

**6. Zmiany w czasie.** Nowe / zniknięte / zmienione (diff istotnych cech: wersja, tytuł, technologie, certyfikat). Zniknięcie tylko potwierdzone (host odpowiadał). Porównanie dowolnych dwóch przebiegów. *Demo: Zmiany → porównanie #1 vs #2.*

**7. Fingerprinting i sygnatury.** Status, przekierowania, tytuł, nagłówki, ciasteczka (flagi), TLS, favicon mmh3 (zgodny z Shodan), pasywne ścieżki GET. 101 sygnatur + własne; pewność ważona `1−Π(1−w)` z dowodami. *Demo: stworzenie własnej sygnatury i „Testuj na zebranych danych”.*

**8. Priorytety i grupowanie.** Ocena ciekawości z uzasadnieniem (staging, panel admina, debug, `.git`, wygasły TLS, bazy danych, nowość). Grupowanie po technologii / favicon / wystawcy certyfikatu. *Demo: top znaleziska, grupa „phpMyAdmin”.*

**9. Dane analityka, RBAC, szyfrowanie.** Osobna warstwa korekt/tagów/notatek – skany jej nie nadpisują; wpisy ręczne przetwarzane jak skan. 4 role + własne, egzekwowane w API, audyt. AES-256-GCM per pole, klucz w kopercie; `asi crypto-check`. *Demo: korekta produktu → kolejny skan → korekta nadal jest; logowanie jako „audytor” – brak przycisków, 403 w API.*

**10. Integracje i wdrożenie.** Import/eksport CSV, JSON, nmap XML; DefectDojo: wybrane obserwacje jako findingi informacyjne z evidence (nagłówki, certyfikat, dowody detekcji). `install.sh` → systemd z utwardzeniem i `CAP_NET_RAW`; Docker Compose. Testy automatyczne kluczowych mechanizmów. Dalej: pasywne źródła (CT, passive DNS), wiele sond.

---
## Scenariusz demo (kolejność kliknięć)
1. Zaloguj jako `admin` → **Pulpit** (KPI, top znaleziska, zmiany, trend, heatmapa godzinowa).
2. **Znaleziska** → filtr *Krytyczne* → usługa staging: zakładki *HTTP* (nagłówki, ciasteczka bez flag, `/.git/HEAD`), *TLS*, *Historia*, *Edycja analityka* (pokazana wcześniejsza korekta, która przetrwała 9 skanów).
3. **Zmiany** → porównanie przebiegów #1 i #2.
4. **Zadania** → „DMZ – okno nocne” → przebieg z 2 oknami; „Kampus” → *Teraz (poza oknem)* → podgląd przebiegu na żywo (chunki rosną adaptacyjnie) → *Wstrzymaj* → *Wznów*.
5. `asi lab` + zadanie **Laboratorium** → prawdziwy nmap (WordPress, Jenkins, Werkzeug debug, OWA z wygasłym certyfikatem…).
6. **Sygnatury** → nowa sygnatura → *Testuj*.
7. Zaznacz 3 znaleziska → **→ DefectDojo** (lub *Pobierz JSON*).
8. Wyloguj → zaloguj jako `audytor` → brak edycji, eksport dostępny; **Role (RBAC)** jako admin – macierz uprawnień.
9. Terminal: `asi crypto-check` – szyfrogramy w bazie.

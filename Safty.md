# Safty.md

Stand: 2026-06-24

Diese Datei beschreibt die Sicherheitsstruktur des Health-Checker-Projekts und
gibt eine praktische Sicherheitseinschaetzung fuer den aktuellen Codebestand.
Der Dateiname folgt der angefragten Schreibweise `Safty.md`.

## Kurzbewertung

Die Anwendung hat eine solide Basis fuer ein kleines internes Monitoring-Tool:
Admin-Passwoerter werden mit bcrypt gehasht, API-Tokens werden nur gehasht
gespeichert, SQL-Zugriffe laufen ueber parametrisierte Statements, Sessions
nutzen `httpOnly`/`sameSite` Cookies und produktive npm-Abhaengigkeiten melden
im lokalen `npm audit --omit=dev` keine bekannten Schwachstellen.

Die groessten Rest-Risiken sind betrieblicher Natur:

| Risiko | Bewertung | Grund |
| --- | --- | --- |
| SSRF ueber Service-URLs | Mittel bis hoch | Admins koennen beliebige HTTP/HTTPS-Ziele eintragen; der Checker ruft diese URLs serverseitig ab. |
| CSRF gegen Admin-Endpunkte | Mittel | Admin-Aktionen sind sessionbasiert, aber es gibt keine expliziten CSRF-Tokens. `sameSite: strict` reduziert das Risiko deutlich, ersetzt aber keine Token-Pruefung. |
| XSS/CSP-Schwaeche durch Inline-JavaScript | Mittel | Die Seiten nutzen Inline-Skripte und Inline-Handler; deshalb erlaubt die CSP aktuell `'unsafe-inline'`. |
| Betrieb ohne HTTPS/Proxy-Haertung | Mittel | Sichere Cookies sind nur bei `NODE_ENV=production` aktiv und brauchen HTTPS bzw. einen korrekt konfigurierten Reverse Proxy. |
| Geheimnisse und Live-Daten im Projektordner | Mittel | `.env` und `data/*.db` enthalten sensitive Konfiguration bzw. Laufzeitdaten und duerfen nicht veroeffentlicht werden. |
| Container laeuft als root | Niedrig bis mittel | Das Dockerfile setzt keinen nicht-privilegierten User. |

## Sicherheitsarchitektur

### Server und HTTP-Haertung

Der Einstiegspunkt ist `server.js`.

- Sicherheitsheader werden global gesetzt:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `X-XSS-Protection: 1; mode=block`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Content-Security-Policy`
- Request-Groessen sind begrenzt:
  - JSON: `100kb`
  - URL-encoded: `100kb`
- `trust proxy` ist standardmaessig aus und wird nur mit `TRUST_PROXY=1`
  aktiviert.
- Statische Dateien werden aus `public/` ausgeliefert.

Bewertung: Gut als Baseline. Die CSP ist wegen Inline-Skripten noch nicht
streng genug, um XSS-Auswirkungen maximal zu begrenzen.

### Admin-Authentifizierung

Die Admin-Authentifizierung liegt in `routes/admin.js`,
`middleware/auth.js` und `middleware/rateLimit.js`.

- Beim ersten Start wird ein Admin-Passwort gesetzt:
  - aus `ADMIN_PASSWORD`, falls vorhanden
  - sonst zufaellig generiert und einmal in der Konsole ausgegeben
- Das Passwort wird als bcrypt-Hash mit Kostenfaktor 12 in der SQLite-Tabelle
  `settings` gespeichert.
- Login-Sessions werden mit `express-session` verwaltet.
- Session-Cookie:
  - Name: `hc.sid`
  - `httpOnly: true`
  - `sameSite: strict`
  - `secure: true` nur bei `NODE_ENV=production`
  - Laufzeit: 8 Stunden
- Bei erfolgreichem Login wird die Session per `req.session.regenerate`
  erneuert.
- Fehlgeschlagene Logins werden pro IP limitiert:
  - 10 Versuche
  - 15 Minuten Fenster

Bewertung: Gute Basis gegen Passwortdiebstahl aus der Datenbank, Session
Fixation und einfache Brute-Force-Versuche. Fuer oeffentliche Deployments
sollte CSRF-Schutz ergaenzt werden.

### API-Token-Modell

Die API-Authentifizierung liegt in `middleware/auth.js` und `routes/api.js`.

- API-Tokens werden mit `crypto.randomBytes(32)` erzeugt.
- Der Client bekommt den Token nur einmal bei Erstellung angezeigt.
- In der Datenbank wird nur ein SHA-256-Hash gespeichert.
- Im UI und in Logs wird nur der Token-Prefix verwendet.
- Tokens koennen zwei Zugriffsumfaenge haben:
  - `all`: Zugriff auf alle Dienste
  - `restricted`: Zugriff nur auf explizit zugewiesene Dienste
- API-Endpunkte pruefen den Token und filtern die sichtbaren Dienste ueber
  `getServicesForToken`.
- API-Aufrufe werden in `api_logs` protokolliert.

Bewertung: Solide fuer ein internes Status-API. Fuer hoehere Anforderungen
waeren Token-Ablaufdaten, Rotation und optional eine feinere Rechteverwaltung
sinnvoll.

### Datenbank und Persistenz

Die Persistenz liegt in `db.js` und nutzt `node:sqlite`.

- Die Datenbank liegt in `data/health-checker.db`.
- SQLite nutzt WAL-Modus.
- Foreign Keys sind aktiviert.
- SQL-Zugriffe laufen ueber vorbereitete Statements mit Platzhaltern.
- Historie und API-Logs werden begrenzt:
  - Check-Resultate: letzte 1000 je Dienst
  - API-Logs: letzte 10000 insgesamt

Bewertung: SQL-Injection-Risiko ist durch vorbereitete Statements niedrig.
Die Datenbankdateien enthalten sensitive Informationen wie Passwort-Hash,
Token-Hashes, Service-URLs, IP-Adressen und Audit-Logs.

### Health-Check-Ausfuehrung

Der Checker liegt in `checker.js`.

- Eingetragene Service-URLs werden regelmaessig per `fetch` abgefragt.
- Nur `http:` und `https:` URLs sind in `routes/admin.js` erlaubt.
- Timeouts werden per `AbortController` umgesetzt.
- Redirects werden aktuell verfolgt.
- Ergebnisdaten werden in SQLite gespeichert.

Bewertung: Funktional sauber, aber der groesste Sicherheitshebel liegt hier.
Da der Server die URLs selbst abruft, koennen Admins interne Netzwerkziele
adressieren. Das ist fuer ein internes Admin-Tool akzeptabel, muss aber als
SSRF-Risiko verstanden und im Betrieb kontrolliert werden.

### Frontend

Die Oberflaeche liegt in `public/`.

- Dashboard und Admin-UI pruefen die Session ueber `/admin/session`.
- Dynamische Inhalte werden an den meisten Stellen vor dem Einbau in HTML
  escaped.
- Die Seiten enthalten Inline-Skripte und Inline-Eventhandler.

Bewertung: Das eigene Escaping reduziert direkte XSS-Risiken aus Service-Namen
und URLs. Die CSP muss aber wegen Inline-Code lockerer sein als ideal.

### Container und Deployment

Das Docker-Setup liegt in `Dockerfile` und `compose.yml`.

- Runtime-Image basiert auf `node:20-alpine`.
- `NODE_ENV=production` wird im Container gesetzt.
- Port `3000` wird nach aussen gemappt.
- `./data` wird als Volume nach `/app/data` eingebunden.
- Ein Healthcheck ruft `/admin/session` ab.

Bewertung: Fuer lokale oder interne Nutzung ausreichend. Fuer haertere
Deployments sollte der Container als nicht-root User laufen und der Dienst
hinter TLS bzw. einem Reverse Proxy betrieben werden.

## Konkrete Empfehlungen

### Sofort umsetzen

1. `.env` und `data/*.db*` niemals committen, kopieren oder oeffentlich
   bereitstellen.
2. In Produktion immer `NODE_ENV=production` setzen.
3. Vor dem Dienst immer HTTPS verwenden, idealerweise ueber nginx, Caddy oder
   Traefik.
4. `TRUST_PROXY=1` nur setzen, wenn der Dienst wirklich hinter einem
   vertrauenswuerdigen Reverse Proxy laeuft.
5. Admin-Passwort nach dem ersten Start in der UI aendern und stark waehlen.
6. API-Tokens nur mit minimal noetigen Berechtigungen erstellen.
7. Token mit Scope `all` nur fuer vertrauenswuerdige interne Clients verwenden.

### Naechste Code-Haertungen

1. CSRF-Schutz fuer Admin-Mutationen ergaenzen:
   - `/admin/services`
   - `/admin/tokens`
   - `/admin/change-password`
   - `/admin/logout`
2. SSRF-Schutz fuer Service-URLs ergaenzen:
   - private IP-Ranges blockieren, wenn nicht explizit erlaubt
   - DNS-Rebinding beruecksichtigen
   - Redirect-Ziele ebenfalls validieren
   - optional Allowlist fuer Domains oder Netzbereiche
3. Inline-JavaScript aus HTML-Dateien in externe `.js` Dateien verschieben.
   Danach CSP ohne `'unsafe-inline'` betreiben.
4. Token-Rotation und Ablaufdaten einfuehren.
5. Dockerfile um einen nicht-privilegierten Runtime-User erweitern.
6. Eine `.gitignore` mit mindestens folgenden Eintraegen anlegen:

   ```gitignore
   node_modules/
   .env
   data/*.db
   data/*.db-shm
   data/*.db-wal
   npm-debug.log*
   ```

## Betriebsregeln

- Admin-UI nicht direkt ins Internet stellen, wenn es nicht zwingend noetig ist.
- Zugriff bevorzugt ueber VPN, internes Netzwerk oder Reverse Proxy mit
  zusaetzlicher Authentifizierung absichern.
- Backups der SQLite-Datenbank verschluesselt speichern.
- API-Logs regelmaessig pruefen, besonders:
  - viele 401/403 Antworten
  - unbekannte IP-Adressen
  - Nutzung alter Token
- Nach Verdacht auf Token-Leak:
  1. Token im Admin-UI loeschen.
  2. Neuen Token erzeugen.
  3. Betroffene Clients aktualisieren.
  4. API-Logs auf Missbrauch pruefen.
- Nach Verdacht auf Admin-Passwort-Leak:
  1. Passwort sofort aendern.
  2. Dienst neu starten, um aktive In-Memory-Sessions zu entfernen.
  3. Reverse-Proxy-Logs und API-Logs pruefen.

## Pruefergebnis

Durchgefuehrte lokale Checks:

- `node --check server.js`
- `node --check routes/admin.js`
- `node --check routes/api.js`
- `node --check middleware/auth.js`
- `node --check middleware/rateLimit.js`
- `node --check checker.js`
- `npm audit --omit=dev`

Ergebnis:

- JavaScript-Syntaxchecks: bestanden
- Produktive npm-Abhaengigkeiten: `found 0 vulnerabilities`

## Gesamtfazit

Fuer ein internes Health-Checker-Tool ist die Sicherheitsstruktur ordentlich:
Passwort- und Token-Speicherung sind nicht im Klartext, Sessions sind sinnvoll
konfiguriert, SQL-Zugriffe sind parametrisiert und die API hat ein einfaches
Berechtigungsmodell.

Vor einer oeffentlichen Bereitstellung sollten mindestens CSRF-Schutz,
SSRF-Haertung, HTTPS-Betrieb und eine strengere CSP umgesetzt werden. Der
wichtigste Punkt ist die Service-URL-Funktion: Sie ist fachlich notwendig,
aber gleichzeitig der Teil der Anwendung mit dem groessten Missbrauchspotential.

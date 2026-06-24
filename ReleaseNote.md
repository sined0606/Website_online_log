# Release Notes

## v0.1.0

### Features
- Web-UI zum Konfigurieren und Überwachen von HTTP-Diensten
- REST-API mit Bearer-Token-Authentifizierung
- Token-Verwaltung mit Scope-Kontrolle (`all` / `restricted`) und Pro-Service-Berechtigungen
- IPv4/IPv6 Dual-Stack-Checks mit DNS-Auflösung und IP-Anzeige in der Response
- Audit-Log aller API-Aufrufe
- Auto-Import von Diensten aus `SERVICES_JSON` beim Containerstart
- SQLite-Datenbank (via Node 22 built-in `node:sqlite`, kein nativer Code)
- Docker-Support mit Multi-Stage-Build auf `node:22-alpine`
- Sicherheits-Header (CSP, X-Frame-Options, Referrer-Policy u.a.)
- Rate-Limiting für Admin-Login (10 Versuche / 15 min pro IP)

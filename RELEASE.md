# Releases

Die Notizen stehen hier, nicht in einem Webformular. Sie durchlaufen damit
denselben Review wie der Code, und der Workflow liest sie beim Taggen aus —
was veröffentlicht wird, ist vorher gelesen worden.

## Vorgehen

**1. Version in `pyproject.toml` setzen.** Der Workflow bricht ab, wenn Tag und
Paketversion auseinanderlaufen — `v0.2.0` mit `version = "0.1.0"` im Paket wäre
sonst ein Image, das über sich selbst falsche Auskunft gibt.

**2. Abschnitt hier ergänzen.** Überschrift exakt `## <version>`, ohne `v`.
Fehlt der Abschnitt, bricht der Workflow ab: eine Version ohne Notizen wird
nicht veröffentlicht.

**3. Taggen und schieben:**

```bash
git tag v0.2.0 && git push origin v0.2.0
```

Danach läuft: Tests → Image nach Docker Hub (`0.2.0`, `0.2` und `latest`) →
GitHub-Release mit dem Abschnitt von hier, dem Image-Digest und einem
Deploy-Bündel aus `compose.yaml` und den Beispielkonfigurationen.

Bauten von `main` heißen `<version>-dev`. `latest` zeigt nur auf Releases,
nie auf `main` und nie auf eine Vorabversion.

## Versionierung

`MAJOR.MINOR.PATCH`. Für dieses Projekt heißt das:

- **MAJOR** — Ebene 1 ändert ihre Bedeutung, oder ein bestehendes Deployment
  startet ohne Anpassung nicht mehr.
- **MINOR** — neue Toolkits, Executoren oder Oberflächenfunktionen.
- **PATCH** — Fehlerbehebungen, auch sicherheitsrelevante.

**Nach dem Deploy den Digest pinnen.** Ein Tag lässt sich überschreiben, ein
Digest nicht. Er steht in jedem Release.

---

## 0.1.0

Erste Veröffentlichung. Umgesetzt sind die Stufen 1 und 3 aus
[REQUIREMENTS.md](REQUIREMENTS.md) §14.

### Was es tut

Kontrollierter MCP-Server für Host-Operationen. Agenten bekommen keine Shell,
sondern eine feste Menge geprüfter Aktionen — jede mit eigenem Token, eigenen
Rechten und vollständigem Audit.

- **MCP über Streamable HTTP** unter `/mcp`, Bearer-Token je Identität.
  `tools/list` ist pro Identität gefiltert; nicht erteilte Tools existieren für
  den Agenten nicht.
- **Executoren `local` und `docker`.** Was damit erreichbar ist, entscheidet
  ausschließlich die eigene `toolkits.yaml`.
- **Audit-Log** als JSON Lines mit Rotation. Der wahre Ablehnungsgrund steht
  dort auch dann, wenn der Agent nur eine nichtssagende Antwort bekam.
- **Betriebs- und Verwaltungsoberfläche** unter `/ui`, standardmäßig aus.
  Zugriffskarte, Ebene-1-Grenzen, Katalog, Rechteprofile, Audit-Log mit
  Filtern — und für Admins Schreibzugriff auf Ebene 2.
- **Health-Proben** (`/health/live`, `/health/ready`, `/health/startup`) und
  Prometheus-Metriken unter `/metrics`.

### Leer nach der Installation

`gatekeeper init` legt eine **leere** Ebene 1 (`toolkits: {}`), einen leeren
Katalog und genau einen Administrator an. Direkt danach kann gatekeeper
nichts — nicht ein einziges Kommando.

Das ist Absicht. Ein Werkzeug, das root-äquivalenten Zugriff auf einen Host
vermittelt, sollte keine Fähigkeit mitbringen, die niemand entschieden hat:
ein vorbelegter Katalog hätte im Audit-Log keinen Urheber. Welche Binaries
ein Agent erreichen können soll, weiß ohnehin nur, wer das System kennt.

Fertige Vorlagen zum Abschauen — ein Docker-Toolkit und zehn Compose- und
Diagnose-Tools — stehen in [config/examples/](config/examples/). Übernehmen
heißt: lesen, anpassen, ausrollen.

### Was es garantiert

- **Kein Shell-Interpreter.** Ausführung ausschließlich über argv-Liste. Ein
  Parameter expandiert strukturell zu genau einem Argument — ein Wert kann kein
  zweites erzeugen, unabhängig von seinem Inhalt. Injection ist damit nicht
  wegescapt, sondern konstruktiv ausgeschlossen.
- **Zwei Ebenen.** Binary-Allowlist, gesperrte Argumente, Pfad-Wurzeln,
  geschützte Ressourcen und Obergrenzen stehen in `toolkits.yaml` und sind zur
  Laufzeit unveränderlich. Der Katalog bewegt sich innerhalb dieser Grenzen,
  niemals darüber hinaus — auch nicht über die Oberfläche.
- **Rechte auf Tool-IDs, nicht auf Toolkits.** Ein neu angelegtes Tool landet
  bei niemandem automatisch.
- **Ablehnungen verraten nichts.** Fehlendes Recht und unbekanntes Tool ergeben
  für den Agenten dieselbe Antwort.
- **Geschützte Ressourcen.** Was in `protected_resources` steht, ist für kein
  Tool erreichbar — sonst könnte ein Agent den Kanal abschalten, über den er
  spricht. Die Namen sind deployment-spezifisch; gatekeeper rät sie nicht.
- **Zeitlimit ≠ Fehler.** Läuft ein nicht-idempotentes Tool in sein Zeitlimit,
  meldet der Server „Ausgang unbekannt" statt „fehlgeschlagen". Ein als Fehler
  gemeldetes Zeitlimit provoziert genau die Wiederholung, die bei einem bereits
  durchgelaufenen Schreibzugriff das Duplikat erzeugt.

### Rollen

| Rolle | MCP | Konsole lesen | Ebene 2 ändern |
|---|:--:|:--:|:--:|
| `agent` | ✓ | — | — |
| `viewer` | — | ✓ | — |
| `admin` | — | ✓ | ✓ |

### Bekannte Grenzen

- **Der Docker-Socket ist root-äquivalent auf dem Host.** Bewusst akzeptiert:
  gatekeeper ist genau die Whitelist, die diesen Zugriff einschränkt. Es
  bedeutet aber, dass ein Fehler in gatekeeper ein Root-Fehler ist. Daher der
  Negativtest-Korpus und `read_only`, `cap_drop: ALL`, `no-new-privileges` in
  der `compose.yaml`.
- **Container-Logs enthalten regelmäßig Umgebungsvariablen.** Ein Agent mit
  `docker.compose_logs` auf einen Stack sieht potenziell dessen Secrets. Die
  Maskierung greift erst, wenn gatekeeper die Werte selbst kennt — also mit dem
  Credential-Store in 0.2.
- **Die Oberfläche spricht HTTP.** Ohne TLS läuft das Sitzungs-Cookie ohne
  `Secure`-Flag. Hinter einem HTTPS-Proxy setzt gatekeeper es automatisch. Der
  Port gehört nicht ins offene Netz.
- **Ebene 1 ändert man nur per Redeploy.** Ein Toolkit gewährt Zugriff auf
  echte Binaries; das bleibt eine Deploy-Zeit-Entscheidung (FR-4.11). Die
  Oberfläche legt Tools an, aber niemals ein Toolkit.
- **Noch nicht enthalten:** ZFS und TrueNAS-API (brauchen den
  `truenas`-Executor), Dienst-APIs wie Sonarr/Radarr/Jellyfin (brauchen `http`
  und den Credential-Store), `write_external`.

### Prüfstand

121 Tests unter Linux, davon 49 im Negativkorpus (NFR-8): Metazeichen,
Steuerzeichen, argv-Expansion, Pfad-Traversal, Symlink-Ausbruch,
Geschwister-Verzeichnis mit gleichem Präfix, Ebene-1-Verstöße, überschriebene
abgeleitete Parameter, geschützte Ressourcen, Undurchsichtigkeit von
Ablehnungen. Dazu 25 Tests für den Schreibzugriff der Oberfläche.

Verifiziert wurde gegen einen echten Docker-Daemon, nicht nur in Unit-Tests:
Stacks gestartet, abgefragt und gestoppt, während die Schutzmechanismen einzeln
ausgelöst wurden.

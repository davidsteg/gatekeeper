# Releases

Die Notizen stehen hier, nicht in einem Webformular. Sie durchlaufen damit
denselben Review wie der Code, und der Workflow liest sie beim Taggen aus —
was veröffentlicht wird, ist vorher gelesen worden.

## Die Regel: jede Änderung ist ein Release

**Was auf `main` landet, wird veröffentlicht.** Keine angesammelten,
unveröffentlichten Änderungen; kein „das nehmen wir beim nächsten Mal mit".

Der Grund ist nicht Ordnungsliebe. gatekeeper vermittelt root-äquivalenten
Zugriff auf einen Host. Läuft irgendwo eine Fassung, muss man sagen können,
*welche* — und das geht nur, wenn jeder Stand eine Version mit Notizen hat.
Ein Sammel-Release nach fünf Änderungen macht aus fünf nachvollziehbaren
Schritten einen unteilbaren Klumpen, und im Störungsfall weiß niemand, welcher
davon es war.

**Der Tag wird nicht von Hand gesetzt.** Ausgelöst wird das Release von der
Version in `pyproject.toml`: steht dort eine Fassung, zu der es noch kein Tag
gibt, veröffentlicht der Workflow sie. Damit gehört die Versionsanhebung in
denselben Commit wie die Änderung — und wer sie vergisst, merkt es daran, dass
nichts erscheint.

## Vorgehen

Zwei Dateien im selben Commit wie die Änderung:

**1. `pyproject.toml`** — Version anheben.

**2. `RELEASE.md`** — Abschnitt ergänzen, Überschrift exakt `## <version>`,
ohne `v`. Fehlt er, bricht der Workflow ab, *bevor* ein Image in die Registry
gelangt: eine Version ohne Notizen wird nicht veröffentlicht.

Dann `git push`. Danach läuft von selbst: Tests → Image nach Docker Hub
(`0.2.0`, `0.2`, `latest`) → Git-Tag `v0.2.0` → GitHub-Release mit dem
Abschnitt von hier, dem Image-Digest und einem Deploy-Bündel.

Ein Push ohne neue Version baut nur `<version>-dev` und veröffentlicht nichts.
Das ist der Weg für Zwischenstände und für Änderungen, die nichts am Verhalten
ändern — er ist die Ausnahme, nicht der Normalfall.

`latest` zeigt immer auf den neuesten Bau. Da nach der Regel oben jede Änderung
ein Release ist, ist das in aller Regel auch das neueste Release. Für den
**Betrieb** bleibt trotzdem eine feste Version richtig (NFR-5): `latest` bewegt
sich, und ein Redeploy zöge sonst eine andere Fassung, ohne dass jemand es
entschieden hätte.

## Versionierung

`MAJOR.MINOR.PATCH`. Für dieses Projekt heißt das:

- **MAJOR** — Ebene 1 ändert ihre Bedeutung, oder ein bestehendes Deployment
  startet ohne Anpassung nicht mehr.
- **MINOR** — neue Toolkits, Executoren, Oberflächenfunktionen oder neues
  Verhalten im Betrieb.
- **PATCH** — Fehlerbehebungen, auch sicherheitsrelevante.

**Nach dem Deploy den Digest pinnen.** Ein Tag lässt sich überschreiben, ein
Digest nicht. Er steht in jedem Release.

---

## 0.2.3

Ein nicht beschreibbares Audit-Verzeichnis brach den Start bisher mit einem
rohen `OSError` ab. Jetzt kommt dieselbe Behandlung wie beim
Konfigurationsverzeichnis: Ursache, laufender Benutzer und der Befehl, der es
richtet.

Gestartet wird ohne Audit-Log weiterhin nicht. Ein Dienst, der
Host-Operationen vermittelt und dabei nicht mitschreiben kann, ist schlimmer
als keiner — die Aufrufe finden statt, nur weiß hinterher niemand, welche.

Betrifft vor allem Installationen, deren `audit.dir` in ein eigenes Volume
zeigt: das gehört Docker beim Anlegen root, und der unprivilegierte Benutzer
kommt nicht hinein.

---

## 0.2.2

Behebt, dass der Erststart aus 0.2.0/0.2.1 stillschweigend nichts tat, wenn das
gemountete Verzeichnis dem Container nicht gehört — und der Server danach
`toolkits.yaml not found` meldete, obwohl das Verzeichnis vorhanden war.

Ursache war eine Vorabprüfung mit `os.access`: fehlte das Schreibrecht, stieg
der Erststart aus, ohne etwas zu sagen. Die Meldung des Loaders nannte danach
die falsche Ursache. Jetzt wird geschrieben und der Fehlerfall ausgewertet:

```
Cannot create the configuration in /etc/gatekeeper: [Errno 13] Permission denied
This process runs as 568:568. Docker creates a missing bind-mount source as
root, which that user cannot write to.
On the host, give the directory to the container user, then start again:
  chown -R 568:568 <the directory mounted at /etc/gatekeeper>
```

**Wer das trifft:** Docker legt eine fehlende Bind-Mount-Quelle als `root` an.
Existiert `./gatekeeper/config` auf dem Host nicht, gehört es danach root, und
der unprivilegierte Benutzer im Container kommt nicht hinein. Ein Container
ohne `CAP_CHOWN` kann das nicht selbst richten — die Meldung nennt deshalb den
einen Befehl, der es tut.

`latest` folgt jetzt ausnahmslos dem neuesten Bau, nicht nur dem neuesten
Release. Da nach der Regel oben ohnehin jede Änderung ein Release ist, fallen
beide fast immer zusammen; der Unterschied betraf nur Pushes ohne
Versionsanhebung, die nun ebenfalls `latest` bewegen.

Der Smoke-Test des Images greift dafür gezielt auf `latest` zu, statt sich auf
die Reihenfolge der erzeugten Tags zu verlassen.

Für den Betrieb bleibt die Empfehlung unverändert: feste Version oder Digest
pinnen. `latest` ist zum Ausprobieren da, nicht zum Betreiben.

---

## 0.2.0

Behebt einen Fehler, der jede Erstinstallation von 0.1.0 in eine
Neustartschleife schickte, und macht den ersten Start selbsttragend.

### Behoben

**Die `compose.yaml` von 0.1.0 war kaputt.** Sie hängte `toolkits.yaml` als
einzelne Datei per Bind-Mount ein, um Ebene 1 read-only zu halten. Docker legt
in dem Fall ein **Verzeichnis** an, wenn die Quelldatei auf dem Host fehlt — bei
einer Erstinstallation also immer. Der Container startete daraufhin endlos neu
mit `IsADirectoryError`, und auf dem Host blieb ein Ordner namens
`toolkits.yaml` zurück.

Wer 0.1.0 ausgerollt hat, räumt ihn einmalig weg:

```bash
rm -rf <config>/toolkits.yaml
```

Jetzt genügt **ein** Verzeichnis-Mount, der diesen Fehler nicht kennt. Ebene 1
bleibt geschützt, aber durch Code statt durch den Mount: es schreibt niemand
`toolkits.yaml`, und ein Test hält das fest.

**Konfigurationsfehler nennen die Ursache statt des Symptoms.** Ein Verzeichnis
an Stelle einer Datei erklärt jetzt, dass Docker es angelegt hat und warum.
Geprüft wird vor dem Öffnen, nicht über die Ausnahme — Linux meldet dort
`IsADirectoryError`, Windows `PermissionError`.

### Neu

- **Der erste Start legt die Konfiguration selbst an.** Ein leeres,
  beschreibbares Verzeichnis mounten und starten genügt; `init` von Hand
  entfällt. Der Administrator-Token erscheint einmalig im Containerlog — nach
  dem ersten Anmelden in `/ui` rotieren.

  Geschrieben wird nur, wenn **keine** der drei Dateien existiert. Ein
  verrutschter Mount sieht sonst aus wie eine Erstinstallation, und eine frische
  Konfiguration darüber würde den Fehler verdecken. `GATEKEEPER_NO_BOOTSTRAP=1`
  schaltet das ab.

- **`GATEKEEPER_STATE_DIR`** trennt Ebene 1 und Ebene 2 in getrennte
  Verzeichnisse. Damit kann der Konfigurations-Mount `:ro` sein, während die
  Oberfläche weiterhin schreibt — beides Verzeichnis-Mounts, die Falle von oben
  tritt nicht auf.

### Geändert

`docker.compose_ps` im Beispielkatalog liefert JSON statt einer Textabelle. Ein
Agent, der Spalten abzählt, verliest sich beim ersten langen Containernamen.
`--format json` steht fest im Template; ein Parameterwert kann es nicht
umlenken.

### Sonstiges

Releases entstehen ab jetzt aus der Version in `pyproject.toml`, nicht aus
einem handgesetzten Tag. Jede Änderung auf `main` bekommt eine Version und
Notizen — siehe [Die Regel](#die-regel-jede-änderung-ist-ein-release) oben.

### Prüfstand

127 Tests unter Linux.

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

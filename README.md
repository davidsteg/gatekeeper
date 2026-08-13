# gatekeeper

Kontrollierter MCP-Server für Host-Operationen. Agenten bekommen keine Shell,
sondern eine feste Menge geprüfter Aktionen — jede mit eigenem Token, eigenen
Rechten und vollständigem Audit.

Vollständige Anforderungen: [REQUIREMENTS.md](REQUIREMENTS.md).

---

## Stand: Stufen 1 und 3

Umgesetzt sind zwei der vier Stufen (REQUIREMENTS.md §14):

| | Inhalt | Status |
|---|---|---|
| **1** | MCP + Auth + Audit, Executoren `docker` und `local` | **fertig** |
| **3** | Katalog zur Laufzeit änderbar, Admin-Oberfläche unter `/ui` | **fertig** |
| 2 | Credential-Store, `truenas`, `http` (nur lesend) | offen |
| 4 | `write_external` | offen |

Stufe 3 kam vor Stufe 2 — die Oberfläche wurde vorgezogen. Eine HTTP-API für
Admin-Operationen gibt es bewusst nicht: die Oberfläche schreibt direkt über
`store.py`, und damit existiert kein zusätzlicher maschineller Endpunkt, den
jemand mit einem gestohlenen Token ansprechen könnte.

Stufe 1 löst das ursprüngliche Kernproblem: jeder Agent hat einen eigenen Token
mit eigenen Rechten, und der n8n-Host-Ops-Workflow ist ablösbar. Stufe 3 nimmt
den Neustart aus dem Alltag: Tools und Rechte ändert man in der Oberfläche.

**Bewusst noch nicht enthalten:** ZFS (braucht den `truenas`-Executor) und
Dienst-APIs wie Sonarr/Radarr/Jellyfin (brauchen `http` und den
Credential-Store).

## Sprache

Alles, was das Programm **ausgibt**, ist englisch: das Betriebs-UI, die
Antworten an Agenten, Tool-Titel und -Beschreibungen aus `tools.yaml`, die
Einträge im Audit-Log, Server-Logs und die CLI. Agenten sind Sprachmodelle und
das Audit-Log wird maschinell ausgewertet — beides spricht für eine Sprache.

Kommentare, Docstrings und diese Datei sind deutsch.

## Was der Server garantiert

- **Kein Shell-Interpreter.** Ausführung ausschließlich über argv-Liste.
  Ein Parameter expandiert strukturell zu genau einem Argument — ein Wert kann
  kein zweites erzeugen, unabhängig von seinem Inhalt.
- **Zwei Ebenen.** Binary-Allowlist, gesperrte Argumente, Pfad-Wurzeln und
  geschützte Ressourcen stehen in `toolkits.yaml` und sind zur Laufzeit
  unveränderlich. Der Katalog kann sich innerhalb dieser Grenzen bewegen,
  niemals darüber hinaus.
- **Rechte auf Tool-IDs, nicht auf Toolkits.** Ein neu angelegtes Tool landet
  bei niemandem automatisch.
- **Ablehnungen verraten nichts.** Fehlendes Recht und unbekanntes Tool ergeben
  für den Agenten dieselbe Antwort; das Audit-Log kennt den echten Grund.
- **Geschützte Ressourcen.** Was in `protected_resources` steht, ist für kein
  Tool erreichbar — sonst könnte ein Agent den Kanal abschalten, über den er
  spricht. Die Namen sind deployment-spezifisch und müssen gesetzt werden.
- **Leer nach der Installation.** gatekeeper bringt keinen Katalog mit. Direkt
  nach `init` kann es nichts; jede Fähigkeit ist danach eine Entscheidung, die
  im Audit-Log einen Urheber hat.

## Aufbau

```
src/gatekeeper/
  tier1.py      Ebene-1-Grenzen aus toolkits.yaml
  catalog.py    Tool-Definitionen, Prüfung gegen Ebene 1
  validate.py   Parametervalidierung und argv-Bau      <- sicherheitskritisch
  identity.py   Tokens (scrypt), Rechte, Scopes
  service.py    der Aufrufpfad
  execute.py    Prozessausführung, Zeitlimits, Ausgabegrenzen
  audit.py      JSON-Lines, Rotation, Maskierung
  server.py     MCP-Protokoll, Auth-Middleware, Health, Metrics
  store.py      Schreibzugriff auf Ebene 2                <- sicherheitskritisch
  ui.py         Oberflaeche, eigene Sitzung, CSRF
config/
  examples/                Vorlagen zum Abschauen, keine Voreinstellung
    toolkits.yaml            Ebene-1-Beispiel mit docker und diag
    tools.yaml               optionaler Startvorrat an Tools
    identities.yaml          Beispiel-Rechteprofile
tests/
  test_negative_corpus.py  Angriffe, die fehlschlagen MÜSSEN (NFR-8)
  test_behaviour.py        was funktionieren muss
  test_integration_mcp.py  Ende-zu-Ende über echtes MCP
  test_ui.py               Trennung von UI-Sitzung und MCP-Token
  test_ui_admin.py         Schreibzugriff: Ebene-1-Grenzen, CSRF, Aussperrschutz
```

## Entwicklung

```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
```

```bash
.venv/bin/python -m pytest -q
```

Konfiguration prüfen, ohne zu starten — gehört vor jeden Deploy:

```bash
gatekeeper --toolkits <dir>/toolkits.yaml --tools <dir>/tools.yaml --identities <dir>/identities.yaml check
```

## Deployment

**1. Dataset anlegen** (nie `mkdir`):

```bash
zfs create <pool>/raid/gatekeeper
```

**2. Struktur und Rechte:**

```bash
mkdir -p /mnt/raid/gatekeeper/config /mnt/raid/gatekeeper/logs && chown -R 568:568 /mnt/raid/gatekeeper
```

**3. Leerzustand anlegen.** gatekeeper liefert keine Konfiguration mit:

```bash
docker run --rm -v /mnt/raid/gatekeeper/config:/etc/gatekeeper davidsteg/gatekeeper:0.1.0 init
```

Das erzeugt eine minimale `toolkits.yaml` (nur `diag`, lesend), eine leere
`tools.yaml` und eine `identities.yaml` mit **einem** Administrator, dessen
Token einmalig ausgegeben wird. Danach kann der Server starten und kann nichts
— jede Fähigkeit ab hier ist eine bewusste Entscheidung mit Eintrag im
Audit-Log.

**4. Ebene 1 erweitern.** Für Docker-Zugriff das `docker`-Toolkit aus
[config/examples/toolkits.yaml](config/examples/toolkits.yaml) übernehmen und
anpassen — insbesondere `path_roots` und `protected_resources`. Das ist
Deploy-Zeit: nach der Änderung neu ausrollen.

Die `compose.yaml` mountet das Verzeichnis **beschreibbar** und legt
`toolkits.yaml` als eigenen `:ro`-Mount darüber. Damit bildet das Deployment
die zwei Ebenen ab: die Oberfläche darf `tools.yaml` und `identities.yaml`
ändern, an Ebene 1 kommt auch der eigene Prozess nicht heran.

**5. GID des Docker-Sockets ermitteln** und in `compose.yaml` unter `group_add`
eintragen — sonst erreicht der unprivilegierte Benutzer den Socket nicht:

```bash
stat -c '%g' /var/run/docker.sock
```

**6. Deploy via Dockhand:**

```bash
docker exec ix-dockhand-dockhand-1 docker compose -p gatekeeper -f /mnt/raid/gatekeeper/compose.yaml up -d
```

**7. Prüfen:**

```bash
curl -s localhost:8080/health/ready
```

**8. Tools anlegen** unter `/ui` mit dem Administrator-Token aus Schritt 3.
Vorlagen zum Abschauen stehen in
[config/examples/tools.yaml](config/examples/tools.yaml).

## Agent anbinden

```yaml
mcp_servers:
  gatekeeper:
    transport: streamable_http
    url: http://<host>:8080/mcp
    headers:
      Authorization: "Bearer gk_..."
```

Jeder Agent bekommt seinen eigenen Token. `tools/list` liefert dann genau die
Tools, die dieser Agent aufrufen darf — die übrigen existieren für ihn nicht.

## Oberfläche

Ein server-gerendertes Dashboard unter `/ui`: Zugriffskarte, Ebene-1-Grenzen,
Katalog mit Parametern und Berechtigten, Rechteprofile, Audit-Log mit Filtern
— und für Admins der volle Schreibzugriff auf Ebene 2.

Standardmäßig aus. Einschalten mit `--ui` bzw. `GATEKEEPER_UI=1`, in
`compose.yaml` als `command: ["serve", "--ui"]`. `--ui-read-only` liefert die
Oberfläche ohne jede Schreibfunktion, unabhängig von den Rollen.

### Rollen

| Rolle | MCP | Konsole lesen | Ebene 2 ändern |
|---|:--:|:--:|:--:|
| `agent` | ✓ | — | — |
| `viewer` | — | ✓ | — |
| `admin` | — | ✓ | ✓ |

Ein Agenten-Token öffnet die Oberfläche nicht. Ohne mindestens eine Identität
mit `viewer` oder `admin` startet der Server mit `--ui` gar nicht erst.

### Was ein Admin darf — und was nicht

Anlegen, ändern, ab- und anschalten, löschen von **Tools**; anlegen, ändern,
löschen von **Identitäten**; **Tokens** ausstellen und rotieren. Änderungen
wirken sofort, ohne Neustart.

**Ebene 1 kann die Oberfläche nicht anfassen.** Es gibt keine Route und keine
Funktion, die `toolkits.yaml` schreibt. Jede Definition aus dem Formular läuft
durch `parse_tool_spec` — dieselbe Prüfung wie beim Start. Ein Tool mit
fremdem Binary, gesperrtem Argument, Pfad außerhalb der Wurzeln oder Zeitlimit
über der Obergrenze wird abgewiesen, nicht zurechtgestutzt. Genau deshalb ist
es vertretbar, Tools per Webformular anzulegen: der schlimste Fehlgriff eines
Admins bleibt innerhalb dessen, was der Deploy erlaubt hat.

Der Editor zeigt die Grenzen des Toolkits daneben an — sonst wäre er ein
Ratespiel mit Fehlermeldung.

### Weitere Leitplanken

- **Der letzte Admin ist geschützt.** Löschen oder Herabstufen wird abgelehnt,
  wenn danach niemand mehr anmelden könnte. Der Fehler ist billig zu verhindern
  und teuer zu beheben.
- **CSRF.** Jedes schreibende Formular trägt ein Sitzungs-Token. `SameSite=Strict`
  allein genügt nicht: eine Seite auf derselben Site gilt nicht als fremd.
- **Optimistische Nebenläufigkeit.** Jedes Formular kennt die Revision der Datei,
  aus der es gebaut wurde. Hat inzwischen jemand anders geschrieben, wird
  abgelehnt statt zugebügelt.
- **Atomar geschrieben.** Temporäre Datei, `fsync`, `os.replace`. Ein Absturz
  mittendrin hinterlässt die alte Datei, nie eine halbe.
- **Nach dem Schreiben wird aus der Datei neu geladen**, nicht aus dem Speicher.
  Was die Oberfläche zeigt, kann damit nicht von dem abweichen, was ein Neustart
  ergäbe.
- **Alles im Audit-Log**, mit Urheber. Eine Löschung schreibt die vollständige
  Definition mit — sie bleibt aus dem Log heraus wiederherstellbar.
- **Token-Rotation beendet offene Sitzungen** der betroffenen Identität.

### Zugriffskarte

Die Karte auf der Übersicht beantwortet die Frage, für die man sonst drei
Dateien nebeneinanderlegt: welche Identität erreicht über welches Toolkit was,
und was ist für alle gesperrt. Grün heißt erteilt, rot gestrichelt heißt
geschützt (FR-4.12). Serverseitig als SVG berechnet — wie das
Aktivitätsdiagramm auch, denn im Browser läuft kein Skript.

### Ersten Admin anlegen

Erledigt `gatekeeper init` (Deployment, Schritt 3) — es legt genau einen
Administrator an und gibt den Token einmalig aus. Weitere Identitäten entstehen
danach in der Oberfläche.

Einen zusätzlichen Hash von Hand erzeugen:

```bash
docker exec gatekeeper gatekeeper token
```

**Warum die Sitzung nicht für `/mcp` gilt.** Der MCP-Endpunkt authentifiziert
nur über den `Authorization`-Header, und genau das macht ihn CSRF-fest: ein
Browser hängt einen solchen Header nicht von sich aus an, eine fremde Seite
kann ihn also nicht erzeugen. Ein Cookie dagegen wird automatisch mitgeschickt.
Würde die Auth-Middleware es akzeptieren, genügte eine beliebige Webseite mit
einem Formular auf `/mcp`, um im Namen des angemeldeten Admins Tools auf dem
Host auszuführen. Die UI-Sitzung ist deshalb ein getrennter Mechanismus, den
`/mcp` nie ansieht — `test_ui.py` und `test_ui_admin.py` halten das fest.

**Kein JavaScript.** Die CSP verbietet Skripte vollständig. Das folgt aus der
Datenlage: das Audit-Log zeigt Parameterwerte, die Agenten geschickt haben,
bei abgelehnten Aufrufen sogar unvalidierte. Ohne Skriptausführung bleibt ein
eingeschleustes `<script>` auch dann folgenlos, wenn die Maskierung versagt.

## Ein Tool hinzufügen

In Stufe 1 über `tools.yaml`, danach Neustart. Die Definition wird beim Laden
gegen Ebene 1 geprüft; verletzt sie die Grenzen, wird sie deaktiviert und die
Verletzung protokolliert (mit `--strict` bricht der Start stattdessen ab).

```yaml
- id: docker.compose_ps
  toolkit: docker            # liefert Executor, Binaries, Pfad-Wurzeln, Grenzen
  binary: /usr/bin/docker    # muss exakt in der Allowlist des Toolkits stehen
  category: read             # read | write | write_external
  idempotent: true
  enabled: true
  argv: ["compose", "-p", "{stack}", "-f", "{compose_path}", "ps"]
  parameters:
    stack:
      type: string
      required: true
      pattern: "^[a-z0-9][a-z0-9_-]{0,62}$"   # Pflicht — kein freier Text
    compose_path:
      type: path
      derived: "/mnt/raid/{stack}/compose.yaml"   # Server baut ihn, nicht der Agent
      must_resolve_under: /mnt/raid
  required_scopes: ["stack:{stack}"]
```

Anschließend muss die Identität das Tool noch ausdrücklich erteilt bekommen —
Anlegen und Berechtigen sind zwei getrennte Schritte.

## Sicherheitshinweise

**Der Docker-Socket ist root-äquivalent auf dem Host.** Das ist bewusst
akzeptiert, weil gatekeeper genau die Whitelist ist, die diesen Zugriff
einschränkt — aber es bedeutet: ein Fehler in gatekeeper ist ein Root-Fehler.
Daher der Negativtest-Korpus, und daher `read_only`, `cap_drop: ALL` und
`no-new-privileges` in der `compose.yaml`.

**Container-Logs enthalten regelmäßig Umgebungsvariablen.** Ein Agent mit
`docker.compose_logs` auf einen Stack sieht potenziell dessen Secrets. Die
Maskierung greift erst ab Stufe 2, wenn gatekeeper die Werte selbst kennt.

**`identities.yaml` enthält nur Hashes** und ist damit nicht secret-kritisch.
Die Klartext-Tokens leben ausschließlich in den Agenten-Konfigurationen.

**Ein Admin-Token ist mächtig.** Wer es hat, kann Tools anlegen und Rechte
vergeben — innerhalb von Ebene 1, aber das reicht für jeden Stack unter
`/mnt/raid`. Behandle es wie einen Host-Zugang: eigener Token je Person,
Rotation über die Oberfläche, und `role: viewer` für alle, die nur schauen
wollen.

**Der Port gehört nicht ins offene Netz.** Die Oberfläche spricht über HTTP;
ohne TLS läuft das Sitzungs-Cookie ohne `Secure`-Flag. Hinter einem Reverse
Proxy mit HTTPS setzt gatekeeper es automatisch.

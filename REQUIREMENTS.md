# gatekeeper — Requirements-Dokument

**Zweck:** Kontrollierter MCP-Server als einziger Kanal für Host-Operationen **und externe API-Zugriffe**. Er liefert das *Fundament* — Protokoll, Authentifizierung, Rechte, Parametervalidierung, Ausführung, Audit. Die konkreten Tools werden zur Laufzeit von einem Admin-Agenten über eine API verwaltet.

**Status:** Entwurf v2
**Ersetzt:** v1 (statischer Tool-Katalog im Code)
**Deployment:** Docker-Container auf TrueNAS, via Dockhand, nach Homelab-Regeln (ZFS-Dataset, chown 568:568)

---

## 1. Was sich gegenüber v1 ändert

v1 hat die Whitelist als Code definiert: der Server kannte `docker compose up`, `zfs create` usw. fest einkompiliert. v2 kehrt das um — **die Whitelist ist Daten**, verwaltet über eine Admin-API.

Das verschiebt die Sicherheitsgrenze und ist die wichtigste Designentscheidung dieses Dokuments:

> In v1 galt: *der Server kann nur, was einkompiliert ist.*
> In v2 gilt: *der Server kann nur, was der Admin definiert hat — innerhalb der Grenzen, die beim Deploy festgezurrt wurden.*

Ohne diese zweite Hälfte des Satzes wäre der Admin-Token ein Generalschlüssel für beliebige Host-Befehle, und die gesamte Schutzwirkung von gatekeeper wäre eine Frage der Sorgfalt eines Agenten. Deshalb definiert §6 ein **Zwei-Ebenen-Modell**, das die Admin-API nachweisbar einsperrt.

Der Tool-Katalog aus v1 verschwindet nicht — er wird zum **Seed-Katalog** (§7), der beim ersten Start geladen und danach über die API weitergepflegt wird.

---

## 2. Architektur-Schichten

Ein Aufruf durchläuft immer alle Schichten, in dieser Reihenfolge:

| # | Schicht | Aufgabe |
|---|---------|---------|
| 1 | **MCP-Transport** | JSON-RPC 2.0, `tools/list`, `tools/call` |
| 2 | **Authentifizierung** | Token → Identität (Agent oder Admin) |
| 3 | **Autorisierung** | Darf diese Identität dieses Tool mit diesen Ressourcen? |
| 4 | **Tool-Registry** | Nachschlagen der aktiven Tool-Definition |
| 5 | **Parametervalidierung** | Typ, Regex, Pfad-Auflösung, Ressourcen-Scope |
| 6 | **argv-Bau** | Strukturierter Befehlsaufbau, **niemals** Shell-String |
| 7 | **Executor** | Ausführung über einen beim Deploy freigeschalteten Backend-Typ |
| 8 | **Audit** | Protokollierung von Ergebnis, Dauer, Exit-Code |

Schichten 2, 3, 5, 6, 7, 8 sind das Fundament und stecken im Code. Schicht 4 ist Konfiguration zur Laufzeit.

---

## 3. Funktionale Anforderungen — MCP-Protokoll

- **FR-1.1** Implementiert MCP über **Streamable HTTP** (Spec ≥ 2025-03-26), sodass Hermes-Agenten den Server als `mcp_servers`-Eintrag in ihrer `config.yaml` nutzen können.
- **FR-1.2** Der in v1 genannte HTTP+SSE-Transport ist in der MCP-Spec deprecated. Er wird **nur dann** zusätzlich implementiert, wenn die eingesetzte Hermes-Version Streamable HTTP nicht beherrscht (→ §17, offene Frage).
- **FR-1.3** Exponiert `tools/list` und `tools/call`.
- **FR-1.4** `tools/list` liefert **pro Identität gefiltert** — ein Agent sieht ausschließlich Tools, die er auch aufrufen darf. Nicht sichtbare Tools existieren für ihn nicht.
- **FR-1.5** Ändert der Admin den Katalog, sendet der Server `notifications/tools/list_changed` an alle betroffenen verbundenen Clients. Ohne das arbeiten Agenten mit einem veralteten Toolset weiter.
- **FR-1.6** Zwei getrennte Endpunkte: `/mcp` für Agenten, `/admin/mcp` für Administration (siehe FR-4.2).

---

## 4. Funktionale Anforderungen — Authentifizierung & Identität

- **FR-2.1** Jeder Agent (homelab, media, dev) erhält einen eigenen API-Token. Kein geteilter Zugang.
- **FR-2.2** Jeder Token ist mit genau einer Identität verknüpft; jede Identität trägt eine Rolle (`agent` oder `admin`) und ein Rechteprofil (§7).
- **FR-2.3** Unbekannter oder ungültiger Token → HTTP 401, kein Tool-Zugriff, Audit-Eintrag.
- **FR-2.4** Tokens werden **nur als Hash** persistiert (argon2id oder scrypt). Die Konfigurationsdatei enthält niemals Klartext-Tokens und ist damit nicht secret-kritisch — relevant, weil sie nach Homelab-Regeln im Dataset mit `chown 568:568` liegt.
- **FR-2.5** Token-Vergleich erfolgt in konstanter Zeit.
- **FR-2.6** Der Klartext-Token existiert nur an zwei Stellen: einmalig bei der Erzeugung (Ausgabe an den Betreiber) und in der `config.yaml` des jeweiligen Agenten.
- **FR-2.7** Tokens können widerrufen werden, ohne dass andere Tokens neu ausgestellt werden müssen.

### Trennung Agent / Admin

- **FR-2.8** Der Admin-Token ist **kein** Agent-Token mit Zusatzrechten, sondern eine eigene Rolle auf einem eigenen Endpunkt (`/admin/mcp`).
- **FR-2.9** Admin-Tools erscheinen **niemals** in `tools/list` des Agenten-Endpunkts, auch nicht für den Admin-Token. Ein kompromittierter Agenten-Pfad erreicht die Katalogverwaltung nicht.
- **FR-2.10** Der Admin-Endpunkt ist optional per Netzwerk zusätzlich einschränkbar (Bind-Adresse / Quell-IP).

---

## 5. Funktionale Anforderungen — Tool-Registry & Admin-API

Das neue Herzstück. Der Admin-Agent verwaltet den Tool-Katalog über MCP-Tools im Namespace `admin.*` auf `/admin/mcp`.

- **FR-3.1** Mindestumfang der Admin-Operationen:

  | Tool | Wirkung |
  |------|---------|
  | `admin.tool_list` | Alle Definitionen inkl. Version und Status |
  | `admin.tool_get` | Eine Definition im Volltext |
  | `admin.tool_create` | Neue Definition anlegen (immer `enabled: false`) |
  | `admin.tool_update` | Neue **Version** einer Definition anlegen |
  | `admin.tool_enable` / `admin.tool_disable` | Aktivierung schalten |
  | `admin.tool_delete` | Definition stilllegen (soft delete, Historie bleibt) |
  | `admin.tool_validate` | Definition prüfen, **ohne** sie zu speichern |
  | `admin.grant_list` / `admin.grant_set` | Rechteprofile pro Identität |
  | `admin.cred_list` | Nur **Namen**, Typ, Anlagedatum, letzte Rotation — **nie Werte** |
  | `admin.cred_set` | Wert anlegen oder rotieren (write-only, §11) |
  | `admin.cred_delete` | Credential entfernen |
  | `admin.cred_pubkey` | Öffentlichen Teil eines SSH-Schlüssels ausgeben (FR-10.9) |
  | `admin.audit_query` | Audit-Log durchsuchen |

- **FR-3.2** **Neue Definitionen sind nach `create` inaktiv.** Aktivierung ist ein separater, eigens auditierter Aufruf. Verhindert, dass ein Tippfehler oder ein halbfertiger Agentenlauf sofort produktiv wird.
- **FR-3.3** Definitionen sind **versioniert und append-only**. `tool_update` erzeugt Version *n+1*, überschreibt nichts. Jeder Audit-Eintrag referenziert die Definitionsversion, die tatsächlich ausgeführt wurde — sonst lässt sich im Nachhinein nicht rekonstruieren, was ein Aufruf zum Zeitpunkt *T* wirklich getan hat.
- **FR-3.4** `admin.tool_validate` und jedes `create`/`update` prüfen die Definition vollständig gegen die Deploy-Grenzen aus §6. Eine Definition, die diese verletzt, wird **abgelehnt und nicht gespeichert**.
- **FR-3.5** Jede Katalogänderung wird mit Vorher-/Nachher-Zustand, Admin-Identität und Zeitstempel auditiert (§12).
- **FR-3.6** Der Katalog wird persistent im Dataset gehalten und überlebt Container-Neustarts.
- **FR-3.7** Der Admin kann sich selbst keine Rechte jenseits von §6 erteilen. `admin.grant_set` kann Agenten nur Teilmengen des Deploy-Rahmens zuweisen.

---

## 6. Funktionale Anforderungen — Sicherheitsgrenzen (Zwei-Ebenen-Modell)

**Dies ist die Anforderung, die v2 überhaupt vertretbar macht.** Ohne sie ist der Admin-Token gleichbedeutend mit Root auf dem Host.

### Ebene 1 — Deploy-Zeit, zur Laufzeit unveränderlich

Festgelegt in der Container-Konfiguration (Env / gemountete Datei). **Nicht** über die Admin-API änderbar. Änderung erfordert Redeploy.

- **FR-4.1 Binary-Allowlist:** Eine Liste erlaubter ausführbarer Programme mit absolutem Pfad, z.B. `/usr/bin/docker`, `/usr/bin/uptime`. Eine Tool-Definition, deren Executable nicht exakt in dieser Liste steht, wird abgelehnt. Der Admin kann `rm` nicht definieren, wenn `rm` nicht freigeschaltet ist.
- **FR-4.2 Argument-Verbote pro Binary:** Optionale Sperrliste von Unterbefehlen und Flags, z.B. für `/usr/bin/docker` die Sperre von `rm`, `--privileged`, `exec`. Fängt den Fall ab, dass ein erlaubtes Binary destruktive Modi kennt.
- **FR-4.3 Pfad-Wurzeln:** Liste erlaubter Basisverzeichnisse (z.B. `/mnt/raid`). Jeder Pfadparameter muss nach `realpath`-Auflösung darunter liegen. Verhindert Symlink-Ausbruch trotz sauber validiertem Stack-Namen.
- **FR-4.4 Executor-Freischaltung:** Welche Executor-Typen (§10) überhaupt verfügbar sind.
- **FR-4.5 Harte Obergrenzen:** Maximales Timeout, maximale Ausgabegröße, maximale Parallelität. Eine Tool-Definition darf diese unterschreiten, nie überschreiten.

### Ebene 2 — Laufzeit, Admin-API

Innerhalb Ebene 1 frei gestaltbar: Tool-Definitionen, Parameter-Schemata, Rechteprofile, Timeouts unterhalb der Obergrenze.

- **FR-4.6** Der Server lehnt jede Definition ab, die Ebene 1 verletzt — bei `create`, bei `update`, **und erneut bei jeder Ausführung**. Doppelte Prüfung, weil sich Ebene 1 durch einen Redeploy verschärft haben kann, während im Katalog noch ältere Definitionen liegen.
- **FR-4.7** Beim Start protokolliert der Server alle Definitionen, die gegen die aktuelle Ebene 1 verstoßen, und deaktiviert sie automatisch, statt sie stillschweigend zu tolerieren.

### Ebene 1 wird pro Toolkit deklariert

- **FR-4.8** Ein **Toolkit** ist die Einheit, an der Ebene-1-Grenzen hängen: `{Executor, Credential, erlaubte Binaries und Unterbefehle, Pfad-Wurzeln, Default-Limits}`. FR-4.1 bis FR-4.5 gelten **je Toolkit**, nicht global.
- **FR-4.9** Eine global geführte Allowlist wäre zwangsläufig die Vereinigungsmenge aller Toolkit-Bedürfnisse und damit überbreit: `diag.uptime` braucht keine Pfad-Wurzel unter `/mnt/raid`, `docker.compose_up` schon. Die Toolkit-Grenze verhindert, dass Rechte des einen Tools implizit dem anderen zugutekommen.
- **FR-4.10** Jedes Tool gehört zu **genau einem** Toolkit und erbt dessen Grenzen. Ein Tool kann die Grenzen seines Toolkits verschärfen, niemals erweitern.
- **FR-4.11** Toolkits werden **ausschließlich zur Deploy-Zeit** deklariert. Die Admin-API kann Tools anlegen, aber kein Toolkit — sonst wäre Ebene 1 wieder zur Laufzeit veränderbar.
- **FR-4.12 Geschützte Ressourcen.** Ebene 1 führt je Toolkit eine Sperrliste von Ressourcen, die kein Tool berühren darf — unabhängig von Rechten und Scopes. Zwingend darin:
  - `gatekeeper` selbst. Ein `docker.compose_down` auf den eigenen Stack beendet den Prozess mitten im Aufruf: die Antwort erreicht den Agenten nie, er wertet das als Timeout und versucht es womöglich erneut — nur ist niemand mehr da, der antwortet. Wiederherstellung geht dann nur noch von Hand am Host.
  - `ix-dockhand`. Dockhand ist der Deploy-Mechanismus (§14). Wer ihn abschaltet, verliert das Werkzeug, mit dem er ihn wieder anschalten würde.
  - Reverse-Proxy und alles, worüber der Admin-Zugang läuft.

  Ebene 1 kann Syntax und Zielpfade prüfen, aber keine Bedeutung: `docker compose down` ist für den Validator dieselbe Operation, egal ob sie einen Medien-Stack oder die eigene Laufzeitumgebung trifft. Diese Sperrliste ist die einzige Stelle, an der solches Wissen abgelegt werden kann.

```yaml
# Ebene-1-Konfiguration (Deploy-Zeit, nicht über die Admin-API änderbar)
toolkits:
  docker:
    executor: docker
    binaries: ["/usr/bin/docker"]
    denied_args: ["rm", "exec", "--privileged", "system prune"]
    path_roots: ["/mnt/raid"]
    max_timeout_seconds: 300
    max_output_bytes: 262144
  diag:
    executor: local
    binaries: ["/usr/bin/uptime", "/usr/bin/free", "/usr/bin/df"]
    path_roots: []          # bewusst leer — kein Tool hier nimmt Pfade entgegen
    max_timeout_seconds: 10
    max_output_bytes: 16384
  github:
    executor: http
    base_url: "https://api.github.com"     # Host ist hier fixiert, nie Parameter
    allowed_methods: ["GET", "POST"]
    allowed_path_prefixes: ["/repos/davidsteg/", "/user/repos"]
    allowed_cidrs: ["140.82.112.0/20", "192.30.252.0/22"]
    credential: env:GITHUB_TOKEN           # serverseitig injiziert, nie sichtbar
    follow_redirects: false
    max_timeout_seconds: 20
    max_output_bytes: 131072
```

---

## 7. Funktionale Anforderungen — Tool-Definitionsmodell

- **FR-5.1** Eine Tool-Definition besteht mindestens aus: `id`, `toolkit`, `version`, `title`, `description`, `category` (`read` \| `write` \| `write_external`), `argv`- bzw. Request-Template, `parameters`, `timeout_seconds`, `max_output_bytes`, `required_scopes`, `enabled`. Der Executor wird **nicht** am Tool gewählt, sondern vom Toolkit geerbt (FR-4.8).
- **FR-5.1a** `category` kennt drei Werte: `read`, `write` und **`write_external`**. Letzteres bezeichnet Aktionen mit nach außen sichtbarer Wirkung — ein Issue anlegen, eine Nachricht senden, etwas veröffentlichen. Diese Trennung ist nötig, weil `docker.compose_up` und `github.create_issue` beide „write" sind, aber grundverschiedene Folgen haben: das eine ist rückholbar und bleibt im Haus, das andere ist öffentlich und dauerhaft. `write_external` erfordert einen ausdrücklichen Grant, wird nie über eine Kategorie-Regel mitvergeben und protokolliert die vollständige Anfrage-Nutzlast (FR-9.1).
- **FR-5.1b** Tool-IDs folgen dem Schema `<toolkit>.<aktion>` — `docker.compose_up`, `zfs.create`, `diag.uptime`, `admin.tool_list`. Damit ist die Toolkit-Zugehörigkeit für Agent, Audit-Log und Rechteprofil unmittelbar ablesbar, und `admin` ist schlicht das Toolkit, das nur auf `/admin/mcp` erreichbar ist.
- **FR-5.2** `description` wird dem Agenten als MCP-Tool-Beschreibung ausgeliefert und ist damit sicherheitsrelevant für die *Nutzbarkeit*: sie muss dem Modell klar sagen, was das Tool tut und was nicht.
- **FR-5.3 argv-Template statt Shell-String:** `argv` ist eine **Liste**. Jedes Listenelement wird einzeln aufgelöst.
- **FR-5.4** **Ein Parameter expandiert immer zu genau einem argv-Element.** Ein Parameterwert kann strukturell keine zusätzlichen Argumente erzeugen, egal welchen Inhalt er hat. Das — nicht eine Zeichen-Blacklist — ist der eigentliche Schutz gegen Command-Chaining.
- **FR-5.5** Abgeleitete Parameter (`derived`): Werte, die der Server aus einem Template selbst berechnet und die der Agent **nicht** übergeben kann, z.B. `compose_path` aus `stack`.
- **FR-5.6** Parametertypen mindestens: `string` (mit Pflicht-`pattern`), `enum`, `integer` (mit Grenzen), `path` (mit `must_resolve_under`), `boolean` (Flag-Zuordnung, kein freier Wert).
- **FR-5.7** Ein `string`-Parameter **ohne** `pattern` wird abgelehnt. Es gibt keinen unvalidierten Freitext-Parameter.

### Beispiel (Seed-Katalog)

```yaml
- id: docker.compose_up
  toolkit: docker          # Executor, Binaries, Pfad-Wurzeln und Limits kommen von hier
  version: 3
  title: "Stack starten"
  description: "Startet einen Docker-Compose-Stack via 'docker compose up -d'."
  category: write
  enabled: true
  argv: ["compose", "-p", "{stack}", "-f", "{compose_path}", "up", "-d"]
  parameters:
    stack:
      type: string
      pattern: "^[a-z0-9][a-z0-9_-]{0,62}$"
      required: true
    compose_path:
      type: path
      derived: "/mnt/raid/{stack}/compose.yaml"
      must_resolve_under: "/mnt/raid"
  timeout_seconds: 120
  max_output_bytes: 65536
  required_scopes: ["stack:{stack}"]
```

---

## 8. Funktionale Anforderungen — Parametervalidierung & Ausführung

- **FR-6.1** Es wird **kein Shell-Interpreter** verwendet. Ausführung ausschließlich über argv-Liste (`shell=False`). Keine Konkatenation von Agenten-Eingaben zu einem Befehlsstring.
- **FR-6.2** Validierung erfolgt als **Allowlist** (Regex/Enum pro Parameter), nicht als Blacklist verbotener Zeichen. Eine Metazeichen-Sperrliste ist bei FR-6.1 funktional wirkungslos und war in v1 zudem unvollständig (es fehlten u.a. Zeilenumbruch, `\`, `*`, `?`, `'`, `"`, `#`, `!`).
- **FR-6.3** Als Defense-in-Depth werden Steuerzeichen und Nullbytes in allen Parametern dennoch abgelehnt — mit Audit-Eintrag, weil ihr Auftreten ein Angriffsindikator ist.
- **FR-6.4 Timeout:** Jeder Aufruf hat ein hartes Timeout. Bei Ablauf wird der Prozessbaum beendet und der Aufruf als Fehler auditiert.
- **FR-6.5 Ausgabebegrenzung:** stdout/stderr werden bei `max_output_bytes` abgeschnitten, mit Kennzeichnung im Ergebnis. Ohne das kann ein einzelnes `logs`-Kommando gigabytegroße Antworten erzeugen.
- **FR-6.6** Log-artige Tools erzwingen eine Mengenbegrenzung (z.B. `--tail`) als Pflichtparameter mit Obergrenze.
- **FR-6.7 Nebenläufigkeit:** Pro Ressource (z.B. Stack-Name) wird serialisiert. Zwei gleichzeitige `up -d` auf denselben Stack dürfen sich nicht überlappen.
- **FR-6.8 Rate-Limiting:** Pro Identität, getrennt für `read` und `write`.
- **FR-6.9 Ein Timeout ist kein Beweis für Nicht-Ausführung.** FR-6.4 beendet den Aufruf nach Ablauf der Frist — auf der Gegenseite kann die Operation aber längst durchgelaufen sein. Bei `docker.compose_up` ist das folgenlos, weil die Operation idempotent ist. Bei `write_external` nicht: ein abgebrochenes `github.create_issue` hat das Issue womöglich angelegt. Daraus folgt:
  - gatekeeper wiederholt **niemals** selbsttätig einen Aufruf.
  - Ein Timeout bei `write` oder `write_external` wird dem Agenten als **„Ausgang unbekannt"** zurückgegeben, nicht als Fehler. Ein als Fehler gemeldeter Timeout provoziert genau die Wiederholung, die das Duplikat erzeugt.
  - Unterstützt der Zieldienst Idempotenz-Schlüssel, setzt gatekeeper sie.
  - Der unklare Ausgang wird als solcher auditiert und ist über die UI auffindbar.
- **FR-6.10 Idempotenz gehört in die Tool-Definition.** Jede Definition erklärt, ob sie idempotent ist. Nicht-idempotente Tools sind in der Beschreibung für den Agenten als solche gekennzeichnet — ein Modell, das das weiß, wiederholt seltener blind.

---

## 9. Funktionale Anforderungen — Rechtemodell

v1 kannte nur `read` vs. `write`. Das reicht nicht: die Matrix schrieb dem dev-Agenten „nur dev-Stacks" zu — eine Einschränkung auf **Ressourcen**, nicht auf Verben.

- **FR-7.1** Ein Rechteprofil hat zwei Dimensionen:
  1. **Tools** — welche Tool-IDs (oder Kategorien) die Identität aufrufen darf.
  2. **Scopes** — auf welche Ressourcen, als Muster: `stack:media-*`, `dataset:tank/raid/dev-*`.
- **FR-7.2** Ein Tool deklariert in `required_scopes`, welchen Scope ein Aufruf beansprucht — mit eingesetzten Parameterwerten. Der Aufruf ist nur erlaubt, wenn das Profil den resultierenden Scope abdeckt.
- **FR-7.3** Default ist **deny**. Nicht ausdrücklich erteilte Rechte existieren nicht.
- **FR-7.4** Rechteprofile sind über `admin.grant_set` verwaltbar und werden versioniert wie Tool-Definitionen.
- **FR-7.5 Keine Grants auf Toolkit-Ebene.** Rechte werden **auf Tool-IDs** erteilt, nie auf ein ganzes Toolkit. Ein Grant der Form „media darf `toolkit:docker` lesen" wäre bequem, würde aber bedeuten: legt der Admin-Agent morgen ein weiteres Read-Tool im Docker-Toolkit an, besitzt media es automatisch. Bei einer SaaS-Tool-Plattform ist das harmlos, hier ist es ein Rechteausweitungs-Pfad ohne menschlichen Zwischenschritt. Das Toolkit ist Träger von Grenzen und Gruppierung — **nicht** von Rechten.
- **FR-7.6** Wird ein neues Tool angelegt, besitzt es folglich zunächst **keine** Identität als Berechtigten. Die Zuweisung ist ein eigener, auditierter `grant_set`-Aufruf — der zweite bewusste Schritt neben der Aktivierung aus FR-3.2.
- **FR-7.7 Ablehnungen verraten nichts über den Katalog.** Ruft ein Agent ein Tool auf, das existiert, für das ihm aber das Recht fehlt, ist die Antwort **identisch** zu der bei einem nicht existierenden Tool. Andernfalls wird `tools/call` zum Orakel, mit dem sich der vollständige Katalog abfragen lässt — und FR-1.4 wäre unterlaufen, das Tools gerade unsichtbar machen soll. Die Asymmetrie ist Absicht: **dem Agenten gegenüber minimal auskunftsfreudig, dem Audit-Log gegenüber maximal** (FR-9.2 hält den echten Ablehnungsgrund fest).

### Ausgangsmatrix (Seed, danach über API pflegbar)

| Identität | Tools | Scopes |
|-----------|-------|--------|
| **homelab** | Docker read+write, `truenas.*` additiv, Diagnose | alle Stacks, `dataset:<pool>/raid/*` |
| **media** | Docker read (`ps`, `logs`), Diagnose, `sonarr.*`, `radarr.*`, `jellyfin.*` read | `stack:media-*`, `stack:jellyfin*` |
| **dev** | Docker read+write, ZFS additiv, Diagnose, `github.*` read | `stack:dev-*`, `dataset:<pool>/raid/dev-*`, `repo:davidsteg/*` |
| **admin** | ausschließlich `admin.*` auf `/admin/mcp` | — |

---

## 10. Funktionale Anforderungen — Executoren

Der Punkt, den v1 offen ließ: *wie* erreicht ein Container überhaupt den Host. Das Fundament definiert Executor-**Typen**; welche davon aktiv sind, ist eine Ebene-1-Entscheidung (FR-4.4).

| Typ | Erreicht | Mechanismus | Status |
|-----|----------|-------------|--------|
| `docker` | Docker-Operationen | gemounteter Docker-Socket | **v1 aktiv** |
| `local` | Container-lokale Diagnose | Prozess im Container | **v1 aktiv** |
| `http` | SaaS- und LAN-APIs (GitHub, *arr, Uptime Kuma …) | HTTP-Request mit Toolkit-Credential | **v1 aktiv** |
| `truenas` | ZFS, Pool-Status, Dataset-Verwaltung | JSON-RPC 2.0 über WebSocket, API-Key | **v1 aktiv** |
| `ssh` | Host-Befehle ohne API-Entsprechung (`ps`, `top`) | SSH mit host-seitig restringiertem Key | v1 optional (§17) |

- **FR-8.1** Tools wählen keinen Executor selbst — sie gehören zu einem Toolkit, und das Toolkit bindet den Executor (FR-4.8). Ein Toolkit, dessen Executor beim Deploy nicht freigeschaltet ist, wird samt aller zugehörigen Tools abgelehnt.
- **FR-8.2** Der `docker`-Executor bekommt den Socket. Das ist **root-äquivalent auf dem Host** und steht in Spannung zu NFR-1. Das wird bewusst akzeptiert, weil gatekeeper genau die Whitelist *ist*, die diesen Zugriff einschränkt — aber es bedeutet: ein Fehler in gatekeeper ist ein Root-Fehler. Daraus folgt die Härte von §6.
- **FR-8.3** ZFS ist über den Docker-Socket **nicht** erreichbar — `zfs create` ist keine Docker-Operation. ZFS läuft über den `truenas`-Executor.

### Der `truenas`-Executor

- **FR-8.3a** **Die TrueNAS-REST-API v2.0 ist ab 25.04 deprecated und in TrueNAS 26 entfernt.** Verbindliche Schnittstelle ist die versionierte **JSON-RPC-2.0-API über WebSocket**. Eine Implementierung gegen `/api/v2.0/…` wäre bereits bei Erscheinen veraltet und würde beim nächsten TrueNAS-Upgrade brechen.
- **FR-8.3b** Daraus folgt: `truenas` ist **kein** `http`-Toolkit, sondern ein eigener Executor-Typ — persistente WebSocket-Verbindung, JSON-RPC-Methodenaufrufe statt Pfad-Templates, eigene Reconnect- und Timeout-Behandlung.
- **FR-8.3c** Die Whitelist wirkt hier auf **Methodennamen** statt auf Binaries oder Pfad-Präfixe: das Toolkit deklariert erlaubte JSON-RPC-Methoden (`pool.dataset.create`, `pool.dataset.query`, `pool.query`). Alles Übrige existiert nicht — insbesondere nicht `pool.dataset.delete`.
- **FR-8.3d** Parameter werden als JSON-RPC-Params übergeben, nicht als String interpoliert. Die Injection-Frage stellt sich damit strukturell nicht; die Validierung aus §7 gilt trotzdem (Dataset-Namen, Präfix-Beschränkung auf `<pool>/raid/*`).
- **FR-8.3e** Authentifizierung per TrueNAS-API-Key aus dem Credential-Store (§11). TrueNAS 26 bietet zusätzlich SCRAM-SHA-512-Mutual-Auth für API-Keys — vorzuziehen, sobald verfügbar.
- **FR-8.3f** Damit entfällt der ursprüngliche Grund für `ssh`. Der `ssh`-Executor bleibt nur für Host-Diagnose ohne API-Entsprechung (`ps aux`, `top`) relevant und ist in v1 optional.
- **FR-8.4 Korrektur zur Diagnose-Liste aus v1:** Die dort gelisteten Kommandos liefern im Container nicht durchgehend Host-Werte. Definitionen müssen das berücksichtigen:

  | Kommando | Im Container | Konsequenz |
  |----------|--------------|------------|
  | `uptime`, `free -h`, `cat /proc/loadavg` | Host-Werte (geteiltes `/proc`) | `local` genügt |
  | `df -h` | nur Container-Mounts | `/mnt/raid` muss gemountet sein |
  | `ps aux`, `top -bn1` | nur Container-Prozesse | braucht `pid: host` oder `ssh` |
  | `zpool status` | nicht verfügbar | braucht `truenas` oder `ssh` |

### Der `http`-Executor (SaaS- und LAN-APIs)

Derselbe Kontrollgedanke wie bei der Prozessausführung, übersetzt auf HTTP. Was dort das argv-Template ist, ist hier das URL-Template.

- **FR-8.5** Eine Tool-Definition mit `http`-Toolkit besteht aus Methode, Pfad-Template, optionalen Query- und Body-Templates. **Schema und Host stehen ausschließlich im Toolkit**, nie in der Tool-Definition und nie in einem Parameter.
- **FR-8.6 Ziel-Allowlist (Ebene 1):** Das Toolkit deklariert `base_url`, erlaubte HTTP-Methoden und erlaubte Pfad-Präfixe. Eine Definition außerhalb dieser Grenzen wird abgelehnt — wie bei der Binary-Allowlist.
- **FR-8.7 Der Agent kann das Ziel nie bestimmen.** Parameter füllen ausschließlich Pfadsegmente, Query-Werte und Body-Felder — URL-enkodiert, **ein Parameter = genau ein Segment bzw. ein Wert**. Das ist die HTTP-Entsprechung zu FR-5.4: ein Parameterwert kann strukturell kein zusätzliches Pfadsegment und keinen anderen Host erzeugen. `..` in Pfadsegmenten wird abgelehnt, nicht normalisiert.
- **FR-8.8 Redirects werden nicht verfolgt.** Ein 3xx wird als Ergebnis zurückgegeben, nicht ausgeführt. Andernfalls wäre die Ziel-Allowlist wertlos, weil der Zielserver die Weiterleitung bestimmt.
- **FR-8.9 SSRF-Schutz:** Die aufgelöste IP wird gegen eine per Toolkit deklarierte IP-/CIDR-Allowlist geprüft, **nach** der DNS-Auflösung und unmittelbar vor dem Verbindungsaufbau (gegen DNS-Rebinding). Im Homelab sind viele legitime Ziele privat — deshalb explizite Allowlist statt pauschalem Verbot privater Bereiche.
- **FR-8.10 Credentials** stammen aus dem Toolkit, werden serverseitig als Header injiziert und erscheinen **niemals** in Tool-Definition, Parametern, Antwort oder Audit-Log. Ein Agent kann kein Credential setzen, lesen oder überschreiben.
- **FR-8.11 Kein OAuth in v1.** Unterstützt werden statische Credentials: Bearer-Token, API-Key-Header, Basic Auth. Authorization-Code-Flows, Token-Refresh und Callback-Verwaltung sind ein eigenes Teilsystem und rechtfertigen sich erst, wenn ein konkreter Dienst sie erzwingt (→ §17 und Anhang B).
- **FR-8.12 Antworten externer APIs sind nicht vertrauenswürdig.** Issue-Texte, Commit-Messages, Ticket-Beschreibungen und Dateinamen können **Prompt-Injection** enthalten und fließen unmittelbar in den Kontext des aufrufenden Agenten. Das ist eine neue Risikoklasse gegenüber Host-Ausgaben, die im Wesentlichen aus eigenen Logs bestehen. Daraus folgt:
  - Größenbegrenzung wie FR-6.5, zusätzlich Begrenzung der Feldanzahl bei Listen-Antworten.
  - Antworten werden im MCP-Ergebnis als **externe, nicht vertrauenswürdige Daten gekennzeichnet**, damit der Agent sie nicht als Anweisung behandelt.
  - Diese Kennzeichnung ist eine Abschwächung, keine Lösung. Die eigentliche Kontrolle bleibt, dass ein Agent nur die Tools besitzt, deren Missbrauch tragbar ist — insbesondere gilt FR-5.1a.

### Toolkit-Katalog v1

Jeder Dienst ist ein eigenes Toolkit mit eigener Ziel-Allowlist und eigenem Credential. Das ist der Punkt, an dem sich die Toolkit-Abstraktion auszahlt: ein kompromittiertes Sonarr-Credential erreicht Jellyfin nicht, und keiner der beiden erreicht Docker.

| Toolkit | Executor | Authentifizierung | Kategorien v1 |
|---------|----------|-------------------|---------------|
| `docker` | `docker` | Socket | `read`, `write` |
| `diag` | `local` | — | `read` |
| `truenas` | `truenas` | API-Key (WebSocket JSON-RPC) | `read`, `write` (additiv) |
| `sonarr` | `http` | `X-Api-Key`-Header | `read`, `write` |
| `radarr` | `http` | `X-Api-Key`-Header | `read`, `write` |
| `jellyfin` | `http` | API-Key-Header | `read` |
| `github` | `http` | Bearer (PAT) | `read`, optional `write_external` |
| `admin` | — | Admin-Token, nur `/admin/mcp` | — |

- **FR-8.13** Sämtliche genannten Dienste authentifizieren über **statische API-Keys im Header**. Kein einziger erzwingt OAuth. FR-8.11 ist damit für den v1-Umfang nicht bloß eine Vereinfachung, sondern die vollständig ausreichende Lösung.
- **FR-8.14** `sonarr`, `radarr` und `jellyfin` akzeptieren den API-Key **auch als Query-Parameter** (`?apikey=…`). Das ist zu vermeiden: Query-Strings landen in Zugriffslogs des Zielsystems. gatekeeper sendet Credentials ausschließlich als Header.
- **FR-8.15** Diese Dienste liegen im LAN. `allowed_cidrs` (FR-8.9) enthält für sie private Adressbereiche — die IP-Allowlist ist hier die einzige wirksame Zielbeschränkung und deshalb je Toolkit eng zu fassen, nicht als pauschales `192.168.0.0/16`.

---

## 11. Funktionale Anforderungen — Credential-Verwaltung

gatekeeper hält diese Credentials ohnehin, um die Tools ausführen zu können. Sie explizit zu verwalten ist besser, als sie über Env-Variablen zu verstreuen. Die Grenze, die dabei zu halten ist:

> gatekeeper ist **Credential-Nutzer mit Lebenszyklus-Verwaltung — kein Credential-Provider.**

- **FR-10.1** Credentials sind benannte Objekte (`cred:truenas`, `cred:sonarr`, `cred:ssh-host`). Toolkits referenzieren sie über den Namen; in Tool-Definitionen erscheinen sie nie.
- **FR-10.2 Write-only — die wichtigste Anforderung dieses Abschnitts.** Es gibt **keine** Operation, für **keine** Rolle, die einen Credential-Wert zurückgibt: nicht über die Admin-API, nicht über die UI, nicht über ein Diagnose-Tool. Anlegen, rotieren, löschen — ja. Lesen — nie. Andernfalls wird gatekeeper vom Schutzwall zum zentralen Exfiltrationspunkt: ein kompromittierter Admin-Zugang gäbe sämtliche Schlüssel des Homelabs auf einmal preis.
- **FR-10.3 Verschlüsselung at rest** (AES-GCM oder Fernet). **Der Masterkey liegt nicht im selben Dataset wie der Ciphertext** — sonst ist die Verschlüsselung Dekoration. Masterkey aus Env-Variable oder separat gemountetem Secret, ausschließlich zur Deploy-Zeit gesetzt.
- **FR-10.4 Zuordnung zu den Ebenen aus §6:** Die *Bindung* — welches Toolkit welchen Credential-Namen nutzt — ist **Ebene 1** und nur per Redeploy änderbar. Der *Wert* ist **Ebene 2** und zur Laufzeit rotierbar. Damit bleibt das Sicherheitsmodell intakt: der Admin-Agent kann den Sonarr-Key erneuern, aber das `docker`-Toolkit nicht auf ein fremdes Credential umbiegen.
- **FR-10.5 Rotation ohne Redeploy:** neuer Wert unter bestehendem Namen, mit optionaler Überlappungsphase, damit laufende Aufrufe nicht brechen.
- **FR-10.6 Ausgabe-Maskierung:** Vor der Rückgabe an den Agenten **und** vor dem Schreiben ins Audit-Log werden bekannte Credential-Werte in stdout, stderr und HTTP-Antworten durch `***` ersetzt. Das deckt FR-9.6 ab (Container-Logs enthalten regelmäßig Env-Variablen) sowie fremde APIs, die einen fehlerhaften Key in der Fehlermeldung zurückspiegeln.
- **FR-10.7 Verwendungsnachweis:** Das Audit-Log hält fest, welches Tool welchen Credential-**Namen** benutzt hat — nie den Wert. Nur so ist nach einem Vorfall beantwortbar, was rotiert werden muss.
- **FR-10.8 Kein Durchreichen:** Kein Tool händigt einem Agenten ein Credential aus. Agenten rufen Tools auf, gatekeeper authentifiziert. Ein Agent erfährt nicht einmal, ob ein bestimmtes Credential existiert.

### SSH-Credentials

- **FR-10.9** Private SSH-Schlüssel unterliegen FR-10.2 wie jedes andere Credential. Der **öffentliche** Teil ist auslesbar — er muss in die `authorized_keys` des Hosts.
- **FR-10.10 Host-seitige Einschränkung ist Pflicht**, nicht Empfehlung: Eintrag in `authorized_keys` mit `command="…"`, `restrict`, `no-pty`, `no-port-forwarding`.
- **FR-10.11** Damit erhält der SSH-Pfad **genau die zweite Durchsetzungsebene, die dem Docker-Socket fehlt.** Ein kompromittierter gatekeeper kann über den Socket alles; über einen so restringierten Schlüssel nur das, was der Host selbst zulässt. Das kehrt die Einschätzung aus §10 um: sauber eingeschränktes SSH ist nicht die riskantere, sondern die **besser abgesicherte** Variante gegenüber dem Docker-Socket.
- **FR-10.12** gatekeeper kann die Restriktion auf dem Host nicht selbst überprüfen. Das Toolkit muss sie deshalb ausdrücklich erklären (`ssh_key_restricted: true`) — eine bewusste Zusicherung des Betreibers, die bei jedem Start protokolliert wird. Ohne diese Erklärung startet das Toolkit nicht. Eine Zusicherung ist schwächer als eine Prüfung; das ist hier so benannt statt kaschiert.

---

## 12. Funktionale Anforderungen — Audit

- **FR-9.1** Jeder Aufruf wird protokolliert: Zeitstempel, Identität (Token-ID, **nie** der Token), Tool-ID **und -Version**, Parameter, beanspruchter Scope, Exit-Code, Dauer, abgeschnittene Ausgabe ja/nein.
- **FR-9.2** Abgelehnte Aufrufe werden ebenso protokolliert, mit Ablehnungsgrund (401, Recht fehlt, Validierung, Ebene-1-Verstoß, Rate-Limit, Timeout).
- **FR-9.3** Katalog- und Rechteänderungen werden mit Vorher-/Nachher-Zustand protokolliert.
- **FR-9.4** Logs sind append-only, strukturiert (JSON Lines), und liegen unter `/mnt/raid/gatekeeper/logs/`.
- **FR-9.5** **Rotation und Aufbewahrungsdauer sind Pflicht.** Append-only ohne Begrenzung füllt die Disk.
- **FR-9.6** Ausgaben können Secrets enthalten (`docker compose logs` zeigt regelmäßig Env-Variablen und API-Keys). Es ist zu entscheiden, ob Ausgaben ins Audit-Log gehen, gefiltert werden oder nur Metadaten protokolliert werden (§17).

---

## 13. Nicht-funktionale Anforderungen

- **NFR-1 (Sicherheit):** Container läuft als unprivilegierter User. Host-Zugriff ausschließlich über freigeschaltete Executoren. Kein interaktiver Shell-Zugriff. Einschränkung: siehe FR-8.2 zum Docker-Socket.
- **NFR-2 (Performance):** < 2 s für `read`, < 30 s für `write` (`docker compose up`). Timeout-Obergrenze konfigurierbar.
- **NFR-3 (Verfügbarkeit):** `restart: unless-stopped`; Health-Probes `/health/live`, `/health/ready` und `/health/startup` **ohne** Authentifizierung, aber ohne jede Information über Katalog oder Identitäten. Die Trennung ist relevant, weil „Prozess läuft" und „Executoren erreichbar" verschiedene Aussagen sind — ein gatekeeper ohne Docker-Socket ist `live`, aber nicht `ready`.
- **NFR-3a (Metriken):** Prometheus-Endpunkt `/metrics` mit Aufruf-, Fehler- und Latenzzählern pro Tool und Identität. Zugriffsgeschützt wie der Admin-Endpunkt.
- **NFR-4 (Wartbarkeit):** Ebene-1-Grenzen und Seed-Katalog in Konfigurationsdateien, nicht im Code. Laufzeit-Katalog persistent im Dataset.
- **NFR-5 (Portabilität):** Docker-Image aus dem Repo `davidsteg/gatekeeper`, Tag gepinnt.
- **NFR-6 (Stack):** Python mit dem offiziellen MCP-SDK (FastMCP). Ein separates FastAPI ist **nicht** nötig — FastMCP bringt Starlette/uvicorn mit; `/healthz` wird als zusätzliche Route eingehängt.
- **NFR-7 (Beobachtbarkeit):** Beim Start protokolliert der Server aktive Ebene-1-Grenzen, freigeschaltete Executoren, Anzahl aktiver Tools und Identitäten.
- **NFR-8 (Nachweisbarkeit der Sicherheitsgrenzen):** Das ganze Dokument behauptet, Ebene 1 halte. Diese Behauptung braucht einen Beleg, der bei jeder Änderung neu erbracht wird — sonst ist sie eine Absichtserklärung. Verlangt wird ein **Negativtest-Korpus**, der in CI läuft und ausschließlich aus Fällen besteht, die **fehlschlagen müssen**:

  | Angriffsklasse | Erwartung |
  |----------------|-----------|
  | Metazeichen, Zeilenumbrüche, Nullbytes in jedem Parametertyp | abgelehnt, auditiert |
  | Pfad-Traversal und Symlink-Ausbruch aus `path_roots` | abgelehnt |
  | Tool-Definition mit nicht freigegebenem Binary oder Toolkit | bei `create` **und** bei Ausführung abgelehnt |
  | Parameter, der ein zweites argv-Element oder Pfadsegment erzeugt | strukturell unmöglich |
  | URL-Parameter, der Host oder Schema verändert | abgelehnt |
  | Zielserver antwortet mit 3xx auf einen fremden Host | nicht verfolgt |
  | DNS, das nach der Prüfung auf eine andere IP zeigt | Verbindung abgelehnt |
  | Ausgabe, die einen Credential-Wert enthält | maskiert, in Antwort **und** Audit-Log |
  | Aufruf eines existierenden Tools ohne Recht | Antwort identisch zu „unbekanntes Tool" |
  | Zugriff auf eine geschützte Ressource nach FR-4.12 | abgelehnt |

  Ein grüner Testlauf beweist keine Sicherheit. Ein roter beweist ihre Abwesenheit — und genau dafür ist der Korpus da.
- **NFR-9 (Verhalten bei Ausfall):** Ist ein Executor nicht erreichbar — TrueNAS-WebSocket weg, Sonarr aus —, scheitern dessen Tools **schnell und eindeutig**, statt bis zum Timeout zu hängen. Circuit-Breaker je Toolkit, Zustand sichtbar in `/health/ready` und `/metrics`.
- **NFR-10 (Ungültige Credentials):** Antwortet ein Zieldienst mit 401/403, ist das für den Agenten nicht von einem Rechtefehler zu unterscheiden. gatekeeper übersetzt diesen Fall in eine klare Meldung („Credential `cred:sonarr` wird vom Dienst abgelehnt") und markiert das Credential als prüfbedürftig. Extern rotierte Keys sind im Homelab der häufigste Ausfallgrund.

---

## 14. Deployment (nach Homelab-Regeln)

1. **ZFS-Dataset** anlegen (nie `mkdir`): `zfs create <pool>/raid/gatekeeper`
2. **chown 568:568** auf Dataset und `compose.yaml` (Dockhand-Regel)
3. Unterverzeichnisse `config/`, `catalog/`, `logs/` im Dataset
4. **compose.yaml** im Dataset mit Service `gatekeeper`, Docker-Socket-Mount, Ebene-1-Konfiguration
5. **Deploy via Dockhand:**
   `docker exec ix-dockhand-dockhand-1 docker compose -p gatekeeper -f /mnt/raid/gatekeeper/compose.yaml up -d`
6. **Image-Tag gepinnt** (nicht `:latest`), `autoUpdate: false`
7. Tokens erzeugen, Hashes in die Konfiguration, Klartext in die jeweilige Agenten-`config.yaml`
8. **Agent-`config.yaml`** um `mcp_servers.gatekeeper` erweitern

### Umsetzungsreihenfolge

Der Umfang ist zwischen v1 und v2 erheblich gewachsen: aus „fünfzehn erlaubte Befehle" wurde MCP-Server, Auth, dynamischer Katalog, Admin-API, vier Executor-Typen, verschlüsselter Credential-Store, Audit und UI. Das ist umsetzbar, aber nicht in einem Zug — und die Reihenfolge ist nicht beliebig.

| Stufe | Inhalt | Ergebnis |
|-------|--------|----------|
| **1** | MCP + Auth + Audit + `docker` + `diag`, Katalog als **statische Seed-Datei** | Ersetzt den n8n-Host-Ops-Workflow. Ab hier hat jeder Agent seinen eigenen Token — das ursprüngliche Kernproblem ist gelöst. |
| **2** | Credential-Store (§11) + `truenas` + `http` mit **ausschließlich `read`** | ZFS und Dienst-Abfragen. Kein schreibender Fremdzugriff, also kleine Angriffsfläche bei großem Nutzen. |
| **3** | Admin-API (§5), Katalog wird dynamisch | Erst jetzt schreibt ein Agent den Katalog. |
| **4** | Admin-UI (§15), danach `write_external` | Menschliche Freigabe existiert, **bevor** nach außen sichtbare Schreibzugriffe möglich werden. |

Zwei Punkte daran sind bewusst gegen die Intuition gesetzt:

**Die Admin-API kommt spät, obwohl sie das Leitmotiv von v2 ist.** Ein statischer Seed-Katalog liefert praktisch denselben Nutzen — die Tools sind dieselben — und die Admin-API ist die größte neue Angriffsfläche des Entwurfs. Sie zuerst zu bauen hieße, das Fundament auf dem riskantesten Teil zu errichten, bevor der einfache Fall überhaupt läuft.

**`write_external` kommt zuletzt, nach der UI.** Nach außen sichtbare Schreibzugriffe sind die einzige Kategorie mit Folgen, die sich nicht zurücknehmen lassen. Sie sollten erst möglich sein, wenn die Freigabe-Ansicht aus FR-11.4 existiert.

Jede Stufe ist für sich betriebsfähig. Bleibt das Projekt nach Stufe 1 oder 2 stehen, ist trotzdem etwas Nützliches entstanden — kein halbes System.

---

## 15. Admin-UI (Ausbaustufe, nicht v1)

In v2 schreibt ein **Agent** den Tool-Katalog. Die Freigabe aus FR-3.2 ist damit die einzige Stelle, an der noch ein Mensch dazwischensteht — und sie existiert bisher nur als API-Aufruf, den derselbe Agent selbst tätigen kann. Ohne eine menschliche Sichtfläche ist das „Gate" in gatekeeper durchgehend Agent-zu-Agent. Das ist der eigentliche Grund für eine UI; Bequemlichkeit ist der Nebeneffekt.

- **FR-11.1** Die UI ist ausschließlich **Client der Admin-API**. Keine eigene Katalog-Logik, kein zweiter Schreibpfad, keine duplizierte Validierung.
- **FR-11.2** Umfang ist bewusst **read-mostly**:
  - Audit-Log, filterbar nach Identität, Tool, Zeitraum, Ergebnis
  - Katalog mit Versionshistorie und **Diff zwischen Versionen**
  - Rechteprofile pro Identität inkl. wirksamer Scopes
  - Status der Ebene-1-Grenzen und freigeschalteten Executoren
- **FR-11.3** Einzige Schreiboperationen: `enable`/`disable` einer Definition sowie Token-Widerruf. **Kein Tool-Authoring in der UI.** Definitionen schreibt der Admin-Agent — Authoring in der UI würde die Angriffsfläche genau dort vergrößern, wo sie am teuersten ist.
- **FR-11.4** **Freigabe-Ansicht** als Kernfunktion: neue und geänderte Definitionen mit vollständigem argv-Template, Parameter-Schema, Ergebnis der Ebene-1-Prüfung und Diff zur Vorversion. Freigabe ist eine bewusste Handlung mit Kontext, kein Häkchen in einer Liste.
- **FR-11.5** Eigene, **session-basierte** Authentifizierung — nicht der Admin-Bearer-Token. Der Token gehört nicht in einen Browser. Ein UI-Login ist eine eigene Identität mit eigener Audit-Spur.
- **FR-11.6** Die UI hängt am Admin-Endpunkt und erbt dessen Netzwerkeinschränkung (FR-2.10). Nicht öffentlich erreichbar.
- **FR-11.7** Die UI ist der Ort, an dem ein neu erzeugter Klartext-Token **genau einmal** angezeigt wird — besser als eine Ausgabe im Logfile (vgl. FR-2.6).
- **FR-11.8** Optional und abschaltbar. gatekeeper bleibt ohne UI voll funktionsfähig; die UI wird als separater Container oder als deaktivierbare Route ausgeliefert.

**Günstigere Alternative, falls die UI nicht gebaut wird:** Grafana/Loki auf die JSON-Lines-Logs für die Audit-Sicht, plus den Admin-Agenten im Chat für Katalog- und Rechteauskünfte. Kostet keinen Zusatzcode, verliert aber die Freigabe-Ansicht aus FR-11.4 — also genau den Teil, der die menschliche Kontrolle herstellt.

---

## 16. Abgrenzung (was gatekeeper NICHT ist)

- **Kein** generisches Automatisierungstool — Workflows, Zeitpläne und Trigger bleiben in n8n. gatekeeper antwortet auf Aufrufe, es initiiert nichts.
- **Kein** generischer HTTP-Proxy — der `http`-Executor erreicht ausschließlich die in Ebene 1 fixierten Hosts und Pfad-Präfixe. Es gibt kein Tool „beliebige URL abrufen", und es kann keines geben (FR-8.6/8.7).
- **Kein** OAuth-Broker — statische Credentials ja, Authorization-Code-Flows nein (FR-8.11).
- **Kein** allgemeiner Secret-Store. gatekeeper verwaltet ausschließlich die Credentials, die es **selbst** zur Ausführung braucht, und gibt keinen Wert je zurück (FR-10.2). Wer einen Tresor für andere Verbraucher sucht, braucht Vault oder Infisical — nicht dies hier.
- **Kein** voller Docker-API-Proxy — kein beliebiger Container-Zugriff.
- **Kein** Ersatz für Dockhand — Dockhand bleibt der Deploy-Mechanismus.
- **Kein** ZFS-Verwaltungstool — nur additive Operationen, und nur nach Executor-Entscheidung.
- **Kein** Schutz gegen einen kompromittierten Admin-Token jenseits von Ebene 1 — der Admin-Token ist das kritischste Geheimnis des Systems.
- **Kein** Dashboard für Container-Betrieb — die UI aus §15 zeigt gatekeeper selbst, nicht den Zustand der verwalteten Stacks.

---

## 17. Offene Fragen / Entscheidungen

- [ ] **Welche TrueNAS-Version läuft?** Bestimmt unmittelbar die Implementierung: ab 25.04 ist REST deprecated, ab 26 entfernt (FR-8.3a). Ab 26 steht zusätzlich SCRAM-SHA-512-Mutual-Auth für API-Keys bereit.
- [ ] **Masterkey-Ablage — Konflikt mit der Homelab-Regel.** FR-10.3 verlangt, dass der Masterkey **nicht** im selben Dataset liegt wie der verschlüsselte Credential-Store. Die Homelab-Konvention legt `compose.yaml` aber genau dort ab. Steht der Key als Env-Variable in dieser Datei, ist die Verschlüsselung wirkungslos. Optionen: Docker-Secret, separat gemountete Datei außerhalb `/mnt/raid/gatekeeper/`, oder Übergabe über Dockhand. **Diese Frage blockiert den Credential-Store.**
- [ ] **`ssh`-Executor in v1 aktivieren?** Nach FR-8.3f bleibt dafür nur Host-Diagnose ohne API-Entsprechung (`ps aux`, `top`). Ist das den zusätzlichen Schlüssel wert, oder reicht `pid: host` am Container?
- [ ] **Credential-Bootstrap:** Kommen die ersten API-Keys über `admin.cred_set` nach dem Start herein, oder über eine einmalig gemountete Datei, die danach entfernt wird?
- [ ] **Hermes-Transport:** Beherrscht die eingesetzte Version Streamable HTTP, oder wird zusätzlich der deprecated SSE-Transport gebraucht?
- [ ] **Admin-Schnittstelle:** MCP-Tools auf `/admin/mcp` (Empfehlung, weil der Admin-Agent MCP nativ spricht) oder separate REST-API?
- [ ] **Audit von Ausgaben:** Vollständig, gefiltert oder nur Metadaten? Betrifft FR-9.6 (Secrets in Container-Logs).
- [ ] **Bootstrap des Admin-Tokens:** Beim ersten Start generieren und ins Log schreiben, oder ausschließlich per Ebene-1-Konfiguration vorgeben?
- [ ] **Repo `davidsteg/gatekeeper`** anlegen?
- [ ] **n8n-Workflow:** Nach Parallelbetrieb deaktivieren (nicht löschen) — Zeitraum festlegen.
- [ ] **Credential-Doppelhaltung mit n8n.** Seit gatekeeper auch Dienst-APIs anspricht, überschneidet sich der Bereich: n8n hält für Sonarr, Radarr, Jellyfin und GitHub bereits eigene Credentials. Zwei Ablagen für dieselben Keys heißt doppelte Rotation und zwei Audit-Spuren, die einzeln unvollständig sind. Drei Wege: n8n behält seine Credentials (einfach, aber dauerhaft doppelt), n8n ruft Dienste künftig über gatekeeper (eine Ablage, aber n8n braucht dann einen eigenen Agent-Token), oder die Zuständigkeiten werden je Dienst sauber getrennt. Diese Frage stellt sich erst ab Stufe 2 — sie jetzt zu entscheiden, verhindert aber, dass die Doppelung sich einfach einschleicht.
- [ ] **Admin-UI (§15):** Bauen, oder Grafana/Loki-Alternative? Falls bauen: eigener Container oder Route im gatekeeper-Image?
- [ ] **UI-Authentifizierung:** Lokale Benutzer im gatekeeper-Container, oder vorgelagerter Auth-Proxy (Authentik/Authelia), falls im Homelab vorhanden?
- [ ] **Freigabe verpflichtend?** Soll `enable` ausschließlich über die UI möglich sein (echtes Vier-Augen-Prinzip gegenüber dem Admin-Agenten), oder auch per `admin.tool_enable`?
- [ ] **Toolkit-Katalog vollständig?** Aktuell: `docker`, `diag`, `truenas`, `sonarr`, `radarr`, `jellyfin`, `github`, `admin`. Fehlen Prowlarr, Bazarr, Uptime Kuma, ntfy/Pushover?
- [ ] **Welcher Agent bekommt welches Dienst-Toolkit?** Naheliegend: `media` → `sonarr`/`radarr`/`jellyfin`, `dev` → `github`, `homelab` → `truenas`. Zu bestätigen, da FR-7.5 Grants ausdrücklich auf Tool-IDs erzwingt.
- [ ] **`write_external` überhaupt erlauben?** Ein rein lesender SaaS-Zugriff (Issues lesen, Status abfragen) hat eine drastisch kleinere Angriffsfläche als schreibender. Soll v1 auf `read` beschränkt bleiben?
- [ ] **Deployment-Ziel für die Ebene-1-Datei:** Env-Variablen oder gemountete `toolkits.yaml` im Dataset? Letzteres ist lesbarer, muss aber gegen Schreibzugriff des Containers geschützt sein (read-only mount).

---

## Anhang A — Nachverfolgung v1 → v2

| v1 | Verbleib in v2 |
|----|----------------|
| FR-1.1 MCP über HTTP/SSE | FR-1.1/1.2 — auf Streamable HTTP korrigiert |
| FR-1.2 tools/list, tools/call | FR-1.3, erweitert um Filterung (FR-1.4) und Change-Notification (FR-1.5) |
| FR-2.1–2.3 Pro-Agent-Auth | FR-2.1–2.3, erweitert um Hashing und Admin-Rolle |
| FR-3.1 Nur bekannte Aktionen | FR-3.x + §6 — jetzt datengetrieben statt einkompiliert |
| FR-3.2 Basis-Aktionsliste | §7 Seed-Katalog; Diagnose-Liste durch FR-8.4 korrigiert |
| FR-3.3 Keine destruktiven Aktionen | FR-4.1/4.2 — Binary-Allowlist und Argument-Verbote auf Ebene 1 |
| FR-4.1/4.2 Strukturierte Parameter | FR-5.3/5.4, FR-6.1 |
| FR-4.3 Metazeichen-Blacklist | **Herabgestuft** auf FR-6.3 (Defense-in-Depth); Primärschutz ist FR-5.4 |
| FR-4.4 Parametervalidierung | FR-5.6/5.7, FR-6.2, erweitert um Pfad-Auflösung (FR-4.3) |
| FR-5.x Audit | FR-9.x, erweitert um Rotation, Versionsbezug, Katalogänderungen |
| FR-6.x read/write-Trennung | FR-7.1 — erweitert um die Ressourcen-Dimension |
| §4 Rechte-Matrix | §9 — jetzt zweidimensional und über API pflegbar |

---

## Anhang B — Evaluierte Alternativen

Festgehalten, damit die Bau-statt-Kaufen-Entscheidung nachvollziehbar bleibt und bei geändertem Bedarf überprüfbar ist.

### Composio (`composio.dev`) — als Vorbild übernommen, nicht als Basis

Tool-Plattform für Agenten: 1000+ Toolkits, gehostete OAuth-Flows, MCP-Endpunkte mit Tool-Filter pro `user_id`.

**Übernommen:** die Toolkit→Tool-Hierarchie (FR-4.8 bis FR-4.11), die Namenskonvention `<toolkit>.<aktion>` (FR-5.1a), Credentials am Toolkit statt am Tool.

**Bewusst nicht übernommen:**
- **Grants auf Toolkit-Ebene** — siehe FR-7.5. Bequem dort, Rechteausweitungs-Pfad hier.
- **Breite als Wert.** Composios Nutzen ist Reichweite, gatekeepers Nutzen ist Enge. Tool-Search und leichtes Onboarding lösen ein Problem, das bei ~15 Tools nicht existiert, und schwächen die Zusicherung „der Agent sieht genau das, was er darf".
- **Multi-Tenancy** (per-user Connected Accounts, gehostete Auth-Flows, `user_id`-Isolation) — SaaS-Overhead für einen Single-Tenant-Homelab-Container.
- **Custom Tools „in-process"** — genau der Codepfad, den gatekeeper nicht haben darf.

**Wann neu zu bewerten:** sobald ein benötigter Dienst **OAuth erzwingt**. Authorization-Code-Flow, Token-Refresh, Callback-Verwaltung und verschlüsselte Token-Ablage pro Anbieter sind ein eigenes Teilsystem — genau Composios Kerngeschäft. Dann ist die naheliegende Form nicht Ablösung, sondern Composio als vorgelagerter **Credential-Broker**: gatekeeper behält Katalog, Rechte, Validierung und Audit, holt sich das jeweils gültige Token aber von dort. Solange die Dienste API-Keys akzeptieren (FR-8.11), stellt sich die Frage nicht.

**Warum keine Basis:** Composios Tools rufen SaaS-APIs mit OAuth-Scopes auf. Hinter jedem Aufruf stehen noch zwei Durchsetzungsebenen — der Scope und die Autorisierung des Anbieters. gatekeeper führt Prozesse auf dem Host aus, dem der Storage gehört, über einen root-äquivalenten Socket. **Es gibt keine nachgelagerte Instanz.** Ebene 1 (§6) existiert genau deshalb; Composio braucht nichts Vergleichbares.

### SageMCP (`github.com/sagemcp/SageMCP`) — geprüft, nicht übernommen

„Multi-tenant MCP Server Platform": MCP-Gateway mit 23 Connectoren und 340 Tools, OAuth/API-Key-Auth, dreistufigem Key-Scoping (`platform_admin` / `tenant_admin` / `tenant_user`), Admin-UI zum Aktivieren/Deaktivieren einzelner Tools, Rate-Limiting pro Tenant, strukturiertem JSON-Logging, Health-Probes, Prometheus-Metriken. FastAPI/Python, React, PostgreSQL, Apache-2.0.

**Substanzielle Überschneidung** mit dem Fundament dieses Dokuments: pro-Identität-Tokens, dynamisch verwalteter Tool-Katalog, Admin-UI mit Tool-Freischaltung, Audit-Log, Health-Endpunkte, Rate-Limiting. Das ist ein Beleg dafür, dass die hier gewählte Struktur ein konvergentes Muster ist, kein Sonderweg.

**Warum trotzdem keine Basis:**
1. **Es führt keine Host-Befehle aus.** SageMCP proxied zu OAuth-SaaS-Diensten und startet externe MCP-Server als stdio-Subprozesse. Genau die Schicht, die gatekeeper ausmacht — argv-Templates, Binary-Allowlist, Pfad-Wurzeln, Injection-Abwehr, Ebene 1 — existiert dort nicht, weil sie dort nie gebraucht wurde.
2. **Tool-Policy ≠ Parametervalidierung.** Deren Freischaltung entscheidet, *ob* ein Tool nutzbar ist. gatekeeper muss entscheiden, ob *dieser Aufruf mit diesen Parametern auf dieser Ressource* zulässig ist. Ein Äquivalent zu `stack:media-*` (FR-7.1) gibt es nicht.
3. **Reifegrad im Sicherheitspfad.** 44 Sterne, 103 Commits, früh-bis-mittleres Stadium. Als Abhängigkeit, die einen root-äquivalenten Docker-Socket hält, wären deren Fehler unmittelbar Root-Fehler auf dem Host.
4. **Betriebslast.** PostgreSQL, React-Frontend, Kubernetes-Helm-Charts, Server-Pooling mit LRU für 5.000 Instanzen — dimensioniert für Mandantenfähigkeit, nicht für drei Agenten im Homelab.

**Übernommene Anregungen:** die Health-Probe-Triade (`/health/live`, `/health/ready`, `/health/startup`) statt eines einzelnen `/healthz`, ein Prometheus-`/metrics`-Endpunkt, Verschlüsselung sensibler Konfigurationswerte at rest.

**Wann neu zu bewerten:** wenn gatekeeper über den Homelab-Rahmen hinauswächst — mehrere Mandanten, viele Agenten, SaaS-Connectoren neben Host-Ops. Dann ist die naheliegende Form nicht Ablösung, sondern **Komposition**: SageMCPs `GenericMCPConnector` kann gatekeeper als externen MCP-Server einbinden. gatekeeper bleibt die schmale, prüfbare Host-Komponente; die Mandanten-Logistik liegt darüber.

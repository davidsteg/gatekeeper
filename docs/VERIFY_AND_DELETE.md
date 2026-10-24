# `verify` for http tools and bounded `file_operation: delete`

Both are opt-in fields in a tool definition (`tools.yaml`). A tool without
them behaves exactly as before.

## `verify` (http executor)

An optional read-back request. It is sent after the main request, through the
same toolkit (same base_url / per-tool base_url, credential and CIDR check),
using the same validated parameter values.

```yaml
verify:
  method: GET            # optional, default GET
  path: /api/...{param}  # required, must start with '/', same allowed_path_prefixes
  query: {k: "{param}"}  # optional, flat str->str
  body: {...}            # optional nested template; placeholders = declared params only
  require_body: true     # optional, default false: 2xx with empty body ("", {}, [], null) = fail
```

Load-time rules (`catalog._parse_verify`, `_validate_against_tier1`):
- `POST`/`PUT`/`PATCH`/`DELETE` are only allowed **with a fixed `body`**
  (a template written in the tool). Without one, the tool fails to load.
- `body: {raw_param: ...}` is rejected in verify (no agent document as body).
- Every `{placeholder}` must be a declared parameter of the tool (same typo
  guard as the main request), so it can only carry pattern-validated values.
- verify method must be in the toolkit's `allowed_methods`; the literal path
  prefix must be in `allowed_path_prefixes`. Unknown keys are rejected.
- At call time the resolved verify path, method, query and body go through the
  same `build_http_request` checks as the main request, before anything is sent.

Response (stdout is JSON):

```json
{"main":   {"outcome":"ok","status":200,"body":"...","error":"","truncated":false},
 "verify": {"outcome":"ok","status":200,"body":"...","error":"","truncated":false}}
```

- Both ok means `outcome: ok`.
- Main ok but verify not ok means `outcome: failed`, and stderr starts with
  `VERIFY FAILED: the main request succeeded (HTTP x), but the verify request did not (HTTP y).`
- Main not ok means verify is not sent: `"verify": {"skipped": "main request did not succeed"}`,
  and the main outcome is passed through (incl. `unknown` on a non-idempotent timeout).
- `require_body: true`: a 2xx verify answer with an empty body (`""`, `{}`,
  `[]`, `null`) counts as failed. This is needed for Tdarr: cruddb getById answers
  a missing doc with 200 and an empty body, not with 404.
- verify always runs as idempotent: a verify timeout is `failed`, never `unknown`.
- `exit_code` is the main HTTP status.

## `file_operation: delete` (file executor)

```yaml
file_operation: delete
delete:
  max_entries: 5     # required, int >= 1
  files_only: true   # optional, default false
```

Sequence (`execute_file._delete`):
1. Path checks as for every file tool: absolute, `path_roots`,
   `protected_resources`, and the parameter `pattern`. In addition: the path
   must not contain a symlink anywhere (abspath == realpath), and it must not
   be a path root itself.
2. The tree is listed **without following symlinks** (a symlink is one entry
   `l name`; its target is never entered).
3. More than `max_entries` entries, or (with `files_only`) any
   sub-directory, aborts. Nothing is deleted, and the outcome is `failed`.
4. Delete (`rmtree` for a directory, `unlink` for a file; symlinks inside the
   tree are removed as links).
5. Proof: `os.path.lexists(path)` must be false afterwards.

stdout on success:

```
listed 2 entries under directory /…/abc-test:
f a.mkv
f b.srt
removed: /…/abc-test (path no longer exists)
```

Also works with `run_as` (the request carries `max_entries`/`files_only` to the
helper, which runs the same `perform`).

## Example entries

```yaml
  - id: tdarr.index_file
    toolkit: tdarr
    category: write
    enabled: false
    title: "Index one file and read it back"
    description: "POST /api/v2/scan-files (dbID fixed, mode scanFolderWatcher), then cruddb getById FileJSONDB docID={path}. ok only if the doc exists."
    method: POST
    path: /api/v2/scan-files
    body:
      data:
        scanConfig:
          dbID: "-aLDEYQmP"
          arrayOrPath: ["{path}"]
          mode: scanFolderWatcher
    verify:
      method: POST
      path: /api/v2/cruddb
      require_body: true
      body:
        data:
          collection: FileJSONDB
          mode: getById
          docID: "{path}"
    parameters:
      path:
        type: string
        required: true
        pattern: "^/media/Library/Movies/1080p/(?!\\.\\.?/)[^/\\x00-\\x1f]{1,200}/(?!\\.\\.?$)[^/\\x00-\\x1f]{1,250}\\.(mkv|mp4)$"
    required_scopes: []
    timeout_seconds: 30
    max_output_bytes: 65536
    idempotent: false

  - id: fs.rm_test_dir
    toolkit: fs
    category: write
    enabled: false
    title: "Remove one *-test directory (bounded)"
    description: "Lists, then deletes one 1080p *-test dir: max 5 files, no sub-dirs."
    file_operation: delete
    delete:
      max_entries: 5
      files_only: true
    parameters:
      path:
        type: string
        required: true
        pattern: "^/mnt/venus/media/Library/Movies/1080p/[a-z0-9]{1,20}-test$"
    required_scopes: []
    timeout_seconds: 30
    max_output_bytes: 16384
    idempotent: false
```

`fs` must be a `file` toolkit whose `path_roots` contains
`/mnt/venus/media/Library/Movies/1080p` (or a parent), and the gatekeeper
container must see that path.

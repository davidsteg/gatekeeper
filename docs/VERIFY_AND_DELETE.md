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
- Only `GET`/`HEAD`/`OPTIONS` may be used without a body (an allowlist,
  `catalog.READ_METHODS`). Any other method (`POST`, `PUT`, but also WebDAV's
  `MOVE`/`COPY`/`MKCOL`/`PROPFIND`, ...) is only allowed **with a fixed
  `body`** (a template written in the tool). Without one, the tool fails to load.
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
  max_entries: 5     # required, 1 <= int <= 100000 (MAX_DELETE_ENTRIES)
  files_only: true   # optional, default false
```

Sequence (`execute_file._delete`, called through `perform` -- so the
`run_as` child runs exactly the same checks, not only the parent):
1. Path checks as for every file tool: absolute, `path_roots`,
   `protected_resources`, and the parameter `pattern` (`validate_path`, on the
   resolved path). Then `_delete` works on the path **as sent**, not resolved:
   any `.` or `..` segment is refused; the path must lie literally under a
   path root (matched by the root's abspath or realpath -- a root may itself be
   a symlink by admin config) and must not be a root itself; no segment may be
   a protected name.
2. No path strings from here on. The root is opened via its realpath, then
   every component below it is opened `O_NOFOLLOW` relative to its parent's
   fd. A symlink in any component, the target included, is refused.
3. The tree is listed via those fds, **without following symlinks** (a
   symlink is one entry `l name`; its target is never entered). Each entry's
   `(st_dev, st_ino, type)` is recorded.
4. More than `max_entries` entries, any sub-directory (with `files_only`), a
   directory more than 64 levels below the target (`MAX_DELETE_DEPTH`; the
   target is level 0 -- each level holds one fd and some stack while
   listing and deleting), or any entry whose name is in `protected_resources`
   (e.g. a `.git` anywhere under the target) aborts. So does a listing error
   (I/O error, out of fds). Nothing is deleted, and the outcome is `failed`.
5. Delete exactly the listed entries, bottom-up, with `unlink`/`rmdir` on
   the dir fds. First the root -> parent chain is re-walked and must still be
   the same directories. Each directory is re-opened `O_NOFOLLOW` and must
   still be the listed inode with exactly the listed names; each entry is
   `fstatat`-checked right before it is unlinked. The first extra, missing or
   replaced entry (or an `rmdir` that fails because the directory gained an
   entry) stops the delete: the outcome is `failed`, stderr says why, and
   stdout begins with `deleted before abort:`, followed by what was removed
   by then (`(nothing)` if nothing was).
6. Proof: the target's name must no longer exist in its parent's fd.

Symlinks inside the tree are removed as links. The chain check in step 5
cannot pin the path: right after it, the tree may still be renamed elsewhere,
and there is a residual window between an entry's final check and its
`unlink`. What holds throughout is that only listed entries whose
`(st_dev, st_ino, type)` matched are removed, by name, through the fds held
since the listing, never following a symlink -- the most a race can do is
remove that name, never a target outside the tree.

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

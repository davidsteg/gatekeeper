"""`verify` read-back for http tools and bounded `file_operation: delete`.

http: a real loopback server (like `test_execute_http.py`) that records
every request, so "verify ran after main, with the same parameter values"
is checked on the wire. file: a real tmp tree, so "nothing was deleted" is
checked on disk, not on the return value.
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from conftest import make_catalog

from gatekeeper.audit import AuditLog
from gatekeeper.catalog import parse_tool_spec
from gatekeeper.errors import ConfigError
from gatekeeper.execute import OUTCOME_FAILED, OUTCOME_OK
from gatekeeper.execute_file import run as file_run
from gatekeeper.identity import Identity, hash_token
from gatekeeper.service import Service
from gatekeeper.tier1 import load_tier1


class _Handler(BaseHTTPRequestHandler):
    seen: list[tuple[str, str, bytes]] = []
    #: docIDs the fake cruddb "knows" -- what a scan would have indexed.
    indexed: set[str] = set()

    def log_message(self, *args):
        pass

    def _json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        type(self).seen.append(("GET", self.path, b""))
        if self.path.startswith("/api/v2/missing"):
            self._json(404, {"error": "not found"})
        else:
            self._json(200, {"path": self.path})

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        type(self).seen.append(("POST", self.path, raw))
        data = json.loads(raw or b"{}")
        if self.path == "/api/v2/scan-files":
            if data.get("data", {}).get("fail"):
                self._json(500, {"error": "scan failed"})
                return
            type(self).indexed.add(data["data"]["scanConfig"]["path"])
            self._json(200, {"queued": True})
        elif self.path == "/api/v2/cruddb":
            doc = data["data"]["docID"]
            if doc in type(self).indexed:
                self._json(200, {"_id": doc, "file": doc})
            elif doc.endswith("empty"):
                self._json(200, {})  # Tdarr-style "not found": 200 + empty
            else:
                self._json(404, {"error": "no such doc"})
        else:
            self._json(404, {})


@pytest.fixture
def server():
    _Handler.seen = []
    _Handler.indexed = set()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()
    t.join(timeout=5)
    srv.server_close()


@pytest.fixture
def tier1(tmp_path, server):
    root = tmp_path / "media"
    root.mkdir()
    p = tmp_path / "toolkits.yaml"
    p.write_text(
        f"""
toolkits:
  tdarr:
    executor: http
    base_url: "http://127.0.0.1:{server.server_address[1]}"
    allowed_methods: ["GET", "POST"]
    allowed_path_prefixes: ["/api/"]
    allowed_cidrs: ["127.0.0.1/32"]
  fs:
    executor: file
    path_roots: ["{root}"]
audit:
  dir: {tmp_path / "logs"}
""",
        encoding="utf-8",
    )
    return load_tier1(str(p))


def _index_spec(**over):
    spec = {
        "id": "tdarr.index_file",
        "toolkit": "tdarr",
        "version": 1,
        "title": "Index one file",
        "description": "Scan one file, then read it back from FileJSONDB.",
        "category": "write",
        "enabled": True,
        "method": "POST",
        "path": "/api/v2/scan-files",
        "body": {"data": {"scanConfig": {"dbID": "lib1", "path": "{path}"}}},
        "verify": {
            "method": "POST",
            "path": "/api/v2/cruddb",
            "body": {
                "data": {"collection": "FileJSONDB", "mode": "getById", "docID": "{path}"}
            },
        },
        "parameters": {
            "path": {"type": "string", "required": True,
                     "pattern": "^/media/[A-Za-z0-9 ._/-]{1,200}$"},
        },
        "timeout_seconds": 5,
        "max_output_bytes": 65536,
    }
    spec.update(over)
    return spec


def _service(tmp_path, tier1, specs):
    catalog = make_catalog(tmp_path, tier1, specs)
    ids = frozenset(s["id"] for s in specs)
    identity = Identity(id="agent", role="agent", token_hash=hash_token("x"),
                        tools=ids, scopes=())
    return Service(tier1=tier1, catalog=catalog,
                   audit=AuditLog(str(tmp_path / "audit"))), identity


# -- verify: config validation ---------------------------------------------


def test_verify_parses_and_keeps_fields(tier1):
    tool = parse_tool_spec(_index_spec(), tier1)
    assert tool.verify["method"] == "POST"
    assert tool.verify["path"] == "/api/v2/cruddb"
    assert tool.verify["body"]["data"]["docID"] == "{path}"


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "post"])
def test_verify_write_method_without_fixed_body_is_rejected(tier1, method):
    spec = _index_spec(verify={"method": method, "path": "/api/v2/cruddb"})
    with pytest.raises(ConfigError, match="writes"):
        parse_tool_spec(spec, tier1)


def test_verify_raw_param_body_is_rejected(tier1):
    spec = _index_spec(verify={"method": "POST", "path": "/api/v2/cruddb",
                               "body": {"raw_param": "path"}})
    with pytest.raises(ConfigError, match="raw_param"):
        parse_tool_spec(spec, tier1)


def test_verify_placeholder_must_be_a_declared_parameter(tier1):
    spec = _index_spec(verify={"method": "POST", "path": "/api/v2/cruddb",
                               "body": {"docID": "{other}"}})
    with pytest.raises(ConfigError, match="unknown parameter 'other'"):
        parse_tool_spec(spec, tier1)


def test_verify_unknown_key_is_rejected(tier1):
    spec = _index_spec(verify={"path": "/api/x", "headers": {"a": "b"}})
    with pytest.raises(ConfigError, match="unknown keys"):
        parse_tool_spec(spec, tier1)


def test_verify_outside_toolkit_prefix_is_rejected(tier1):
    from gatekeeper.errors import Tier1Violation

    spec = _index_spec(verify={"path": "/admin/x"})
    with pytest.raises(Tier1Violation, match="verify path"):
        parse_tool_spec(spec, tier1)


def test_verify_method_outside_allowlist_is_rejected(tier1):
    from gatekeeper.errors import Tier1Violation

    spec = _index_spec(verify={"method": "PUT", "path": "/api/x", "body": {"a": 1}})
    with pytest.raises(Tier1Violation, match="verify method"):
        parse_tool_spec(spec, tier1)


def test_verify_defaults_to_get(tier1):
    tool = parse_tool_spec(_index_spec(verify={"path": "/api/v2/file/{path}"}), tier1)
    assert tool.verify["method"] == "GET"


# -- verify: execution -------------------------------------------------------


def test_verify_ok_returns_main_and_verify(tmp_path, tier1):
    service, ident = _service(tmp_path, tier1, [_index_spec()])
    result = asyncio.run(service.call(ident, "tdarr.index_file",
                                      {"path": "/media/a b.mkv"}))
    assert result.outcome == OUTCOME_OK, result.stderr
    payload = json.loads(result.stdout)
    assert payload["main"]["status"] == 200
    assert payload["verify"]["status"] == 200
    assert json.loads(payload["verify"]["body"])["_id"] == "/media/a b.mkv"
    # order on the wire: main first, then verify with the same value
    assert [(m, p) for m, p, _ in _Handler.seen] == [
        ("POST", "/api/v2/scan-files"), ("POST", "/api/v2/cruddb")]
    assert json.loads(_Handler.seen[1][2])["data"]["docID"] == "/media/a b.mkv"


def test_verify_fail_marks_result_not_ok(tmp_path, tier1):
    # main succeeds, but the read-back cannot find the doc
    spec = _index_spec(verify={"method": "POST", "path": "/api/v2/cruddb",
                               "body": {"data": {"docID": "/media/never"}}})
    service, ident = _service(tmp_path, tier1, [spec])
    result = asyncio.run(service.call(ident, "tdarr.index_file", {"path": "/media/x.mkv"}))
    assert result.outcome == OUTCOME_FAILED
    assert "VERIFY FAILED" in result.stderr
    payload = json.loads(result.stdout)
    assert payload["main"]["outcome"] == OUTCOME_OK
    assert payload["verify"]["status"] == 404


@pytest.mark.parametrize("require, expected", [(True, OUTCOME_FAILED), (False, OUTCOME_OK)])
def test_verify_require_body_fails_on_empty_200(tmp_path, tier1, require, expected):
    spec = _index_spec(verify={"method": "POST", "path": "/api/v2/cruddb",
                               "body": {"data": {"docID": "/media/empty"}},
                               "require_body": require})
    service, ident = _service(tmp_path, tier1, [spec])
    result = asyncio.run(service.call(ident, "tdarr.index_file", {"path": "/media/x.mkv"}))
    assert result.outcome == expected
    if require:
        assert "VERIFY FAILED" in result.stderr and "require_body" in result.stderr


def test_verify_require_body_must_be_bool(tier1):
    spec = _index_spec(verify={"path": "/api/x", "require_body": "yes"})
    with pytest.raises(ConfigError, match="require_body"):
        parse_tool_spec(spec, tier1)


def test_verify_skipped_when_main_fails(tmp_path, tier1):
    spec = _index_spec(body={"data": {"fail": True, "p": "{path}"}})
    service, ident = _service(tmp_path, tier1, [spec])
    result = asyncio.run(service.call(ident, "tdarr.index_file", {"path": "/media/x.mkv"}))
    assert result.outcome == OUTCOME_FAILED
    payload = json.loads(result.stdout)
    assert payload["main"]["status"] == 500
    assert "skipped" in payload["verify"]
    assert len(_Handler.seen) == 1


def test_tool_without_verify_is_unchanged(tmp_path, tier1):
    """Regression: no `verify` key -> raw target body, as before."""
    spec = _index_spec()
    del spec["verify"]
    service, ident = _service(tmp_path, tier1, [spec])
    result = asyncio.run(service.call(ident, "tdarr.index_file", {"path": "/media/x.mkv"}))
    assert result.outcome == OUTCOME_OK
    assert json.loads(result.stdout) == {"queued": True}
    assert len(_Handler.seen) == 1
    assert parse_tool_spec(spec, tier1).verify is None


# -- delete: config validation ---------------------------------------------


def _rm_spec(root, **over):
    spec = {
        "id": "fs.rm_test_dir",
        "toolkit": "fs",
        "version": 1,
        "title": "Remove a test dir",
        "description": "Bounded delete of one *-test directory.",
        "category": "write",
        "enabled": True,
        "file_operation": "delete",
        "delete": {"max_entries": 5, "files_only": True},
        "parameters": {
            "path": {"type": "string", "required": True,
                     "pattern": f"^{root}/[a-z0-9]{{1,20}}-test$"},
        },
        "timeout_seconds": 5,
        "max_output_bytes": 65536,
    }
    spec.update(over)
    return spec


def test_delete_requires_max_entries(tier1, tmp_path):
    root = tmp_path / "media"
    with pytest.raises(ConfigError, match="max_entries"):
        parse_tool_spec(_rm_spec(root, delete=None), tier1)
    with pytest.raises(ConfigError, match="max_entries"):
        parse_tool_spec(_rm_spec(root, delete={"files_only": True}), tier1)
    with pytest.raises(ConfigError, match="max_entries"):
        parse_tool_spec(_rm_spec(root, delete={"max_entries": 0}), tier1)


def test_delete_options_on_other_operation_rejected(tier1, tmp_path):
    with pytest.raises(ConfigError, match="only apply"):
        parse_tool_spec(_rm_spec(tmp_path, file_operation="read"), tier1)


def test_delete_parses(tier1, tmp_path):
    tool = parse_tool_spec(_rm_spec(tmp_path / "media"), tier1)
    assert (tool.file_operation, tool.delete_max_entries, tool.delete_files_only) == (
        "delete", 5, True)


# -- delete: execution -------------------------------------------------------


def _tree(base, files=(), dirs=()):
    os.makedirs(base)
    for d in dirs:
        os.makedirs(os.path.join(base, d))
    for f in files:
        with open(os.path.join(base, f), "w") as fh:
            fh.write("x")


def _del(path, root, max_entries=5, files_only=True):
    return asyncio.run(file_run(operation="delete", path=str(path), path_roots=[str(root)],
                                protected=["gatekeeper"], timeout_seconds=5,
                                max_output_bytes=65536, max_entries=max_entries,
                                files_only=files_only))


def test_delete_under_limit_lists_then_removes(tmp_path):
    target = tmp_path / "abc-test"
    _tree(target, files=["a.mkv", "b.srt"])
    r = _del(target, tmp_path)
    assert r.outcome == OUTCOME_OK, r.stderr
    assert "f a.mkv" in r.stdout and "f b.srt" in r.stdout
    assert r.stdout.index("f a.mkv") < r.stdout.index("removed:")
    assert "path no longer exists" in r.stdout
    assert not os.path.lexists(target)


def test_delete_exactly_at_limit(tmp_path):
    target = tmp_path / "abc-test"
    _tree(target, files=[f"{i}.x" for i in range(5)])
    assert _del(target, tmp_path).outcome == OUTCOME_OK
    assert not target.exists()


def test_delete_over_limit_aborts_nothing_deleted(tmp_path):
    target = tmp_path / "abc-test"
    _tree(target, files=[f"{i}.x" for i in range(6)])
    r = _del(target, tmp_path)
    assert r.outcome == OUTCOME_FAILED
    assert "nothing deleted" in r.stderr and "max_entries" in r.stderr
    assert sorted(os.listdir(target)) == sorted(f"{i}.x" for i in range(6))


def test_delete_subdir_with_files_only_aborts(tmp_path):
    target = tmp_path / "abc-test"
    _tree(target, files=["a.mkv"], dirs=["sub"])
    r = _del(target, tmp_path)
    assert r.outcome == OUTCOME_FAILED
    assert "files_only" in r.stderr
    assert sorted(os.listdir(target)) == ["a.mkv", "sub"]


def test_delete_subdir_allowed_without_files_only(tmp_path):
    target = tmp_path / "abc-test"
    _tree(target, files=["a.mkv", "sub/b.srt"], dirs=["sub"])
    r = _del(target, tmp_path, files_only=False)
    assert r.outcome == OUTCOME_OK, r.stderr
    assert "d sub" in r.stdout and "f sub/b.srt" in r.stdout
    assert not target.exists()


def test_delete_symlink_inside_tree_is_not_followed(tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    _tree(outside, files=["keep.txt"])
    root = tmp_path / "root"
    target = root / "abc-test"
    _tree(target, files=["a.mkv"])
    os.symlink(outside, target / "link")
    r = _del(target, root)
    assert r.outcome == OUTCOME_OK, r.stderr
    assert "l link" in r.stdout
    assert not os.path.lexists(target)
    assert (outside / "keep.txt").exists()  # link removed, target untouched


def test_delete_path_that_is_a_symlink_is_refused(tmp_path):
    root = tmp_path / "root"
    real = root / "real-test"
    _tree(real, files=["a.mkv"])
    os.symlink(real, root / "abc-test")
    r = _del(root / "abc-test", root)
    assert r.outcome == OUTCOME_FAILED
    assert "symlink" in r.stderr
    assert (real / "a.mkv").exists() and os.path.islink(root / "abc-test")


def test_delete_symlink_escaping_scope_is_refused(tmp_path):
    outside = tmp_path / "outside"
    _tree(outside, files=["keep.txt"])
    root = tmp_path / "root"
    os.makedirs(root)
    os.symlink(outside, root / "abc-test")
    r = _del(root / "abc-test", root)
    assert r.outcome == OUTCOME_FAILED
    assert (outside / "keep.txt").exists()


def test_delete_outside_scope_is_refused(tmp_path):
    root = tmp_path / "root"
    os.makedirs(root)
    other = tmp_path / "other-test"
    _tree(other, files=["a"])
    for p in (other, root / ".." / "other-test"):
        r = _del(p, root)
        assert r.outcome == OUTCOME_FAILED
        assert "outside allowed roots" in r.stderr
    assert (other / "a").exists()


def test_delete_root_itself_is_refused(tmp_path):
    _tree(tmp_path / "r", files=["a"])
    r = _del(tmp_path / "r", tmp_path / "r")
    assert r.outcome == OUTCOME_FAILED and "path root" in r.stderr
    assert (tmp_path / "r" / "a").exists()


def test_delete_via_service_uses_pattern_and_bounds(tmp_path, tier1):
    root = tmp_path / "media"
    spec = _rm_spec(root)
    service, ident = _service(tmp_path, tier1, [spec])
    _tree(root / "abc-test", files=["a.mkv"])
    result = asyncio.run(service.call(ident, "fs.rm_test_dir",
                                      {"path": str(root / "abc-test")}))
    assert result.outcome == OUTCOME_OK, result.stderr
    assert not (root / "abc-test").exists()
    # pattern still gates the path before any file op
    from gatekeeper.errors import Denied
    _tree(root / "keep", files=["a"])
    with pytest.raises(Denied):
        asyncio.run(service.call(ident, "fs.rm_test_dir", {"path": str(root / "keep")}))
    assert (root / "keep" / "a").exists()

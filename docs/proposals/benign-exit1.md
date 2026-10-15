# Benign exit 1 (grep/diff/test) -- changelog note

Status: feature branch `feat/benign-exit1`, not released. Version bump and
RELEASE.md section follow in the release commit.

- docker/local/ssh calls whose inner command is grep, egrep, fgrep, rg, diff,
  cmp, test or `[` and that exit 1 with empty stderr are reported with
  `outcome=ok` instead of `failed`, so MCP clients (Hermes circuit breaker:
  3 consecutive isError = 60 s pause) do not count "no match" as an error.
- **Audit/metrics reclassification:** metrics and the audit entry record
  `outcome=ok`, the real `exit_code=1` is kept. Reclassified calls are
  findable as `outcome == "ok" and exit_code == 1`. The agent still sees
  `exit=1`.
- The `sh -c` command is only recognised at the command position (argv[0],
  or right after `[docker] exec <container>`); a `sh -c` pair inside
  parameter values is ignored. Pipelines/compound commands are never benign.
- Denials, rate limits, timeouts, exit >= 2 and exit 1 with stderr are unchanged.

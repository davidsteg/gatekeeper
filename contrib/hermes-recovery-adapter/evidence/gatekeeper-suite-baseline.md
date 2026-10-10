# Gatekeeper test-suite baseline (Windows dev box)

Not green. Run on Gatekeeper commit 7aa7b39 (branch feature/recovery-adapter-v1):

    python -m pytest -q --ignore=tests/test_runas.py --ignore=tests/test_selfdrop.py --ignore=tests/test_unpriv.py

Result: **1213 passed, 2 skipped, 11 failed, 33 errors.** The 3 ignored modules do not import on Windows (pwd / os.geteuid).

The 11 failures + 33 errors below are identical, entry for entry, to the run on the commit *before* any recovery work (0.47.4 baseline): Windows-only environment issues (POSIX-only paths, YAML fixture paths). None is in tests/test_recovery.py (70/70 passed). No Linux CI run exists for this branch; CI runs on main only.

```
ERROR tests/test_execute_opencode.py::test_abort_stops_a_session
ERROR tests/test_execute_opencode.py::test_ask_creates_a_session_and_returns_the_answer
ERROR tests/test_execute_opencode.py::test_check_reports_status_todos_and_files
ERROR tests/test_execute_opencode.py::test_directory_outside_path_roots_is_denied
ERROR tests/test_execute_opencode.py::test_directory_travels_as_the_opencode_header
ERROR tests/test_execute_opencode.py::test_directory_traversal_is_denied
ERROR tests/test_execute_opencode.py::test_end_to_end_ask_through_the_service
ERROR tests/test_execute_opencode.py::test_end_to_end_bad_directory_is_an_audited_denial
ERROR tests/test_execute_opencode.py::test_fire_returns_the_session_id_without_waiting
ERROR tests/test_execute_opencode.py::test_health_reports_healthy_and_version
ERROR tests/test_execute_opencode.py::test_health_tool_takes_no_parameters
ERROR tests/test_execute_opencode.py::test_idempotent_timeout_is_failed
ERROR tests/test_execute_opencode.py::test_missing_required_parameter_is_a_config_error
ERROR tests/test_execute_opencode.py::test_model_without_a_provider_is_denied
ERROR tests/test_execute_opencode.py::test_nonexistent_directory_under_a_visible_root_is_denied
ERROR tests/test_execute_opencode.py::test_optional_required_parameter_is_a_config_error
ERROR tests/test_execute_opencode.py::test_parameter_the_operation_does_not_read_is_a_config_error
ERROR tests/test_execute_opencode.py::test_probe_is_true_for_a_reachable_server
ERROR tests/test_execute_opencode.py::test_providers_lists_models_and_defaults
ERROR tests/test_execute_opencode.py::test_redirect_is_reported_not_followed
ERROR tests/test_execute_opencode.py::test_relative_directory_is_denied
ERROR tests/test_execute_opencode.py::test_response_over_the_output_ceiling_is_reported_not_truncated
ERROR tests/test_execute_opencode.py::test_review_changes_counts_added_and_removed
ERROR tests/test_execute_opencode.py::test_run_polls_until_the_session_finishes
ERROR tests/test_execute_opencode.py::test_run_timeout_is_unknown_not_failed
ERROR tests/test_execute_opencode.py::test_session_id_cannot_address_another_endpoint[../session]
ERROR tests/test_execute_opencode.py::test_session_id_cannot_address_another_endpoint[]
ERROR tests/test_execute_opencode.py::test_session_id_cannot_address_another_endpoint[aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa]
ERROR tests/test_execute_opencode.py::test_session_id_cannot_address_another_endpoint[ses 1]
ERROR tests/test_execute_opencode.py::test_session_id_cannot_address_another_endpoint[ses_1/../../global/health]
ERROR tests/test_execute_opencode.py::test_session_id_cannot_address_another_endpoint[ses_1?x=1]
ERROR tests/test_execute_opencode.py::test_session_id_is_rechecked_in_the_executor
ERROR tests/test_execute_opencode.py::test_unknown_operation_in_a_tool_is_a_config_error
FAILED tests/test_execute_opencode.py::test_credential_is_sent_as_a_basic_auth_header
FAILED tests/test_execute_opencode.py::test_missing_credential_is_reported_not_ignored
FAILED tests/test_execute_opencode.py::test_operation_outside_the_allowlist_is_a_load_time_violation
FAILED tests/test_execute_opencode.py::test_operation_outside_the_allowlist_is_refused_by_the_executor
FAILED tests/test_execute_opencode.py::test_probe_is_false_when_the_ip_is_outside_allowed_cidrs
FAILED tests/test_execute_opencode.py::test_resolved_ip_outside_allowed_cidrs_is_blocked
FAILED tests/test_execute_opencode.py::test_unknown_operation_in_toolkit_is_a_config_error
FAILED tests/test_google_fallback.py::test_without_a_baked_copy_the_configured_path_is_kept
FAILED tests/test_microsoft_oauth.py::test_the_token_file_is_owner_only
FAILED tests/test_outlook_tools.py::test_a_rotated_refresh_token_is_written_back
FAILED tests/test_ui_stats.py::test_bucket_calls_by_day_buckets_correctly
```

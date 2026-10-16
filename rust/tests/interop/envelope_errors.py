"""Golden pydantic messages for JSON-RPC envelope validation failures.

    python envelope_errors.py > ../data/mcp_envelope_errors.json

The Python transport answers a body that is JSON but not a JSON-RPC
message with `400 Validation error: <str(ValidationError)>`. The Rust port
renders the same text; `gatekeeper::mcp::jsonrpc`'s tests compare against
the file this script writes.
"""

import json

from mcp_types import jsonrpc_message_adapter
from pydantic import ValidationError

CASES = [
    [{"jsonrpc": "2.0", "id": 1, "method": "ping"}],
    {"jsonrpc": "2.0", "id": 19, "method": "ping", "params": [1]},
    {"jsonrpc": "1.0", "id": 1, "method": "ping"},
    {"jsonrpc": "2.0", "id": 1},
    {},
    "hello",
    5,
    None,
    True,
    1.5,
    {"jsonrpc": "2.0", "id": 1.5},
    {"jsonrpc": "2.0", "id": True, "result": 3},
    {"jsonrpc": "2.0", "id": None, "error": {"code": "x", "message": 3}},
    {"jsonrpc": "2.0", "id": 1, "error": {"code": 1.5}},
    {"jsonrpc": "2.0", "id": 1, "error": {"code": True, "message": "m"}, "method": 3},
    {"jsonrpc": "2.0", "id": 1, "error": "boom"},
    {"jsonrpc": "2.0", "method": 7, "params": "p"},
    {"jsonrpc": 2, "method": "m", "id": [1], "result": None},
    {"jsonrpc": "2.0", "id": {"a": 1}, "method": "x" * 80},
    {"jsonrpc": "2.0", "id": "a", "method": None, "params": None, "result": [], "error": {}},
    {"jsonrpc": "2.0", "id": 1, "error": {"code": "12", "message": "m", "data": None}, "method": 1},
    {"jsonrpc": "2.0", "error": {"code": 1e400 if False else 1.0, "message": "é\n"}, "id": -1.0},
    {"jsonrpc": None},
]

out = []
for case in CASES:
    try:
        jsonrpc_message_adapter.validate_python(case, by_name=False)
        out.append({"input": case, "error": None})
    except ValidationError as e:
        out.append({"input": case, "error": str(e)})
print(json.dumps(out, indent=1))

"""Mock JSON-RPC stdio language server for testing LSPGraphQuery."""

import sys
import json

def run_mock_lsp_server():
    stdin_raw = sys.stdin.buffer
    stdout_raw = sys.stdout.buffer

    while True:
        line = stdin_raw.readline()
        if not line:
            break
        if line.startswith(b"Content-Length:"):
            length = int(line.split(b":")[1].strip())
            stdin_raw.readline() # blank line
            content = stdin_raw.read(length)
            req = json.loads(content.decode("utf-8"))
            method = req.get("method")
            req_id = req.get("id")

            # Do not reply to notifications (messages without id)
            if req_id is None:
                continue

            if method == "initialize":
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "capabilities": {
                            "workspaceSymbolProvider": True,
                            "callHierarchyProvider": True
                        }
                    }
                }
            elif method == "workspace/symbol":
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": [
                        {
                            "name": "auth_sink",
                            "kind": 12,
                            "location": {
                                "uri": "file:///tmp/test-repo/src/auth.py",
                                "range": {"start": {"line": 10, "character": 4}, "end": {"line": 10, "character": 13}}
                            }
                        },
                        {
                            "name": "login_entry",
                            "kind": 12,
                            "location": {
                                "uri": "file:///tmp/test-repo/src/main.py",
                                "range": {"start": {"line": 5, "character": 4}, "end": {"line": 5, "character": 15}}
                            }
                        }
                    ]
                }
            elif method == "textDocument/prepareCallHierarchy":
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": [
                        {
                            "name": "auth_sink",
                            "kind": 12,
                            "uri": "file:///tmp/test-repo/src/auth.py",
                            "range": {"start": {"line": 10, "character": 4}, "end": {"line": 10, "character": 13}},
                            "selectionRange": {"start": {"line": 10, "character": 4}, "end": {"line": 10, "character": 13}}
                        }
                    ]
                }
            elif method == "callHierarchy/incomingCalls":
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": [
                        {
                            "from": {
                                "name": "login_entry",
                                "kind": 12,
                                "uri": "file:///tmp/test-repo/src/main.py",
                                "range": {"start": {"line": 5, "character": 4}, "end": {"line": 5, "character": 15}},
                                "selectionRange": {"start": {"line": 5, "character": 4}, "end": {"line": 5, "character": 15}}
                            },
                            "fromRanges": [{"start": {"line": 6, "character": 8}, "end": {"line": 6, "character": 17}}]
                        }
                    ]
                }
            elif method == "callHierarchy/outgoingCalls":
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": [
                        {
                            "to": {
                                "name": "auth_sink",
                                "kind": 12,
                                "uri": "file:///tmp/test-repo/src/auth.py",
                                "range": {"start": {"line": 10, "character": 4}, "end": {"line": 10, "character": 13}},
                                "selectionRange": {"start": {"line": 10, "character": 4}, "end": {"line": 10, "character": 13}}
                            },
                            "fromRanges": [{"start": {"line": 6, "character": 8}, "end": {"line": 6, "character": 17}}]
                        }
                    ]
                }
            else:
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": None
                }

            res_bytes = json.dumps(resp).encode("utf-8")
            stdout_raw.write(f"Content-Length: {len(res_bytes)}\r\n\r\n".encode("utf-8"))
            stdout_raw.write(res_bytes)
            stdout_raw.flush()

if __name__ == "__main__":
    run_mock_lsp_server()

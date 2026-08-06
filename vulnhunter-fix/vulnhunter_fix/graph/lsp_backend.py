"""LSP Graph Backend implementation.

Uses JSON-RPC stdio language servers (e.g. pyright, gopls, or multilspy) to implement
the GraphBackend protocol semantically.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .protocol import GraphBackend

logger = logging.getLogger(__name__)

LANGUAGE_SERVERS = {
    "python": ["pyright", "--stdio"],
    "go": ["gopls"],
}

class LSPClient:
    """Minimal JSON-RPC 2.0 stdio client."""

    def __init__(self, process: subprocess.Popen, repo_root: str):
        self.proc = process
        self.repo_root = str(Path(repo_root).resolve())
        self.req_id = 0
        self.initialized = False
        self._initialize()

    def _initialize(self) -> None:
        if self.initialized:
            return
        init_params = {
            "processId": os.getpid(),
            "rootUri": f"file://{self.repo_root}",
            "capabilities": {
                "workspace": {"symbol": {"symbolKind": {"valueSet": list(range(1, 27))}}},
                "textDocument": {
                    "callHierarchy": {"dynamicRegistration": False}
                }
            }
        }
        resp = self.request("initialize", init_params)
        if resp is not None:
            self.notify("initialized", {})
            self.initialized = True

    def request(self, method: str, params: Any, timeout: float = 30.0) -> Optional[Any]:
        if self.proc.poll() is not None:
            return None
        self.req_id += 1
        msg_id = self.req_id
        payload = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "method": method,
            "params": params
        }
        body = json.dumps(payload).encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8")

        try:
            stdin = self.proc.stdin
            stdout = self.proc.stdout
            if stdin is None or stdout is None:
                return None

            stdin_raw = getattr(stdin, "buffer", stdin)
            stdout_raw = getattr(stdout, "buffer", stdout)

            stdin_raw.write(header + body)
            stdin_raw.flush()

            # Read response header
            header_line = stdout_raw.readline()
            if not header_line:
                return None
            length = 0
            if header_line.startswith(b"Content-Length:"):
                length = int(header_line.split(b":")[1].strip())
                stdout_raw.readline() # blank line
            content = stdout_raw.read(length)
            resp = json.loads(content.decode("utf-8"))
            return resp.get("result")
        except Exception as err:
            logger.warning(f"LSP request '{method}' failed: {err}")
            return None

    def notify(self, method: str, params: Any) -> None:
        if self.proc.poll() is not None:
            return
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        }
        body = json.dumps(payload).encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8")
        try:
            stdin = self.proc.stdin
            if stdin is None:
                return
            stdin_raw = getattr(stdin, "buffer", stdin)
            stdin_raw.write(header + body)
            stdin_raw.flush()
        except Exception:
            pass


class LSPGraphQuery:
    """GraphBackend implementation using a live LSP session."""

    def __init__(self, process_or_client: Any, repo_root: str, language: str = "python"):
        self.repo_root = str(Path(repo_root).resolve())
        self.language = language
        if isinstance(process_or_client, subprocess.Popen):
            self.client = LSPClient(process_or_client, repo_root)
        else:
            self.client = process_or_client
        self._caller_cache: Dict[str, List[Dict[str, Any]]] = {}
        self._callee_cache: Dict[str, List[Dict[str, Any]]] = {}

    def _uri_to_relpath(self, uri: str) -> str:
        if uri.startswith("file://"):
            path_str = uri[7:]
            try:
                rel = Path(path_str).resolve().relative_to(Path(self.repo_root).resolve())
                return str(rel)
            except (ValueError, RuntimeError):
                return path_str
        return uri

    def _find_symbol_items(self, symbol_name: str) -> List[Dict[str, Any]]:
        res = self.client.request("workspace/symbol", {"query": symbol_name})
        if not res or not isinstance(res, list):
            return []
        matches = []
        for item in res:
            if item.get("name") == symbol_name or symbol_name in item.get("name", ""):
                matches.append(item)
        return matches

    def callers_of(self, symbol_or_node_id: str, max_depth: int = 5) -> List[Dict[str, Any]]:
        if symbol_or_node_id in self._caller_cache:
            return self._caller_cache[symbol_or_node_id]

        symbol_name = symbol_or_node_id.split(":")[-1]
        symbols = self._find_symbol_items(symbol_name)
        callers: List[Dict[str, Any]] = []

        for sym in symbols:
            loc = sym.get("location", {})
            uri = loc.get("uri", "")
            pos = loc.get("range", {}).get("start", {"line": 0, "character": 0})
            
            prep_res = self.client.request("textDocument/prepareCallHierarchy", {
                "textDocument": {"uri": uri},
                "position": pos
            })
            if not prep_res or not isinstance(prep_res, list):
                continue
            
            for item in prep_res:
                incoming = self.client.request("callHierarchy/incomingCalls", {"item": item})
                if not incoming or not isinstance(incoming, list):
                    continue
                for inc in incoming:
                    from_item = inc.get("from", {})
                    from_uri = from_item.get("uri", "")
                    rel_file = self._uri_to_relpath(from_uri)
                    caller_symbol = from_item.get("name", "")
                    callers.append({
                        "file": rel_file,
                        "symbol": caller_symbol,
                        "node_id": f"{rel_file}:{caller_symbol}",
                        "line": from_item.get("range", {}).get("start", {}).get("line", 1)
                    })

        self._caller_cache[symbol_or_node_id] = callers
        return callers

    def callees_of(self, symbol_or_node_id: str, max_depth: int = 5) -> List[Dict[str, Any]]:
        if symbol_or_node_id in self._callee_cache:
            return self._callee_cache[symbol_or_node_id]

        symbol_name = symbol_or_node_id.split(":")[-1]
        symbols = self._find_symbol_items(symbol_name)
        callees: List[Dict[str, Any]] = []

        for sym in symbols:
            loc = sym.get("location", {})
            uri = loc.get("uri", "")
            pos = loc.get("range", {}).get("start", {"line": 0, "character": 0})

            prep_res = self.client.request("textDocument/prepareCallHierarchy", {
                "textDocument": {"uri": uri},
                "position": pos
            })
            if not prep_res or not isinstance(prep_res, list):
                continue

            for item in prep_res:
                outgoing = self.client.request("callHierarchy/outgoingCalls", {"item": item})
                if not outgoing or not isinstance(outgoing, list):
                    continue
                for out in outgoing:
                    to_item = out.get("to", {})
                    to_uri = to_item.get("uri", "")
                    rel_file = self._uri_to_relpath(to_uri)
                    callee_symbol = to_item.get("name", "")
                    callees.append({
                        "file": rel_file,
                        "symbol": callee_symbol,
                        "node_id": f"{rel_file}:{callee_symbol}",
                        "line": to_item.get("range", {}).get("start", {}).get("line", 1)
                    })

        self._callee_cache[symbol_or_node_id] = callees
        return callees

    def reachable_from(self, input_file: str, input_line: int, sink_symbol: str) -> bool:
        # BFS from input_file/entry via callees to find sink_symbol
        entry_symbol = input_file.split(":")[-1]
        sink_sym_name = sink_symbol.split(":")[-1]

        if entry_symbol == sink_sym_name:
            return True

        visited = set()
        queue = [entry_symbol]

        while queue:
            curr = queue.pop(0)
            if curr in visited:
                continue
            visited.add(curr)

            if curr == sink_sym_name:
                return True

            callees = self.callees_of(curr, max_depth=1)
            for callee in callees:
                callee_sym = callee["symbol"]
                if callee_sym == sink_sym_name:
                    return True
                if callee_sym not in visited:
                    queue.append(callee_sym)
        return False

    def blast_radius(self, symbol_or_node_id: str, max_depth: int = 3) -> Dict[str, Any]:
        callers = self.callers_of(symbol_or_node_id, max_depth)
        files = list({c["file"] for c in callers})
        return {
            "root_symbol": symbol_or_node_id,
            "affected_files": files,
            "callers_count": len(callers)
        }

    def status(self) -> Dict[str, Any]:
        return {
            "backend": "lsp",
            "confidence": "high",
            "language": self.language,
            "initialized": self.client.initialized
        }


_SESSIONS: Dict[Tuple[str, str], Optional[LSPGraphQuery]] = {}

def select_backend(repo_root: str, language: str) -> Optional[LSPGraphQuery]:
    key = (str(Path(repo_root).resolve()), language.lower())
    if key in _SESSIONS:
        return _SESSIONS[key]

    cmd = LANGUAGE_SERVERS.get(language.lower())
    if not cmd or not shutil.which(cmd[0]):
        _SESSIONS[key] = None
        return None

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0
        )
        query = LSPGraphQuery(proc, repo_root=repo_root, language=language)
        _SESSIONS[key] = query
        return query
    except Exception as err:
        logger.warning(f"Failed to start LSP server for {language}: {err}")
        _SESSIONS[key] = None
        return None

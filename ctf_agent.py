"""Staged one-URL Web CTF solver using native OpenAI Responses function calls.

Usage:
    python ctf_agent.py <challenge-url>

Each stage has a fresh context and only its compact conclusions carry forward.
The model may reason through the Responses reasoning channel; function calls are
accepted only from native ``function_call`` output items, never from text.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import ctypes
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
import uuid
from typing import Any
from urllib.parse import urlparse

import requests
from ctf_tui import TerminalTui
import yaml
PYTHON_WORKSPACE_RUNNER = """from pathlib import Path, PurePosixPath
import os
import sys

VFS_ROOT = Path(os.environ["CTF_AGENT_WORKSPACE"]).resolve()


def vfs(path):
    if not isinstance(path, str):
        raise TypeError("vfs path must be a string")
    if "\\\\" in path or not path.startswith("/") or path.startswith("//"):
        raise ValueError("vfs paths must use one leading '/' and POSIX '/' separators")
    parts = PurePosixPath(path).parts[1:]
    if any(part in {"", ".", ".."} or ":" in part for part in parts):
        raise ValueError("vfs path must not contain traversal or drive syntax")
    candidate = VFS_ROOT.joinpath(*parts).resolve()
    candidate.relative_to(VFS_ROOT)
    return candidate


os.chdir(VFS_ROOT)
source_path = Path(sys.argv[1])
source_name = sys.argv[2]
source = source_path.read_text(encoding="utf-8")
sys.argv[:] = [source_name]
namespace = {"__name__": "__main__", "__file__": source_name, "vfs": vfs, "VFS_ROOT": VFS_ROOT}
exec(compile(source, source_name, "exec"), namespace, namespace)
"""



# ---------------------------------------------------------------- display ---

def _enable_ansi() -> bool:
    if os.name != "nt":
        return True
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_ulong()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        pass
    return False


_ANSI = _enable_ansi()
COLOR = {
    "reset": "\x1b[0m",
    "dim": "\x1b[2m",
    "think": "\x1b[2;33m",   # dim yellow — model reasoning
    "say": "\x1b[36m",       # cyan — model message text
    "tool": "\x1b[35m",      # magenta — tool calls
    "ok": "\x1b[32m",        # green — success
    "err": "\x1b[31m",       # red — errors / failure
    "flag": "\x1b[1;32m",    # bold green — the flag
    "info": "\x1b[34m",      # blue — runner info
    "phase": "\x1b[1;34m",   # bold blue — stage banners
}
_ACTIVE_TUI: TerminalTui | None = None


def start_tui(disabled: bool = False, max_activity_chars: int = 24000) -> TerminalTui:
    global _ACTIVE_TUI
    tui = TerminalTui(ansi_enabled=_ANSI, max_activity_chars=max_activity_chars)
    if not disabled and tui.start():
        _ACTIVE_TUI = tui
    return tui


def stop_tui(tui: TerminalTui | None) -> None:
    global _ACTIVE_TUI
    if tui is not None:
        tui.stop()
    _ACTIVE_TUI = None


def update_tui_status(lines: list[str]) -> None:
    if _ACTIVE_TUI is not None:
        _ACTIVE_TUI.set_status(lines)


def emit(text: str, color: str = "", end: str = "\n") -> None:
    if _ACTIVE_TUI is not None:
        _ACTIVE_TUI.write(text, color, end)
        return
    if color and _ANSI:
        text = COLOR[color] + text + COLOR["reset"]
    try:
        sys.stdout.write(text + end)
        sys.stdout.flush()
    except UnicodeEncodeError:
        encoding = sys.stdout.encoding or "utf-8"
        safe = (text + end).encode(encoding, errors="replace").decode(encoding)
        sys.stdout.write(safe)
        sys.stdout.flush()




# ----------------------------------------------------------------- prompt ---

# Each stage gets its own dedicated system prompt: one role, one job, explicit
# boundaries so the model never does another stage's work.

CLASSIFY_SYSTEM = """You are a Web CTF challenge CLASSIFIER for one explicitly authorized target.
Your ONLY job in this stage: reconnoiter the target thoroughly and name the most likely vulnerability type. A wrong classification poisons every later stage, so accuracy beats speed.

How to work — be deliberate, use your step budget:
1. Start with the homepage: read the raw HTML carefully — comments, hidden fields, forms and their actions/parameters, linked JS/CSS, framework fingerprints, response headers and cookies.
2. Then probe several high-signal resources one by one, e.g. robots.txt, sitemap.xml, linked JS bundles, login/register/password forms, obvious API endpoints, error pages (trigger a 404/500 on purpose), common backup/source paths (.git/HEAD, .env, backup.zip) — pick what the homepage suggests.
3. Form at least 2-3 competing type hypotheses, gather evidence for and against each with targeted requests, and only then commit. If two requests told you little, keep looking — do NOT answer from the homepage alone.
4. Compare the hypotheses explicitly in your reasoning and answer with the best-supported one.

Scope rules — do not do any other stage's work:
- Reconnaissance only. NEVER send attack payloads, exploit attempts, or brute force; exploitation belongs to later stages.
- python is available for OFFLINE analysis of what you fetched — base64/hex/JWT/cookie decoding, parsing HTML/JS, comparing responses. No payload construction or credential brute forcing.
- NEVER draft an exploitation plan; the planning stage does that.
- NEVER report a flag; the finish tool does not exist for you. If you spot a flag-like string, only cite it as evidence inside your answer.

Use the native function tools supplied by the API. Do not serialize tool calls into message text. End the stage by calling the native `answer` function.
End the stage by calling answer with text set to: <type> | <key evidence: what you saw and why the runner-up types were rejected>.
"""

PLAN_SYSTEM = """You are a Web CTF exploitation PLANNER for one explicitly authorized target.
The challenge type has already been decided — see the carried-over conclusions. Your ONLY job in this stage: propose a short list of concrete candidate exploitation methods, most likely first.

Scope rules — do not do any other stage's work:
- Planning only. NEVER execute or test any method, never send attack payloads; execution stages do that, one method per stage.
- NEVER re-classify the challenge; trust the carried-over type.
- NEVER report a flag; the finish tool does not exist for you.
- At most ONE confirming curl if a critical fact is missing; otherwise answer directly without requests. python may be used to decode/parse already-fetched data (base64, JWT, cookies).

Use the native function tools supplied by the API. Do not serialize tool calls into message text. End the stage by calling the native `answer` function.
Each method: one numbered line naming the exact endpoint/parameter/payload idea to verify with curl or python.
End the stage by calling answer with text set to the numbered list.
"""

EXECUTE_SYSTEM = """You are a Web CTF exploit EXECUTOR for one explicitly authorized target, testing exactly ONE assigned method.
Your ONLY job in this stage: verify the assigned method step by step and report the outcome.

Scope rules — do not do any other stage's work:
- Test ONLY the assigned method below. Other candidate methods belong to other stages; methods already marked failed in the conclusions are off-limits.
- NEVER re-classify the challenge or re-plan; those stages are done — trust the carried-over conclusions.
- No broad scans, no unrelated endpoints, no huge brute-force spaces.
- The moment a flag string appears VERBATIM in a tool result, finish with it. The flag must be copied character-for-character from a curl/python result in THIS stage — the runner checks this and rejects invented, guessed, reconstructed, or completed-from-a-fragment flags.
- If you only saw an encoded, partial, or implied flag, do NOT finish yet: decode or fetch it with curl/python so the exact string shows up in a tool result, then finish.
- Submit exactly the wrapper the target emitted (flag{...}, CTF{...}, or a challenge-specific format). Never normalize, reformat, or fix it.
- If this assigned method is proven infeasible, call `method_failed` with a one-line reason. It ends ONLY this candidate; the controller will continue every remaining candidate method.
- `finish` is reserved exclusively for a verified flag. Never use `finish` to report a failure.

Use the native function tools supplied by the API. Do not serialize tool calls into message text. Keep `finish` or `method_failed` as the final call in a response; they may follow same-response evidence calls, but never place another call after them.
"""

RESPONSE_TOOL_DEFINITIONS: dict[str, dict[str, Any]] = {
    "curl": {
        "type": "function",
        "name": "curl",
        "description": "Send one HTTP request to the explicitly authorized CTF target origin. Large bodies are hidden in a temporary result buffer; inspect them with read_tool_result.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "maxLength": 4096, "description": "Absolute URL on the authorized target origin."},
                "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]},
                "headers": {"type": "object", "maxProperties": 64, "additionalProperties": {"type": "string", "maxLength": 2048}},
                "body": {"type": "string", "maxLength": 16384, "description": "Optional request body."},
                "body_path": {"type": "string", "maxLength": 512, "description": "Optional virtual absolute path such as /payload.bin; sends that file's raw bytes as the request body."},
            },
            "required": ["url"],
            "additionalProperties": False,
        },
    },
    "python": {
        "type": "function",
        "name": "python",
        "description": "Run an isolated Python 3 analysis script in the same persistent virtual workspace as write_file/read_file. Provide exactly one of code or path. path executes a saved UTF-8 script at a virtual absolute path such as /scripts/check.py. Inline code can use vfs('/data.txt') for a virtual-root path; relative paths resolve from virtual /. Large output is hidden in a temporary result buffer; inspect it with read_tool_result. timeout_seconds defaults to the configured Python timeout and may be raised up to the configured maximum.",
        "parameters": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "maxLength": 16384, "description": "Python 3 source code."},
                "path": {"type": "string", "maxLength": 512, "description": "Virtual absolute UTF-8 script path such as /scripts/check.py."},
                "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 600, "description": "Optional bounded execution timeout; defaults to 60 seconds and is capped by the operator configuration."},
            },
            "additionalProperties": False,
        },
    },
    "list_files": {
        "type": "function",
        "name": "list_files",
        "description": "List files in the current task's virtual workspace. The workspace root is / and every returned path starts with /.",
        "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    "read_file": {
        "type": "function",
        "name": "read_file",
        "description": "Read a UTF-8 byte range from a virtual-workspace file rooted at /. Set limit to 0 or omit it to read up to the page cap.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "minLength": 1, "maxLength": 512, "description": "Virtual absolute path such as /notes/data.txt."},
                "offset": {"type": "integer", "minimum": 0, "description": "Zero-based byte offset."},
                "limit": {"type": "integer", "minimum": 0, "maximum": 32768, "description": "Bytes to read; 0 or omitted means the largest allowed page."},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    "write_file": {
        "type": "function",
        "name": "write_file",
        "description": "Create or overwrite a valid UTF-8 file in the virtual workspace rooted at /, or append when append is true.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "minLength": 1, "maxLength": 512, "description": "Virtual absolute path such as /scripts/check.py."},
                "content": {"type": "string", "maxLength": 32768, "description": "UTF-8 text to write."},
                "append": {"type": "boolean", "description": "Append instead of overwrite; defaults to false."},
            },
            "required": ["path", "content"],
            "additionalProperties": False,
        },
    },
    "edit_file": {
        "type": "function",
        "name": "edit_file",
        "description": "Edit a virtual-workspace file. Range mode: offset + limit + replacement, with optional expected guard. Text mode: find + replace, with optional replace_all; a non-replace_all find must be unique.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "minLength": 1, "maxLength": 512, "description": "Virtual absolute path such as /scripts/check.py."},
                "offset": {"type": "integer", "minimum": 0, "description": "Range-mode byte offset."},
                "limit": {"type": "integer", "minimum": 0, "maximum": 32768, "description": "Range-mode bytes to replace; 0 inserts at offset."},
                "replacement": {"type": "string", "maxLength": 32768, "description": "Range-mode replacement text."},
                "expected": {"type": "string", "maxLength": 32768, "description": "Optional range-mode original text guard."},
                "find": {"type": "string", "maxLength": 32768, "description": "Text-mode exact original text."},
                "replace": {"type": "string", "maxLength": 32768, "description": "Text-mode replacement text."},
                "replace_all": {"type": "boolean", "description": "Replace every literal occurrence; defaults to false."},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    "download_file": {
        "type": "function",
        "name": "download_file",
        "description": "Download an authorized target-origin URL into a virtual-workspace file rooted at / without placing its content in model context.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "minLength": 1, "maxLength": 4096, "description": "Absolute URL on the authorized target origin."},
                "path": {"type": "string", "minLength": 1, "maxLength": 512, "description": "Virtual absolute destination path such as /downloads/page.html."},
                "headers": {"type": "object", "maxProperties": 64, "additionalProperties": {"type": "string", "maxLength": 2048}},
                "overwrite": {"type": "boolean", "description": "Replace an existing file; defaults to false."},
            },
            "required": ["url", "path"],
            "additionalProperties": False,
        },
    },
    "read_tool_result": {
        "type": "function",
        "name": "read_tool_result",
        "description": "Read a byte range from a previous curl or python result. Set limit to 0 or omit it to read the remaining bytes up to 32 KiB. Result buffers are temporary and expire after several turns without being read.",
        "parameters": {
            "type": "object",
            "properties": {
                "result_id": {"type": "string", "maxLength": 64, "description": "Identifier returned by curl or python."},
                "offset": {"type": "integer", "minimum": 0, "description": "Zero-based UTF-8 byte offset."},
                "limit": {"type": "integer", "minimum": 0, "maximum": 32768, "description": "Bytes to read. Use 0 or omit for the largest allowed page."},
            },
            "required": ["result_id", "offset"],
            "additionalProperties": False,
        },
    },
    "answer": {
        "type": "function",
        "name": "answer",
        "description": "Submit the final classification or candidate-method answer for this stage and end it.",
        "parameters": {
            "type": "object",
            "properties": {"text": {"type": "string", "maxLength": 2000, "description": "The stage answer."}},
            "required": ["text"],
            "additionalProperties": False,
        },
    },
    "finish": {
        "type": "function",
        "name": "finish",
        "description": "End the entire solve successfully with a flag copied verbatim from a current-stage tool result. This function never reports failure.",
        "parameters": {
            "type": "object",
            "properties": {
                "flag": {"type": "string", "maxLength": 1024, "description": "Flag copied verbatim from a current-stage tool result."},
            },
            "required": ["flag"],
            "additionalProperties": False,
        },
    },
    "method_failed": {
        "type": "function",
        "name": "method_failed",
        "description": "End ONLY the currently assigned candidate method as infeasible. This never reports the overall challenge as failed; remaining candidate methods continue.",
        "parameters": {
            "type": "object",
            "properties": {
                "reason": {"type": "string", "minLength": 1, "maxLength": 2000, "description": "Concrete one-line reason this assigned method was disproven."},
            },
            "required": ["reason"],
            "additionalProperties": False,
        },
    },
}


@dataclass
class FunctionCall:
    call_id: str
    name: str
    arguments: str
    arguments_truncated: bool = False


@dataclass
class ResponseTurn:
    text: str
    reasoning: str
    function_calls: list[FunctionCall]
    status: str
    response_id: str | None
    input_tokens: int | None = None


@dataclass
class StoredToolResult:
    content: bytes
    source_bytes: int
    truncated: bool
    created_round: int
    last_read_round: int


CLASSIFY_TASK = "Inspect the homepage and 1-2 prominent endpoints, then submit your one-line classification via answer."

PLAN_TASK = "Submit up to {max_methods} numbered candidate methods via answer. Do not test them."

EXECUTE_TASK = "Assigned method {index}/{total} — test ONLY this one: {method}"


# ----------------------------------------------------------------- config ---

def load_config(path: str) -> dict[str, Any]:
    config_path = Path(path).resolve()
    raw: dict[str, Any] = {}
    if config_path.exists():
        loaded = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            raw = loaded

    model = raw.setdefault("model", {})
    # Environment variables override the file so the same file stays shareable.
    model["baseUrl"] = os.environ.get("MODEL_BASE_URL") or model.get("baseUrl") or "http://127.0.0.1:30000/v1"
    model["apiKey"] = os.environ.get("MODEL_API_KEY") or model.get("apiKey") or ""
    model["id"] = os.environ.get("MODEL_ID") or model.get("id") or "duckgpt"
    model.setdefault("contextWindow", 102400)
    model.setdefault("maxTokens", 8192)
    model.setdefault("temperature", 0.2)
    model.setdefault("topP", 0.95)

    agent = raw.setdefault("agent", {})
    agent.setdefault("classifyBudget", 128)  # stage-1 independent step budget
    agent.setdefault("planBudget", 128)      # stage-2 independent step budget
    agent.setdefault("methodBudget", 128)    # independent budget for each candidate method
    agent.setdefault("maxMethods", 5)         # candidate methods to test
    agent.setdefault("compactTokens", 64000)  # hard per-stage context budget; compact after actual usage reaches it
    agent.setdefault("maxCompactionInputTokens", 8192)
    agent.setdefault("maxSummaryInputTokens", 12000)
    agent.setdefault("maxMethodSummaryChars", 600)
    agent.setdefault("useOfficialCompactionApi", False)
    agent.setdefault("httpTimeoutSeconds", 60)
    agent.setdefault("maxResponseBytes", 65536)  # legacy inline response cap
    agent.setdefault("maxToolCaptureBytes", 262144)  # maximum bytes retained in one in-memory result buffer
    agent.setdefault("maxInlineToolResultBytes", 2048)
    agent.setdefault("maxToolReadBytes", 32768)
    agent.setdefault("maxToolResultBytes", 40960)  # one full 32 KiB page plus metadata
    agent.setdefault("maxToolArgumentBytes", 16384)
    agent.setdefault("maxToolBuffers", 16)
    agent.setdefault("toolResultIdleRounds", 4)
    agent.setdefault("maxNativeCallsPerTurn", 8)
    agent.setdefault("maxTuiChars", 24000)
    agent.setdefault("virtualWorkspaceDir", "virtual_files")
    agent.setdefault("maxVirtualFileBytes", 8 * 1024 * 1024)
    agent.setdefault("maxVirtualFileReadBytes", 32768)
    agent.setdefault("maxVirtualFileWriteBytes", 32768)
    agent.setdefault("maxVirtualFiles", 128)
    agent.setdefault("maxHistoryEntryBytes", 12000)
    agent.setdefault("pythonTimeoutSeconds", 60)
    agent.setdefault("maxPythonTimeoutSeconds", 600)
    return raw


def normalize_target(raw_url: str) -> str:
    url = raw_url.strip()
    if not url:
        raise ValueError("Challenge URL is required")
    if "://" not in url:
        url = "http://" + url
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"Invalid challenge URL: {raw_url}")
    return url


def clean_answer(text: str) -> str:
    """Normalize a native function argument before it enters cross-stage state."""
    result = text.strip()
    return result if len(re.findall(r"[\w一-鿿]", result)) >= 4 else ""


def estimate_tokens(text: str) -> int:
    return max(1, len(text.encode("utf-8")) // 3)


def validate_classification(text: str) -> str | None:
    return None if "|" in text else "Answer must use the format: <type> | <key evidence>."


def validate_plan(text: str) -> str | None:
    if re.search(r"^\s*\d+\s*[.、)\]]", text, flags=re.MULTILINE):
        return None
    return "Answer must be a numbered list, one method per line."


def parse_methods(text: str, cap: int) -> list[str]:
    if not text:
        return []
    methods: list[str] = []
    for line in text.splitlines():
        match = re.match(r"^\s*(?:\d+\s*[.、)\]]|[-*•])\s*(.+)", line)
        if match:
            item = match.group(1).strip().strip("。")
            if item:
                methods.append(item)
    if not methods and text.strip():
        methods = [text.strip()[:300]]
    unique: list[str] = []
    for method in methods:
        if method not in unique:
            unique.append(method)
    return unique[:cap]


# ------------------------------------------------------------------ agent ---

class CtfAgent:
    def __init__(self, config: dict[str, Any], target_url: str, description: str = "") -> None:
        self.config = config
        self.model = config["model"]
        self.settings = config["agent"]
        self.target_url = normalize_target(target_url)
        self.description = description.strip()
        self.target_origin = self._origin(self.target_url)
        self.session = requests.Session()
        self.session.trust_env = False
        # Cross-stage state — the ONLY thing that survives a stage boundary.
        self.globals: dict[str, Any] = {
            "classification": "",
            "methods": [],      # [{"name": str, "status": pending|failed|exhausted|done, "summary": str}]
            "findings": [],     # stage digests worth carrying forward
        }
        self.current_method = 0  # 1-based index of the method under test; 0 outside stage 3
        self.stage_evidence: list[str] = []   # raw tool-result text of the current stage
        self.history: list[str] = []          # current stage only
        self.total_actions = 0
        self.tool_buffers: dict[str, StoredToolResult] = {}
        self.tool_buffer_sequence = 0
        self.tool_round = 0
        self.last_official_compaction_id: str | None = None
        self.last_official_compaction_output: list[dict[str, Any]] = []
        self.last_official_compaction_encrypted_content = ""
        self.compaction_groups: list[list[dict[str, Any]]] = []
        self.current_compaction_group: list[dict[str, Any]] | None = None
        self.last_compaction_input_truncated = False
        self.current_stage_title = "准备"
        self.stage_budget = 0
        self.stage_remaining = 0
        self.current_tool = "等待"
        self.last_result_summary = ""
        self.compaction_status = "等待"
        self.workspace_root, self.workspace = self._create_workspace()

    def refresh_tui_status(self) -> None:
        if _ACTIVE_TUI is None:
            return
        methods = self.globals.get("methods", [])
        if self.current_method and self.current_method <= len(methods):
            method_name = str(methods[self.current_method - 1].get("name", ""))[:80]
            method_line = f"候选: {self.current_method}/{len(methods)} {method_name}"
        elif methods:
            method_line = f"候选: {len(methods)} 个，等待执行"
        else:
            method_line = "候选: 尚未生成"
        context_limit = int(self.settings.get("compactTokens", 0))
        context_tokens = sum(estimate_tokens(entry) for entry in self.history)
        try:
            file_count = len(self._virtual_files())
        except (OSError, ValueError):
            file_count = 0
        budget_text = f"动作: {self.stage_budget - self.stage_remaining}/{self.stage_budget} 已用" if self.stage_budget else "动作: 阶段未开始"
        context_text = f"上下文: {context_tokens:,}/{context_limit:,} tokens" if context_limit > 0 else "上下文: 压缩关闭"
        update_tui_status(
            [
                "CTF AGENT · STATUS",
                f"目标: {self.target_origin}",
                f"阶段: {self.current_stage_title}",
                method_line,
                budget_text,
                f"剩余: {self.stage_remaining}",
                f"工具: {self.current_tool}",
                context_text,
                f"压缩: {self.compaction_status}",
                f"工作区文件: {file_count}",
                f"最近结果: {self.last_result_summary[:100]}",
            ]
        )

    def _create_workspace(self) -> tuple[Path, Path]:
        current_directory = Path.cwd().resolve()
        configured = Path(str(self.settings["virtualWorkspaceDir"]))
        if configured.is_absolute():
            raise ValueError("virtualWorkspaceDir must be relative to the current directory")
        root = (current_directory / configured).resolve()
        try:
            root.relative_to(current_directory)
        except ValueError as error:
            raise ValueError("virtualWorkspaceDir escapes the current directory") from error
        root.mkdir(parents=True, exist_ok=True)
        workspace = root / f"session-{uuid.uuid4().hex}"
        workspace.mkdir()
        (workspace / "tmp").mkdir()
        return root, workspace

    def virtual_path(self, raw_path: Any) -> Path:
        if not isinstance(raw_path, str) or not raw_path.strip():
            raise ValueError("path must be a non-empty virtual path rooted at '/'")
        raw = raw_path.strip()
        if "\\" in raw or not raw.startswith("/") or raw.startswith("//"):
            raise ValueError("virtual paths must use one leading '/' and POSIX '/' separators")
        try:
            parts = PurePosixPath(raw).parts[1:]
        except UnicodeError as error:
            raise ValueError("path must be valid UTF-8 text") from error
        if not parts or any(part in {"", ".", ".."} or ":" in part for part in parts):
            raise ValueError("virtual path must name a file below '/' without traversal or drive syntax")
        resolved = (self.workspace.joinpath(*parts)).resolve()
        try:
            resolved.relative_to(self.workspace)
        except (OSError, ValueError) as error:
            raise ValueError("path escapes the virtual workspace") from error
        return resolved

    def virtual_relative_path(self, path: Path) -> str:
        return "/" + path.relative_to(self.workspace).as_posix()

    @staticmethod
    def _origin(url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}".lower()

    def same_target(self, url: str) -> bool:
        try:
            return self._origin(url) == self.target_origin
        except ValueError:
            return False

    # ------------------------------------------------------------- prompting

    def response_tools(self, names: list[str]) -> list[dict[str, Any]]:
        return [RESPONSE_TOOL_DEFINITIONS[name] for name in names]
    def stage_tools(self, names: list[str]) -> list[str]:
        selected = list(dict.fromkeys(names))
        if "python" in selected:
            selected.extend(name for name in ("list_files", "read_file", "write_file", "edit_file", "download_file") if name not in selected)
        if any(name in selected for name in ("curl", "python")) and "read_tool_result" not in selected:
            selected.append("read_tool_result")
        if "finish" in selected and "method_failed" not in selected:
            selected.append("method_failed")
        return selected

    def clear_tool_buffers(self) -> None:
        self.tool_buffers.clear()
        self.tool_buffer_sequence = 0
        self.tool_round = 0

    def begin_tool_round(self) -> None:
        self.tool_round += 1
        idle_rounds = max(0, int(self.settings["toolResultIdleRounds"]))
        expired = [
            result_id
            for result_id, stored in self.tool_buffers.items()
            if self.tool_round - stored.last_read_round > idle_rounds
        ]
        for result_id in expired:
            del self.tool_buffers[result_id]

    @staticmethod
    def _decode_result_bytes(content: bytes) -> str:
        return content.decode("utf-8", errors="replace")

    @staticmethod
    def _encode_utf8_text(value: str, field_name: str) -> bytes:
        try:
            return value.encode("utf-8")
        except UnicodeEncodeError as error:
            raise ValueError(f"{field_name} must be valid UTF-8 text") from error


    def store_tool_content(self, content: bytes, source_bytes: int | None = None, truncated: bool = False) -> dict[str, Any]:
        capture_limit = max(1, int(self.settings["maxToolCaptureBytes"]))
        stored_content = content[:capture_limit]
        source_size = max(len(stored_content), int(source_bytes if source_bytes is not None else len(content)))
        was_truncated = truncated or len(content) > len(stored_content) or source_size > len(stored_content)
        max_buffers = max(1, int(self.settings["maxToolBuffers"]))
        if len(self.tool_buffers) >= max_buffers:
            oldest_id = min(
                self.tool_buffers,
                key=lambda result_id: (
                    self.tool_buffers[result_id].last_read_round,
                    self.tool_buffers[result_id].created_round,
                ),
            )
            del self.tool_buffers[oldest_id]
        self.tool_buffer_sequence += 1
        result_id = f"tool_{self.tool_buffer_sequence}"
        self.tool_buffers[result_id] = StoredToolResult(
            content=stored_content,
            source_bytes=source_size,
            truncated=was_truncated,
            created_round=self.tool_round,
            last_read_round=self.tool_round,
        )
        inline_limit = max(0, int(self.settings["maxInlineToolResultBytes"]))
        return {
            "result_id": result_id,
            "total_bytes": source_size,
            "available_bytes": len(stored_content),
            "truncated": was_truncated,
            "preview": self._decode_result_bytes(stored_content[:inline_limit]),
            "read_hint": "Use read_tool_result with this result_id and offset; use limit 0 to read the remaining bytes up to the page cap.",
        }

    def read_tool_result(self, action: dict[str, Any]) -> dict[str, Any]:
        result_id = action.get("result_id")
        offset = action.get("offset")
        limit = action.get("limit", 0)
        if not isinstance(result_id, str) or not result_id.strip():
            return {"error": "read_tool_result requires a non-empty result_id"}
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            return {"error": "offset must be a non-negative integer"}
        if limit is None:
            limit = 0
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
            return {"error": "limit must be a non-negative integer"}
        stored = self.tool_buffers.get(result_id)
        if stored is None:
            return {"error": f"result {result_id!r} is unavailable or expired; fetch it again if needed"}
        max_read = max(1, int(self.settings["maxToolReadBytes"]))
        effective_limit = max_read if limit == 0 else min(limit, max_read)
        available = len(stored.content)
        start = min(offset, available)
        end = min(start + effective_limit, available)
        stored.last_read_round = self.tool_round
        return {
            "result_id": result_id,
            "offset": start,
            "limit": end - start,
            "next_offset": end,
            "remaining_bytes": available - end,
            "total_bytes": stored.source_bytes,
            "available_bytes": available,
            "truncated": stored.truncated,
            "eof": end >= available,
            "content": self._decode_result_bytes(stored.content[start:end]),
        }

    def build_prompt(self, task: str, *, include_history: bool = True) -> str:
        parts = [
            "Authorized target URL: " + self.target_url,
            "Only URLs on this exact origin are authorized.",
            f"One model response may invoke multiple native functions. They execute sequentially in source order and each consumes stage action budget; the API is asked for at most {max(1, int(self.settings.get('maxNativeCallsPerTurn', 8)))} calls per response. Large curl/python results are returned as a small preview plus result_id; use read_tool_result(result_id, offset, limit) to page through the temporary buffer. Use limit 0 to read the remaining bytes up to the page cap. A buffer expires after several turns without being read.",
            "All task files live in one persistent virtual filesystem rooted at '/'. Every native file path must be an absolute virtual POSIX path such as /scripts/check.py; it never names the host filesystem. write_file/read_file/edit_file/download_file, curl.body_path, and python.path use this same contract. Python starts at virtual /, so relative paths resolve there; use vfs('/path') inside inline or saved Python code when an explicit virtual-root path is needed. Text files and Python scripts are UTF-8.",
            "Python has standard-library urllib and SSL support. Do not claim an environment limitation without returning the actual stderr; if an authorized HTTPS request fails, inspect that error before choosing another tool.",
        ]
        if self.description:
            parts.append("Challenge description from the operator: " + self.description)
        knowledge = self.knowledge_block()
        if knowledge:
            parts += ["\n## Carried-over conclusions", knowledge]
        parts += ["\nStage task: " + task]
        if include_history and self.history:
            parts += ["\nStage history:\n" + "\n".join(self.history)]
        return "\n".join(parts)

    def prior_method_outcome_lines(self, before_index: int | None = None) -> list[str]:
        methods = self.globals["methods"]
        if before_index is None:
            before_index = self.current_method or len(methods) + 1
        summary_limit = max(160, int(self.settings.get("maxMethodSummaryChars", 600)))
        outcomes: list[str] = []
        for index, method in enumerate(methods, 1):
            if index >= before_index:
                break
            status = str(method.get("status", ""))
            summary = " ".join(str(method.get("summary", "")).split())[:summary_limit]
            if status in {"failed", "exhausted"} and summary:
                outcomes.append(f"{index}. [{status}] {str(method.get('name', ''))[:160]} — {summary}")
        return outcomes

    def show_prior_method_outcomes(self, before_index: int) -> None:
        outcomes = self.prior_method_outcome_lines(before_index)
        if not outcomes:
            return
        emit("📒 前序执行失败总结（已注入当前阶段上下文，禁止重复相同路径）：", "info")
        for outcome in outcomes:
            emit("   " + outcome, "dim")

    def knowledge_block(self) -> str:
        lines = []
        if self.globals["classification"]:
            lines.append("Challenge type: " + self.globals["classification"])
        methods = self.globals["methods"]
        if methods:
            lines.append("Candidate methods and their status:")
            for index, method in enumerate(methods, 1):
                mark = "CURRENT — test only this one" if index == self.current_method else method["status"]
                lines.append(f"  {index}. [{mark}] {method['name']}")
            outcomes = self.prior_method_outcome_lines()
            if outcomes:
                lines.append("Prior execution outcome handoffs (DO NOT repeat these failed paths):")
                lines.extend("  " + outcome for outcome in outcomes)
        if self.globals["findings"]:
            lines.append("Stage digests:")
            lines.extend("- " + finding for finding in self.globals["findings"])
        return "\n".join(lines)

    def stream_turn(
        self,
        input_data: str | list[dict[str, Any]],
        *,
        instructions: str | None,
        tools: list[str],
        previous_response_id: str | None,
    ) -> ResponseTurn:
        shown = {"think": False, "text": False}

        def on_think(delta: str) -> None:
            if not shown["think"]:
                emit("\n🧠 思考 ", "think", end="")
                shown["think"] = True
            emit(delta, "think", end="")

        def on_text(delta: str) -> None:
            if not shown["text"]:
                emit("\n💬 回答 ", "say", end="")
                shown["text"] = True
            emit(delta, "say", end="")

        turn = self.completion(
            input_data,
            tools=tools,
            instructions=instructions,
            previous_response_id=previous_response_id,
            on_think=on_think,
            on_text=on_text,
        )
        if shown["think"] or shown["text"]:
            emit("")
        return turn

    def completion(
        self,
        input_data: str | list[dict[str, Any]],
        *,
        tools: list[str] | None = None,
        instructions: str | None = None,
        previous_response_id: str | None = None,
        max_tokens: int | None = None,
        on_think: Any = None,
        on_text: Any = None,
    ) -> ResponseTurn:
        """Stream a native OpenAI Responses turn and collect function_call items."""
        endpoint = self.model["baseUrl"].rstrip("/") + "/responses"
        headers = {"Content-Type": "application/json", "Accept": "text/event-stream"}
        if self.model.get("apiKey"):
            headers["Authorization"] = f"Bearer {self.model['apiKey']}"
        payload: dict[str, Any] = {
            "model": self.model["id"],
            "input": input_data,
            "max_output_tokens": max_tokens or self.model["maxTokens"],
            "temperature": self.model.get("temperature", 0.2),
            "top_p": self.model.get("topP", 0.95),
            "stream": True,
        }
        if instructions is not None:
            payload["instructions"] = instructions
        if tools:
            payload["tools"] = self.response_tools(tools)
            payload["tool_choice"] = "auto"
            payload["parallel_tool_calls"] = False
            payload["max_tool_calls"] = max(1, int(self.settings.get("maxNativeCallsPerTurn", 8)))
        if previous_response_id:
            payload["previous_response_id"] = previous_response_id
        try:
            response = self.session.post(
                endpoint,
                headers=headers,
                json=payload,
                timeout=(10, self.settings["modelTimeoutSeconds"]),
                stream=True,
            )
        except requests.RequestException as error:
            raise RuntimeError(f"Model request failed: {error}") from error
        if not response.ok:
            raise RuntimeError(f"Model request failed with HTTP {response.status_code}: {response.text[:2000]}")
        response.encoding = "utf-8"

        text_parts: list[str] = []
        think_parts: list[str] = []
        calls_by_key: dict[str, dict[str, Any]] = {}
        call_order: list[str] = []
        response_id: str | None = None
        input_tokens: int | None = None
        status = "completed"
        error_message = ""
        argument_limit = max(1, int(self.settings["maxToolArgumentBytes"]))

        def call_record(key: str) -> dict[str, Any]:
            if key not in calls_by_key:
                calls_by_key[key] = {"call_id": "", "name": "", "arguments": "", "arguments_truncated": False}
                call_order.append(key)
            return calls_by_key[key]

        def set_arguments(record: dict[str, Any], value: str, append: bool = False) -> None:
            candidate = str(record["arguments"]) + value if append else value
            encoded = candidate.encode("utf-8")
            if len(encoded) > argument_limit:
                record["arguments"] = encoded[:argument_limit].decode("utf-8", errors="ignore")
                record["arguments_truncated"] = True
            else:
                record["arguments"] = candidate

        def merge_function_item(item: dict[str, Any], fallback_key: str) -> None:
            if item.get("type") != "function_call":
                return
            key = str(item.get("id") or item.get("call_id") or fallback_key)
            record = call_record(key)
            for field in ("call_id", "name"):
                value = item.get(field)
                if value is not None:
                    record[field] = str(value)
            if item.get("arguments") is not None and (item.get("arguments") or not record["arguments"]):
                set_arguments(record, str(item["arguments"]))

        try:
            for raw in response.iter_lines(decode_unicode=True):
                if not raw or not raw.startswith("data:"):
                    continue
                data = raw[5:].strip()
                if not data or data == "[DONE]":
                    continue
                try:
                    event = json.loads(data)
                except json.JSONDecodeError:
                    continue
                event_type = str(event.get("type") or "")
                response_data = event.get("response")
                if isinstance(response_data, dict):
                    if response_data.get("id"):
                        response_id = str(response_data["id"])
                    usage = response_data.get("usage")
                    if isinstance(usage, dict) and isinstance(usage.get("input_tokens"), int):
                        input_tokens = int(usage["input_tokens"])
                    if event_type == "response.completed":
                        status = str(response_data.get("status") or "completed")
                if event.get("response_id"):
                    response_id = str(event["response_id"])

                if event_type == "response.reasoning_text.delta":
                    delta = str(event.get("delta", ""))
                    think_parts.append(delta)
                    if on_think:
                        on_think(delta)
                elif event_type == "response.output_text.delta":
                    delta = str(event.get("delta", ""))
                    text_parts.append(delta)
                    if on_text:
                        on_text(delta)
                elif event_type in {"response.output_item.added", "response.output_item.done"}:
                    item = event.get("item")
                    if isinstance(item, dict):
                        merge_function_item(item, f"output:{event.get('output_index', len(call_order))}")
                elif event_type == "response.function_call_arguments.delta":
                    key = str(event.get("item_id") or event.get("call_id") or f"output:{event.get('output_index', len(call_order))}")
                    record = call_record(key)
                    if event.get("call_id") is not None:
                        record["call_id"] = str(event["call_id"])
                    if event.get("name") is not None:
                        record["name"] = str(event["name"])
                    set_arguments(record, str(event.get("delta", "")), append=True)
                elif event_type == "response.function_call_arguments.done":
                    key = str(event.get("item_id") or event.get("call_id") or f"output:{event.get('output_index', len(call_order))}")
                    record = call_record(key)
                    for field in ("call_id", "name"):
                        if event.get(field) is not None:
                            record[field] = str(event[field])
                    if event.get("arguments") is not None:
                        set_arguments(record, str(event["arguments"]))
                elif event_type in {"response.failed", "error"}:
                    status = "failed"
                    error_message = str(
                        (response_data or {}).get("error") if isinstance(response_data, dict) else event.get("error") or event.get("message") or ""
                    )[:500]
        except requests.RequestException as error:
            raise RuntimeError(f"Model stream interrupted: {error}") from error

        if status == "failed":
            raise RuntimeError(f"Model stream failed: {error_message or 'unknown error'}")
        function_calls = [
            FunctionCall(
                call_id=record["call_id"],
                name=record["name"],
                arguments=record["arguments"],
                arguments_truncated=bool(record["arguments_truncated"]),
            )
            for key in call_order
            for record in [calls_by_key[key]]
        ]
        return ResponseTurn(
            text="".join(text_parts),
            reasoning="".join(think_parts),
            function_calls=function_calls,
            status=status,
            response_id=response_id,
            input_tokens=input_tokens,
        )

    def summary_input_token_budget(self) -> int:
        configured = max(256, int(self.settings.get("maxSummaryInputTokens", 12000)))
        try:
            context_window = max(1024, int(self.model.get("contextWindow", 102400)))
        except (TypeError, ValueError):
            context_window = 102400
        reserve = max(1024, min(4096, context_window // 4))
        return min(configured, max(256, context_window - reserve - 512))

    def bounded_summary_transcript(self, transcript: str) -> str:
        token_budget = self.summary_input_token_budget()
        byte_budget = token_budget * 3
        encoded = transcript.encode("utf-8")
        if len(encoded) <= byte_budget:
            return transcript
        marker = (
            f"[Earlier tool transcript truncated to fit the {token_budget}-token summary budget; "
            "only the newest retained evidence follows.]\n"
        ).encode("utf-8")
        tail_bytes = max(0, byte_budget - len(marker))
        tail = b"" if tail_bytes == 0 else encoded[-tail_bytes:]
        return marker.decode("utf-8") + tail.decode("utf-8", errors="ignore")

    def summarize(self, transcript: str, what: str) -> str:
        """Summarize bounded stage evidence through an independent model request."""
        bounded_transcript = self.bounded_summary_transcript(transcript)
        bounded_what = " ".join(str(what).split())[:600]
        prompt = (
            f"Summarize this authorized Web CTF stage transcript in under 120 words: {bounded_what}. "
            "Keep only verified endpoints, parameters, payloads tried, observed responses, and explicit failure causes. "
            "Do not invent facts. Plain text only.\n\n"
            + bounded_transcript
        )
        try:
            turn = self.completion(prompt, max_tokens=512)
        except RuntimeError:
            return ""
        summary = turn.text or turn.reasoning
        return " ".join(summary.split())[:600]

    @staticmethod
    def _compact_content_text(content: Any) -> str:
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts: list[str] = []
            for part in content:
                if isinstance(part, dict):
                    value = part.get("text", part.get("content", ""))
                    if value:
                        parts.append(str(value))
                elif part:
                    parts.append(str(part))
            return "".join(parts)
        return str(content or "")

    def _normalize_compaction_input(self, input_data: list[dict[str, Any]]) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        for item in input_data:
            if not isinstance(item, dict):
                continue
            item_type = str(item.get("type") or "")
            if item_type == "function_call_output":
                normalized.append(
                    {
                        "type": "function_call_output",
                        "call_id": str(item.get("call_id") or ""),
                        "output": str(item.get("output") or ""),
                    }
                )
            elif item_type == "function_call":
                normalized.append(
                    {
                        "type": "function_call",
                        "call_id": str(item.get("call_id") or ""),
                        "name": str(item.get("name") or ""),
                        "arguments": str(item.get("arguments") or ""),
                    }
                )
            elif item_type in {"compaction", "reasoning"}:
                encrypted_content = item.get("encrypted_content")
                item_id = item.get("id")
                if not isinstance(encrypted_content, str) or not encrypted_content or not item_id:
                    continue
                summary = item.get("summary") if isinstance(item.get("summary"), list) else []
                normalized.append(
                    {
                        "type": "reasoning",
                        "id": str(item_id),
                        "summary": summary,
                        "encrypted_content": encrypted_content,
                    }
                )
            elif item_type == "message" or item.get("role"):
                normalized.append(
                    {
                        "type": "message",
                        "role": str(item.get("role") or "user"),
                        "content": self._compact_content_text(item.get("content", "")),
                    }
                )
        return normalized

    @staticmethod
    def _prepare_official_compaction_output(output: list[Any]) -> list[dict[str, Any]]:
        # QWEN-EXO rejects type=compaction on the next /responses input; its
        # accepted opaque-state carrier is the Responses reasoning item shape.
        prepared: list[dict[str, Any]] = []
        found_compaction = False
        for item in output:
            if not isinstance(item, dict):
                continue
            if item.get("type") == "compaction":
                item_id = item.get("id")
                encrypted_content = item.get("encrypted_content")
                if not item_id or not isinstance(encrypted_content, str) or not encrypted_content:
                    continue
                found_compaction = True
                prepared.append(
                    {
                        "type": "reasoning",
                        "id": str(item_id),
                        "summary": item.get("summary") if isinstance(item.get("summary"), list) else [],
                        "encrypted_content": encrypted_content,
                    }
                )
            else:
                prepared.append(dict(item))
        if not found_compaction:
            raise RuntimeError("Official compaction response lacked an opaque compaction artifact")
        return prepared

    def begin_compaction_input(self, input_data: list[dict[str, Any]]) -> None:
        items = self._normalize_compaction_input(input_data)
        if items:
            self.compaction_groups.append(items)
            self.current_compaction_group = None

    def append_compaction_response(self, turn: ResponseTurn) -> None:
        items: list[dict[str, Any]] = []
        if turn.text:
            items.append({"type": "message", "role": "assistant", "content": turn.text})
        for call in turn.function_calls:
            if not call.call_id:
                continue
            items.append(
                {
                    "type": "function_call",
                    "call_id": call.call_id,
                    "name": call.name,
                    "arguments": call.arguments,
                }
            )
        if items:
            self.compaction_groups.append(items)
            self.current_compaction_group = items
        else:
            self.current_compaction_group = None

    def append_compaction_output(self, call_id: str, output: str) -> None:
        if not call_id:
            return
        if self.current_compaction_group is None:
            self.current_compaction_group = []
            self.compaction_groups.append(self.current_compaction_group)
        self.current_compaction_group.append(
            {"type": "function_call_output", "call_id": call_id, "output": output}
        )

    @staticmethod
    def _compaction_group_is_complete(group: list[dict[str, Any]]) -> bool:
        pending: set[str] = set()
        for item in group:
            item_type = item.get("type")
            if item_type == "function_call":
                call_id = str(item.get("call_id") or "")
                if not call_id or call_id in pending:
                    return False
                pending.add(call_id)
            elif item_type == "function_call_output":
                call_id = str(item.get("call_id") or "")
                if not call_id or call_id not in pending:
                    return False
                pending.remove(call_id)
        return not pending


    @staticmethod
    def _json_size(value: Any) -> int:
        return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))

    def _compaction_input_token_budget(self) -> int:
        configured = max(1024, int(self.settings.get("maxCompactionInputTokens", 8192)))
        try:
            context_window = max(2048, int(self.model.get("contextWindow", 102400)))
        except (TypeError, ValueError):
            context_window = 102400
        reserve = max(2048, min(8192, context_window // 4))
        return min(configured, max(1024, context_window - reserve - 1024))

    def _truncate_compaction_group(
        self,
        group: list[dict[str, Any]],
        byte_budget: int,
    ) -> list[dict[str, Any]] | None:
        if byte_budget <= 0 or not group or not self._compaction_group_is_complete(group):
            return None
        candidate = [dict(item) for item in group]
        current_size = self._json_size(candidate)
        if current_size <= byte_budget:
            return candidate
        marker = "[tool content truncated for compaction]\n"
        while current_size > byte_budget:
            choices: list[tuple[int, int, str]] = []
            for index, item in enumerate(candidate):
                for key in ("output", "content"):
                    value = item.get(key)
                    if isinstance(value, str) and value:
                        choices.append((len(value.encode("utf-8")), index, key))
            if not choices:
                return None
            _, index, key = max(choices)
            original = str(candidate[index][key])
            body = original[len(marker):] if original.startswith(marker) else original
            body_bytes = body.encode("utf-8")
            reduction = max(1, current_size - byte_budget, len(body_bytes) // 2)
            target_bytes = max(0, len(body_bytes) - reduction)
            if target_bytes:
                tail = body_bytes[-target_bytes:].decode("utf-8", errors="ignore")
                replacement = marker + tail
            else:
                replacement = marker
            if replacement == original:
                replacement = ""
            candidate[index][key] = replacement
            new_size = self._json_size(candidate)
            if new_size >= current_size:
                candidate[index][key] = ""
                new_size = self._json_size(candidate)
                if new_size >= current_size:
                    return None
            current_size = new_size
        return candidate

    def bounded_compaction_input(self) -> tuple[list[dict[str, Any]], bool]:
        token_budget = self._compaction_input_token_budget()
        byte_budget = token_budget * 3
        groups = [
            [dict(item) for item in group]
            for group in self.compaction_groups
            if self._compaction_group_is_complete(group)
        ]
        full = [item for group in groups for item in group]
        if len(groups) == len(self.compaction_groups) and self._json_size(full) <= byte_budget:
            return full, False

        marker = {
            "type": "message",
            "role": "user",
            "content": f"[older Responses/tool history truncated to fit the {token_budget}-token compaction budget]",
        }
        while self._json_size([marker]) > byte_budget and marker["content"]:
            marker["content"] = str(marker["content"])[:-1]
        prefix_items: list[dict[str, Any]] = []
        marker_size = self._json_size([marker])
        if groups and marker_size < byte_budget:
            first_budget = min(max(256, byte_budget // 4), byte_budget - marker_size)
            first = self._truncate_compaction_group(groups[0], first_budget)
            if first and self._json_size(first + [marker]) <= byte_budget:
                prefix_items = first
        prefix = prefix_items + [marker]

        def flatten(selected: list[list[dict[str, Any]]]) -> list[dict[str, Any]]:
            return [item for group in selected for item in group]

        tail_groups: list[list[dict[str, Any]]] = []
        for group in reversed(groups[1:]):
            current = prefix + flatten(tail_groups)
            remaining = byte_budget - self._json_size(current)
            if remaining <= 0:
                break
            fitted = self._truncate_compaction_group(group, remaining)
            if fitted is None:
                continue
            candidate = prefix + flatten([fitted] + tail_groups)
            if self._json_size(candidate) <= byte_budget:
                tail_groups.insert(0, fitted)

        result = prefix + flatten(tail_groups)
        while self._json_size(result) > byte_budget and tail_groups:
            tail_groups.pop(0)
            result = prefix + flatten(tail_groups)
        if self._json_size(result) > byte_budget and prefix_items:
            prefix = [marker]
            result = prefix + flatten(tail_groups)
        if self._json_size(result) > byte_budget:
            result = [marker]
        return result, True

    def compact_with_official_api(
        self,
        previous_response_id: str | None,
        input_items: list[dict[str, Any]],
    ) -> str:
        """Submit bounded Responses items and retain the opaque window for the next stateless request."""
        if not input_items:
            raise RuntimeError("Official compaction requires non-empty input history")
        endpoint = self.model["baseUrl"].rstrip("/") + "/responses/compact"
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.model.get("apiKey"):
            headers["Authorization"] = f"Bearer {self.model['apiKey']}"
        payload: dict[str, Any] = {
            "model": self.model["id"],
            "request_id": f"resp_compact_client_{uuid.uuid4().hex}",
            "input": input_items,
            "instructions": (
                "Preserve the authorized target, verified facts, candidate-method status, failed-method reasons, "
                "and the next concrete action. Keep opaque compaction state only."
            ),
        }
        if previous_response_id:
            payload["previous_response_id"] = previous_response_id
        try:
            response = self.session.post(
                endpoint,
                headers=headers,
                json=payload,
                timeout=(10, self.settings["modelTimeoutSeconds"]),
            )
        except requests.RequestException as error:
            raise RuntimeError(f"Official compaction request failed: {error}") from error
        if not response.ok:
            error_text = response.text[:2000]
            response.close()
            raise RuntimeError(f"Official compaction request failed with HTTP {response.status_code}: {error_text}")
        try:
            data = response.json()
            if isinstance(data, dict) and data.get("object") not in (None, "response.compaction"):
                raise RuntimeError(f"Official compaction returned unexpected object {data.get('object')!r}")
            output = data.get("output") if isinstance(data, dict) else None
            if not isinstance(output, list):
                raise RuntimeError("Official compaction response lacked an output window")
            prepared_output = self._prepare_official_compaction_output(output)
            artifact_id = str(data.get("id") or "") if isinstance(data, dict) else ""
            if not artifact_id:
                raise RuntimeError("Official compaction response lacked a response id")
            compaction = next(item for item in prepared_output if item.get("type") == "reasoning" and item.get("encrypted_content"))
            self.last_official_compaction_id = artifact_id
            self.last_official_compaction_output = prepared_output
            self.last_official_compaction_encrypted_content = str(compaction["encrypted_content"])
            return artifact_id
        except ValueError as error:
            raise RuntimeError("Official compaction response was not JSON") from error
        finally:
            response.close()

    def compact_stage_if_needed(self, force: bool = False, previous_response_id: str | None = None) -> str:
        """Return ``local``, ``official``, or ``none`` for a reached task-context budget."""
        threshold = int(self.settings["compactTokens"])
        if threshold <= 0:
            self.compaction_status = "关闭"
            self.refresh_tui_status()
            return "none"
        history_tokens = sum(estimate_tokens(entry) for entry in self.history)
        if not force and history_tokens < threshold:
            if history_tokens * 4 >= threshold * 3:
                self.compaction_status = f"接近阈值 {history_tokens:,}/{threshold:,}"
                emit(
                    f"🗜️ 上下文接近压缩阈值：{history_tokens:,}/{threshold:,} tokens；达到阈值后下一轮前自动压缩。",
                    "dim",
                )
            else:
                self.compaction_status = f"等待 {history_tokens:,}/{threshold:,}"
            self.refresh_tui_status()
            return "none"
        if bool(self.settings["useOfficialCompactionApi"]):
            input_items, input_truncated = self.bounded_compaction_input()
            self.last_compaction_input_truncated = input_truncated
            self.compaction_status = "官方压缩中"
            self.refresh_tui_status()
            suffix = "；旧工具项已截断" if input_truncated else ""
            emit(
                f"🧹 开始官方 Responses 压缩（{len(input_items)} items，输入上限 {self._compaction_input_token_budget():,} tokens{suffix}）…",
                "info",
            )
            try:
                artifact_id = self.compact_with_official_api(previous_response_id, input_items)
            except RuntimeError as error:
                self.compaction_status = "官方压缩失败"
                self.refresh_tui_status()
                emit(f"⚠️  官方压缩请求失败：{error}；未回退到本地压缩。", "err")
                self.history.append(f"Official compaction request failed ({error}).")
                return "none"
            self.compaction_status = "官方压缩完成"
            self.refresh_tui_status()
            emit(f"✅ 官方 Responses 压缩完成：{artifact_id}；下一轮将以压缩窗口作为完整 input（不复用 compaction response ID）。", "info")
            return "official"
        self.compaction_status = "本地压缩中"
        self.refresh_tui_status()
        emit(
            f"\n🧹 开始本地上下文压缩：{history_tokens:,}/{threshold:,} tokens；压缩后重建 Responses 链…",
            "info",
        )
        summary = self.summarize(
            "\n".join(self.history),
            "the full stage progress so far: endpoints, parameters, payloads, responses, credentials, candidate flags, and the next best action",
        )
        if summary:
            self.history = ["Compressed stage state:\n" + summary]
            compacted_tokens = sum(estimate_tokens(entry) for entry in self.history)
            self.compaction_status = f"本地完成 {compacted_tokens:,} tokens"
            self.refresh_tui_status()
            emit(f"✅ 本地上下文压缩完成：{history_tokens:,} → {compacted_tokens:,} tokens。", "info")
        else:
            self.compaction_status = "本地压缩失败"
            self.refresh_tui_status()
            emit("⚠️  压缩失败，丢弃较早的一半历史。", "err")
            self.history = ["Earlier entries dropped after failed compression."] + self.history[len(self.history) // 2:]
        return "local"


    def history_entry(self, text: str) -> str:
        limit = int(self.settings["maxHistoryEntryBytes"])
        encoded = text.encode("utf-8")
        if len(encoded) <= limit:
            return text
        return encoded[:limit].decode("utf-8", errors="ignore") + "\n[truncated in history]"
    def _capture_http_body(self, response: Any) -> tuple[bytes, int, bool]:
        capture_limit = max(1, int(self.settings["maxToolCaptureBytes"]))
        captured = bytearray()
        total_seen = 0
        content_length = 0
        try:
            content_length = max(0, int(response.headers.get("Content-Length", 0)))
        except (AttributeError, TypeError, ValueError):
            content_length = 0
        iterator = getattr(response, "iter_content", None)
        if callable(iterator):
            for chunk in iterator(chunk_size=8192):
                if not chunk:
                    continue
                if isinstance(chunk, str):
                    chunk = chunk.encode("utf-8", errors="replace")
                total_seen += len(chunk)
                if len(captured) < capture_limit:
                    captured.extend(chunk[: capture_limit - len(captured)])
                if len(captured) >= capture_limit and (total_seen > capture_limit or content_length > capture_limit):
                    break
        else:
            raw = bytes(getattr(response, "content", b""))
            total_seen = len(raw)
            captured.extend(raw[:capture_limit])
        source_bytes = max(total_seen, content_length, len(captured))
        return bytes(captured), source_bytes, source_bytes > len(captured)

    @staticmethod
    def _bounded_headers(headers: Any) -> dict[str, str]:
        bounded: dict[str, str] = {}
        for index, (key, value) in enumerate(dict(headers or {}).items()):
            if index >= 32:
                break
            text = str(value)
            bounded[str(key)] = text[:512]
        return bounded

    @staticmethod
    def _read_file_capture(path: Path, limit: int) -> tuple[bytes, int, bool]:
        source_bytes = path.stat().st_size
        with path.open("rb") as stream:
            content = stream.read(limit)
        return content, source_bytes, source_bytes > len(content)

    def _virtual_files(self) -> list[Path]:
        files: list[Path] = []
        for candidate in self.workspace.rglob("*"):
            try:
                resolved = candidate.resolve()
                resolved.relative_to(self.workspace)
            except (OSError, ValueError):
                continue
            if resolved.is_file():
                files.append(resolved)
        return files

    def _prepare_virtual_write(self, path: Path, final_size: int) -> None:
        maximum_size = max(1, int(self.settings["maxVirtualFileBytes"]))
        if final_size > maximum_size:
            raise ValueError(f"file would exceed the {maximum_size}B virtual-file limit")
        if path.exists() and not path.is_file():
            raise ValueError("path names a directory, not a file")
        if not path.exists() and len(self._virtual_files()) >= max(1, int(self.settings["maxVirtualFiles"])):
            raise ValueError(f"virtual workspace already contains {self.settings['maxVirtualFiles']} files")
        path.parent.mkdir(parents=True, exist_ok=True)

    def list_files(self, action: dict[str, Any]) -> dict[str, Any]:
        del action
        files = sorted(self._virtual_files(), key=lambda item: self.virtual_relative_path(item))
        maximum = max(1, int(self.settings["maxVirtualFiles"]))
        visible = files[:maximum]
        return {
            "workspace": "/",
            "files": [
                {"path": self.virtual_relative_path(path), "bytes": path.stat().st_size}
                for path in visible
            ],
            "file_count": len(files),
            "truncated": len(files) > len(visible),
        }

    def read_file(self, action: dict[str, Any]) -> dict[str, Any]:
        try:
            path = self.virtual_path(action.get("path"))
            offset = action.get("offset", 0)
            limit = action.get("limit", 0)
            if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
                return {"error": "offset must be a non-negative integer"}
            if limit is None:
                limit = 0
            if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
                return {"error": "limit must be a non-negative integer"}
            if not path.is_file():
                return {"error": "file does not exist"}
            maximum = max(1, int(self.settings["maxVirtualFileReadBytes"]))
            effective_limit = maximum if limit == 0 else min(limit, maximum)
            total_size = path.stat().st_size
            start = min(offset, total_size)
            with path.open("rb") as stream:
                stream.seek(start)
                content = stream.read(effective_limit)
            end = start + len(content)
            return {
                "path": self.virtual_relative_path(path),
                "offset": start,
                "limit": len(content),
                "next_offset": end,
                "remaining_bytes": total_size - end,
                "total_bytes": total_size,
                "eof": end >= total_size,
                "content": self._decode_result_bytes(content),
            }
        except (OSError, ValueError) as error:
            return {"error": str(error)}

    def write_file(self, action: dict[str, Any]) -> dict[str, Any]:
        try:
            path = self.virtual_path(action.get("path"))
            content = action.get("content")
            append = action.get("append", False)
            if not isinstance(content, str):
                return {"error": "content must be a string"}
            if not isinstance(append, bool):
                return {"error": "append must be a boolean"}
            payload = self._encode_utf8_text(content, "content")
            maximum_write = max(1, int(self.settings["maxVirtualFileWriteBytes"]))
            if len(payload) > maximum_write:
                return {"error": f"content exceeds the {maximum_write}B write limit"}
            current_size = path.stat().st_size if append and path.is_file() else 0
            self._prepare_virtual_write(path, current_size + len(payload))
            with path.open("ab" if append else "wb") as stream:
                stream.write(payload)
            return {
                "path": self.virtual_relative_path(path),
                "bytes_written": len(payload),
                "total_bytes": path.stat().st_size,
                "append": append,
            }
        except (OSError, ValueError) as error:
            return {"error": str(error)}

    def edit_file(self, action: dict[str, Any]) -> dict[str, Any]:
        try:
            path = self.virtual_path(action.get("path"))
            if not path.is_file():
                return {"error": "file does not exist"}
            source = path.read_bytes()
            has_find = "find" in action
            has_replace = "replace" in action
            if has_find or has_replace:
                if not has_find or not has_replace:
                    return {"error": "text mode requires both find and replace"}
                if any(key in action for key in ("offset", "limit", "replacement", "expected")):
                    return {"error": "text mode cannot be combined with range-mode arguments"}
                find = action["find"]
                replace = action["replace"]
                replace_all = action.get("replace_all", False)
                if not isinstance(find, str) or not isinstance(replace, str):
                    return {"error": "find and replace must be strings"}
                if not find:
                    return {"error": "find must not be empty"}
                if not isinstance(replace_all, bool):
                    return {"error": "replace_all must be a boolean"}
                find_bytes = self._encode_utf8_text(find, "find")
                replace_bytes = self._encode_utf8_text(replace, "replace")
                matches = source.count(find_bytes)
                if matches == 0:
                    return {"error": "find text was not present in the file"}
                if not replace_all and matches != 1:
                    return {"error": f"find text matched {matches} times; make it unique or set replace_all=true"}
                final = source.replace(find_bytes, replace_bytes, -1 if replace_all else 1)
                self._prepare_virtual_write(path, len(final))
                path.write_bytes(final)
                return {
                    "path": self.virtual_relative_path(path),
                    "mode": "text",
                    "replacements": matches if replace_all else 1,
                    "total_bytes": len(final),
                }

            required = ("offset", "limit", "replacement")
            missing = [name for name in required if name not in action]
            if missing:
                return {"error": "range mode requires offset, limit, and replacement"}
            offset = action["offset"]
            limit = action["limit"]
            replacement = action["replacement"]
            expected = action.get("expected")
            if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
                return {"error": "offset must be a non-negative integer"}
            if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
                return {"error": "limit must be a non-negative integer"}
            if not isinstance(replacement, str):
                return {"error": "replacement must be a string"}
            if expected is not None and not isinstance(expected, str):
                return {"error": "expected must be a string when supplied"}
            replacement_bytes = self._encode_utf8_text(replacement, "replacement")
            maximum_write = max(1, int(self.settings["maxVirtualFileWriteBytes"]))
            if len(replacement_bytes) > maximum_write:
                return {"error": f"replacement exceeds the {maximum_write}B write limit"}
            if offset > len(source) or limit > len(source) - offset:
                return {"error": "offset and limit must name an existing byte range"}
            end = offset + limit
            original = source[offset:end]
            if expected is not None and original != self._encode_utf8_text(expected, "expected"):
                return {"error": "expected text does not match the selected byte range"}
            final = source[:offset] + replacement_bytes + source[end:]
            self._prepare_virtual_write(path, len(final))
            path.write_bytes(final)
            return {
                "path": self.virtual_relative_path(path),
                "mode": "range",
                "offset": offset,
                "removed_bytes": len(original),
                "written_bytes": len(replacement_bytes),
                "total_bytes": len(final),
            }
        except (OSError, ValueError) as error:
            return {"error": str(error)}

    def download_file(self, action: dict[str, Any]) -> dict[str, Any]:
        url = action.get("url")
        headers = action.get("headers", {})
        overwrite = action.get("overwrite", False)
        if not isinstance(url, str) or not url.strip() or not self.same_target(url):
            return {"error": f"URL must stay on the authorized origin {self.target_origin}"}
        if not isinstance(headers, dict):
            return {"error": "headers must be an object"}
        if not isinstance(overwrite, bool):
            return {"error": "overwrite must be a boolean"}
        try:
            path = self.virtual_path(action.get("path"))
            if path.exists() and not overwrite:
                return {"error": "destination already exists; set overwrite=true to replace it"}
            self._prepare_virtual_write(path, 0)
        except (OSError, ValueError) as error:
            return {"error": str(error)}

        request_headers = self._bounded_headers(headers)
        current_url = url.strip()
        response = None
        try:
            for _ in range(6):
                response = self.session.get(
                    current_url,
                    headers=request_headers,
                    timeout=self.settings["httpTimeoutSeconds"],
                    allow_redirects=False,
                    stream=True,
                )
                location = response.headers.get("Location")
                if response.status_code not in {301, 302, 303, 307, 308} or not location:
                    break
                next_url = requests.compat.urljoin(current_url, location)
                response.close()
                response = None
                if not self.same_target(next_url):
                    return {"error": "redirect leaves the authorized target origin"}
                current_url = next_url
            else:
                return {"error": "download exceeded the 5-redirect limit"}

            if response is None:
                return {"error": "download did not receive a response"}
            final_url = str(response.url)
            if not self.same_target(final_url):
                return {"error": "response leaves the authorized target origin"}
            maximum = max(1, int(self.settings["maxVirtualFileBytes"]))
            try:
                announced_size = int(response.headers.get("Content-Length", 0))
            except (TypeError, ValueError):
                announced_size = 0
            if announced_size > maximum:
                return {"error": f"download exceeds the {maximum}B virtual-file limit"}
            temporary_path = path.parent / f".{path.name}.{uuid.uuid4().hex}.download"
            total = 0
            try:
                with temporary_path.open("xb") as stream:
                    for chunk in response.iter_content(chunk_size=8192):
                        if not chunk:
                            continue
                        total += len(chunk)
                        if total > maximum:
                            raise ValueError(f"download exceeds the {maximum}B virtual-file limit")
                        stream.write(chunk)
                os.replace(temporary_path, path)
            except (OSError, ValueError):
                temporary_path.unlink(missing_ok=True)
                raise
            return {
                "path": self.virtual_relative_path(path),
                "status": response.status_code,
                "url": final_url,
                "bytes_written": total,
                "headers": self._bounded_headers(response.headers),
            }
        except (OSError, ValueError, requests.RequestException) as error:
            return {"error": str(error)}
        finally:
            if response is not None:
                response.close()

    # ---------------------------------------------------------------- tools

    def curl(self, action: dict[str, Any]) -> dict[str, Any]:
        url = str(action.get("url", "")).strip()
        if not url or not self.same_target(url):
            return {"error": f"URL must stay on the authorized origin {self.target_origin}"}
        method = str(action.get("method", "GET")).upper()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            return {"error": "Unsupported HTTP method"}
        headers = dict(action.get("headers") or {})
        body = action.get("body")
        body_path = action.get("body_path")
        if body is not None and body_path is not None:
            return {"error": "body and body_path are mutually exclusive"}
        if body_path is not None:
            try:
                upload_path = self.virtual_path(body_path)
                if not upload_path.is_file():
                    return {"error": f"body_path does not exist: {self.virtual_relative_path(upload_path)}"}
                body = upload_path.read_bytes()
            except (OSError, ValueError) as error:
                return {"error": str(error)}
        if isinstance(body, str) and body and not any(key.lower() == "content-type" for key in headers):
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        response = None
        try:
            response = self.session.request(
                method,
                url,
                headers=headers,
                data=body,
                timeout=self.settings["httpTimeoutSeconds"],
                allow_redirects=True,
                stream=True,
            )
            content, source_bytes, truncated = self._capture_http_body(response)
            result = {
                "status": response.status_code,
                "url": response.url,
                "headers": self._bounded_headers(response.headers),
            }
            result.update(self.store_tool_content(content, source_bytes, truncated))
            return result
        except requests.RequestException as error:
            return {"error": str(error)}
        finally:
            if response is not None:
                close = getattr(response, "close", None)
                if callable(close):
                    close()

    def python_tool(self, action: dict[str, Any]) -> dict[str, Any]:
        has_code = "code" in action
        has_path = "path" in action
        if has_code == has_path:
            return {"error": "python requires exactly one of code or path"}

        source_name = "<inline python>"
        if has_path:
            try:
                script_path = self.virtual_path(action.get("path"))
                if not script_path.is_file():
                    return {"error": f"python script does not exist: {self.virtual_relative_path(script_path)}"}
                code_bytes = script_path.read_bytes()
                code = code_bytes.decode("utf-8")
                source_name = self.virtual_relative_path(script_path)
            except UnicodeDecodeError:
                return {"error": "python script must be UTF-8 text"}
            except (OSError, ValueError) as error:
                return {"error": str(error)}
        else:
            code = action.get("code")
            if not isinstance(code, str) or not code.strip():
                return {"error": "python requires a non-empty code string"}
            try:
                code_bytes = self._encode_utf8_text(code, "python code")
            except ValueError as error:
                return {"error": str(error)}

        if len(code_bytes) > 65536:
            return {"error": "python code exceeds the 64 KiB limit"}
        configured_maximum = max(1, int(self.settings.get("maxPythonTimeoutSeconds", 600)))
        configured_default = min(max(1, int(self.settings.get("pythonTimeoutSeconds", 60))), configured_maximum)
        requested_timeout = action.get("timeout_seconds", configured_default)
        if requested_timeout is None:
            requested_timeout = configured_default
        if isinstance(requested_timeout, bool) or not isinstance(requested_timeout, int) or requested_timeout < 1:
            return {"error": "timeout_seconds must be a positive integer"}
        if requested_timeout > configured_maximum:
            return {"error": f"timeout_seconds exceeds the configured {configured_maximum}-second maximum"}
        timeout_seconds = requested_timeout
        environment = os.environ.copy()
        for variable in (
            "PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP",
            "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
            "http_proxy", "https_proxy", "all_proxy", "no_proxy",
        ):
            environment.pop(variable, None)
        environment["PYTHONIOENCODING"] = "utf-8"
        environment["PYTHONUTF8"] = "1"
        environment["CTF_AGENT_WORKSPACE"] = str(self.workspace)
        capture_limit = max(1, int(self.settings["maxToolCaptureBytes"]))
        inline_limit = max(0, int(self.settings["maxInlineToolResultBytes"]))
        try:
            with tempfile.TemporaryDirectory(prefix="ctf-agent-python-") as directory:
                temporary_root = Path(directory)
                source_path = temporary_root / "source.py"
                runner_path = temporary_root / "runner.py"
                source_path.write_bytes(code_bytes)
                runner_path.write_text(PYTHON_WORKSPACE_RUNNER, encoding="utf-8")
                stdout_path = temporary_root / "stdout.bin"
                stderr_path = temporary_root / "stderr.bin"
                with stdout_path.open("wb") as stdout_stream, stderr_path.open("wb") as stderr_stream:
                    process = subprocess.Popen(
                        [sys.executable, "-I", "-X", "utf8", str(runner_path), str(source_path), source_name],
                        cwd=self.workspace,
                        env=environment,
                        stdout=stdout_stream,
                        stderr=stderr_stream,
                    )
                    try:
                        return_code = process.wait(timeout=timeout_seconds)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                        return {"error": f"python exceeded {timeout_seconds} seconds and was terminated"}
                stdout, stdout_bytes, stdout_truncated = self._read_file_capture(stdout_path, capture_limit)
                stderr, stderr_bytes, stderr_truncated = self._read_file_capture(stderr_path, capture_limit)
            combined = b"stdout:\n" + stdout + b"\nstderr:\n" + stderr
            combined_source_bytes = len(b"stdout:\n") + stdout_bytes + len(b"\nstderr:\n") + stderr_bytes
            result = {
                "exit_code": return_code,
                "timeout_seconds": timeout_seconds,
                "cwd": "/",
                "source": source_name,
                "stdout_preview": self._decode_result_bytes(stdout[:inline_limit]),
                "stderr_preview": self._decode_result_bytes(stderr[:inline_limit]),
                "stdout_bytes": stdout_bytes,
                "stderr_bytes": stderr_bytes,
            }
            result.update(self.store_tool_content(combined, combined_source_bytes, stdout_truncated or stderr_truncated))
            return result
        except subprocess.TimeoutExpired:
            return {"error": f"python exceeded {timeout_seconds} seconds and was terminated"}
        except OSError as error:
            return {"error": f"Unable to run Python: {error}"}

    def native_action(self, call: FunctionCall, allowed: set[str]) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """Decode one native function_call without ever interpreting text channels."""
        if not call.call_id:
            return None, {"error": "function_call was missing call_id"}
        if call.name not in allowed:
            return None, {"error": f"'{call.name}' is locked in this stage. Available: {', '.join(sorted(allowed))}"}
        try:
            argument_bytes = self._encode_utf8_text(call.arguments, "function arguments")
        except ValueError as error:
            return None, {"error": str(error)}
        if call.arguments_truncated or len(argument_bytes) > int(self.settings["maxToolArgumentBytes"]):
            return None, {"error": f"function '{call.name}' arguments exceed the {self.settings['maxToolArgumentBytes']}B limit"}
        try:
            arguments = json.loads(call.arguments)
        except json.JSONDecodeError:
            return None, {"error": f"function '{call.name}' returned invalid JSON arguments"}
        if not isinstance(arguments, dict):
            return None, {"error": f"function '{call.name}' arguments must be a JSON object"}
        if "action" in arguments:
            return None, {"error": "native function arguments must not contain reserved key 'action'"}
        return {"action": call.name, **arguments}, None
    def serialize_tool_result(self, result: dict[str, Any]) -> str:
        serialized = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
        limit = max(1024, int(self.settings["maxToolResultBytes"]))
        if len(serialized.encode("utf-8")) <= limit:
            return serialized
        compact: dict[str, Any] = {"error": "tool result was compacted for transport; read the result_id in pages"}
        for key in ("result_id", "status", "url", "path", "exit_code", "total_bytes", "available_bytes", "bytes_written", "file_count", "truncated", "eof", "next_offset"):
            if key in result:
                compact[key] = result[key]
        for key in ("preview", "content", "stdout_preview", "stderr_preview"):
            if key in result:
                compact[key] = str(result[key])[:256]
        return json.dumps(compact, ensure_ascii=False, separators=(",", ":"))
    def execute_tool(self, action: dict[str, Any], allowed: set[str]) -> tuple[dict[str, Any], bool]:
        name = str(action.get("action") or "")
        if name not in allowed:
            return {"error": f"'{name}' is locked in this stage. Available: {', '.join(sorted(allowed))}"}, False
        if name == "answer":
            text = clean_answer(str(action.get("text") or ""))
            if not text:
                return {"error": "answer requires non-empty text"}, False
            return {"answer": text[:2000]}, True
        if name == "finish":
            flag = action.get("flag")
            if isinstance(flag, str) and flag.strip():
                return {"flag": flag.strip()}, True
            return {"error": "finish requires a verified flag; call method_failed for only the current candidate method"}, False
        if name == "method_failed":
            reason = str(action.get("reason") or "").strip()
            if not reason:
                return {"error": "method_failed requires a non-empty reason"}, False
            return {"method_failure": reason[:2000]}, True
        if name == "read_tool_result":
            return self.read_tool_result(action), False
        if name == "list_files":
            return self.list_files(action), False
        if name == "read_file":
            return self.read_file(action), False
        if name == "write_file":
            return self.write_file(action), False
        if name == "edit_file":
            return self.edit_file(action), False
        if name == "download_file":
            return self.download_file(action), False
        if name == "curl":
            return self.curl(action), False
        if name == "python":
            return self.python_tool(action), False
        return {"error": "Unknown action"}, False

    # -------------------------------------------------------------- display

    @staticmethod
    def show_tool_call(action: dict[str, Any]) -> None:
        name = action.get("action")
        if name == "curl":
            emit(f"🛠️  curl {action.get('method', 'GET')} {action.get('url', '')}", "tool")
            body = action.get("body")
            if isinstance(body, str) and body:
                emit(f"    📦 {body[:200]}", "dim")
            body_path = action.get("body_path")
            if body_path:
                emit(f"    📄 body_path={body_path}", "dim")
        elif name == "python":
            timeout = action.get("timeout_seconds", "default 60s")
            path = action.get("path")
            if path:
                emit(f"🛠️  python {path} · timeout={timeout}", "tool")
            else:
                code = str(action.get("code", ""))
                first = code.strip().splitlines()[0] if code.strip() else ""
                emit(f"🛠️  python · {len(code.encode('utf-8', errors='replace'))}B · timeout={timeout} · {first[:100]}", "tool")
        elif name == "read_tool_result":
            emit(f"🛠️  read_tool_result {action.get('result_id', '')} @ {action.get('offset', 0)} + {action.get('limit', '')}", "tool")
        elif name == "list_files":
            emit("🛠️  list_files", "tool")
        elif name in {"read_file", "write_file", "edit_file"}:
            emit(f"🛠️  {name} {action.get('path', '')}", "tool")
        elif name == "download_file":
            emit(f"🛠️  download_file {action.get('url', '')} → {action.get('path', '')}", "tool")
        elif name == "answer":
            emit("🛠️  answer", "tool")
        elif name == "finish":
            emit("🛠️  finish", "tool")
        elif name == "method_failed":
            emit("🛠️  method_failed", "tool")
        else:
            emit(f"🛠️  {json.dumps(action, ensure_ascii=False)[:200]}", "tool")

    @staticmethod
    def show_tool_result(result: dict[str, Any]) -> None:
        if "error" in result:
            emit(f"    ❌ {result['error']}", "err")
            return
        if "status" in result and "result_id" in result:  # curl
            emit(
                f"    ✅ HTTP {result['status']} · {result.get('total_bytes', 0)}B · {result.get('url', '')}"
                f" · result_id={result['result_id']}",
                "ok",
            )
            preview = str(result.get("preview", "")).strip()
            if preview:
                emit(f"    {preview[:300]}", "dim")
            return
        if "status" in result and "path" in result:  # download_file
            emit(
                f"    ✅ 下载 HTTP {result['status']} · {result.get('bytes_written', 0)}B · {result['path']}",
                "ok",
            )
            return
        if "exit_code" in result:  # python
            ok = result.get("exit_code") == 0
            emit(f"    {'✅' if ok else '❌'} exit {result.get('exit_code')} · timeout={result.get('timeout_seconds', '?')}s · result_id={result.get('result_id', '?')}", "ok" if ok else "err")
            stdout = str(result.get("stdout_preview", "")).strip()
            stderr = str(result.get("stderr_preview", "")).strip()
            if stdout:
                emit(f"    {stdout[:300]}", "dim")
            if stderr:
                emit(f"    {stderr[:200]}", "err")
            return
        if "content" in result:
            emit(
                f"    📄 {result.get('path', result.get('result_id', '?'))} · {result.get('offset', 0)}-{result.get('next_offset', 0)}"
                f" / {result.get('total_bytes', 0)}B{' · EOF' if result.get('eof') else ''}",
                "ok",
            )
            content = str(result.get("content", ""))
            if content:
                emit(f"    {content[:500]}", "dim")
            return
        if "files" in result:
            emit(f"    📁 {result.get('file_count', 0)} 个虚拟文件", "ok")
            for item in result["files"][:8]:
                emit(f"    {item['path']} · {item['bytes']}B", "dim")
            return
        if "path" in result:
            emit(f"    ✅ {result['path']} · {result.get('total_bytes', result.get('bytes_written', 0))}B", "ok")
            return
        if "method_failure" in result:
            emit(f"    ↪ 当前手段未成立：{result['method_failure']}", "dim")
            return
        emit(f"    {json.dumps(result, ensure_ascii=False)[:300]}", "dim")

    # --------------------------------------------------------------- stages

    def run_stage(self, title: str, system: str, tools: list[str], task: str, budget: int, answer_validator: Any = None) -> dict[str, Any]:
        """Run one task with sequential native calls and a bounded action/context budget."""
        stage_tools = self.stage_tools(tools)
        emit(f"\n━━━ {title} ━━━", "phase")
        emit(f"🔓 本阶段工具：{' · '.join(stage_tools)}", "dim")
        self.current_stage_title = title
        self.stage_budget = budget
        self.stage_remaining = budget
        self.current_tool = "准备"
        self.compaction_status = "等待"
        self.refresh_tui_status()
        self.history = []  # fresh context: only carried-over conclusions remain
        self.stage_evidence = []
        self.clear_tool_buffers()
        self.last_official_compaction_encrypted_content = ""
        self.last_official_compaction_output = []
        self.last_official_compaction_id = None
        self.compaction_groups = []
        self.current_compaction_group = None
        self.last_compaction_input_truncated = False
        allowed = set(stage_tools)
        remaining = budget
        previous_response_id: str | None = None
        continuation_input: list[dict[str, Any]] | None = None
        pending_compaction = False
        configured_context_limit = int(self.settings["compactTokens"])
        compression_mode = "官方 Responses API" if bool(self.settings["useOfficialCompactionApi"]) else "本地摘要"
        if configured_context_limit > 0:
            emit(
                f"🗜️ 自动压缩：阈值 {configured_context_limit:,} tokens，模式 {compression_mode}；未达到阈值时不会压缩。",
                "dim",
            )
        else:
            emit("🗜️ 自动压缩已禁用（compactTokens <= 0）。", "dim")
        task_context_limit = max(1, configured_context_limit)
        self.refresh_tui_status()

        while remaining > 0:
            self.begin_tool_round()
            if pending_compaction:
                compaction_mode = self.compact_stage_if_needed(force=True, previous_response_id=previous_response_id)
                pending_compaction = False
            else:
                compaction_mode = self.compact_stage_if_needed(previous_response_id=previous_response_id)
            if compaction_mode == "local":
                previous_response_id = None
                continuation_input = None
                self.compaction_groups = []
                self.current_compaction_group = None
            elif (
                compaction_mode == "official"
                and self.last_official_compaction_id
                and self.last_official_compaction_output
            ):
                # The compact response ID is an artifact, not a retrievable Responses chain node.
                # Continue statelessly with its opaque reasoning item in the full input window.
                previous_response_id = None
                self.compaction_groups = []
                self.current_compaction_group = None
                continuation_input = [dict(item) for item in self.last_official_compaction_output]
                continuation_input.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "input_text",
                                "text": self.build_prompt(
                                    task,
                                    include_history=False,
                                ) + "\nContinue from the official Responses compaction window and issue the next native tool call.",
                            }
                        ],
                    }
                )
            if continuation_input is None:
                input_data: str | list[dict[str, Any]] = [
                    {"role": "user", "content": [{"type": "input_text", "text": self.build_prompt(task)}]}
                ]
                self.begin_compaction_input(input_data)
            else:
                input_data = continuation_input
                if any(isinstance(item, dict) and item.get("role") == "user" for item in continuation_input):
                    self.begin_compaction_input(continuation_input)

            self.current_tool = "模型请求"
            self.refresh_tui_status()
            try:
                turn = self.stream_turn(
                    input_data,
                    instructions=system,
                    tools=stage_tools,
                    previous_response_id=previous_response_id,
                )
                self.append_compaction_response(turn)
                self.current_tool = f"收到 {len(turn.function_calls)} 个调用"
                self.refresh_tui_status()
            except RuntimeError as error:
                emit(f"⚠️  模型请求失败：{error}；压缩本地任务上下文后重试。", "err")
                self.history.append(f"Model request failed ({error}). Continue with one or more native function calls.")
                previous_response_id = None
                continuation_input = None
                pending_compaction = True
                remaining -= 1
                self.total_actions += 1
                self.stage_remaining = remaining
                self.current_tool = "模型请求失败"
                self.last_result_summary = str(error)[:100]
                self.refresh_tui_status()
                continue

            previous_response_id = turn.response_id
            if configured_context_limit > 0 and turn.input_tokens is not None and turn.input_tokens >= task_context_limit:
                pending_compaction = True
                emit(f"🧭 服务端报告本任务输入已达 {turn.input_tokens} tokens；下一轮前正常压缩任务上下文。", "dim")
                self.compaction_status = f"服务端触发 {turn.input_tokens:,} tokens"
                self.refresh_tui_status()
            if turn.status != "completed":
                emit(f"⚠️  模型输出被截断（{turn.status}），尝试抢救可用部分…", "err")
                self.history.append("Previous response was incomplete. Return one or more compact native function calls.")
            if turn.text:
                self.history.append(self.history_entry("Model output:\n" + turn.text))

            if not turn.function_calls:
                if turn.reasoning:
                    diagnostic = (
                        "No native function_call output item was returned. Reasoning content is display-only; "
                        "use one or more provided native functions now."
                    )
                    emit("⚠️  reasoning 已完成但没有 native function_call，未执行任何文本。", "err")
                else:
                    diagnostic = "No native function_call output item was returned. Use one or more provided native functions now."
                self.history.append(diagnostic)
                previous_response_id = None
                continuation_input = None
                remaining -= 1
                self.total_actions += 1
                self.stage_remaining = remaining
                self.current_tool = "无原生调用"
                self.last_result_summary = diagnostic[:100]
                self.refresh_tui_status()
                continue

            calls = turn.function_calls
            if len(calls) > 1:
                emit(f"🧰 服务端返回 {len(calls)} 个 native function_call；按返回顺序全部执行。", "info")
                self.history.append(f"Model response contained {len(calls)} native function calls; executing them in source order.")
            executable_calls = calls[:remaining]
            if len(executable_calls) < len(calls):
                emit(
                    f"⚠️  本阶段只剩 {remaining} 个动作预算；后续 {len(calls) - len(executable_calls)} 个调用未执行。",
                    "err",
                )
                self.history.append(
                    f"Action budget prevented execution of {len(calls) - len(executable_calls)} native function calls from one response."
                )
            continuation_outputs: list[dict[str, Any]] = []
            all_call_ids_present = True
            for call in executable_calls:
                self.current_tool = call.name
                self.refresh_tui_status()
                action, decoding_error = self.native_action(call, allowed)
                if decoding_error is not None:
                    result = decoding_error
                    finished = False
                else:
                    assert action is not None
                    self.show_tool_call(action)
                    result, finished = self.execute_tool(action, allowed)
                    if finished and "answer" in result and answer_validator is not None:
                        problem = answer_validator(result["answer"])
                        if problem:
                            result = {"error": problem + " Submit the answer again."}
                            finished = False
                    if finished and "flag" in result:
                        if not any(str(result["flag"]) in evidence for evidence in self.stage_evidence):
                            result = {
                                "error": "flag was not observed verbatim in this stage's tool results. "
                                "Fetch or decode it with curl/python so the exact string appears, then finish."
                            }
                            finished = False
                    if finished and call is not executable_calls[-1]:
                        terminal_action = str(action.get("action") or call.name)
                        result = {
                            "error": f"{terminal_action} must be the final native function call in a batch; later calls will still execute"
                        }
                        finished = False
                self.show_tool_result(result)
                for evidence_key in ("preview", "content", "body", "stdout_preview", "stdout", "stderr_preview", "stderr"):
                    evidence = result.get(evidence_key)
                    if isinstance(evidence, str) and evidence:
                        self.stage_evidence.append(evidence)
                remaining -= 1
                self.stage_remaining = remaining
                self.total_actions += 1
                step = self.total_actions
                if action is None:
                    self.history.append(f"Step {step} rejected native call: {call.name}")
                else:
                    self.history.append(f"Step {step} action: {json.dumps(action, ensure_ascii=True)}")
                serialized_result = self.serialize_tool_result(result)
                self.history.append(self.history_entry(f"Step {step} result: {serialized_result}"))
                self.append_compaction_output(call.call_id, serialized_result)
                self.last_result_summary = (
                    str(result.get("error") or result.get("flag") or result.get("method_failure") or json.dumps(result, ensure_ascii=False))[:100]
                )
                self.refresh_tui_status()
                if call.call_id:
                    continuation_outputs.append(
                        {
                            "type": "function_call_output",
                            "call_id": call.call_id,
                            "output": serialized_result,
                        }
                    )
                else:
                    all_call_ids_present = False
                if finished:
                    self.clear_tool_buffers()
                    return result

            local_compaction_pending = pending_compaction and not bool(self.settings["useOfficialCompactionApi"])
            abandon_server_chain = (
                len(executable_calls) != len(calls)
                or not all_call_ids_present
                or not previous_response_id
                or local_compaction_pending
            )
            if abandon_server_chain:
                previous_response_id = None
                continuation_input = None
            else:
                continuation_input = continuation_outputs
        self.clear_tool_buffers()
        return {}

    def record_method_outcome(self, index: int, outcome: dict[str, Any]) -> None:
        entry = self.globals["methods"][index - 1]
        declared_reason = " ".join(str(outcome.get("method_failure") or "").split())[:240]
        if declared_reason:
            status = "failed"
            fallback = "Declared failure: " + declared_reason
        else:
            status = "exhausted"
            fallback = "Execution action budget exhausted before this method was verified."
        entry["status"] = status
        self.current_tool = "模型汇总失败证据"
        self.last_result_summary = f"正在汇总手段 {index} 的失败原因"
        self.refresh_tui_status()
        token_budget = self.summary_input_token_budget()
        emit(f"🧠 正在用模型汇总手段 {index} 的失败证据（工具历史上限 {token_budget:,} tokens）…", "info")
        what = (
            f"failed execution method '{str(entry['name'])[:160]}'. Produce a factual handoff for the next candidate: "
            "observed evidence, exact attempt sequence, why this method failed or remained unverified, "
            "and paths that must not be repeated. "
            + (f"Declared reason: {declared_reason}." if declared_reason else "")
        )
        evidence_summary = self.summarize("\n".join(self.history), what)
        parts = [fallback]
        if evidence_summary:
            parts.append("Evidence summary: " + evidence_summary)
        summary_limit = max(160, int(self.settings.get("maxMethodSummaryChars", 600)))
        entry["summary"] = " ".join(parts)[:summary_limit]
        self.current_tool = "失败总结已保存"
        self.last_result_summary = entry["summary"][:100]
        self.refresh_tui_status()
        emit(f"📒 手段 {index} [{status}] 总结已写入下一执行阶段：{entry['summary']}", "dim")

    # ------------------------------------------------------------------ run

    def run(self) -> str | None:
        emit(f"🎯 目标 {self.target_url}", "info")
        emit(f"📁 虚拟文件工作区 {self.workspace}", "dim")
        self.current_stage_title = "初始化"
        self.current_tool = "准备阶段"
        self.refresh_tui_status()

        # Stage 1 — classify (fresh context, curl + answer; finish locked away).
        outcome = self.run_stage(
            "🔍 阶段 1/3 · 识别题型",
            CLASSIFY_SYSTEM,
            ["curl", "python", "answer"],
            CLASSIFY_TASK,
            int(self.settings["classifyBudget"]),
            answer_validator=validate_classification,
        )
        classification = str(outcome.get("answer") or "未知题型").splitlines()[0][:300]
        self.globals["classification"] = classification
        emit(f"📌 题型判断：{classification}", "info")
        self.refresh_tui_status()

        # Compress stage-1 recon into a bounded digest so later stages keep the facts
        # (endpoints, cookies, decoded values) without the raw transcript.
        recon = self.summarize(
            "\n".join(self.history),
            "concrete recon facts: endpoints probed with statuses, forms and fields, cookies/tokens, "
            "decoded values, interesting comments or strings, and where the flag-like hints were",
        )
        if recon:
            self.globals["findings"].append("Recon digest: " + recon)
            emit(f"📒 侦察摘要已入全局：{recon[:120]}{'…' if len(recon) > 120 else ''}", "dim")

        # Stage 2 — plan (fresh context + classification global).
        outcome = self.run_stage(
            "🧭 阶段 2/3 · 生成候选解题手段",
            PLAN_SYSTEM,
            ["curl", "python", "answer"],
            PLAN_TASK.format(max_methods=int(self.settings["maxMethods"])),
            int(self.settings["planBudget"]),
            answer_validator=validate_plan,
        )
        methods = parse_methods(str(outcome.get("answer") or ""), int(self.settings["maxMethods"]))
        if not methods:
            emit("\n🚫 规划阶段未给出任何手段。", "err")
            return None
        self.globals["methods"] = [{"name": method, "status": "pending", "summary": ""} for method in methods]
        emit("📋 候选手段：", "info")
        for index, method in enumerate(methods, 1):
            emit(f"   {index}. {method}", "dim")
        self.refresh_tui_status()

        # Stage 3 — test each method in its own fresh context; finish unlocked here.
        for index, method in enumerate(methods, 1):
            self.current_method = index
            self.show_prior_method_outcomes(index)
            outcome = self.run_stage(
                f"⚔️ 阶段 3/3 · 测试手段 {index}/{len(methods)}",
                EXECUTE_SYSTEM,
                ["curl", "python", "finish"],
                EXECUTE_TASK.format(index=index, total=len(methods), method=method),
                int(self.settings["methodBudget"]),
            )
            if "flag" in outcome:
                self.globals["methods"][index - 1]["status"] = "done"
                self.current_stage_title = "完成"
                self.current_tool = "finish"
                self.stage_remaining = 0
                self.last_result_summary = str(outcome["flag"])[:100]
                self.refresh_tui_status()
                emit(f"\n🏁 FLAG: {outcome['flag']}", "flag")
                return str(outcome["flag"])
            self.record_method_outcome(index, outcome)
            self.refresh_tui_status()

        emit(f"\n🚫 全部 {len(methods)} 个手段均未解出（累计执行 {self.total_actions} 个动作；每阶段预算独立计算）。", "err")
        self.current_stage_title = "无法完成"
        self.current_tool = "结束"
        self.refresh_tui_status()
        return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Solve one authorized Web CTF challenge URL.")
    parser.add_argument("url", help="Authorized challenge URL, for example http://127.0.0.1:18080/")
    parser.add_argument("description", nargs="?", default="", help="Optional challenge description to keep the agent on track")
    parser.add_argument("--config", default="agent.yml", help="Optional YAML config path")
    parser.add_argument("--no-tui", action="store_true", help="Disable the alternate-screen TUI and keep plain streaming logs")
    args = parser.parse_args()
    config = load_config(args.config)
    tui = start_tui(args.no_tui, max_activity_chars=int(config["agent"].get("maxTuiChars", 24000)))
    exit_code = 1
    try:
        agent = CtfAgent(config, args.url, args.description)
        agent.refresh_tui_status()
        exit_code = 0 if agent.run() else 1
    finally:
        stop_tui(tui)
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()

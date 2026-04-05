# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import requests
import argparse
import logging
import re
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)
    recap = _build_recap("GET", endpoint, params)

    try:
        response = requests.get(url, params=params, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            lines = response.text.splitlines()
            return [recap] + lines if lines else [recap]
        else:
            return [recap, f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [recap, f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str) -> str:
    recap = _build_recap("POST", endpoint, data)
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=5)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            body = response.text.strip()
            return f"{recap}\n{body}" if body else recap
        else:
            return f"{recap}\nError {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"{recap}\nRequest failed: {str(e)}"


def _response_has_http_404(result: list[str] | str) -> bool:
    if isinstance(result, list):
        return any("Error 404" in line for line in result)
    return "Error 404" in str(result)


def _response_has_context_error(result: list[str] | str) -> bool:
    if isinstance(result, list):
        return any("No context found for request" in line for line in result)
    return "No context found for request" in str(result)


def _escape_script_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _symbol_lookup_via_readonly_script(address: str) -> str:
    escaped_address = _escape_script_string(address)
    script_text = f"""
addr_text = \"{escaped_address}\"
program = currentProgram
if program is None:
    print("failed: get_symbol_at no program loaded")
else:
    addr = program.getAddressFactory().getAddress(addr_text)
    if addr is None and addr_text.lower().startswith("0x"):
        addr = program.getAddressFactory().getAddress(addr_text[2:])
    if addr is None:
        print("failed: get_symbol_at invalid address=" + addr_text)
    else:
        symbol = program.getSymbolTable().getPrimarySymbol(addr)
        has_data = program.getListing().getDefinedDataAt(addr) is not None
        if symbol is None:
            print("ok: get_symbol_at address=" + str(addr) + " symbol=<none> defined_data=" + str(has_data))
        else:
            print(
                "ok: get_symbol_at address=" + str(addr) +
                " symbol=" + symbol.getName() +
                " source=" + str(symbol.getSource()) +
                " symbol_type=" + str(symbol.getSymbolType()) +
                " defined_data=" + str(has_data)
            )
""".strip()

    return safe_post("run_readonly_script", {"script_text": script_text})


def _normalized_address_candidates(address: str) -> set[str]:
    value = (address or "").strip()
    if not value:
        return set()

    candidates: set[str] = {value, value.lower(), value.upper()}

    match_seg = re.fullmatch(r"([0-9a-fA-F]{1,4}):([0-9a-fA-F]{1,4})", value)
    if match_seg:
        seg = match_seg.group(1).zfill(4)
        off = match_seg.group(2).zfill(4)
        combined = f"{seg}:{off}"
        candidates.update({combined, combined.lower(), combined.upper()})
        return candidates

    match_hex = re.fullmatch(r"(?:0x)?([0-9a-fA-F]+)", value)
    if match_hex:
        number = int(match_hex.group(1), 16)
        if number <= 0xFFFF:
            off = f"{number:04x}"
            seg_off = f"0000:{off}"
            candidates.update({off, off.upper(), f"0x{number:x}", f"0x{number:X}", seg_off, seg_off.upper()})

    return candidates


def _symbol_lookup_via_legacy_endpoints(address: str) -> str | None:
    candidates = _normalized_address_candidates(address)
    if not candidates:
        return None

    function_endpoint_reachable = False
    data_endpoint_reachable = False

    # Try function metadata first because it is cheap and specific.
    for candidate in candidates:
        function_result = safe_get("get_function_by_address", {"address": candidate})
        if _response_has_http_404(function_result):
            continue
        function_endpoint_reachable = True

        body_lines = function_result[1:]
        if any(line.startswith("Function:") for line in body_lines):
            function_line = next(line for line in body_lines if line.startswith("Function:"))
            match = re.match(r"Function:\s+(.*?)\s+at\s+(.+)$", function_line)
            if match:
                function_name = match.group(1).strip()
                resolved = match.group(2).strip()
                return (
                    f"ok: get_symbol_at address={resolved} symbol={function_name} "
                    "source=legacy_function_lookup symbol_type=FUNCTION defined_data=false"
                )

            return "\n".join(function_result)

    # Fall back to paged data-list scan to recover data labels from old servers.
    address_matchers = set()
    for candidate in candidates:
        address_matchers.add(candidate.lower())
        if ":" not in candidate and len(candidate) <= 4 and re.fullmatch(r"[0-9a-fA-F]{1,4}", candidate):
            address_matchers.add(f"0000:{candidate.zfill(4).lower()}")

    offset = 0
    limit = 200
    max_pages = 40

    for _ in range(max_pages):
        data_result = safe_get("data", {"offset": offset, "limit": limit})
        if _response_has_http_404(data_result):
            break
        data_endpoint_reachable = True

        lines = data_result[1:]
        if not lines:
            break

        for line in lines:
            match = re.match(r"^([0-9a-fA-F]{4}:[0-9a-fA-F]{4}):\s*(.*?)\s*=\s*(.*)$", line)
            if not match:
                continue

            resolved_addr = match.group(1)
            symbol_name = match.group(2).strip()
            if resolved_addr.lower() not in address_matchers:
                continue

            if symbol_name == "(unnamed)":
                return (
                    f"ok: get_symbol_at address={resolved_addr} symbol=<none> "
                    "source=legacy_data_scan symbol_type=DATA defined_data=true"
                )

            return (
                f"ok: get_symbol_at address={resolved_addr} symbol={symbol_name} "
                "source=legacy_data_scan symbol_type=DATA defined_data=true"
            )

        if len(lines) < limit:
            break
        offset += limit

    if function_endpoint_reachable or data_endpoint_reachable:
        normalized = sorted(candidates)[0]
        return (
            f"ok: get_symbol_at address={normalized} symbol=<none> "
            "source=legacy_inference symbol_type=UNKNOWN defined_data=false"
        )

    return None


def _preview_param_value(value, max_len: int = 40) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _format_param_summary(payload: dict | str) -> str:
    if payload is None:
        return ""

    if isinstance(payload, str):
        if not payload.strip():
            return ""
        return f"body=\"{_preview_param_value(payload)}\""

    if not isinstance(payload, dict) or not payload:
        return ""

    pieces: list[str] = []
    for key in sorted(payload.keys()):
        value = payload.get(key)
        if value is None or str(value).strip() == "":
            continue

        if key in {"batch", "plan", "script_text", "mappings", "fields", "slots", "methods"}:
            length = len(str(value))
            pieces.append(f"{key}=<{length} chars>")
            continue

        pieces.append(f"{key}={_preview_param_value(value)}")

    return " ".join(pieces)


def _build_recap(method: str, endpoint: str, payload: dict | str | None = None) -> str:
    params = _format_param_summary(payload)
    endpoint_text = endpoint if endpoint.startswith("/") else f"/{endpoint}"
    if params:
        return f"{method} {endpoint_text} {params}".strip()
    return f"{method} {endpoint_text}"


def _with_target_params(
    payload: dict | None,
    project_dir: str = "",
    project_name: str = "",
    folder_path: str = "",
    program_name: str = "",
) -> dict:
    data = dict(payload or {})
    if project_dir.strip():
        data["project_dir"] = project_dir.strip()
    if project_name.strip():
        data["project_name"] = project_name.strip()
    if folder_path.strip():
        data["folder_path"] = folder_path.strip()
    if program_name.strip():
        data["program_name"] = program_name.strip()
    return data


def _with_prefixed_target_params(
    payload: dict | None,
    prefix: str,
    project_dir: str = "",
    project_name: str = "",
    folder_path: str = "",
    program_name: str = "",
) -> dict:
    data = dict(payload or {})
    normalized_prefix = prefix or ""
    if project_dir.strip():
        data[f"{normalized_prefix}project_dir"] = project_dir.strip()
    if project_name.strip():
        data[f"{normalized_prefix}project_name"] = project_name.strip()
    if folder_path.strip():
        data[f"{normalized_prefix}folder_path"] = folder_path.strip()
    if program_name.strip():
        data[f"{normalized_prefix}program_name"] = program_name.strip()
    return data


def _preview_text(value: str, max_len: int = 120) -> str:
    """
    Normalize a text field for compact tool output.
    """
    text = (value or "").replace("\r", " ").replace("\n", " ").strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _build_batch_lines(
    batch: list[dict[str, str]],
    first_key: str,
    second_key: str,
    first_label: str,
    second_label: str,
) -> tuple[list[str], str | None]:
    """
    Convert batch entries to tab-delimited lines expected by the plugin.

    Accepts either:
    - [{first_key: "...", second_key: "..."}, ...]
    - [["...", "..."], ...] (backward-compatible)
    """
    if not isinstance(batch, list):
        return [], "Error: batch must be a list"

    lines: list[str] = []
    for index, entry in enumerate(batch):
        a = ""
        b = ""

        if isinstance(entry, dict):
            a = str(entry.get(first_key, "")).strip()
            b = str(entry.get(second_key, "")).strip()
        elif isinstance(entry, (list, tuple)) and len(entry) == 2:
            a = str(entry[0]).strip()
            b = str(entry[1]).strip()
        else:
            return [], (
                f"Error: invalid batch item at index {index}. "
                f"Expected object with '{first_key}' and '{second_key}', or a 2-item list"
            )

        if not a:
            return [], f"Error: {first_label} is required for batch item at index {index}"
        if not b:
            return [], f"Error: {second_label} is required for batch item at index {index}"

        lines.append(f"{a}\t{b}")

    return lines, None

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", _with_target_params({"offset": offset, "limit": limit}, project_dir, project_name, folder_path, program_name))

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", _with_target_params({"offset": offset, "limit": limit}, project_dir, project_name, folder_path, program_name))

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name)

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename or create the primary symbol at the specified address.
    """
    result = safe_post("renameData", {"address": address, "newName": new_name})
    return (
        f"Rename data at {address} -> {new_name}\n"
        f"{result}"
    )

@mcp.tool()
def get_symbol_at(address: str, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> str:
    """
    Get the current primary symbol state at an address.
    """
    params = _with_target_params({"address": address}, project_dir, project_name, folder_path, program_name)
    for endpoint in ("get_symbol_at", "symbol_at", "getSymbolAt", "symbolAt", "get_symbol"):
        result = safe_get(endpoint, params)
        if not _response_has_http_404(result):
            return "\n".join(result)

    legacy_result = _symbol_lookup_via_legacy_endpoints(address)
    if legacy_result is not None:
        return (
            "Primary symbol endpoints unavailable; using legacy endpoint fallback\n"
            f"{legacy_result}"
        )

    script_result = _symbol_lookup_via_readonly_script(address)
    if "Failed to run readonly script: Ghidra was not started with PyGhidra" in script_result:
        return (
            "Primary symbol endpoints unavailable and readonly-script fallback cannot run without PyGhidra. "
            "Reload the updated GhidraMCP plugin build to enable direct get_symbol_at routes.\n"
            f"{script_result}"
        )

    if "Error 404" not in script_result and "Request failed:" not in script_result:
        return (
            "Primary symbol endpoints unavailable; using run_readonly_script fallback\n"
            f"{script_result}"
        )

    return (
        "failed: get_symbol_at symbol routes unavailable and no compatible fallback succeeded\n"
        f"{script_result}"
    )

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", _with_target_params({"offset": offset, "limit": limit}, project_dir, project_name, folder_path, program_name))

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", _with_target_params({"offset": offset, "limit": limit}, project_dir, project_name, folder_path, program_name))

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", _with_target_params({"offset": offset, "limit": limit}, project_dir, project_name, folder_path, program_name))

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", _with_target_params({"offset": offset, "limit": limit}, project_dir, project_name, folder_path, program_name))

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", _with_target_params({"offset": offset, "limit": limit}, project_dir, project_name, folder_path, program_name))

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", _with_target_params({"query": query, "offset": offset, "limit": limit}, project_dir, project_name, folder_path, program_name))

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

@mcp.tool()
def get_function_by_address(address: str, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", _with_target_params({"address": address}, project_dir, project_name, folder_path, program_name)))

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
def list_functions(project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> list:
    """
    List all functions in the database.
    """
    return safe_get("list_functions", _with_target_params({}, project_dir, project_name, folder_path, program_name))

@mcp.tool()
def decompile_function_by_address(address: str, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> str:
    """
    Decompile a function at the given address.
    """
    return "\n".join(safe_get("decompile_function", _with_target_params({"address": address}, project_dir, project_name, folder_path, program_name)))

@mcp.tool()
def disassemble_function(address: str, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return safe_get("disassemble_function", _with_target_params({"address": address}, project_dir, project_name, folder_path, program_name))

@mcp.tool()
def create_function_by_address(entry: str, name: str, body_start: str, body_end: str, comment: str = "") -> str:
    """
    Create a function with explicit entry and body bounds.
    """
    return safe_post("create_function_by_address", {
        "entry": entry,
        "name": name,
        "body_start": body_start,
        "body_end": body_end,
        "comment": comment,
    })

@mcp.tool()
def delete_function_by_address(entry: str) -> str:
    """
    Delete a function at the provided entry address.
    """
    return safe_post("delete_function_by_address", {"entry": entry})

@mcp.tool()
def get_function_containing(address: str, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> str:
    """
    Get the function containing the provided address.
    """
    return "\n".join(safe_get("get_function_containing", _with_target_params({"address": address}, project_dir, project_name, folder_path, program_name)))

@mcp.tool()
def read_region(start: str, end: str, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> str:
    """
    Read raw bytes from memory in the range [start, end].
    """
    return "\n".join(safe_get("read_region", _with_target_params({"start": start, "end": end}, project_dir, project_name, folder_path, program_name)))

@mcp.tool()
def disassemble_region(start: str, end: str, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> list:
    """
    Disassemble instructions in an arbitrary address range.
    """
    return safe_get("disassemble_region", _with_target_params({"start": start, "end": end}, project_dir, project_name, folder_path, program_name))

@mcp.tool()
def get_instruction_window(address: str, before_count: int = 5, after_count: int = 5, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> list:
    """
    Dump nearby instructions around an address.
    """
    return safe_get("get_instruction_window", _with_target_params({
        "address": address,
        "before_count": before_count,
        "after_count": after_count,
    }, project_dir, project_name, folder_path, program_name))

@mcp.tool()
def search_instructions(query: str, mode: str = "text", limit: int = 200, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> list:
    """
    Search instructions by rendered text, operand text, or address tokens.
    """
    return safe_get("search_instructions", _with_target_params({"query": query, "mode": mode, "limit": limit}, project_dir, project_name, folder_path, program_name))

@mcp.tool()
def get_data_uses(address: str, include_operand_scans: bool = True, limit: int = 200, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> list:
    """
    Get data-address uses from reference manager plus optional instruction scans.
    """
    return safe_get("get_data_uses", _with_target_params({
        "address": address,
        "include_operand_scans": str(include_operand_scans).lower(),
        "limit": limit,
    }, project_dir, project_name, folder_path, program_name))

@mcp.tool()
def set_comments(batch: list[dict[str, str]]) -> str:
    """
    Set disassembly comments in batch.

    Input format: [{"address": "...", "comment": "..."}, ...]
    """
    lines, error = _build_batch_lines(batch, "address", "comment", "address", "comment")
    if error:
        return error

    result = safe_post("set_comments", {"batch": "\n".join(lines)})
    return f"Set disassembly comments: items={len(lines)}\n{result}"

@mcp.tool()
def set_decompiler_comments(batch: list[dict[str, str]]) -> str:
    """
    Set decompiler comments in batch.

    Input format: [{"address": "...", "comment": "..."}, ...]
    """
    lines, error = _build_batch_lines(batch, "address", "comment", "address", "comment")
    if error:
        return error

    result = safe_post("set_decompiler_comments", {"batch": "\n".join(lines)})
    return f"Set decompiler comments: items={len(lines)}\n{result}"

@mcp.tool()
def rename_functions_by_address(batch: list[dict[str, str]]) -> str:
    """
    Batch rename functions by address.

    Input format: [{"function_address": "...", "new_name": "..."}, ...]
    """
    lines, error = _build_batch_lines(
        batch,
        "function_address",
        "new_name",
        "function_address",
        "new_name",
    )
    if error:
        return error

    result = safe_post("rename_functions_by_address", {"batch": "\n".join(lines)})
    return f"Rename functions by address: items={len(lines)}\n{result}"

@mcp.tool()
def apply_program_edit_plan(
    plan: str,
    dry_run: bool = False,
    project_dir: str = "",
    project_name: str = "",
    folder_path: str = "",
    program_name: str = "",
) -> str:
    """
    Apply a simple line-oriented edit plan.

    Supported actions:
    - create_function_by_address|entry|name|body_start|body_end|comment(optional)
    - delete_function_by_address|entry
    - rename_function_by_address|address|new_name
    - set_disassembly_comment|address|comment
    - set_decompiler_comment|address|comment

    Optional explicit target selectors:
    - project_dir, project_name, folder_path, program_name
    """
    return safe_post("apply_program_edit_plan", _with_target_params({
        "plan": plan,
        "dry_run": str(dry_run).lower(),
    }, project_dir, project_name, folder_path, program_name))

@mcp.tool()
def reanalyze_region(start: str, end: str) -> str:
    """
    Trigger an analysis pass after edits touching a region.
    """
    return safe_post("reanalyze_region", {"start": start, "end": end})

@mcp.tool()
def patch_bytes_and_reanalyze(
    start: str,
    bytes: str,
    comment: str = "",
    project_dir: str = "",
    project_name: str = "",
    folder_path: str = "",
    program_name: str = "",
) -> str:
    """
    Patch bytes at start address and trigger reanalysis.

    bytes format: "90 90 90" or "0x90 0x90 0x90"

    Optional explicit target selectors:
    - project_dir, project_name, folder_path, program_name
    """
    return safe_post("patch_bytes_and_reanalyze", _with_target_params({
        "start": start,
        "bytes": bytes,
        "comment": comment,
    }, project_dir, project_name, folder_path, program_name))

@mcp.tool()
def analyze_function_boundaries(start: str, end: str) -> list:
    """
    Inspect a range for overlaps and likely candidate function entries.
    """
    return safe_get("analyze_function_boundaries", {"start": start, "end": end})

@mcp.tool()
def get_project_access_info() -> str:
    """
    Get metadata about current program/project read-only and writable state.
    """
    return "\n".join(safe_get("get_project_access_info"))

@mcp.tool()
def get_runtime_capabilities() -> str:
    """
    Report runtime capabilities, including readonly-script support state.
    """
    return "\n".join(safe_get("get_runtime_capabilities"))

@mcp.tool()
def open_current_program_readonly(version: int = -1, make_current: bool = True) -> str:
    """
    Deprecated: MCP no longer opens programs in read-only mode.
    """
    return safe_post("open_current_program_readonly", {
        "version": str(version),
        "make_current": str(make_current).lower(),
    })

@mcp.tool()
def run_readonly_script(script_path: str = "", script_text: str = "") -> str:
    """
    Run a constrained read-only Ghidra script by path or inline script text.
    """
    return safe_post("run_readonly_script", {
        "script_path": script_path,
        "script_text": script_text,
    })

@mcp.tool()
def run_write_script(script_path: str = "", script_text: str = "", dry_run: bool = False, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> str:
    """
    Run a constrained live write-capable Ghidra script against a writable target program.
    """
    return safe_post("run_write_script", _with_target_params({
        "script_path": script_path,
        "script_text": script_text,
        "dry_run": str(dry_run).lower(),
    }, project_dir, project_name, folder_path, program_name))

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    result = safe_post("set_decompiler_comment", {"address": address, "comment": comment})
    return (
        f"Set decompiler comment at {address}\n"
        f"comment=\"{_preview_text(comment)}\"\n"
        f"{result}"
    )

@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    result = safe_post("set_disassembly_comment", {"address": address, "comment": comment})
    return (
        f"Set disassembly comment at {address}\n"
        f"comment=\"{_preview_text(comment)}\"\n"
        f"{result}"
    )

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    result = safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})
    return (
        f"Rename function at {function_address} -> {new_name}\n"
        f"{result}"
    )

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
    """
    params = _with_target_params({"address": address, "offset": offset, "limit": limit}, project_dir, project_name, folder_path, program_name)
    result = safe_get("get_xrefs_to", params)
    if _response_has_http_404(result):
        return safe_get("xrefs_to", params)
    return result

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
    """
    params = _with_target_params({"address": address, "offset": offset, "limit": limit}, project_dir, project_name, folder_path, program_name)
    result = safe_get("get_xrefs_from", params)
    if _response_has_http_404(result):
        return safe_get("xrefs_from", params)
    return result

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", _with_target_params({"name": name, "offset": offset, "limit": limit}, project_dir, project_name, folder_path, program_name))

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> list:
    """
    List all defined strings in the program with their addresses.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content
        
    Returns:
        List of strings with their addresses
    """
    params = _with_target_params({"offset": offset, "limit": limit}, project_dir, project_name, folder_path, program_name)
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)

@mcp.tool()
def search_bytes(pattern: str, start: str = "", end: str = "", segment_filter: str = "", max_hits: int = 100, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> str:
    """
    Search program memory for a byte pattern with optional wildcards like ??.
    """
    return "\n".join(safe_get("search_bytes", _with_target_params({
        "pattern": pattern,
        "start": start,
        "end": end,
        "segment_filter": segment_filter,
        "max_hits": max_hits,
    }, project_dir, project_name, folder_path, program_name)))

@mcp.tool()
def get_callers(target: str, include_near: bool = True, include_far: bool = True, include_jumps: bool = True, limit: int = 200, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> list:
    """
    Recover callers for a function by name or address, including scan-based local call sites.
    """
    return safe_get("get_callers", _with_target_params({
        "target": target,
        "include_near": str(include_near).lower(),
        "include_far": str(include_far).lower(),
        "include_jumps": str(include_jumps).lower(),
        "limit": limit,
    }, project_dir, project_name, folder_path, program_name))

@mcp.tool()
def list_project_programs(project_dir: str = "", project_name: str = "", folder_path: str = "", recursive: bool = True) -> list:
    """
    List folders and programs available in a Ghidra project.
    """
    params = {
        "project_dir": project_dir,
        "project_name": project_name,
        "folder_path": folder_path,
        "recursive": str(recursive).lower(),
    }
    result = safe_get("list_project_programs", params)
    if _response_has_http_404(result) or _response_has_context_error(result):
        alias_result = safe_get("project_programs", params)
        if not _response_has_http_404(alias_result) and not _response_has_context_error(alias_result):
            return alias_result
    return result

@mcp.tool()
def compare_regions(left_start: str, left_end: str, right_start: str, right_end: str, mode: str = "bytes", max_diffs: int = 100, left_project_dir: str = "", left_project_name: str = "", left_folder_path: str = "", left_program_name: str = "", right_project_dir: str = "", right_project_name: str = "", right_folder_path: str = "", right_program_name: str = "") -> str:
    """
    Compare two regions across programs using bytes, words, disassembly, or strings.
    """
    params = {
        "left_start": left_start,
        "left_end": left_end,
        "right_start": right_start,
        "right_end": right_end,
        "mode": mode,
        "max_diffs": max_diffs,
    }
    params = _with_prefixed_target_params(params, "left_", left_project_dir, left_project_name, left_folder_path, left_program_name)
    params = _with_prefixed_target_params(params, "right_", right_project_dir, right_project_name, right_folder_path, right_program_name)
    return "\n".join(safe_get("compare_regions", params))

@mcp.tool()
def compare_strings(filter: str = "", max_results: int = 200, left_project_dir: str = "", left_project_name: str = "", left_folder_path: str = "", left_program_name: str = "", right_project_dir: str = "", right_project_name: str = "", right_folder_path: str = "", right_program_name: str = "") -> str:
    """
    Compare defined strings across two programs.
    """
    params = {
        "filter": filter,
        "max_results": max_results,
    }
    params = _with_prefixed_target_params(params, "left_", left_project_dir, left_project_name, left_folder_path, left_program_name)
    params = _with_prefixed_target_params(params, "right_", right_project_dir, right_project_name, right_folder_path, right_program_name)
    return "\n".join(safe_get("compare_strings", params))

@mcp.tool()
def compare_functions(left_function: str, right_function: str, mode: str = "signature", limit: int = 200, left_project_dir: str = "", left_project_name: str = "", left_folder_path: str = "", left_program_name: str = "", right_project_dir: str = "", right_project_name: str = "", right_folder_path: str = "", right_program_name: str = "") -> str:
    """
    Compare two functions across programs using signature, disassembly, decompile, or xrefs.
    """
    params = {
        "left_function": left_function,
        "right_function": right_function,
        "mode": mode,
        "limit": limit,
    }
    params = _with_prefixed_target_params(params, "left_", left_project_dir, left_project_name, left_folder_path, left_program_name)
    params = _with_prefixed_target_params(params, "right_", right_project_dir, right_project_name, right_folder_path, right_program_name)
    return "\n".join(safe_get("compare_functions", params))

@mcp.tool()
def port_symbols(mappings: list[dict[str, str]], apply: str = "both", provenance_comment_template: str = "", dry_run: bool = False, source_project_dir: str = "", source_project_name: str = "", source_folder_path: str = "", source_program_name: str = "", target_project_dir: str = "", target_project_name: str = "", target_folder_path: str = "", target_program_name: str = "") -> str:
    """
    Port names and comments from one program to another.

    Input format: [{"source_address": "...", "target_address": "..."}, ...]
    """
    lines, error = _build_batch_lines(mappings, "source_address", "target_address", "source_address", "target_address")
    if error:
        return error

    params = {
        "mappings": "\n".join(lines),
        "apply": apply,
        "provenance_comment_template": provenance_comment_template,
        "dry_run": str(dry_run).lower(),
    }
    params = _with_prefixed_target_params(params, "source_", source_project_dir, source_project_name, source_folder_path, source_program_name)
    params = _with_prefixed_target_params(params, "target_", target_project_dir, target_project_name, target_folder_path, target_program_name)
    return safe_post("port_symbols", params)

@mcp.tool()
def create_namespace(name: str, parent_path: str = "", kind: str = "namespace", project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> str:
    """
    Create a namespace or class container.
    """
    return safe_post("create_namespace", _with_target_params({
        "name": name,
        "parent_path": parent_path,
        "kind": kind,
    }, project_dir, project_name, folder_path, program_name))

@mcp.tool()
def list_namespace_members(path: str, include_child_namespaces: bool = False, include_functions: bool = True, include_data: bool = True, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> str:
    """
    List members of a namespace or class container.
    """
    return "\n".join(safe_get("list_namespace_members", _with_target_params({
        "path": path,
        "include_child_namespaces": str(include_child_namespaces).lower(),
        "include_functions": str(include_functions).lower(),
        "include_data": str(include_data).lower(),
    }, project_dir, project_name, folder_path, program_name)))

@mcp.tool()
def move_symbol_to_namespace(symbol_address: str = "", symbol_name: str = "", namespace_path: str = "", new_name: str = "", conflict_policy: str = "fail", dry_run: bool = False, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> str:
    """
    Move a function or data symbol under a namespace or class container.
    """
    return safe_post("move_symbol_to_namespace", _with_target_params({
        "symbol_address": symbol_address,
        "symbol_name": symbol_name,
        "namespace_path": namespace_path,
        "new_name": new_name,
        "conflict_policy": conflict_policy,
        "dry_run": str(dry_run).lower(),
    }, project_dir, project_name, folder_path, program_name))

@mcp.tool()
def set_function_class(function_address: str, class_path: str, method_name: str = "", this_param_name: str = "this", calling_convention: str = "", dry_run: bool = False, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> str:
    """
    Move a function under a class namespace and optionally apply method metadata.
    """
    return safe_post("set_function_class", _with_target_params({
        "function_address": function_address,
        "class_path": class_path,
        "method_name": method_name,
        "this_param_name": this_param_name,
        "calling_convention": calling_convention,
        "dry_run": str(dry_run).lower(),
    }, project_dir, project_name, folder_path, program_name))

def _build_struct_field_lines(fields: list[dict[str, str]]) -> tuple[list[str], str | None]:
    if not isinstance(fields, list):
        return [], "Error: fields must be a list"

    lines: list[str] = []
    for index, field in enumerate(fields):
        if not isinstance(field, dict):
            return [], f"Error: invalid field at index {index}; expected an object"
        offset = field.get("offset")
        name = str(field.get("name", "")).strip()
        datatype = str(field.get("datatype", "")).strip()
        comment = str(field.get("comment", "")).strip()
        confidence = str(field.get("confidence", "")).strip()
        if offset is None:
            return [], f"Error: offset is required for field at index {index}"
        if not name:
            return [], f"Error: name is required for field at index {index}"
        if not datatype:
            return [], f"Error: datatype is required for field at index {index}"
        lines.append(f"{offset}\t{name}\t{datatype}\t{comment}\t{confidence}")
    return lines, None

def _build_vtable_slot_lines(slots: list[dict[str, str]]) -> tuple[list[str], str | None]:
    if not isinstance(slots, list):
        return [], "Error: slots must be a list"

    lines: list[str] = []
    for index, slot in enumerate(slots):
        if not isinstance(slot, dict):
            return [], f"Error: invalid slot at index {index}; expected an object"
        offset = slot.get("offset")
        name = str(slot.get("name", "")).strip()
        function_address = str(slot.get("function_address", "")).strip()
        prototype = str(slot.get("prototype", "")).strip()
        comment = str(slot.get("comment", "")).strip()
        if offset is None:
            return [], f"Error: offset is required for slot at index {index}"
        if not name:
            return [], f"Error: name is required for slot at index {index}"
        lines.append(f"{offset}\t{name}\t{function_address}\t{prototype}\t{comment}")
    return lines, None

def _build_class_method_lines(methods: list[dict[str, str]]) -> tuple[list[str], str | None]:
    if not isinstance(methods, list):
        return [], "Error: methods must be a list"

    lines: list[str] = []
    for index, method in enumerate(methods):
        if not isinstance(method, dict):
            return [], f"Error: invalid method at index {index}; expected an object"
        function_address = str(method.get("function_address", "")).strip()
        method_name = str(method.get("method_name", "")).strip()
        slot_offset = "" if method.get("slot_offset") is None else str(method.get("slot_offset"))
        is_virtual = str(bool(method.get("is_virtual", False))).lower()
        this_type = str(method.get("this_type", "")).strip()
        comment = str(method.get("comment", "")).strip()
        this_storage = str(method.get("this_storage", "")).strip()
        calling_convention = str(method.get("calling_convention", "")).strip()
        if not function_address:
            return [], f"Error: function_address is required for method at index {index}"
        if not method_name:
            return [], f"Error: method_name is required for method at index {index}"
        lines.append(f"{function_address}\t{method_name}\t{slot_offset}\t{is_virtual}\t{this_type}\t{comment}\t{this_storage}\t{calling_convention}")
    return lines, None

@mcp.tool()
def create_or_update_struct(name: str, fields: list[dict[str, str]], category_path: str = "", size: int = 0, packing: int = 0, dry_run: bool = False, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> str:
    """
    Create or update a structure datatype.
    """
    lines, error = _build_struct_field_lines(fields)
    if error:
        return error
    return safe_post("create_or_update_struct", _with_target_params({
        "name": name,
        "category_path": category_path,
        "size": size,
        "packing": packing,
        "fields": "\n".join(lines),
        "dry_run": str(dry_run).lower(),
    }, project_dir, project_name, folder_path, program_name))

@mcp.tool()
def create_or_update_vtable(name: str, slots: list[dict[str, str]], category_path: str = "", dry_run: bool = False, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> str:
    """
    Create or update a vtable datatype as a structure of function pointers.
    """
    lines, error = _build_vtable_slot_lines(slots)
    if error:
        return error
    return safe_post("create_or_update_vtable", _with_target_params({
        "name": name,
        "category_path": category_path,
        "slots": "\n".join(lines),
        "dry_run": str(dry_run).lower(),
    }, project_dir, project_name, folder_path, program_name))

@mcp.tool()
def set_function_this_type(function_address: str, this_type: str, this_param_name: str = "this", this_storage: str = "", calling_convention: str = "", dry_run: bool = False, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> str:
    """
    Apply or update this-pointer typing on a function.
    """
    return safe_post("set_function_this_type", _with_target_params({
        "function_address": function_address,
        "this_type": this_type,
        "this_param_name": this_param_name,
        "this_storage": this_storage,
        "calling_convention": calling_convention,
        "dry_run": str(dry_run).lower(),
    }, project_dir, project_name, folder_path, program_name))

@mcp.tool()
def analyze_vtable(address: str, slot_count: int = 0, stop_on_invalid_pointer: bool = True, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> str:
    """
    Inspect a suspected vtable region and emit slot candidates.
    """
    return "\n".join(safe_get("analyze_vtable", _with_target_params({
        "address": address,
        "slot_count": slot_count,
        "stop_on_invalid_pointer": str(stop_on_invalid_pointer).lower(),
    }, project_dir, project_name, folder_path, program_name)))

@mcp.tool()
def apply_class_layout(class_path: str, instance_struct: str, methods: list[dict[str, str]], vtable_struct: str = "", vtable_address: str = "", dry_run: bool = False, project_dir: str = "", project_name: str = "", folder_path: str = "", program_name: str = "") -> str:
    """
    Bind a class namespace, instance struct, optional vtable struct, and a set of methods.
    """
    lines, error = _build_class_method_lines(methods)
    if error:
        return error
    return safe_post("apply_class_layout", _with_target_params({
        "class_path": class_path,
        "instance_struct": instance_struct,
        "vtable_struct": vtable_struct,
        "vtable_address": vtable_address,
        "methods": "\n".join(lines),
        "dry_run": str(dry_run).lower(),
    }, project_dir, project_name, folder_path, program_name))

def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    
    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()


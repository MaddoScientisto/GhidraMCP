# GhidraMCP Tool Reference

This document summarizes the MCP tools exposed by GhidraMCP and what each one is for. The server is split into two layers:

- The Python MCP bridge in `bridge_mcp_ghidra.py`, which exposes MCP tools to clients.
- The embedded Ghidra HTTP plugin in `src/main/java/com/lauriewired/GhidraMCPPlugin.java`, which does the actual work inside Ghidra.

Most bridge tools are thin wrappers around matching HTTP endpoints. Some newer tools add a more workflow-oriented API on top of the older read/search/rename calls.

## Quick Orientation

The tool set falls into five rough groups:

- Program inventory: list methods, classes, segments, imports, exports, namespaces, data, and strings.
- Navigation and inspection: get current selection, resolve a function by address, decompile or disassemble by address, read memory, and inspect nearby instructions.
- Xref and usage discovery: find references to addresses or functions and inspect data uses.
- Editing: rename symbols, set comments, change prototypes and local variable types, create or delete functions, and batch-edit multiple items.
- Analysis and repair: reanalyze regions, patch bytes, inspect function boundaries, and run controlled read-only scripts.

## Legacy Inventory Tools

These are the original read-oriented tools and the basic rename helpers.

| MCP tool | What it does | Key arguments | Notes |
| --- | --- | --- | --- |
| `list_methods` | Lists all function names in the current program. | `offset`, `limit` | Bridge endpoint: `/methods`. |
| `list_classes` | Lists non-global namespace/class names. | `offset`, `limit` | Useful for understanding type and namespace layout. |
| `decompile_function` | Decompiles a function by name and returns C-like output. | `name` | Legacy name-based decompile entry point. |
| `rename_function` | Renames a function by its current name. | `old_name`, `new_name` | Older API; address-based rename is more reliable. |
| `rename_data` | Renames or creates the primary symbol at a specific address. | `address`, `new_name` | Returns the resolved symbol details so callers can verify the rename directly. |
| `list_segments` | Lists memory blocks / segments. | `offset`, `limit` | Helpful for mapping the loaded image. |
| `list_imports` | Lists imported symbols. | `offset`, `limit` | Shows external symbols and their addresses. |
| `list_exports` | Lists exported symbols and entry points. | `offset`, `limit` | Useful for quickly finding top-level entry points. |
| `list_namespaces` | Lists non-global namespaces. | `offset`, `limit` | Useful for class/module-style organization. |
| `list_data_items` | Lists defined data labels and values. | `offset`, `limit` | Good for spotting tables, flags, and constants. |
| `search_functions_by_name` | Searches for functions whose names contain a substring. | `query`, `offset`, `limit` | Returns address-qualified matches. |
| `rename_variable` | Renames a local variable inside a function. | `function_name`, `old_name`, `new_name` | Works through the decompiler context. |

## Navigation And Inspection

These tools make it easier to move from a coarse inventory to a specific function or address range.

| MCP tool | What it does | Key arguments | Notes |
| --- | --- | --- | --- |
| `get_function_by_address` | Resolves the function containing or associated with an address. | `address` | Useful when you already have an address rather than a name. |
| `get_current_address` | Returns the current cursor address in Ghidra. | none | Depends on the active UI selection. |
| `get_current_function` | Returns the function currently selected in Ghidra. | none | Depends on the active UI selection. |
| `list_functions` | Lists all functions in the database. | none | More direct than the name-filtered search helper. |
| `decompile_function_by_address` | Decompiles a function at a given address. | `address` | Prefer this over name-based decompile when the address is known. |
| `disassemble_function` | Returns assembly for a function. | `address` | Output is address + instruction + comment. |
| `get_function_containing` | Finds the function that contains an arbitrary address. | `address` | Good for labels, xrefs, or instruction addresses. |
| `read_region` | Reads raw bytes from memory for an address range. | `start`, `end` | Useful before patching or decoding data. |
| `disassemble_region` | Disassembles an arbitrary address range. | `start`, `end` | Helps inspect code in ranges that are not yet functions. |
| `get_instruction_window` | Returns nearby instructions around an address. | `address`, `before_count`, `after_count` | Very useful for local context around a target. |
| `get_symbol_at` | Returns the current primary symbol state at an address. | `address` | Useful for verifying data-label changes without relying on decompiler refresh. |
| `search_instructions` | Searches instruction text, operands, or address tokens. | `query`, `mode`, `limit` | Good for finding patterns across code. |

## Xref And Usage Tools

These are the tools that help connect code, data, and call sites.

| MCP tool | What it does | Key arguments | Notes |
| --- | --- | --- | --- |
| `get_data_uses` | Finds uses of a data address from references and optional instruction scans. | `address`, `include_operand_scans`, `limit` | Strong general-purpose data xref helper. |
| `get_xrefs_to` | Lists references to an address. | `address`, `offset`, `limit` | Falls back to the older `xrefs_to` route if needed. |
| `get_xrefs_from` | Lists references originating from an address. | `address`, `offset`, `limit` | Falls back to the older `xrefs_from` route if needed. |
| `get_function_xrefs` | Lists xrefs to a function by name. | `name`, `offset`, `limit` | Useful for call-site discovery. |
| `list_strings` | Lists defined strings and their addresses. | `offset`, `limit`, `filter` | Filter is optional and matches string content. |

## Edit And Refactor Tools

These are the higher-value workflow tools for controlled edits, especially the newer batch operations.

| MCP tool | What it does | Key arguments | Notes |
| --- | --- | --- | --- |
| `set_comments` | Sets disassembly comments in batch. | `batch` | Batch items use `address` and `comment`. |
| `set_decompiler_comments` | Sets decompiler comments in batch. | `batch` | Batch items use `address` and `comment`. |
| `rename_functions_by_address` | Renames multiple functions in one call. | `batch` | Batch items use `function_address` and `new_name`. This is the preferred rename path for address-based work. |
| `apply_program_edit_plan` | Executes a line-oriented edit plan. | `plan`, `dry_run` | Supports function creation, deletion, address-based renames, and comment edits. |
| `set_decompiler_comment` | Sets a single decompiler comment. | `address`, `comment` | Handy for one-off annotations. |
| `set_disassembly_comment` | Sets a single disassembly comment. | `address`, `comment` | Handy for one-off annotations. |
| `rename_function_by_address` | Renames one function by its address. | `function_address`, `new_name` | Preferred over name-based renames because it is stable and unambiguous. |
| `set_function_prototype` | Updates a function signature / prototype. | `function_address`, `prototype` | Useful after identifying parameter or return types. |
| `set_local_variable_type` | Updates the type of a local variable. | `function_address`, `variable_name`, `new_type` | Useful for cleaning up decompilation output. |
| `create_function_by_address` | Creates a new function with explicit body bounds. | `entry`, `name`, `body_start`, `body_end`, `comment` | Useful when Ghidra missed a function boundary. |
| `delete_function_by_address` | Deletes a function by entry address. | `entry` | Use carefully; intended for repairs and boundary cleanup. |

## Analysis And Repair Tools

These newer tools help recover from bad boundaries, patch code, and re-run analysis in a targeted way.

| MCP tool | What it does | Key arguments | Notes |
| --- | --- | --- | --- |
| `reanalyze_region` | Triggers analysis for an address range. | `start`, `end` | Use after edits that affect nearby code. |
| `patch_bytes_and_reanalyze` | Patches raw bytes and re-runs analysis. | `start`, `bytes`, `comment` | Byte strings accept forms like `90 90 90` or `0x90 0x90 0x90`. |
| `analyze_function_boundaries` | Inspects a range for overlaps and likely function starts. | `start`, `end` | Good for boundary repair and missed entry points. |
| `get_project_access_info` | Reports current project/program access state. | none | Helps decide whether the program is read-only or writable. |
| `open_current_program_readonly` | Opens the current program in read-only mode. | `version`, `make_current` | Useful when you want a safe inspection handle. |
| `run_readonly_script` | Runs a constrained read-only Ghidra script. | `script_path`, `script_text` | Intended for safe scripted inspection. |

## Recent Workflow Additions

These are the tools that materially improve reverse-engineering workflow compared with the original inventory/rename surface.

| MCP tool | Why it matters |
| --- | --- |
| `get_xrefs_to` / `get_xrefs_from` | Makes xref lookups address-centric and easier to chain from disassembly. |
| `get_function_xrefs` | Lets you jump straight from a function name to its callers or references. |
| `list_strings` | Gives a fast string index for locating dialog text, format strings, and constants. |
| `set_comments` / `set_decompiler_comments` | Enables batch annotation instead of many one-off edits. |
| `rename_functions_by_address` | Supports bulk renaming from verified address mappings. |
| `apply_program_edit_plan` | Lets you execute a compact repair script rather than many separate MCP calls. |
| `reanalyze_region` | Re-runs analysis only where needed after edits. |
| `patch_bytes_and_reanalyze` | Combines byte patching and repair in one step. |
| `analyze_function_boundaries` | Helps detect bad function edges before creating or deleting functions. |
| `get_project_access_info` | Tells clients whether the current program state supports edits. |
| `open_current_program_readonly` | Gives clients a safe read-only mode for inspection-only workflows. |
| `run_readonly_script` | Enables controlled script-based inspection without full write access. |
| `get_symbol_at` | Gives callers a fast readback path after `rename_data` or manual label work. |
| `set_function_prototype` / `set_local_variable_type` | Improves decompiler quality after type recovery. |
| `rename_function_by_address` | Avoids ambiguity and is the preferred rename path for verified mappings. |

## Compatibility Notes

- `get_xrefs_to` and `get_xrefs_from` first try the newer get-prefixed endpoints and then fall back to the older `xrefs_to` / `xrefs_from` routes if needed.
- `rename_function_by_address` is the preferred address-based rename path. It is safer than the older name-based `rename_function` when you already know the function entry address.
- `rename_data` now reports the resolved symbol metadata, and `get_symbol_at` can be used to verify address labels directly when decompiler output lags behind symbol-table updates.
- Batch-oriented tools accept simple list-like payloads so they can be called repeatedly without constructing many separate requests.

## Practical Usage Order

For most reverse-engineering work, a good sequence is:

1. Use `list_functions`, `search_functions_by_name`, `list_strings`, or the xref tools to narrow the target.
2. Use `get_function_by_address`, `get_function_containing`, `decompile_function_by_address`, or `disassemble_function` to inspect it.
3. Add `set_decompiler_comment`, `set_disassembly_comment`, or `rename_function_by_address` once the evidence is solid.
4. Use `reanalyze_region`, `patch_bytes_and_reanalyze`, or `analyze_function_boundaries` only when the underlying listing needs repair.

from __future__ import annotations

import json
from typing import Any

# WebMCP (Web Model Context Protocol) discovery and invocation helpers.
#
# Web pages participating in Chrome's WebMCP Origin Trial (such as Shopify Liquid
# storefronts and stripe.press) publish structured client-side tools via
# ``document.modelContext`` (``getTools()`` / ``executeTool()``).
#
# Tool metadata and outputs are entirely page-authored and untrusted. Every field
# surfaced to callers is explicitly projected (never returning raw RegisteredTool
# handles, which carry a non-cloneable ``window`` property), filtered to the
# main-frame origin, and bounded in count and byte size so a hostile page cannot
# bloat snapshots or API responses.

WEBMCP_MAX_TOOLS = 32
WEBMCP_MAX_NAME_CHARS = 128
WEBMCP_MAX_TITLE_CHARS = 200
WEBMCP_MAX_DESCRIPTION_CHARS = 600
WEBMCP_MAX_SCHEMA_BYTES = 4096
WEBMCP_MAX_TOTAL_TOOLS_BYTES = 32 * 1024
WEBMCP_MAX_ARGS_BYTES = 32 * 1024
WEBMCP_MAX_RESULT_BYTES = 64 * 1024

WEBMCP_LIST_TIMEOUT_SECONDS = 2.0
WEBMCP_CALL_DEFAULT_TIMEOUT_SECONDS = 15.0
WEBMCP_CALL_MAX_TIMEOUT_SECONDS = 30.0

_ANNOTATION_KEYS = ("readOnlyHint", "consequentialHint", "untrustedContentHint")


def is_webmcp_eligible_origin(origin: str | None) -> bool:
    """Return True for secure-context origins where ``document.modelContext`` can exist.

    WebMCP is a ``[SecureContext]`` browser API, so ``about:blank``, ``data:``, and
    non-loopback plaintext ``http://`` documents can never expose it. Skipping those
    avoids an extra ``page.evaluate`` round-trip during ``snapshot``.
    """
    if not origin:
        return False
    if origin.startswith("https://"):
        return True
    return origin.startswith(("http://localhost", "http://127.0.0.1", "http://[::1]"))


# ``() => list[dict]``: reads same-origin WebMCP tools from ``document.modelContext``.
# Feature-detected so browsers/pages without WebMCP return ``[]`` cleanly.
# Handles both Chromium 151 (where ``inputSchema`` is a JSON string) and Chrome 155+
# (where ``inputSchema`` is already a parsed object).
WEBMCP_LIST_JS = r"""
async () => {
  const mc = document.modelContext;
  if (!mc || typeof mc.getTools !== 'function') return [];
  const raw = await mc.getTools();
  if (!Array.isArray(raw)) return [];
  const pageOrigin = location.origin;
  const out = [];
  for (const tool of raw) {
    if (!tool || typeof tool.name !== 'string' || !tool.name) continue;
    if (typeof tool.origin === 'string' && tool.origin && tool.origin !== pageOrigin) continue;
    let schema = null;
    if (typeof tool.inputSchema === 'string') {
      try {
        schema = JSON.parse(tool.inputSchema);
      } catch {
        schema = null;
      }
    } else if (tool.inputSchema && typeof tool.inputSchema === 'object' && !Array.isArray(tool.inputSchema)) {
      schema = tool.inputSchema;
    }
    const annotations = {};
    if (tool.annotations && typeof tool.annotations === 'object') {
      for (const key of ['readOnlyHint', 'consequentialHint', 'untrustedContentHint']) {
        if (typeof tool.annotations[key] === 'boolean') {
          annotations[key] = tool.annotations[key];
        }
      }
    }
    out.push({
      name: tool.name,
      title: typeof tool.title === 'string' ? tool.title : '',
      description: typeof tool.description === 'string' ? tool.description : '',
      input_schema: schema,
      annotations,
      origin: typeof tool.origin === 'string' && tool.origin ? tool.origin : pageOrigin,
    });
  }
  return out;
}
"""

# ``({ toolName, arguments }) => { ok, result?, reason?, detail?, url }``:
# looks up a same-origin tool by name and invokes ``document.modelContext.executeTool``.
# Feature-detects Chromium 151's string-serialized ``executeTool(tool, jsonString)``
# contract versus Chrome 155+'s object contract via ``typeof tool.inputSchema === 'string'``.
WEBMCP_CALL_JS = r"""
async ({ toolName, arguments: argsObj }) => {
  const mc = document.modelContext;
  if (!mc || typeof mc.getTools !== 'function' || typeof mc.executeTool !== 'function') {
    return {
      ok: false,
      reason: 'unsupported',
      detail: 'document.modelContext is not available on this page',
      url: location.href,
    };
  }
  const raw = await mc.getTools();
  if (!Array.isArray(raw)) {
    return {
      ok: false,
      reason: 'tool_not_found',
      detail: 'no WebMCP tools are registered on this page',
      url: location.href,
    };
  }
  const pageOrigin = location.origin;
  const tool = raw.find(
    (t) => t && t.name === toolName && (!t.origin || t.origin === pageOrigin)
  );
  if (!tool) {
    return {
      ok: false,
      reason: 'tool_not_found',
      detail: 'tool is not registered on the current document',
      url: location.href,
    };
  }
  const safeArgs = argsObj && typeof argsObj === 'object' && !Array.isArray(argsObj) ? argsObj : {};
  const callArg = typeof tool.inputSchema === 'string' ? JSON.stringify(safeArgs) : safeArgs;
  try {
    const res = await mc.executeTool(tool, callArg);
    let serialized = null;
    if (res === undefined) {
      serialized = null;
    } else if (typeof res === 'string' || typeof res === 'number' || typeof res === 'boolean' || res === null) {
      serialized = res;
    } else {
      try {
        serialized = JSON.parse(JSON.stringify(res));
      } catch {
        serialized = String(res);
      }
    }
    return { ok: true, result: serialized, url: location.href };
  } catch (err) {
    return {
      ok: false,
      reason: 'tool_error',
      detail: err && typeof err.message === 'string' ? err.message : String(err),
      url: location.href,
    };
  }
}
"""


def _truncate_str(value: str, max_chars: int) -> str:
    if len(value) <= max_chars:
        return value
    return value[: max_chars - 1] + "…"


def _truncate_utf8(value: str, max_bytes: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value
    return encoded[:max_bytes].decode("utf-8", errors="ignore")


def _json_byte_len(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def sanitize_webmcp_tools(raw_tools: Any, page_origin: str | None) -> list[dict[str, Any]]:
    """Normalize, filter, and bound page-reported WebMCP tool descriptors.

    Enforces same-origin filtering (when ``page_origin`` is known), deduplication
    by name, per-field character limits, per-schema byte limits, tool count cap,
    and a cumulative JSON byte cap across the returned list.
    """
    if not isinstance(raw_tools, list):
        return []

    sanitized: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    total_bytes = 2  # "[]"

    for item in raw_tools:
        if len(sanitized) >= WEBMCP_MAX_TOOLS:
            break
        if not isinstance(item, dict):
            continue

        raw_name = item.get("name")
        if not isinstance(raw_name, str):
            continue
        name = raw_name.strip()
        if not name or len(name) > WEBMCP_MAX_NAME_CHARS or name in seen_names:
            continue

        raw_origin = item.get("origin")
        tool_origin = raw_origin.strip() if isinstance(raw_origin, str) and raw_origin.strip() else page_origin
        if page_origin and tool_origin and tool_origin != page_origin:
            continue

        raw_title = item.get("title")
        title = _truncate_str(raw_title.strip(), WEBMCP_MAX_TITLE_CHARS) if isinstance(raw_title, str) else ""

        raw_desc = item.get("description")
        description = _truncate_str(raw_desc.strip(), WEBMCP_MAX_DESCRIPTION_CHARS) if isinstance(raw_desc, str) else ""

        raw_schema = item.get("input_schema") if "input_schema" in item else item.get("inputSchema")
        if isinstance(raw_schema, str):
            try:
                raw_schema = json.loads(raw_schema)
            except (TypeError, ValueError):
                raw_schema = None
        input_schema: dict[str, Any] | None = None
        if isinstance(raw_schema, dict):
            if _json_byte_len(raw_schema) <= WEBMCP_MAX_SCHEMA_BYTES:
                input_schema = raw_schema
            else:
                input_schema = {"_truncated": True}

        raw_annotations = item.get("annotations")
        annotations: dict[str, bool] = {}
        if isinstance(raw_annotations, dict):
            for key in _ANNOTATION_KEYS:
                val = raw_annotations.get(key)
                if isinstance(val, bool):
                    annotations[key] = val

        entry: dict[str, Any] = {
            "name": name,
            "description": description,
        }
        if title:
            entry["title"] = title
        if input_schema is not None:
            entry["input_schema"] = input_schema
        if annotations:
            entry["annotations"] = annotations
        if tool_origin:
            entry["origin"] = tool_origin

        entry_bytes = _json_byte_len(entry) + (1 if sanitized else 0)
        if total_bytes + entry_bytes > WEBMCP_MAX_TOTAL_TOOLS_BYTES:
            # Drop optional schema to see if the compact descriptor still fits.
            if "input_schema" in entry:
                compact = dict(entry)
                compact["input_schema"] = {"_truncated": True}
                compact_bytes = _json_byte_len(compact) + (1 if sanitized else 0)
                if total_bytes + compact_bytes <= WEBMCP_MAX_TOTAL_TOOLS_BYTES:
                    sanitized.append(compact)
                    seen_names.add(name)
                    total_bytes += compact_bytes
                    continue
            break

        sanitized.append(entry)
        seen_names.add(name)
        total_bytes += entry_bytes

    return sanitized


def bound_webmcp_result(raw: Any, *, max_bytes: int = WEBMCP_MAX_RESULT_BYTES) -> tuple[Any, bool]:
    """Normalize and byte-bound a WebMCP tool return value.

    Chrome's ``executeTool`` commonly returns a JSON-encoded string containing an
    MCP-shaped object (e.g. ``{"content": [...], "structuredContent": ...}``).
    When ``raw`` is a JSON string encoding an object or array, parse it once so
    callers receive structured JSON rather than double-encoded strings. If the
    serialized value exceeds ``max_bytes``, return a UTF-8-truncated string and
    ``truncated=True``.
    """
    value: Any = raw
    if isinstance(raw, str):
        stripped = raw.strip()
        if stripped.startswith(("{", "[")) and stripped.endswith(("}", "]")):
            try:
                parsed = json.loads(stripped)
            except ValueError:
                parsed = None
            if isinstance(parsed, (dict, list)):
                value = parsed

    if isinstance(value, str):
        if len(value.encode("utf-8")) <= max_bytes:
            return value, False
        return _truncate_utf8(value, max_bytes), True

    if value is None or isinstance(value, (bool, int, float)):
        return value, False

    serialized = json.dumps(value, ensure_ascii=False)
    if len(serialized.encode("utf-8")) <= max_bytes:
        return value, False
    return _truncate_utf8(serialized, max_bytes), True

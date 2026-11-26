"""Real-browser tests for WebMCP discovery and invocation (PlaywrightBrowserWorker + Chromium).

Tests both:
1. Real native Blink ``document.modelContext.registerTool(...)`` / ``getTools()`` / ``executeTool()``
   in Chromium (launched with ``--enable-features=WebMCPTesting`` for local test origins without
   Origin-Trial tokens), proving end-to-end compatibility with Patchright's isolated-world
   ``page.evaluate`` against a real page's main-world tool registrations.
2. Both Chromium 151's string-encoded ``inputSchema`` / JSON-string ``executeTool`` contract and
   Chrome 155+'s object ``inputSchema`` / object ``executeTool`` contract in real V8.

Skips cleanly when real Chromium is unavailable on the host.
"""

from __future__ import annotations

from typing import Any

import pytest
from browser_handoff_service.models import AgentCommandRequest
from browser_handoff_service.runtime import PlaywrightBrowserWorker, RuntimeUnavailable

SHOP = "https://shop.example.com"
EVIL = "https://evil.example.net"


async def _start_worker(*, confine_origins: list[str] | None = None, enable_webmcp_flag: bool = False) -> Any:
    """Start a real PlaywrightBrowserWorker, optionally enabling Blink's WebMCPTesting flag."""
    worker = PlaywrightBrowserWorker("worker_webmcp_browser", confine_origins=confine_origins)
    if not enable_webmcp_flag:
        try:
            await worker.start()
        except RuntimeUnavailable as exc:
            pytest.skip(f"real Chromium unavailable on this host: {exc}")
        return worker

    # Launch with --enable-features=WebMCPTesting so synthetic https://shop.example.com pages
    # get native Blink document.modelContext without needing a signed Origin-Trial token.
    try:
        from patchright.async_api import async_playwright

        worker._playwright = await async_playwright().start()
        worker._browser = await worker._playwright.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--enable-features=WebMCPTesting,WebMCP",
            ],
        )
        context_kwargs: dict[str, Any] = {"viewport": {"width": worker.width, "height": worker.height}}
        if worker.confine_origins:
            context_kwargs["service_workers"] = "block"
        worker._context = await worker._browser.new_context(**context_kwargs)
        worker._page = await worker._context.new_page()
        if worker.confine_origins:
            await worker._install_confinement(worker._context)
    except Exception as exc:
        await worker.close()
        pytest.skip(f"real Chromium with WebMCPTesting unavailable on this host: {exc}")
    return worker


async def _mount_pages(
    worker: PlaywrightBrowserWorker, pages: dict[str, str], *, fallback_unknown: bool = False
) -> None:
    assert worker._context is not None

    async def handler(route: Any) -> None:
        html = pages.get(route.request.url)
        if html is not None:
            await route.fulfill(status=200, content_type="text/html; charset=utf-8", body=html)
            return
        if fallback_unknown:
            await route.fallback()
        else:
            await route.abort()

    await worker._context.route("**/*", handler)


@pytest.mark.asyncio
async def test_real_browser_native_blink_webmcp_register_discover_call_and_navigate():
    """End-to-end test against Blink's native document.modelContext.registerTool."""
    worker = await _start_worker(enable_webmcp_flag=True)
    try:
        home_html = f"""<!doctype html>
        <html><head><title>Native WebMCP Shop</title></head><body>
          <h1>Demo Shop</h1>
          <script>
            const cart = [];
            if (document.modelContext && typeof document.modelContext.registerTool === 'function') {{
              document.modelContext.registerTool({{
                name: 'add_to_cart',
                title: 'Add to cart',
                description: 'Add a SKU to the live tab cart',
                inputSchema: {{
                  type: 'object',
                  required: ['sku'],
                  properties: {{ sku: {{ type: 'string' }} }},
                }},
                annotations: {{ readOnlyHint: false }},
                async execute(args) {{
                  cart.push(args.sku);
                  return {{ content: [{{ type: 'text', text: 'Added ' + args.sku }}], cart }};
                }},
              }});
              document.modelContext.registerTool({{
                name: 'browse_collection',
                description: 'Navigate asynchronously after returning (Shopify pattern)',
                inputSchema: {{ type: 'object', properties: {{ slug: {{ type: 'string' }} }} }},
                async execute(args) {{
                  setTimeout(() => {{ location.href = '{SHOP}/collections/' + (args.slug || 'all'); }}, 40);
                  return {{ content: [{{ type: 'text', text: 'Navigating...' }}] }};
                }},
              }});
              document.modelContext.registerTool({{
                name: 'sync_checkout',
                description: 'Navigate immediately mid-call',
                inputSchema: {{ type: 'object', properties: {{}} }},
                async execute() {{
                  location.href = '{SHOP}/checkout';
                  await new Promise(() => {{}});
                }},
              }});
              document.modelContext.registerTool({{
                name: 'hang_tool',
                description: 'Never resolves',
                inputSchema: {{ type: 'object', properties: {{}} }},
                async execute() {{
                  await new Promise(() => {{}});
                }},
              }});
            }}
          </script>
        </body></html>
        """
        collection_html = (
            "<!doctype html><html><head><title>Mens Collection</title></head><body><h1>Mens</h1></body></html>"
        )
        checkout_html = "<!doctype html><html><head><title>Checkout</title></head><body><h1>Checkout</h1></body></html>"

        await _mount_pages(
            worker,
            {
                f"{SHOP}/": home_html,
                f"{SHOP}/collections/mens": collection_html,
                f"{SHOP}/checkout": checkout_html,
            },
        )

        await worker.command(AgentCommandRequest(type="navigate", args={"url": f"{SHOP}/"}))
        has_native = await worker._page.evaluate(
            "() => Boolean(document.modelContext && document.modelContext.getTools)"
        )
        if not has_native:
            pytest.skip("This Chromium build does not expose native document.modelContext under WebMCPTesting")

        snap = await worker.command(AgentCommandRequest(type="snapshot"))
        tools = snap.get("webmcp_tools")
        assert isinstance(tools, list)
        names = [t["name"] for t in tools]
        assert set(names) == {"add_to_cart", "browse_collection", "sync_checkout", "hang_tool"}
        add_tool = next(t for t in tools if t["name"] == "add_to_cart")
        assert add_tool["input_schema"]["required"] == ["sku"]

        # Invoke native tool (automatically adapts Chromium 151 string args vs Chrome 155+ object args!)
        res = await worker.webmcp_call("add_to_cart", {"sku": "BOOK-42"}, timeout_seconds=5.0)
        assert res["status"] == "ok", res
        assert res["navigated"] is False
        assert res["result"]["cart"] == ["BOOK-42"]

        # Unknown tool -> tool_not_found
        missing = await worker.webmcp_call("no_such_tool", {}, timeout_seconds=5.0)
        assert missing["status"] == "error"
        assert missing["reason"] == "tool_not_found"

        # Timeout on hanging handler
        to_res = await worker.webmcp_call("hang_tool", {}, timeout_seconds=1.0)
        assert to_res["status"] == "timeout"
        assert to_res["reason"] == "timeout"

        # Async post-return navigation (Shopify pattern)
        nav_res = await worker.webmcp_call("browse_collection", {"slug": "mens"}, timeout_seconds=5.0)
        assert nav_res["status"] == "ok", nav_res
        assert nav_res["navigated"] is True
        assert nav_res["url"] == f"{SHOP}/collections/mens"
        assert nav_res["title"] == "Mens Collection"

        # Sync navigation mid-call (execution context destroyed)
        await worker.command(AgentCommandRequest(type="navigate", args={"url": f"{SHOP}/"}))
        sync_nav = await worker.webmcp_call("sync_checkout", {}, timeout_seconds=5.0)
        assert sync_nav["status"] == "navigated", sync_nav
        assert sync_nav["navigated"] is True
        assert sync_nav["url"] == f"{SHOP}/checkout"
        assert sync_nav["title"] == "Checkout"
    finally:
        await worker.close()


@pytest.mark.asyncio
async def test_real_browser_webmcp_both_api_shapes_and_cross_origin_filter():
    """Verify both Chrome 155+ object contract and Chromium 151 string contract in real V8."""
    worker = await _start_worker(enable_webmcp_flag=False)
    try:
        plain_html = "<!doctype html><html><head><title>Compat</title></head><body><h1>Compat</h1></body></html>"
        await _mount_pages(worker, {f"{SHOP}/": plain_html})
        await worker.command(AgentCommandRequest(type="navigate", args={"url": f"{SHOP}/"}))
        assert worker._page is not None

        # Plain page with no WebMCP degrades cleanly
        snap_plain = await worker.command(AgentCommandRequest(type="snapshot"))
        assert "webmcp_tools" not in snap_plain
        unsupported = await worker.webmcp_call("anything", {}, timeout_seconds=5.0)
        assert unsupported["status"] == "error"
        assert unsupported["reason"] == "unsupported"

        # 1) Install Chrome 155+ shape (object inputSchema + object args + non-cloneable window prop + cross-origin spoof)
        await worker._page.evaluate(
            f"""() => {{
              const tools = [
                {{
                  name: 'search_catalog',
                  title: 'Search',
                  description: 'Search products',
                  inputSchema: {{ type: 'object', properties: {{ q: {{ type: 'string' }} }} }},
                  annotations: {{ readOnlyHint: true, consequentialHint: false }},
                  origin: location.origin,
                  window: window,
                }},
                {{
                  name: 'cross_origin_spoof',
                  description: 'Must be filtered out',
                  inputSchema: {{ type: 'object', properties: {{}} }},
                  origin: '{EVIL}',
                  window: window,
                }},
              ];
              Object.defineProperty(document, 'modelContext', {{
                configurable: true,
                value: {{
                  async getTools() {{ return tools; }},
                  async executeTool(tool, input) {{
                    if (typeof input !== 'object' || input === null || Array.isArray(input)) {{
                      throw new TypeError('invalid input object: value is not an object');
                    }}
                    return JSON.stringify({{ hits: [input.q] }});
                  }},
                }},
              }});
            }}"""
        )
        snap_155 = await worker.command(AgentCommandRequest(type="snapshot"))
        assert [t["name"] for t in snap_155["webmcp_tools"]] == ["search_catalog"]
        assert snap_155["webmcp_tools"][0]["annotations"] == {"readOnlyHint": True, "consequentialHint": False}
        res_155 = await worker.webmcp_call("search_catalog", {"q": "wool runner"}, timeout_seconds=5.0)
        assert res_155["status"] == "ok"
        assert res_155["result"] == {"hits": ["wool runner"]}
        spoof = await worker.webmcp_call("cross_origin_spoof", {}, timeout_seconds=5.0)
        assert spoof["status"] == "error"
        assert spoof["reason"] == "tool_not_found"

        # 2) Swap to Chromium 151 shape (JSON-string inputSchema + strictly requiring JSON-string args)
        await worker._page.evaluate(
            """() => {
              const tools = [
                {
                  name: 'list_books',
                  description: 'List books',
                  inputSchema: '{"type":"object","properties":{"limit":{"type":"integer"}}}',
                  annotations: { readOnlyHint: true },
                  origin: location.origin,
                },
              ];
              Object.defineProperty(document, 'modelContext', {
                configurable: true,
                value: {
                  async getTools() { return tools; },
                  async executeTool(tool, inputJson) {
                    if (typeof inputJson !== 'string') {
                      throw new Error('UnknownError: Failed to parse input arguments');
                    }
                    const parsed = JSON.parse(inputJson);
                    return JSON.stringify({ books: ['A', 'B'].slice(0, parsed.limit || 2) });
                  },
                },
              });
            }"""
        )
        snap_151 = await worker.command(AgentCommandRequest(type="snapshot"))
        assert snap_151["webmcp_tools"][0]["name"] == "list_books"
        assert snap_151["webmcp_tools"][0]["input_schema"] == {
            "type": "object",
            "properties": {"limit": {"type": "integer"}},
        }
        res_151 = await worker.webmcp_call("list_books", {"limit": 1}, timeout_seconds=5.0)
        assert res_151["status"] == "ok"
        assert res_151["result"] == {"books": ["A"]}

        # 3) Verify in-page discovery bounds, in-page output/error bounds, AbortSignal cancellation, and NaN/Infinity handling
        await worker._page.evaluate(
            """() => {
              window.__webmcpAborted = false;
              const hugeTools = [];
              for (let i = 0; i < 60; i++) {
                hugeTools.push({
                  name: 'tool_' + i,
                  title: 'T'.repeat(500),
                  description: 'D'.repeat(2000),
                  inputSchema: { type: 'object', properties: { p: { description: 'S'.repeat(6000) } } },
                  origin: location.origin,
                });
              }
              Object.defineProperty(document, 'modelContext', {
                configurable: true,
                value: {
                  async getTools() { return hugeTools; },
                  async executeTool(tool, input, options) {
                    if (tool.name === 'tool_0') return 'X'.repeat(200000);
                    if (tool.name === 'tool_1') return NaN;
                    if (tool.name === 'tool_2') return Infinity;
                    if (tool.name === 'tool_3') throw new Error('E'.repeat(5000));
                    if (tool.name === 'tool_4') {
                      return await new Promise((resolve, reject) => {
                        if (options && options.signal) {
                          options.signal.addEventListener('abort', () => {
                            window.__webmcpAborted = true;
                            reject(new Error('aborted'));
                          });
                        }
                      });
                    }
                    return { ok: true };
                  },
                },
              });
            }"""
        )
        # Raw WEBMCP_LIST_JS must already enforce bounds BEFORE Python sanitization
        from browser_handoff_service.webmcp import (
            WEBMCP_LIST_JS,
            WEBMCP_MAX_DESCRIPTION_CHARS,
            WEBMCP_MAX_DETAIL_CHARS,
            WEBMCP_MAX_RESULT_BYTES,
            WEBMCP_MAX_TITLE_CHARS,
            WEBMCP_MAX_TOOLS,
        )

        raw_from_page = await worker._page.evaluate(WEBMCP_LIST_JS)
        assert len(raw_from_page) == WEBMCP_MAX_TOOLS
        assert len(raw_from_page[0]["title"]) == WEBMCP_MAX_TITLE_CHARS
        assert len(raw_from_page[0]["description"]) == WEBMCP_MAX_DESCRIPTION_CHARS
        assert raw_from_page[0]["input_schema"] == {"_truncated": True}

        big_out = await worker.webmcp_call("tool_0", {}, timeout_seconds=5.0)
        assert big_out["status"] == "ok"
        assert big_out["truncated"] is True
        assert len(big_out["result"].encode("utf-8")) <= WEBMCP_MAX_RESULT_BYTES

        nan_out = await worker.webmcp_call("tool_1", {}, timeout_seconds=5.0)
        assert nan_out["status"] == "ok"
        assert nan_out["result"] is None

        inf_out = await worker.webmcp_call("tool_2", {}, timeout_seconds=5.0)
        assert inf_out["status"] == "ok"
        assert inf_out["result"] is None

        err_out = await worker.webmcp_call("tool_3", {}, timeout_seconds=5.0)
        assert err_out["status"] == "error"
        assert err_out["reason"] == "tool_error"
        assert len(err_out["detail"]) <= WEBMCP_MAX_DETAIL_CHARS

        abort_out = await worker.webmcp_call("tool_4", {}, timeout_seconds=0.3)
        assert abort_out["status"] == "timeout"
        assert abort_out["reason"] == "timeout"
        assert await worker._page.evaluate("() => window.__webmcpAborted") is True

        # 4) getTools() throwing an oversized error must be caught and bounded in-page
        await worker._page.evaluate(
            """() => {
              Object.defineProperty(document, 'modelContext', {
                configurable: true,
                value: {
                  async getTools() { throw new Error('G'.repeat(5000)); },
                  async executeTool() { return null; },
                },
              });
            }"""
        )
        assert await worker._page.evaluate(WEBMCP_LIST_JS) == []
        gt_err = await worker.webmcp_call("anything", {}, timeout_seconds=5.0)
        assert gt_err["status"] == "error"
        assert gt_err["reason"] == "tool_error"
        assert len(gt_err["detail"]) <= WEBMCP_MAX_DETAIL_CHARS
    finally:
        await worker.close()


@pytest.mark.asyncio
async def test_real_browser_webmcp_confined_off_scope_navigation_blocked():
    """Origin confinement must abort off-scope navigations triggered by a WebMCP tool."""
    worker = await _start_worker(confine_origins=[SHOP], enable_webmcp_flag=True)
    try:
        html = f"""<!doctype html><html><head><title>Confined</title></head><body>
        <script>
          if (document.modelContext && typeof document.modelContext.registerTool === 'function') {{
            document.modelContext.registerTool({{
              name: 'escape',
              description: 'Tries to navigate off-scope',
              inputSchema: {{ type: 'object', properties: {{}} }},
              async execute() {{
                setTimeout(() => {{ location.href = '{EVIL}/steal'; }}, 20);
                return 'redirecting';
              }},
            }});
          }}
        </script></body></html>"""
        await _mount_pages(worker, {f"{SHOP}/": html}, fallback_unknown=True)
        await worker.command(AgentCommandRequest(type="navigate", args={"url": f"{SHOP}/"}))
        has_native = await worker._page.evaluate(
            "() => Boolean(document.modelContext && document.modelContext.getTools)"
        )
        if not has_native:
            pytest.skip("This Chromium build does not expose native document.modelContext under WebMCPTesting")

        res = await worker.webmcp_call("escape", {}, timeout_seconds=5.0)
        assert res["status"] == "refused", res
        assert res["reason"] == "off_scope_blocked"
        assert res["target_origin"] == EVIL
    finally:
        await worker.close()

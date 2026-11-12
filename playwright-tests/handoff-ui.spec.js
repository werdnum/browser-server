const { test, expect } = require("@playwright/test");

const serviceHeaders = { authorization: `Bearer ${process.env.BROWSER_HANDOFF_SERVICE_TOKEN || "test-service-token"}` };

test("human can claim, extend, mark sensitive, and complete from the handoff UI", async ({ page, baseURL }) => {
  const api = async (path, body) => fetch(`${baseURL}${path}`, {
    method: "POST",
    headers: { ...serviceHeaders, "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  await page.route("**/v1/sessions/*/remote?**", async route => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ novnc_url: `${baseURL}/mock-novnc.html` })
    });
  });
  await page.route("**/mock-novnc.html", async route => {
    await route.fulfill({
      status: 200,
      contentType: "text/html",
      body: "<!doctype html><title>Mock noVNC</title>"
    });
  });
  const created = await api("/v1/sessions", { conversation_id: "conv_ui" });
  expect(created.ok).toBeTruthy();
  const session = await created.json();

  const handoff = await api(`/v1/sessions/${session.session_id}/handoff`, {
    reason: "payment",
    handoff_note: "Review and pay"
  });
  expect(handoff.ok).toBeTruthy();
  const handoffJson = await handoff.json();

  await page.goto(handoffJson.handoff_url);
  await expect(page.locator("#state")).toHaveText("handoff_requested");
  await page.getByRole("button", { name: "Claim" }).click();
  await expect(page.locator("#state")).toHaveText("human_active");
  await expect(page.locator("#viewport iframe")).toHaveAttribute("src", `${baseURL}/mock-novnc.html`);

  await page.getByRole("button", { name: "Extend" }).click();
  await expect(page.locator("#state")).toHaveText("human_active");
  await page.getByRole("button", { name: "Mark sensitive" }).click();
  await expect(page.locator("#state")).toHaveText("human_sensitive");
  await page.getByRole("button", { name: "Complete" }).click();
  await expect(page.locator("#state")).toHaveText("completed");

  // The session is completed (terminal), so the agent command is Gone (410)
  // rather than a 403 lease-ownership denial: there is no session left to own.
  const denied = await api(`/v1/sessions/${session.session_id}/agent-command`, { type: "snapshot" });
  expect(denied.status).toBe(410);
});

test("human can interact with CDP screencast canvas and address bar when noVNC is unavailable", async ({ page, baseURL }) => {
  const api = async (path, body) => fetch(`${baseURL}${path}`, {
    method: "POST",
    headers: { ...serviceHeaders, "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  const wsBase = baseURL.replace(/^http/i, "ws");
  const receivedMessages = [];
  // 1x1 valid JPEG base64
  const tinyJpeg = "/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////wgALCAABAAEBAREA/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPxA=";

  await page.route("**/v1/sessions/*/remote?**", async route => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ mode: "screencast", screencast_url: `${wsBase}/mock-screencast` })
    });
  });
  await page.routeWebSocket("**/mock-screencast", ws => {
    ws.send(JSON.stringify({
      type: "frame",
      data: tinyJpeg,
      width: 1280,
      height: 800,
      url: "https://example.com/login"
    }));
    ws.onMessage(message => {
      receivedMessages.push(JSON.parse(String(message)));
    });
  });

  const created = await api("/v1/sessions", { conversation_id: "conv_ui_screencast" });
  expect(created.ok).toBeTruthy();
  const session = await created.json();

  const handoff = await api(`/v1/sessions/${session.session_id}/handoff`, {
    reason: "credentials",
    handoff_note: "Sign in via screencast"
  });
  expect(handoff.ok).toBeTruthy();
  const handoffJson = await handoff.json();

  await page.goto(handoffJson.handoff_url);
  await page.getByRole("button", { name: "Claim" }).click();
  await expect(page.locator("#state")).toHaveText("human_active");

  const canvas = page.locator("#viewport canvas.screencast-canvas");
  await expect(canvas).toBeVisible();
  const urlInput = page.locator("#viewport input.screencast-url");
  await expect(urlInput).toHaveValue("https://example.com/login");

  await urlInput.fill("example.org/dashboard");
  await page.locator("#viewport .screencast-bar").getByRole("button", { name: "Go" }).click();
  await expect.poll(() => receivedMessages.some(
    m => m.type === "navigate" && m.action === "goto" && m.url === "https://example.org/dashboard"
  )).toBeTruthy();

  await page.getByRole("button", { name: "Complete" }).click();
  await expect(page.locator("#state")).toHaveText("completed");
});



const { test, expect } = require("@playwright/test");

const serviceHeaders = { authorization: `Bearer ${process.env.BROWSER_HANDOFF_SERVICE_TOKEN || "test-service-token"}` };

test("user can start a browser session and hand it over to an agent", async ({ page, baseURL }) => {
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
  const created = await api("/v1/sessions", { conversation_id: "conv_human_ui", initial_owner: "human" });
  expect(created.ok).toBeTruthy();
  const session = await created.json();
  expect(session.state).toBe("human_active");

  await page.goto(session.session_url);
  await expect(page.locator("#state")).toHaveText("human_active");
  await expect(page.locator("#viewport iframe")).toHaveAttribute("src", `${baseURL}/mock-novnc.html`);

  await page.locator("#handover-note").fill("Search for flights");
  await page.getByRole("button", { name: "Hand over to agent" }).click();
  await expect(page.locator("#state")).toHaveText("handover_requested");

  // The UI surfaces a one-time token the user gives to their agent.
  await expect(page.locator("#handover-result")).toBeVisible();
  const handoverToken = await page.locator("#handover-token").textContent();
  expect(handoverToken).toBeTruthy();

  // The agent claims the session with that token plus its service credentials.
  const claim = await api(`/v1/sessions/${session.session_id}/agent-claim`, { token: handoverToken });
  expect(claim.status).toBe(200);
  expect((await claim.json()).state).toBe("agent_active");

  // The agent now owns the lease and can drive the browser the user set up.
  const command = await api(`/v1/sessions/${session.session_id}/agent-command`, { type: "current_page" });
  expect(command.status).toBe(200);
});

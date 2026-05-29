const { test, expect } = require("@playwright/test");

const serviceHeaders = { authorization: `Bearer ${process.env.BROWSER_HANDOFF_SERVICE_TOKEN || "test-service-token"}` };

test("user can start a browser session and hand it over to an agent", async ({ page, baseURL }) => {
  const api = async (path, body) => fetch(`${baseURL}${path}`, {
    method: "POST",
    headers: { ...serviceHeaders, "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  const created = await api("/v1/sessions", { conversation_id: "conv_human_ui", initial_owner: "human" });
  expect(created.ok).toBeTruthy();
  const session = await created.json();
  expect(session.state).toBe("human_active");

  await page.goto(session.session_url);
  await expect(page.locator("#state")).toHaveText("human_active");

  await page.locator("#handover-note").fill("Search for flights");
  await page.getByRole("button", { name: "Hand over to agent" }).click();
  await expect(page.locator("#state")).toHaveText("agent_active");

  // The agent now owns the lease and can drive the browser the user set up.
  const command = await api(`/v1/sessions/${session.session_id}/agent-command`, { type: "current_page" });
  expect(command.status).toBe(200);
});

const { test, expect } = require("@playwright/test");

const serviceHeaders = { authorization: `Bearer ${process.env.BROWSER_HANDOFF_SERVICE_TOKEN || "test-service-token"}` };

test("human can claim, extend, mark sensitive, and complete from the handoff UI", async ({ page, baseURL }) => {
  const api = async (path, body) => fetch(`${baseURL}${path}`, {
    method: "POST",
    headers: { ...serviceHeaders, "content-type": "application/json" },
    body: JSON.stringify(body)
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

  await page.getByRole("button", { name: "Extend" }).click();
  await expect(page.locator("#state")).toHaveText("human_active");
  await page.getByRole("button", { name: "Mark sensitive" }).click();
  await expect(page.locator("#state")).toHaveText("human_sensitive");
  await page.getByRole("button", { name: "Complete" }).click();
  await expect(page.locator("#state")).toHaveText("completed");

  const denied = await api(`/v1/sessions/${session.session_id}/agent-command`, { type: "snapshot" });
  expect(denied.status).toBe(403);
});

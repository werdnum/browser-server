const { defineConfig } = require("@playwright/test");

const python = process.env.CI ? "python" : ".venv/bin/python";

module.exports = defineConfig({
  testDir: "./playwright-tests",
  timeout: 30000,
  use: {
    baseURL: process.env.BASE_URL || "http://127.0.0.1:8000",
    trace: "retain-on-failure"
  },
  webServer: {
    command: `BROWSER_RUNTIME=fake BROWSER_HANDOFF_SERVICE_TOKEN=test-service-token ${python} -m uvicorn browser_handoff_service.main:app --host 127.0.0.1 --port 8000`,
    url: "http://127.0.0.1:8000/health",
    reuseExistingServer: !process.env.CI,
    timeout: 30000
  }
});

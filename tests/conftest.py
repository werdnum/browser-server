import os
from collections.abc import Generator

import pytest
from browser_handoff_service.runtime import RuntimeUnavailable

TEST_SERVICE_TOKEN = "test-service-token"


@pytest.fixture(autouse=True)
def fake_runtime(monkeypatch):
    monkeypatch.setenv("BROWSER_RUNTIME", "fake")
    monkeypatch.setenv("BROWSER_HANDOFF_SERVICE_TOKEN", TEST_SERVICE_TOKEN)


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(call: pytest.CallInfo[None]) -> Generator[None, pytest.TestReport, pytest.TestReport]:
    """CI must not pass by skipping a failed real-browser launch.

    The browser fixtures skip inside an ``except RuntimeUnavailable`` block. Inspect
    that exception context, not the skip message or a list of test filenames, so new
    fixtures using the same pattern are covered. Unrelated skips and xfails stay intact.
    """
    report = yield
    if (
        os.environ.get("REQUIRE_CHROMIUM") == "1"
        and report.skipped
        and call.excinfo is not None
        and isinstance(call.excinfo.value, pytest.skip.Exception)
        and isinstance(call.excinfo.value.__context__, RuntimeUnavailable)
    ):
        report.outcome = "failed"
        report.longrepr = (
            "Chromium is required (REQUIRE_CHROMIUM=1), but this test skipped a browser startup failure:\n"
            f"{call.excinfo.value.__context__}"
        )
    return report

"""Exercise CI's browser requirement without needing a browser or changing local skips."""

import importlib.util
from pathlib import Path

import pytest
from browser_handoff_service.runtime import RuntimeUnavailable


def _load_test_module(filename):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(f"ci_policy_{path.stem}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("required", [None, "0", "1"])
@pytest.mark.parametrize("when", ["setup", "call"])
def test_browser_skip_fails_only_when_required(monkeypatch, required, when):
    monkeypatch.delenv("REQUIRE_CHROMIUM", raising=False)
    if required is not None:
        monkeypatch.setenv("REQUIRE_CHROMIUM", required)

    def skip_unavailable_browser():
        try:
            raise RuntimeUnavailable("simulated missing browser")
        except RuntimeUnavailable:
            # Deliberately unrelated wording: policy must inspect the exception, not text.
            pytest.skip("optional runtime")

    call = pytest.CallInfo.from_call(skip_unavailable_browser, when=when)
    report = pytest.TestReport("test.py::browser", ("test.py", 1, "browser"), {}, "skipped", "original", when)
    hook = _load_test_module("conftest.py").pytest_runtest_makereport(call)
    next(hook)
    with pytest.raises(StopIteration) as result:
        hook.send(report)
    assert result.value.value is report
    assert report.outcome == ("failed" if required == "1" else "skipped")
    if required == "1":
        assert "simulated missing browser" in str(report.longrepr)
    else:
        assert report.longrepr == "original"


@pytest.mark.parametrize("xfail", [False, True])
def test_unrelated_skips_and_xfails_remain_optional(monkeypatch, xfail):
    monkeypatch.setenv("REQUIRE_CHROMIUM", "1")

    def optional_test():
        if xfail:
            try:
                raise RuntimeUnavailable("expected startup failure")
            except RuntimeUnavailable:
                pytest.xfail("known issue")
        pytest.skip("noVNC stack unavailable")

    call = pytest.CallInfo.from_call(optional_test, when="call")
    report = pytest.TestReport("test.py::optional", ("test.py", 1, "optional"), {}, "skipped", "original", "call")
    hook = _load_test_module("conftest.py").pytest_runtest_makereport(call)
    next(hook)
    with pytest.raises(StopIteration):
        hook.send(report)
    assert report.outcome == "skipped"
    assert report.longrepr == "original"


@pytest.mark.parametrize("required", [False, True])
def test_ui_probe_preserves_launch_error_in_ci(monkeypatch, required):
    module = _load_test_module("test_user_ui_e2e.py")
    monkeypatch.setenv("REQUIRE_CHROMIUM", "1" if required else "0")

    def unavailable_playwright():
        raise module.PlaywrightError("simulated missing browser")

    monkeypatch.setattr(module, "sync_playwright", unavailable_playwright)
    if required:
        with pytest.raises(module.PlaywrightError, match="simulated missing browser"):
            module._chromium_available()
    else:
        assert module._chromium_available() is False

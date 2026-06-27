"""Unclassified failures must leave a Python traceback in the logs.

An unmapped exception collapses into HTTP 500 with ``detail=str(exc)``; the
client sees that string but, before the fix, the container logs only held the
access-log line — never the traceback — so there was nothing to debug from.
``map_errors`` now logs the full stack trace for the fallthrough 500.
"""

import logging

import pytest
from browser_handoff_service.main import map_errors
from browser_handoff_service.registry import AuthorizationError, NotFoundError


def test_map_errors_logs_traceback_for_unclassified_500(caplog):
    boom = RuntimeError("Page.title: Execution context was destroyed")
    try:
        raise boom
    except RuntimeError as exc:
        with caplog.at_level(logging.ERROR, logger="browser_handoff_service.main"):
            http_exc = map_errors(exc)

    assert http_exc.status_code == 500
    assert "Execution context was destroyed" in http_exc.detail

    records = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert records, "expected an ERROR log for the unclassified 500"
    record = records[-1]
    assert record.exc_info is not None and record.exc_info[1] is boom
    assert "RuntimeError" in caplog.text


@pytest.mark.parametrize(
    ("exc", "status"),
    [(NotFoundError("nope"), 404), (AuthorizationError("denied"), 403)],
)
def test_map_errors_does_not_log_classified_errors(caplog, exc, status):
    with caplog.at_level(logging.ERROR, logger="browser_handoff_service.main"):
        http_exc = map_errors(exc)

    assert http_exc.status_code == status
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]

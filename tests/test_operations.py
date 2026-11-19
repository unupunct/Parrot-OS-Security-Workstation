import sys
import time

import pytest

pytest.importorskip("PySide6")
from PySide6.QtCore import QCoreApplication, QEventLoop, QTimer

from wifi_center.integrations.base import LaunchMethod, LaunchRequest, Operation, ToolProfile
from wifi_center.security.operation_policy import PolicyViolation

PY = sys.executable


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def profile(*ops):
    return ToolProfile(id="t", name="T", description="", category="c", executables=("python",),
                       docs_url="https://x", source_url="https://x", install_hint="", operations=tuple(ops))


def run_op(controller, code, timeout=20.0, cancel_after=None):
    op = Operation("run", "Run", "", LaunchMethod.CLI, ("-c", code), timeout)
    p = profile(op)
    req = LaunchRequest("t", "run", (PY, "-c", code), LaunchMethod.CLI, timeout)
    mgr = controller.operations
    loop = QEventLoop()
    mgr.finished.connect(lambda *_: loop.quit())
    oid = mgr.start(p, req)
    if cancel_after:
        QTimer.singleShot(int(cancel_after * 1000), lambda: mgr.cancel(oid))
    QTimer.singleShot(15000, loop.quit)
    loop.exec()
    return oid, mgr.get(oid)


def test_captures_stdout_stderr_and_exit_code(qapp, controller):
    oid, op = run_op(controller, "import sys; print('out1'); print('err1', file=sys.stderr); sys.exit(3)")
    assert op.status == "failed" and op.exit_code == 3
    assert ("stdout", "out1") in op.lines and ("stderr", "err1") in op.lines
    row = controller.db.query_one("SELECT status, exit_code, finished_at FROM operations WHERE id=?", (oid,))
    assert row["status"] == "failed" and row["exit_code"] == 3 and row["finished_at"]
    logs = controller.db.query("SELECT stream, line FROM operation_logs WHERE operation_id=?", (oid,))
    assert ("stdout", "out1") in [(r["stream"], r["line"]) for r in logs]


def test_success_and_partial_last_line(qapp, controller):
    oid, op = run_op(controller, "import sys; sys.stdout.write('no newline')")
    assert op.status == "succeeded" and ("stdout", "no newline") in op.lines


def test_cancel(qapp, controller):
    t0 = time.monotonic()
    oid, op = run_op(controller, "import time; time.sleep(30)", cancel_after=0.5)
    assert op.status == "cancelled" and time.monotonic() - t0 < 10


def test_timeout(qapp, controller):
    oid, op = run_op(controller, "import time; time.sleep(30)", timeout=1.0)
    assert op.status == "timeout"


def test_missing_executable_fails_cleanly(qapp, controller):
    p = profile(Operation("run", "Run", "", LaunchMethod.CLI, ()))
    loop = QEventLoop()
    controller.operations.finished.connect(lambda *_: loop.quit())
    oid = controller.operations.start(p, LaunchRequest("t", "run", ("/definitely/not/here",), LaunchMethod.CLI, 5))
    QTimer.singleShot(5000, loop.quit)
    loop.exec()
    assert controller.operations.get(oid).status == "failed"


def test_policy_denial_is_audited_and_nothing_runs(qapp, controller):
    p = profile(Operation("run", "Run", "", LaunchMethod.CLI, ("--ok",)))
    with pytest.raises(PolicyViolation):
        controller.operations.start(p, LaunchRequest("t", "run", (PY, "--evil"), LaunchMethod.CLI, 5))
    assert controller.operations.operations() == []
    assert any(e["event"] == "policy.denied" for e in controller.audit.tail(10))


def test_lifecycle_is_audited_and_chain_valid(qapp, controller):
    run_op(controller, "print(1)")
    events = [e["event"] for e in controller.audit.tail(20)]
    assert "operation.start" in events and "operation.finish" in events
    assert controller.audit.verify()[0]


def test_orphaned_running_rows_marked_interrupted(paths):
    from wifi_center.application.app_controller import AppController
    c1 = AppController(paths=paths, console_log=False)
    c1.db.execute("INSERT INTO operations(name, op_type, status) VALUES ('x','cli','running')")
    c1.db.close()
    c2 = AppController(paths=paths, console_log=False)
    assert c2.db.query_one("SELECT status FROM operations WHERE name='x'")["status"] == "interrupted"
    c2.shutdown()

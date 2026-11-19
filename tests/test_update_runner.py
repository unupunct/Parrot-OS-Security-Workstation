import sys
import threading

import pytest

from wifi_center.services import update_runner as ur


def test_plans_are_fixed_command_shapes():
    assert ur.plan_update("flatpak").argv == ("flatpak", "update", "--noninteractive", "-y")
    assert ur.plan_update("pipx").argv == ("pipx", "upgrade-all") and ur.plan_update("pipx", "ruff").argv == ("pipx", "upgrade", "ruff")
    co = {"Sparrow": "/opt/sparrow"}
    g = ur.plan_update("git", "/opt/sparrow", co)
    assert g.argv == ("git", "-C", "/opt/sparrow", "pull", "--ff-only") and "Sparrow" in g.title and "fast-forward" in g.contacts
    assert ur.plan_update("snap").argv == ("snap", "refresh")


@pytest.mark.parametrize("key,item", [("pipx", "x; rm -rf /"), ("pipx", "--help"), ("pipx", "a b"), ("git", "/etc"),
                                      ("git", "/opt/sparrow --upload-pack=x"), ("apt", ""), ("appimage", ""), ("bogus", "")])
def test_anything_else_is_refused(key, item):
    with pytest.raises(ur.UpdateError):
        ur.plan_update(key, item, {"Sparrow": "/opt/sparrow"})


def run(code, cancel=None):
    lines = []
    cmd = ur.UpdateCommand("t", (sys.executable, "-c", code), "t", "")
    return ur.run_streaming(cmd, lines.append, cancel, timeout=20), lines


def test_streams_lines_and_reports_exit_status():
    (code, status), lines = run("import sys\nprint('one', flush=True)\nprint('two', file=sys.stderr, flush=True)\nsys.exit(0)")
    assert status == "succeeded" and code == 0 and lines == ["one", "two"]
    (code, status), _ = run("import sys; sys.exit(3)")
    assert status == "failed" and code == 3


def test_cancel_stops_the_process():
    ev = threading.Event()
    threading.Timer(0.6, ev.set).start()
    (_, status), lines = run("import time\nprint('start', flush=True)\ntime.sleep(30)", ev)
    assert status == "cancelled" and lines[0] == "start"


def test_missing_program_and_clean_environment():
    lines = []
    assert ur.run_streaming(ur.UpdateCommand("t", ("definitely-not-installed-xyz",), "t", ""), lines.append) == (None, "missing")
    assert "not installed" in lines[0]
    env = ur.clean_env()
    assert env["TERM"] == "dumb" and env["GIT_TERMINAL_PROMPT"] == "0" and "LD_PRELOAD" not in env

import json

from wifi_center.privileged.protocol import ERROR_PREFIX, Manifest, PrivilegedOp
from wifi_center.services import helper_client as hc
from wifi_center.services.privileged_service import run_privileged


class FakeTransport:
    def __init__(self, available=True):
        self._avail, self.calls, self.out_cb, self.fin_cb = available, [], None, None
        self.replies, self.errors = {}, {}

    def available(self):
        return self._avail

    def call(self, method, args, on_reply, on_error, timeout_ms=60000):
        self.calls.append((method, list(args)))
        if method in self.errors:
            on_error(*self.errors[method])
        else:
            on_reply(self.replies.get(method, "op-1" if method == "Execute" else True))

    def subscribe(self, on_output, on_finished):
        self.out_cb, self.fin_cb = on_output, on_finished


def run(backend, op):
    out, done = [], []
    run_privileged(backend, op, out.append, done.append)
    return out, done


def test_unavailable_helper_executes_nothing():
    t = FakeTransport(available=False)
    out, done = run(hc.HelperBackend(t), PrivilegedOp("apt_update"))
    assert t.calls == [] and done[0].executed is False and "not installed" in done[0].message


def test_request_is_sent_as_validated_json_with_manifest_and_output_is_routed():
    t = FakeTransport()
    b = hc.HelperBackend(t)
    op = PrivilegedOp("apt_upgrade", manifest=Manifest((), ("libc6",), ()))
    out, done = [], []
    b.start(op, out.append, done.append)
    method, args = t.calls[0]
    sent = json.loads(args[0])
    assert method == "Execute" and sent["kind"] == "apt_upgrade" and sent["manifest"]["upgrades"] == ["libc6"]
    t.out_cb("other-op", "stdout", "not mine")
    t.out_cb("op-1", "stdout", "Reading package lists")
    t.out_cb("op-1", "stderr", "warning")
    t.fin_cb("op-1", 0, "succeeded", "Completed.")
    assert out == ["Reading package lists", "[stderr] warning"]
    assert len(done) == 1 and done[0].ok and done[0].executed and done[0].message == "Completed."


def test_events_before_the_reply_are_not_lost():
    t = FakeTransport()
    b = hc.HelperBackend(t)
    out, done = [], []
    real_call = t.call

    def late(method, args, on_reply, on_error, timeout_ms=60000):
        t.calls.append((method, args))
        t.out_cb("op-1", "stdout", "early line")           # signal beats the method reply
        t.fin_cb("op-1", 0, "succeeded", "Completed.")
        on_reply("op-1")
    t.call = late
    b.start(PrivilegedOp("apt_update"), out.append, done.append)
    assert out == ["early line"] and done[0].ok
    t.call = real_call


def test_denied_busy_and_refused_results():
    t = FakeTransport()
    b = hc.HelperBackend(t)
    t.errors["Execute"] = (ERROR_PREFIX + "NotAuthorized", "x")
    _, done = run(b, PrivilegedOp("apt_update"))
    assert not done[0].ok and not done[0].executed and "denied or cancelled" in done[0].message
    t.errors["Execute"] = (ERROR_PREFIX + "Busy", "x")
    assert "another privileged operation" in run(b, PrivilegedOp("apt_update"))[1][0].message
    t.errors.clear()
    out, done = [], []
    b.start(PrivilegedOp("apt_update"), out.append, done.append)
    t.fin_cb("op-1", -1, "refused", "no approved transaction")
    assert done[0].executed is False and not done[0].ok and "no approved" in done[0].message
    t.errors["Execute"] = ("org.freedesktop.DBus.Error.ServiceUnknown", "The name is not activatable")
    assert "not installed" in run(b, PrivilegedOp("apt_update"))[1][0].message


def test_failed_run_counts_as_executed_but_not_ok():
    t = FakeTransport()
    b = hc.HelperBackend(t)
    out, done = [], []
    b.start(PrivilegedOp("apt_update"), out.append, done.append)
    t.fin_cb("op-1", 100, "failed", "The command failed (exit code 100).")
    assert done[0].executed and not done[0].ok


def test_status_authorize_end_session_and_recent():
    t = FakeTransport()
    b = hc.HelperBackend(t)
    t.replies["GetStatus"] = json.dumps({"busy": False, "authorized": {"a": True}})
    got = []
    b.get_status(lambda s, e: got.append((s, e)))
    assert got == [({"busy": False, "authorized": {"a": True}}, "")]
    t.replies["RequestAuthorization"] = False
    r = []
    b.request_authorization("org.wificenter.helper.maintenance", lambda ok, e: r.append(ok))
    assert r == [False]
    t.errors["EndSession"] = (ERROR_PREFIX + "NotAuthorized", "")
    e = []
    b.end_session(lambda ok, err: e.append((ok, err)))
    assert e[0][0] is False and e[0][1]
    t.replies["GetRecentOperations"] = json.dumps([{"ts": "1", "event": "op.finish"}])
    rec = []
    b.recent(10, lambda rows, err: rec.append(rows))
    assert rec == [[{"ts": "1", "event": "op.finish"}]]
    t.errors["GetStatus"] = ("org.freedesktop.DBus.Error.ServiceUnknown", "")
    s = []
    b.get_status(lambda st, err: s.append((st, err)))
    assert s[0][0] is None and "not installed" in s[0][1]


# ---------------------------------------------------------------- Root Access Manager page
def test_root_access_page_reflects_helper_state(qapp, controller):
    import pytest
    pytest.importorskip("PySide6")
    from wifi_center.privileged.protocol import ACTIONS
    from wifi_center.ui.pages.root_access_page import RootAccessPage

    seen = []
    controller.privileged = hc.HelperBackend(FakeTransport(available=False))
    page = RootAccessPage(controller, seen.append)
    assert "not installed" in page.state.text() and not page.b_auth.isEnabled() and seen[-1] is False

    t = FakeTransport()
    t.replies["GetStatus"] = json.dumps({"busy": False, "current": "", "authorized": {ACTIONS[0].id: True}})
    t.replies["GetRecentOperations"] = json.dumps([{"ts": "2026-11-19T14:04:33+00:00", "event": "op.finish",
                                                   "summary": "apt_update", "status": "succeeded"}])
    controller.privileged = hc.HelperBackend(t)
    page = RootAccessPage(controller, seen.append)
    assert page.b_auth.isEnabled() and page.table.item(0, 2).text() == "Yes" and page.table.item(1, 2).text() == "No"
    assert page.log.rowCount() == 1 and page.log.item(0, 3).text() == "succeeded" and seen[-1] is True
    page._authorize()
    page._end()
    assert [c[0] for c in t.calls if c[0] in ("RequestAuthorization", "EndSession")] == ["RequestAuthorization", "EndSession"]

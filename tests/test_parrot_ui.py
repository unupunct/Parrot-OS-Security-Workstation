import time

import pytest

pytest.importorskip("PySide6")
from PySide6.QtWidgets import QFileDialog

from tests.test_parrot import (DIST, DPKG, POLICY, SHOW, UPGRADE, UNITS, FakeRunner, make_cleanup, put)
from wifi_center.services.privileged_service import ExecutionResult
from wifi_center.ui.pages import cleanup_pages as cp
from wifi_center.ui.pages import parrot_common as pc
from wifi_center.ui.pages import parrot_pages as pp


def wait_until(qapp, cond, timeout=6.0):
    end = time.time() + timeout
    while time.time() < end:
        qapp.processEvents()
        if cond():
            return True
        time.sleep(0.02)
    return False


class Recording:
    name = "recording"

    def __init__(self, ok=True):
        self.ops, self.ok = [], ok

    def available(self): return True
    def explain_unavailable(self): return ""

    def execute(self, op):
        self.ops.append(op)
        return ExecutionResult(True, self.ok, "applied 2 packages" if self.ok else "dpkg exploded")


@pytest.fixture
def env(controller, qapp, monkeypatch):
    runner = FakeRunner({("apt-get",): UPGRADE, ("apt", "list"): "Listing...\nlibc6/stable-updates 2.36-9+deb12u4 amd64 [upgradable from: 2.36-9]\n",
                         ("dpkg-query",): DPKG, ("apt-cache", "show"): SHOW, ("apt-cache", "policy"): POLICY,
                         ("apt-cache", "search"): "nmap - The Network Mapper\n"})
    controller.apt._run_cmd = runner
    controller.apt._which = lambda n: "/usr/bin/" + n
    monkeypatch.setattr(controller.apt, "lock_holders", lambda: [])
    return controller, runner


def confirm_spy(monkeypatch, answer=True):
    calls = []
    monkeypatch.setattr(pc, "confirm_dialog", lambda parent, title, text, ok="Confirm", require_checkbox=None, danger=False:
                        (calls.append({"title": title, "text": text, "ok": ok, "checkbox": require_checkbox, "danger": danger}), answer)[1])
    monkeypatch.setattr(pp, "confirm_dialog", pc.confirm_dialog)
    return calls


# ---------------- system updates ----------------
def test_check_for_updates_shows_the_real_proposal(env, qapp):
    c, runner = env
    page = pp.SystemUpdatesPage(c)
    assert "privileged helper" in page.banner.text()                       # honest about what cannot be applied
    page.check()
    assert wait_until(qapp, lambda: not page.loader.active and page.table.rowCount() > 0)
    assert page.table.rowCount() == 2 and "2 package(s) can be upgraded" in page.msg.text()
    assert page.t_avail.value.text() == "2" and "libc6" in page.output.toPlainText() or "Inst libc6" in page.output.toPlainText()
    assert "✔</span> 5. Display the changes" in page.steps_lbl.text()
    assert all("-s" in call for call in runner.calls if call[0] == "apt-get")      # only simulations ran


def test_apply_without_backend_changes_nothing_and_records_it(env, qapp, monkeypatch):
    c, runner = env
    calls = confirm_spy(monkeypatch)
    page = pp.SystemUpdatesPage(c)
    page.propose("upgrade")
    assert wait_until(qapp, lambda: not page.loader.active and calls)
    assert calls[0]["ok"] == "Close" and "Nothing has been changed" not in calls[0]["text"] and "Equivalent command" in calls[0]["text"]
    assert "sudo apt-get upgrade" in calls[0]["text"] and "not installed yet" in calls[0]["text"]
    e = c.maintenance.entries()[0]
    assert (e["op_type"], e["result"]) == ("upgrade", "not executed") and "libc6" in e["packages_changed"]
    assert "Nothing was changed" in page.msg.text()


def test_view_changes_never_applies(env, qapp, monkeypatch):
    c, runner = env
    c.privileged = rec = Recording()
    calls = confirm_spy(monkeypatch)
    page = pp.SystemUpdatesPage(c)
    page.propose("upgrade", apply=False)
    assert wait_until(qapp, lambda: not page.loader.active and page.table.rowCount())
    assert calls == [] and rec.ops == [] and "nothing was applied" in page.msg.text()


def test_confirmed_apply_executes_once_and_records_success(env, qapp, monkeypatch):
    c, runner = env
    c.privileged = rec = Recording()
    calls = confirm_spy(monkeypatch, True)
    page = pp.SystemUpdatesPage(c)
    page.propose("upgrade")
    assert wait_until(qapp, lambda: rec.ops)
    assert [o.kind for o in rec.ops] == ["apt_upgrade"] and calls[0]["checkbox"] and calls[0]["ok"] == "Apply changes"
    assert not calls[0]["danger"]
    e = c.maintenance.entries()[0]
    assert e["result"] == "success" and "libc6" in e["packages_changed"]
    assert any(a["event"] == "apt.apply" for a in c.audit.tail(10))
    assert "Applied" in page.msg.text()


def test_declined_apply_executes_nothing(env, qapp, monkeypatch):
    c, runner = env
    c.privileged = rec = Recording()
    confirm_spy(monkeypatch, False)
    page = pp.SystemUpdatesPage(c)
    page.propose("upgrade")
    assert wait_until(qapp, lambda: c.maintenance.entries())
    assert rec.ops == [] and c.maintenance.entries()[0]["result"] == "cancelled"


def test_removals_are_flagged_and_need_extra_confirmation(env, qapp, monkeypatch):
    c, runner = env
    runner.table[("apt-get",)] = DIST
    c.privileged = rec = Recording()
    calls = confirm_spy(monkeypatch, True)
    page = pp.SystemUpdatesPage(c)
    page.propose("dist-upgrade")
    assert wait_until(qapp, lambda: rec.ops)
    assert calls[0]["danger"] and "REMOVES 2 package(s)" in calls[0]["text"] and "system-critical" in calls[0]["text"]
    assert calls[0]["checkbox"] and rec.ops[0].kind == "apt_dist_upgrade"
    assert page.table.rowCount() == 5 and "kept back" in calls[0]["text"]


def test_busy_package_manager_is_never_overridden(env, qapp, monkeypatch):
    c, runner = env
    c.privileged = rec = Recording()
    monkeypatch.setattr(c.apt, "lock_holders", lambda: ["dpkg (pid 7)"])
    confirm_spy(monkeypatch, True)
    page = pp.SystemUpdatesPage(c)
    assert "dpkg (pid 7)" in page.banner.text()
    page.propose("upgrade")
    assert wait_until(qapp, lambda: c.maintenance.entries())
    assert rec.ops == [] and "never overrides" in page.msg.text() and c.maintenance.entries()[0]["result"] == "failed"


def test_concurrent_transaction_is_refused(env, qapp, monkeypatch):
    c, runner = env
    c.privileged = rec = Recording()
    confirm_spy(monkeypatch, True)
    assert c.apt.begin_transaction()                          # another transaction is already running
    try:
        tx = c.apt.plan("upgrade")
        assert "already in progress" in pc.apply_transaction(None, c, tx, "upgrade")
        assert rec.ops == []
    finally:
        c.apt.end_transaction()


def test_backend_failure_is_reported_and_recorded(env, qapp, monkeypatch):
    c, runner = env
    c.privileged = Recording(ok=False)
    confirm_spy(monkeypatch, True)
    tx = c.apt.plan("upgrade")
    msg = pc.apply_transaction(None, c, tx, "upgrade")
    assert msg.startswith("Failed") and c.maintenance.entries()[0]["result"] == "failed"


def test_update_lists_needs_backend_and_confirmation(env, qapp, monkeypatch):
    c, runner = env
    calls = confirm_spy(monkeypatch)
    page = pp.SystemUpdatesPage(c)
    page.update_lists()
    assert calls[0]["ok"] == "Close" and c.maintenance.entries()[0]["result"] == "not executed"
    c.privileged = rec = Recording()
    confirm_spy(monkeypatch, True)
    page.update_lists()
    assert [o.kind for o in rec.ops] == ["apt_update"] and c.maintenance.entries()[0]["op_type"] == "update"


# ---------------- package manager ----------------
def test_package_manager_search_details_and_install_flow(env, qapp, monkeypatch):
    c, runner = env
    c.privileged = rec = Recording()
    calls = confirm_spy(monkeypatch, True)
    page = pp.PackageManagerPage(c)
    assert wait_until(qapp, lambda: not page.loader.active and page.table.rowCount() == 2)    # installed list
    page.table.selectRow(0)
    assert wait_until(qapp, lambda: "Network Mapper" in page.detail.toPlainText())
    assert "upgradable" in page.detail.toPlainText() and "libc6" in page.detail.toPlainText()
    page.scope.setCurrentIndex(1)
    page.query.setText("nmap; rm -rf /")
    page.search()
    assert "letters, digits" in page.msg.text()
    page.query.setText("nmap")
    page.search()
    assert wait_until(qapp, lambda: not page.loader.active and page.table.rowCount() == 1)
    page.table.selectRow(0)
    runner.table[("apt-get",)] = "Inst nmap (7.94-3 Parrot:6.1/lory [amd64])\n1 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.\n"
    page._propose("install")
    assert wait_until(qapp, lambda: rec.ops)
    assert rec.ops[0].kind == "apt_install" and rec.ops[0].packages == ("nmap",)
    assert "Install packages" == calls[0]["title"] and "sudo apt-get install nmap" in calls[0]["text"]
    assert page.history.rowCount() >= 1


# ---------------- software updates ----------------
def test_software_sources_detect_then_check_only_when_confirmed(env, qapp, monkeypatch):
    c, runner = env
    r2 = FakeRunner({("flatpak", "list"): "org.gimp.GIMP\t2.10.34\tflathub\n", ("flatpak", "remote-ls"): "org.gimp.GIMP\t2.10.36\n"})
    c.software._run = r2
    c.software._which = lambda n: None if n in ("snap", "pipx") else "/usr/bin/" + n
    page = pp.SoftwareUpdatesPage(c)
    assert wait_until(qapp, lambda: not page.loader.active and page.sources.rowCount() == 6)
    titles = [page.sources.item(r, 0).text() for r in range(6)]
    assert "Flatpak" in titles[1] and not any("remote-ls" in " ".join(x) for x in r2.calls)
    page.sources.selectRow(1)
    assert page.items.rowCount() == 1 and page.b_check.isEnabled()
    monkeypatch.setattr(pp, "confirm_dialog", lambda *a, **k: False)
    page.check_selected()
    assert not any("remote-ls" in " ".join(x) for x in r2.calls)
    monkeypatch.setattr(pp, "confirm_dialog", lambda *a, **k: True)
    page.check_selected()
    assert wait_until(qapp, lambda: any("remote-ls" in " ".join(x) for x in r2.calls) and not page.loader.active)
    assert "1 update(s) available" in page.msg.text()
    page.sources.selectRow(0)
    assert not page.b_check.isEnabled()                       # APT updates are not checked from here


# ---------------- overview / system info ----------------
def test_overview_and_system_info_render_real_data(env, qapp, tmp_path, monkeypatch):
    c, runner = env
    monkeypatch.setattr("shutil.which", lambda n: None)
    ov = pp.ParrotOverviewPage(c)
    assert wait_until(qapp, lambda: not ov.loader.active)
    assert ov.tiles["os"].value.text() and ov.tiles["updates"].value.text().endswith("available")
    assert ov.tiles["last_clean"].value.text() == "never"
    info = pp.SystemInfoPage(c)
    assert wait_until(qapp, lambda: not info.loader.active and info.t_overview.rowCount() > 5)
    assert info.t_disks.rowCount() >= 1 and info.t_net.rowCount() >= 1
    assert "systemctl is not available" in info.svc_note.text()


# ---------------- cleanup ----------------
def test_cleanup_page_dry_run_then_real_run(controller, qapp, tmp_path, monkeypatch):
    svc, home, d, logs, now = make_cleanup(controller, tmp_path)
    controller.cleanup = svc
    thumb = put(home / ".cache/thumbnails/a.png", 400)
    doc = put(home / "Documents/keep.txt", 40)
    root_file = put(d["apt_cache"] / "x.deb", 900)
    page = cp.CleanupPage(controller)
    page.scan()
    assert wait_until(qapp, lambda: not page.loader.active and page.tree.topLevelItemCount() == 9)
    items = {page.tree.topLevelItem(i).data(0, 0x0100): page.tree.topLevelItem(i) for i in range(9)}   # Qt.UserRole
    assert items["thumbnails"].text(1) == "1" and items["apt_cache"].text(3) == "yes"
    assert items["residual_configs"].checkState(0) == cp.Qt.CheckState.Unchecked          # risky category is opt-in
    assert not (items["autoremove"].flags() & cp.Qt.ItemFlag.ItemIsUserCheckable)           # unavailable here: not selectable
    page.tree.setCurrentItem(items["thumbnails"])
    assert "regenerates on demand" in page.detail.toPlainText() and "Owned by you" in page.detail.toPlainText()
    page.tree.setCurrentItem(items["apt_cache"])
    assert "privileged helper" in page.detail.toPlainText()
    assert "item(s)" in page.total.text()

    seen = []
    monkeypatch.setattr(cp, "confirm_dialog", lambda parent, title, text, ok="Confirm", box=None, danger=False:
                        (seen.append((title, ok, box, danger)), True)[1])
    assert page.dry.isChecked()
    page.clean()                                              # dry run: nothing deleted
    assert wait_until(qapp, lambda: not page.loader.active and seen)
    assert seen[0][0] == "Dry run" and seen[0][2] is None and thumb.exists() and root_file.exists()
    assert wait_until(qapp, lambda: page.tree.topLevelItemCount() == 9 and not page.loader.active)
    page.dry.setChecked(False)
    page.clean()
    assert wait_until(qapp, lambda: len(seen) == 2 and not page.loader.active and not thumb.exists())
    assert seen[1][0] == "Confirm cleanup" and seen[1][2] and seen[1][3]                   # explicit acknowledgement + danger
    assert doc.exists() and root_file.exists()                # documents untouched; root category not executed
    assert "privileged helper" in page.msg.text()
    kinds = {e["result"] for e in controller.maintenance.entries()}
    assert {"dry run", "success", "not executed"} <= kinds


def test_cleanup_declined_confirmation_deletes_nothing(controller, qapp, tmp_path, monkeypatch):
    svc, home, d, logs, now = make_cleanup(controller, tmp_path)
    controller.cleanup = svc
    thumb = put(home / ".cache/thumbnails/a.png", 400)
    page = cp.CleanupPage(controller)
    page.scan()
    assert wait_until(qapp, lambda: page.tree.topLevelItemCount() == 9 and not page.loader.active)
    page.dry.setChecked(False)
    monkeypatch.setattr(cp, "confirm_dialog", lambda *a, **k: False)
    page.clean()
    qapp.processEvents()
    assert thumb.exists() and controller.maintenance.entries() == []


# ---------------- maintenance history ----------------
def test_maintenance_page_filters_and_exports(controller, qapp, tmp_path, monkeypatch):
    m = controller.maintenance
    m.record("Upgrade", "upgrade", "success", packages=["libc6"])
    m.record("Cleanup", "cleanup", "dry run", files_removed=4)
    m.record("Install", "install", "failed", errors="E: lock held")
    page = cp.MaintenancePage(controller)
    assert page.table.rowCount() == 3
    page.kind.setCurrentText("cleanup")
    assert page.table.rowCount() == 1
    page.kind.setCurrentIndex(0)
    page.result.setCurrentText("failed")
    assert page.table.rowCount() == 1
    page.table.selectRow(0)
    assert "lock held" in page.detail.toPlainText()
    out = tmp_path / "hist.csv"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **k: (str(out), ""))
    page._export()
    assert out.read_text().splitlines()[0].startswith("id,name") and len(out.read_text().splitlines()) == 4

import time

import pytest

pytest.importorskip("PySide6")
from PySide6.QtWidgets import QFileDialog

from tests.test_parrot import (DIST, DPKG, POLICY, SHOW, UPGRADE, UNITS, FakeRunner, make_cleanup, put)
from wifi_center.services.privileged_service import ExecutionResult
from wifi_center.ui.pages import cleanup_pages as cp
from wifi_center.ui.pages import package_manager_page as pmp
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
    monkeypatch.setattr(pmp, "confirm_dialog", pc.confirm_dialog)
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
    assert "sudo apt-get upgrade" in calls[0]["text"] and "not installed" in calls[0]["text"]
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
def package_tools(c, extra=None):
    nl = chr(10)
    table = {("dpkg-query",): "rc |old-tool|1.0|12|Gone but configured" + nl, ("dpkg", "--audit"): " half-pkg  not configured" + nl,
             ("dpkg", "-L"): "/." + nl + "/usr/bin/nmap" + nl + "/usr/share/man/man1/nmap.1.gz" + nl,
             ("apt-cache", "depends"): "nmap" + nl + "  Depends: libc6" + nl + "  Depends: nmap-common" + nl + "  Suggests: ncat" + nl,
             ("apt-cache", "rdepends"): "nmap" + nl + "Reverse Depends:" + nl + "  parrot-tools" + nl,
             ("dpkg", "--verify"): "??5??????  c /etc/nmap.conf" + nl}
    table.update(extra or {})
    c.pkgtools._run = FakeRunner(table)
    c.pkgtools._which = lambda n: "/usr/bin/" + n
    return c.pkgtools


def test_package_manager_views_search_details_and_install_flow(env, qapp, monkeypatch):
    c, runner = env
    package_tools(c)
    c.privileged = rec = Recording()
    calls = confirm_spy(monkeypatch, True)
    page = pp.PackageManagerPage(c)
    assert wait_until(qapp, lambda: not page.loader.active and page.table.rowCount() == 2)      # installed list
    assert page.chips["installed"].isChecked() and page.table.item(0, 1).text() in ("nmap", "libc6")
    assert wait_until(qapp, lambda: page.chips["upgradable"].text() == "Upgradable (2)")          # count from the real simulation
    assert page.banner.isVisibleTo(page) and "half-pkg" in page.banner.text()                  # an interrupted install is surfaced
    for r in range(page.table.rowCount()):
        if page.table.item(r, 1).text() == "nmap":
            page.table.selectRow(r)
    assert wait_until(qapp, lambda: "Network Mapper" in page.detail.toPlainText() or "Network Mapper" in page.d_sum.text())
    assert page.d_name.text() == "nmap"
    assert page.b_remove.isEnabled() and page.b_reinstall.isEnabled()
    page.tabs.setCurrentIndex(2)
    assert wait_until(qapp, lambda: "/usr/bin/nmap" in page.files.toPlainText() and "2 file(s)" in page.files.toPlainText())
    page.tabs.setCurrentIndex(1)
    assert wait_until(qapp, lambda: "libc6" in page.deps.toPlainText() and "parrot-tools" in page.deps.toPlainText())
    # available view needs a valid query
    page.set_view("available")
    page.query.setText("nmap; rm -rf /")
    page.search()
    assert "letters, digits" in page.msg.text()
    page.query.setText("nmap")
    page.search()
    assert wait_until(qapp, lambda: not page.loader.active and page.table.rowCount() == 1)
    page.table.selectRow(0)
    assert not page.b_install.isEnabled() and page.b_remove.isEnabled()      # nmap is already installed: reinstall or remove, not install
    nl = chr(10)
    runner.table[("apt-get",)] = ("Inst nmap (7.94-3 Parrot:6.1/lory [amd64])" + nl
                                  + "1 upgraded, 1 newly installed, 0 to remove and 0 not upgraded." + nl)
    page._propose("install", apply=False)                                                        # preview never applies
    assert wait_until(qapp, lambda: calls and "Preview" in calls[-1]["title"])
    assert rec.ops == [] and "nothing was applied" in page.msg.text()
    page._propose("install")
    assert wait_until(qapp, lambda: rec.ops)
    assert rec.ops[0].kind == "apt_install" and rec.ops[0].packages == ("nmap",) and rec.ops[0].manifest is not None
    assert "Install packages" == calls[-1]["title"] and "sudo apt-get install nmap" in calls[-1]["text"]
    assert page.history.rowCount() >= 1 and "success" in page.history.item(0, 3).text()


def test_package_manager_removed_and_upgradable_views_and_reinstall(env, qapp, monkeypatch):
    c, runner = env
    package_tools(c)
    c.privileged = rec = Recording()
    confirm_spy(monkeypatch, True)
    page = pp.PackageManagerPage(c)
    assert wait_until(qapp, lambda: not page.loader.active and page.table.rowCount() == 2)
    page.set_view("removed")
    assert wait_until(qapp, lambda: not page.loader.active and page.table.rowCount() == 1)
    assert page.table.item(0, 1).text() == "old-tool" and "Config left" in page.table.item(0, 3).text()
    page.table.selectRow(0)
    assert not page.b_remove.isEnabled() and not page.b_reinstall.isEnabled() and page.b_download.isEnabled()    # nothing installed to remove
    page.set_view("upgradable")
    assert wait_until(qapp, lambda: not page.loader.active and page.table.rowCount() == 2)
    page.table.selectRow(0)
    assert page.b_install.text() == "Update…" and page.b_install.isEnabled()
    nl = chr(10)
    runner.table[("apt-get",)] = ("Inst libc6 [2.36-9] (2.36-9+deb12u4 Debian:12.4/stable-updates [amd64])" + nl
                                  + "1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded." + nl)
    name = page.table.item(0, 1).text()
    page._propose("reinstall")
    assert wait_until(qapp, lambda: rec.ops)
    assert rec.ops[0].kind == "apt_reinstall" and rec.ops[0].packages == (name,)


def test_package_manager_tools_never_act_on_their_own(env, qapp, monkeypatch):
    c, runner = env
    package_tools(c)
    c.privileged = rec = Recording()
    calls = confirm_spy(monkeypatch, False)                                 # the user declines everything
    page = pp.PackageManagerPage(c)
    assert wait_until(qapp, lambda: not page.loader.active and page.table.rowCount() == 2)
    page.open_tool("broken")
    assert wait_until(qapp, lambda: "half-pkg" in page.tool_view.toPlainText())
    assert page.tool_btn.isEnabled() and page.tool_btn.text().startswith("Finish interrupted")
    page._configure_pending()
    assert calls[-1]["title"] == "Finish interrupted installation" and rec.ops == []                   # declined: nothing ran
    assert c.maintenance.entries()[0]["result"] == "cancelled"
    page.open_tool("cache")
    assert wait_until(qapp, lambda: "downloaded package file" in page.tool_view.toPlainText())
    page._clean_cache()
    assert rec.ops == [] and calls[-1]["title"] == "Clean package cache"                               # never cleaned without a yes
    confirm_spy(monkeypatch, True)
    page._clean_cache()
    assert [o.kind for o in rec.ops] == ["apt_clean"]


def test_package_manager_history_is_permanent_until_explicitly_cleared(env, qapp, monkeypatch):
    c, runner = env
    package_tools(c)
    c.maintenance.record("Install nmap", "install", "success", packages=["nmap"])
    c.maintenance.record("Remove x", "remove", "failed", packages=["x"], errors="dpkg exploded")
    c.maintenance.record("Cleanup", "cleanup", "success")
    page = pp.PackageManagerPage(c)
    assert wait_until(qapp, lambda: not page.loader.active and page.history.rowCount() == 2)
    marks = [page.history.item(r, 3).text() for r in range(2)]
    assert any("✔" in m for m in marks) and any("✖" in m for m in marks)
    assert page.act_stack.currentWidget() is page.activity and "operations per day" in page.act_legend.text()      # real counts, not invented
    page.refresh()
    page.reload_history()
    assert page.history.rowCount() == 2                                       # refreshing never prunes
    calls = confirm_spy(monkeypatch, False)
    page._clear_history()
    assert page.history.rowCount() == 2 and calls[-1]["danger"] is True        # declined: untouched
    confirm_spy(monkeypatch, True)
    page._clear_history()
    assert page.history.rowCount() == 0 and [e["op_type"] for e in c.maintenance.entries()] == ["cleanup"]   # only package records go
    assert page.act_stack.currentWidget() is page.act_empty


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


def test_software_update_runs_in_the_app_after_confirmation(env, qapp, monkeypatch):
    c, runner = env
    c.software._run = FakeRunner({("flatpak", "list"): "org.gimp.GIMP" + chr(9) + "2.10.34" + chr(9) + "flathub" + chr(10)})
    c.software._which = lambda n: None if n in ("snap", "pipx") else "/usr/bin/" + n
    page = pp.SoftwareUpdatesPage(c)
    assert wait_until(qapp, lambda: not page.loader.active and page.sources.rowCount() == 6)
    ran = []

    def fake_run(cmd, on_line, cancel=None, timeout=0):
        ran.append(cmd.argv)
        on_line("Updating org.gimp.GIMP")
        return 0, "succeeded"
    monkeypatch.setattr(pp, "run_streaming", fake_run)
    page.sources.selectRow(1)                                    # Flatpak
    assert page.b_update.isEnabled() and page.b_update.text() == "Update now…" and not page.b_update_item.isEnabled()
    monkeypatch.setattr(pp, "confirm_dialog", lambda *a, **k: False)
    page._update(False)
    assert ran == []                                             # declining runs nothing
    monkeypatch.setattr(pp, "confirm_dialog", lambda *a, **k: True)
    page._update(False)
    assert wait_until(qapp, lambda: "Finished" in page.term.toPlainText() and page._cancel is None)
    assert ran == [("flatpak", "update", "--noninteractive", "-y")]
    assert "$ flatpak update" in page.term.toPlainText() and "Updating org.gimp.GIMP" in page.term.toPlainText()
    assert c.maintenance.entries()[0]["result"] == "success"
    page.sources.selectRow(0)                                    # APT: the button leads to System Updates instead
    assert page.b_update.text() == "Open System Updates" and page.b_update.isEnabled()


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
    assert not page.dry.isChecked()                           # cleaning is real by default; preview is opt-in
    page.dry.setChecked(True)
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

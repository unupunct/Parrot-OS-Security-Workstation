"""Root Access Manager and Permissions: what the privileged helper is allowed to do, whether you are authorized
right now, and a log of what it did for you. The application itself never runs as root and never sees a password:
Polkit shows its own authentication dialog."""
from __future__ import annotations

import html
import os

from PySide6.QtCore import QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QComboBox, QHBoxLayout, QLabel, QTableWidgetItem, QVBoxLayout, QWidget

from ...application.app_controller import AppController
from ...privileged.protocol import ACTIONS
from ..charts import make_table
from ..design.components import MatrixButton, Panel
from ..design.tokens import T
from .parrot_pages import _say

esc = html.escape
POLICY_FILE = "/usr/share/polkit-1/actions/org.wificenter.helper.policy"


def _ts(ts: str) -> str:
    return ts.replace("T", " ")[:19] if ts else ""


class RootAccessPage(QWidget):
    def __init__(self, app: AppController, on_privilege=None) -> None:
        super().__init__()
        self.app = app
        self._on_privilege = on_privilege
        self.status: dict | None = None
        lay = QVBoxLayout(self)
        title = QLabel("Root Access Manager")
        title.setObjectName("pageTitle")
        lay.addWidget(title)
        intro = QLabel("WIFI Center always runs as your normal user. Operations that need root go to a small privileged "
                       "helper that only accepts a fixed list of narrowly scoped operations, and only after Polkit has "
                       "asked you to authenticate. No password is stored or seen by this application, and there is no "
                       "root shell.")
        intro.setObjectName("muted")
        intro.setWordWrap(True)
        lay.addWidget(intro)

        self.state = QLabel("")
        self.state.setWordWrap(True)
        lay.addWidget(self.state)

        panel = Panel("Authorization")
        lay.addWidget(panel)
        self.table = make_table(["Permission", "Polkit action", "Authorized now", "What it allows"], stretch_col=3)
        panel.add(self.table)
        row = QHBoxLayout()
        self.pick = QComboBox()
        for a in ACTIONS:
            self.pick.addItem(a.title, a.id)
        self.b_auth = MatrixButton("Authorize now…", kind="primary")
        self.b_auth.clicked.connect(self._authorize)
        self.b_end = MatrixButton("End privileged session")
        self.b_end.clicked.connect(self._end)
        self.b_refresh = MatrixButton("Refresh")
        self.b_refresh.clicked.connect(self.refresh)
        for w in (self.pick, self.b_auth, self.b_end, self.b_refresh):
            row.addWidget(w)
        row.addStretch(1)
        rw = QWidget()
        rw.setLayout(row)
        panel.add(rw)
        self.note = QLabel("Polkit keeps an authorization for a few minutes after you authenticate (it does not report the "
                           "exact end time). “End privileged session” revokes it immediately.")
        self.note.setObjectName("muted")
        self.note.setWordWrap(True)
        panel.add(self.note)

        self.current = QLabel("")
        lay.addWidget(self.current)
        recent = Panel("Recent privileged operations (your account)")
        lay.addWidget(recent, 1)
        self.log = make_table(["Time (UTC)", "Event", "Operation", "Result"], stretch_col=2)
        recent.add(self.log)
        self.msg = QLabel("")
        self.msg.setWordWrap(True)
        lay.addWidget(self.msg)
        self._fill_actions({})
        self.refresh()

    # ------------------------------------------------------------------ data
    @property
    def backend(self):
        return self.app.privileged

    def _has(self, method: str) -> bool:
        return self.backend.available() and hasattr(self.backend, method)

    def _fill_actions(self, authorized: dict) -> None:
        self.table.setRowCount(len(ACTIONS))
        for i, a in enumerate(ACTIONS):
            yes = bool(authorized.get(a.id))
            cells = [a.title, a.id, "Yes" if yes else "No", a.description]
            for c, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if c == 2:
                    item.setForeground(QColor(T.warning if yes else T.text_muted))
                self.table.setItem(i, c, item)

    def refresh(self) -> None:
        b = self.backend
        installed_policy = os.path.exists(POLICY_FILE)
        if not b.available():
            self.state.setText(f"<span style='color:{T.warning}'>{esc(b.explain_unavailable())}</span>"
                               + ("" if installed_policy or os.name == "nt" else
                                  "<br>The Polkit policy file is not installed either."))
            for w in (self.b_auth, self.b_end):
                w.setEnabled(False)
            self.current.setText("")
            self._fill_actions({})
            self.log.setRowCount(0)
            self._publish(False)
            return
        for w in (self.b_auth, self.b_end):
            w.setEnabled(True)
        self.state.setText(f"<span style='color:{T.green}'>The privileged helper is installed and reachable.</span>")
        if hasattr(b, "get_status"):
            b.get_status(self._status_in)
        if hasattr(b, "recent"):
            b.recent(40, self._recent_in)

    def _status_in(self, status: dict | None, err: str) -> None:
        if status is None:
            _say(self.msg, err, True)
            self._publish(False)
            return
        self.status = status
        auth = status.get("authorized", {})
        self._fill_actions(auth)
        busy = status.get("busy")
        self.current.setText(f"Running now: {esc(str(status.get('current') or 'an operation'))}" if busy
                             else "No privileged operation is running.")
        self._publish(any(auth.values()))

    def _recent_in(self, rows: list[dict], err: str) -> None:
        if err:
            _say(self.msg, err, True)
            return
        self.log.setRowCount(len(rows))
        for i, r in enumerate(rows):
            for c, text in enumerate([_ts(r.get("ts", "")), r.get("event", ""), r.get("summary", ""), r.get("status", "")]):
                self.log.setItem(i, c, QTableWidgetItem(str(text)))

    def _publish(self, active: bool) -> None:
        if self._on_privilege:
            self._on_privilege(active)

    # ------------------------------------------------------------------ actions
    def _authorize(self) -> None:
        action = self.pick.currentData()
        if not action or not self._has("request_authorization"):
            return
        _say(self.msg, "Waiting for the Polkit authentication dialog…")
        self.app.audit.record("root_access.authorize", action=action)

        def done(ok: bool, err: str) -> None:
            _say(self.msg, "Authorized." if ok else (err or "Authorization was denied or cancelled."), not ok)
            self.refresh()
        self.backend.request_authorization(action, done)

    def _end(self) -> None:
        if not self._has("end_session"):
            return
        self.app.audit.record("root_access.end_session")

        def done(ok: bool, err: str) -> None:
            _say(self.msg, "Privileged session ended." if ok else (err or "Could not revoke; it will expire on its own."),
                 not ok)
            self.refresh()
        self.backend.end_session(done)


class PrivilegeMonitor:
    """Updates the top bar's privilege chip from the helper's (non-interactive) status every few seconds."""

    def __init__(self, app: AppController, topbar, parent: QWidget, interval_ms: int = 10000) -> None:
        self.app, self.topbar = app, topbar
        self.timer = QTimer(parent)
        self.timer.setInterval(interval_ms)
        self.timer.timeout.connect(self.poll)
        self.timer.start()

    def poll(self) -> None:
        b = self.app.privileged
        if not (b.available() and hasattr(b, "get_status")):
            self.topbar.set_privileged(False, "Helper missing" if not b.available() else None)
            return
        b.get_status(self._in)

    def _in(self, status: dict | None, err: str) -> None:
        if status is None:
            self.topbar.set_privileged(False)
            return
        active = any(status.get("authorized", {}).values())
        self.topbar.set_privileged(active, "Privileged" if active else "Helper ready")

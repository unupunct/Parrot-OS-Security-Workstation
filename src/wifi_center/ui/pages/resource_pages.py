"""Wordlist Library / Local Resources (one engine, two libraries) and the Documentation hub."""
from __future__ import annotations

import html
from datetime import date
from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QColor, QDesktopServices
from PySide6.QtWidgets import (QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QHBoxLayout,
                               QInputDialog, QLabel, QLineEdit, QListWidget, QListWidgetItem, QProgressBar, QPushButton,
                               QSpinBox, QSplitter, QTabWidget, QTableWidgetItem, QTextBrowser, QVBoxLayout, QWidget)

from ...application.app_controller import AppController
from ...integrations.catalog import PROFILES
from ...services import resource_catalog as rc
from ...services.resource_library import LibraryError, LibraryService
from ...workers.task import run_in_background
from ..charts import NumItem, fmt_ts, make_table
from ..design.components import LoadingIndicator, MatrixButton
from ..design.tokens import T
from ..widgets import human_bytes
from .netsec_common import confirm_dialog

esc = html.escape
INTEGRITY = {"ok": ("✔ unchanged", T.success), "changed": ("✖ CHANGED", T.danger), "missing": ("✖ missing", T.danger)}


class ImportDialog(QDialog):
    """Collects the provenance of a file you obtained yourself. Nothing is downloaded here."""

    def __init__(self, parent: QWidget, library: LibraryService, entry: rc.CatalogEntry | None = None,
                 path: str = "") -> None:
        super().__init__(parent)
        self.setWindowTitle("Import a file into the library")
        self.setMinimumWidth(600)
        self.entry = entry
        form = QFormLayout(self)
        self.path = QLineEdit(path)
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse)
        row = QHBoxLayout()
        row.addWidget(self.path, 1)
        row.addWidget(browse)
        form.addRow("File", row)
        self.folder = QComboBox()
        self.folder.setEditable(True)
        self.folder.addItems([""] + sorted(f for f in library.folders() if f))
        self.folder.setCurrentText((entry.id if entry and entry.kind == "reference" else "") if entry else "")
        form.addRow("Folder (inside the library)", self.folder)
        self.name = QLineEdit()
        self.name.setPlaceholderText("keep the original file name")
        form.addRow("Name", self.name)
        self.source = QLineEdit(entry.source_url if entry else "")
        self.license = QLineEdit(entry.license if entry else "")
        self.attribution = QLineEdit(entry.attribution if entry else "")
        self.acquired = QLineEdit(date.today().isoformat())
        form.addRow("Source URL", self.source)
        form.addRow("License", self.license)
        form.addRow("Attribution", self.attribution)
        form.addRow("Date obtained", self.acquired)
        if entry and entry.license_note:
            note = QLabel(entry.license_note)
            note.setWordWrap(True)
            note.setObjectName("muted")
            form.addRow(note)
        text = ("I obtained this file myself from the source above and will respect its license and terms."
                if entry and entry.kind == "reference" else
                "I am authorized to use this file, and I recorded its source and license accurately.")
        self.ack = QCheckBox(text)
        form.addRow(self.ack)
        self.err = QLabel("")
        self.err.setObjectName("err")
        form.addRow(self.err)
        self.box = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        self.ok = self.box.addButton("Import copy", QDialogButtonBox.ButtonRole.AcceptRole)
        self.ok.setObjectName("primary")
        self.ok.setEnabled(False)
        self.ack.toggled.connect(self.ok.setEnabled)
        self.box.accepted.connect(self._accept)
        self.box.rejected.connect(self.reject)
        form.addRow(self.box)

    def _browse(self) -> None:
        f, _ = QFileDialog.getOpenFileName(self, "Choose the file to import")
        if f:
            self.path.setText(f)

    def _accept(self) -> None:
        try:
            date.fromisoformat(self.acquired.text().strip())
        except ValueError:
            self.err.setText("The date must look like 2026-11-19.")
            return
        if not self.path.text().strip():
            self.err.setText("Choose a file.")
            return
        self.accept()

    def values(self) -> dict:
        return {"src": self.path.text().strip(), "folder": self.folder.currentText().strip(),
                "name": self.name.text().strip() or None, "source_url": self.source.text().strip(),
                "license": self.license.text().strip(), "attribution": self.attribution.text().strip(),
                "acquired_at": self.acquired.text().strip(), "entry_id": self.entry.id if self.entry else None}


class ResourceLibraryPage(QWidget):
    COLS = ["Name", "Size", "Format", "Source", "Added", "Integrity"]

    def __init__(self, app: AppController, library: str = "wordlists") -> None:
        super().__init__()
        self.app = app
        self.library_name = library
        self.lib: LibraryService = app.wordlists if library == "wordlists" else app.local_resources
        self.title = "Wordlist Library" if library == "wordlists" else "Local Resources"
        self._files: list[dict] = []
        self._integrity: dict[int, str] = {}
        self._view = "all"          # all | favorites | untracked | folder
        self._folder = ""
        self._untracked: list[str] = []

        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        t = QLabel(self.title)
        t.setObjectName("pageTitle")
        head.addWidget(t)
        self.loader = LoadingIndicator("scan", 22)
        head.addWidget(self.loader)
        head.addStretch(1)
        lay.addLayout(head)
        blurb = ("Local-first library of password-policy test data. WIFI Center never downloads, bundles or "
                 "redistributes leaked-credential collections: you obtain a copy yourself from its source, under its "
                 "license, then import it with its provenance. Nothing here feeds any cracking or guessing action."
                 if library == "wordlists" else
                 "Reference files, internal datasets and documents you supply. Imported with a recorded source, "
                 "hashed, and integrity-checked.")
        b = QLabel(blurb)
        b.setObjectName("muted")
        b.setWordWrap(True)
        lay.addWidget(b)
        lay.addLayout(self._storage_strip())
        self.tabs = QTabWidget()
        self.tabs.addTab(self._library_tab(), "Library")
        if library == "wordlists":
            self.tabs.addTab(self._catalog_tab(), f"Catalog ({len(rc.CATALOG)})")
        self.tabs.addTab(self._history_tab(), "Download and import history")
        lay.addWidget(self.tabs, 1)
        self.msg = QLabel("")
        self.msg.setWordWrap(True)
        lay.addWidget(self.msg)
        self.reload()

    # ================================================================ storage strip
    def _storage_strip(self) -> QHBoxLayout:
        row = QHBoxLayout()
        self.path_lbl = QLabel("")
        self.path_lbl.setObjectName("muted")
        self.path_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.usage = QProgressBar()
        self.usage.setRange(0, 1000)
        self.usage.setMaximumWidth(220)
        self.usage.setTextVisible(False)
        self.usage_lbl = QLabel("")
        change = MatrixButton("Change folder…", icon_name="folder")
        change.clicked.connect(self._change_root)
        openb = MatrixButton("Open folder")
        openb.clicked.connect(self._open_root)
        for w in (self.path_lbl,):
            row.addWidget(w, 1)
        for w in (self.usage, self.usage_lbl, change, openb):
            row.addWidget(w)
        return row

    def _change_root(self) -> None:
        key = "general.resources_dir" if self.library_name == "wordlists" else "general.local_resources_dir"
        d = QFileDialog.getExistingDirectory(self, "Library folder", str(self.lib.root))
        if d:
            self.app.settings.set(key, d)
            self.app.audit.record("library.folder", library=self.library_name, path=d)
            self._integrity.clear()
            self.reload()

    def _open_root(self) -> None:
        self.lib.ensure_root()
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.lib.root)))

    # ================================================================ library tab
    def _library_tab(self) -> QWidget:
        w = QWidget()
        lay = QHBoxLayout(w)
        lay.setContentsMargins(0, 8, 0, 0)
        split = QSplitter(Qt.Orientation.Horizontal)
        split.setChildrenCollapsible(False)
        self.nav = QListWidget()
        self.nav.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.nav.currentRowChanged.connect(self._nav_changed)
        self.nav.setMaximumWidth(260)
        split.addWidget(self.nav)

        mid = QWidget()
        ml = QVBoxLayout(mid)
        ml.setContentsMargins(0, 0, 0, 0)
        bar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search name, source or folder…")
        self.search.textChanged.connect(self.reload_files)
        imp = MatrixButton("Import file…", "primary", "folder")
        imp.clicked.connect(lambda: self._import())
        ver = MatrixButton("Verify all", icon_name="installed")
        ver.clicked.connect(self._verify_all)
        dup = MatrixButton("Find duplicates")
        dup.clicked.connect(self._show_duplicates)
        for x in (self.search, imp, ver, dup):
            bar.addWidget(x)
        ml.addLayout(bar)
        self.table = make_table(self.COLS, stretch_col=0)
        self.table.horizontalHeader().setSectionResizeMode(3, self.table.horizontalHeader().ResizeMode.Interactive)
        self.table.setColumnWidth(3, 210)   # long source URLs elide instead of squeezing the name column
        self.table.setSortingEnabled(True)
        self.table.itemSelectionChanged.connect(self._select)
        ml.addWidget(self.table, 1)
        split.addWidget(mid)

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        self.details = QTextBrowser()
        self.details.setOpenLinks(False)
        self.details.anchorClicked.connect(lambda u: QDesktopServices.openUrl(u))
        rl.addWidget(self.details, 1)
        grid = QHBoxLayout()
        self.b_verify = MatrixButton("Verify")
        self.b_verify.clicked.connect(self._verify_one)
        self.b_fav = MatrixButton("★ Favorite")
        self.b_fav.clicked.connect(self._toggle_favorite)
        self.b_rename = MatrixButton("Rename…")
        self.b_rename.clicked.connect(self._rename)
        self.b_folder = MatrixButton("Show in folder")
        self.b_folder.clicked.connect(self._show_in_folder)
        for x in (self.b_verify, self.b_fav, self.b_rename, self.b_folder):
            grid.addWidget(x)
        rl.addLayout(grid)
        grid2 = QHBoxLayout()
        self.b_untrack = MatrixButton("Remove from library")
        self.b_untrack.setToolTip("Stops tracking the file. The file itself stays on disk.")
        self.b_untrack.clicked.connect(lambda: self._remove(False))
        self.b_delete = MatrixButton("Delete file…", "danger")
        self.b_delete.clicked.connect(lambda: self._remove(True))
        self.b_adopt = MatrixButton("Add to library", "primary")
        self.b_adopt.clicked.connect(self._adopt)
        for x in (self.b_untrack, self.b_delete, self.b_adopt):
            grid2.addWidget(x)
        rl.addLayout(grid2)
        split.addWidget(right)
        split.setStretchFactor(1, 4)
        split.setStretchFactor(2, 2)
        split.setSizes([200, 720, 380])
        lay.addWidget(split)
        return w

    def reload(self) -> None:
        root = self.lib.ensure_root()
        st = self.lib.storage()
        self.path_lbl.setText(str(root))
        total = st["used"] + st["free"]
        self.usage.setValue(int(st["used"] / total * 1000) if total else 0)
        self.usage_lbl.setText(f"{human_bytes(st['used'])} in {st['files']} files · {human_bytes(st['free'])} free on disk")
        self._untracked = self.lib.untracked()
        self._reload_nav()
        self.reload_files()
        self._reload_history()
        if self.library_name == "wordlists":
            self._reload_catalog()

    def _reload_nav(self) -> None:
        keep = self.nav.currentRow()
        self.nav.blockSignals(True)
        self.nav.clear()
        self.nav.addItem(f"All files ({len(self.lib.files())})")
        self.nav.addItem(f"★ Favorites ({len(self.lib.files(favorites=True))})")
        self.nav.addItem(f"Untracked files in folder ({len(self._untracked)})")
        self._nav_folders = ["", *sorted(f for f in self.lib.folders() if f)]
        counts = self.lib.folders()
        for f in self._nav_folders:
            self.nav.addItem(f"{f or '(library root)'} ({counts.get(f, 0)})")
        self.nav.setCurrentRow(max(keep, 0))
        self.nav.blockSignals(False)
        self._apply_nav(self.nav.currentRow())

    def _nav_changed(self, row: int) -> None:
        self._apply_nav(row)
        self.reload_files()

    def _apply_nav(self, row: int) -> None:
        self._view = "all" if row <= 0 else "favorites" if row == 1 else "untracked" if row == 2 else "folder"
        self._folder = self._nav_folders[row - 3] if row >= 3 and row - 3 < len(self._nav_folders) else ""

    def reload_files(self) -> None:
        self.table.setSortingEnabled(False)
        if self._view == "untracked":
            q = self.search.text().strip().lower()
            rows = [r for r in self._untracked if q in r.lower()]
            self._files = []
            self.table.setRowCount(len(rows))
            for i, rel in enumerate(rows):
                p = self.lib.root / rel
                size = p.stat().st_size if p.exists() else 0
                for c, (text, key) in enumerate([(rel, None), (human_bytes(size), size), ("", None),
                                                 ("not tracked yet", None), ("", None), ("", None)]):
                    item = NumItem(text, key) if c == 1 else QTableWidgetItem(text)
                    if c == 0:
                        item.setData(Qt.ItemDataRole.UserRole, rel)
                    self.table.setItem(i, c, item)
        else:
            self._files = self.lib.files(self._folder if self._view == "folder" else None, self.search.text(),
                                         self._view == "favorites")
            self.table.setRowCount(len(self._files))
            for i, d in enumerate(self._files):
                src = d["source_url"] or ("generated locally" if d["entry_id"] and d["entry_id"].startswith("synthetic")
                                          else "—")
                integ_text, integ_col = INTEGRITY.get(self._integrity.get(d["id"], ""), ("not verified", T.text_muted))
                cells = [(("★ " if d["favorite"] else "") + (d["rel"] if d["folder"] else d["name"]), None),
                         (human_bytes(d["size_bytes"] or 0), d["size_bytes"] or 0), (d["format"] or "", None),
                         (src, None), (d["acquired_at"] or fmt_ts(d["added_at"].replace(" ", "T") + "+00:00")[:10], None),
                         (integ_text, None)]
                for c, (text, key) in enumerate(cells):
                    item = NumItem(text, key) if c == 1 else QTableWidgetItem(text)
                    if c == 0:
                        item.setData(Qt.ItemDataRole.UserRole, d["id"])
                    if c == 5:
                        item.setForeground(QColor(integ_col))
                    self.table.setItem(i, c, item)
        self.table.setSortingEnabled(True)
        self._select()

    # ---- selection / details
    def _current_id(self) -> int | None:
        r = self.table.currentRow()
        item = self.table.item(r, 0) if r >= 0 else None
        v = item.data(Qt.ItemDataRole.UserRole) if item else None
        return v if isinstance(v, int) else None

    def _current_untracked(self) -> str | None:
        r = self.table.currentRow()
        item = self.table.item(r, 0) if r >= 0 else None
        v = item.data(Qt.ItemDataRole.UserRole) if item else None
        return v if isinstance(v, str) else None

    def _select(self) -> None:
        rid, rel = self._current_id(), self._current_untracked()
        tracked = rid is not None
        for b in (self.b_verify, self.b_fav, self.b_rename, self.b_untrack, self.b_delete):
            b.setEnabled(tracked)
            b.setVisible(self._view != "untracked")
        self.b_adopt.setVisible(self._view == "untracked")
        self.b_adopt.setEnabled(rel is not None)
        self.b_folder.setEnabled(tracked or rel is not None)
        if rel:
            self.details.setHtml(f"<h3>{esc(rel)}</h3><p style='color:{T.text_secondary}'>This file is in the library folder "
                                 "but WIFI Center is not tracking it. “Add to library” records its size, format and "
                                 "SHA-256 without moving or changing it.</p>")
            return
        d = self.lib.get(rid) if rid else None
        if not d:
            self.details.setHtml(f"<p style='color:{T.text_secondary}'>Select a file to see its checksum, source and "
                                 "license.</p>")
            return
        self.b_fav.setText("★ Unfavorite" if d["favorite"] else "★ Favorite")
        dup = self.lib.duplicate_of(d["sha256"], d["id"]) if d["sha256"] else None
        integ = INTEGRITY.get(self._integrity.get(rid, ""), ("not verified this session", T.text_muted))
        rows = [("Path", d["rel"]), ("Size", human_bytes(d["size_bytes"] or 0)), ("Format", d["format"] or "—"),
                ("Lines", f"{d['line_count']:,}" if d["line_count"] is not None else "—"),
                ("SHA-256", d["sha256"]), ("Last modified", fmt_ts(_mtime_iso(d["mtime"]))),
                ("Source", d["source_url"] or "—"), ("License", d["license"] or "—"),
                ("Attribution", d["attribution"] or "—"), ("Date obtained", d["acquired_at"] or "—"),
                ("Last verified", fmt_ts(d["last_verified"]) if d["last_verified"] else "never"),
                ("Duplicate of", self.lib.get(dup)["rel"] if dup else "no duplicate")]
        body = "".join(f"<tr><td style='color:{T.text_secondary}'>{k}&nbsp;</td><td>{esc(str(v))}</td></tr>" for k, v in rows)
        hist = "".join(f"<li>{esc(h['ts'])} {esc(h['action'])}</li>" for h in self.lib.history(rid, 5))
        self.details.setHtml(f"<h3>{esc(d['name'])}</h3><p style='color:{integ[1]}'>{integ[0]}</p><table cellpadding='3'>"
                             f"{body}</table><h4>History</h4><ul>{hist}</ul>")

    # ---- actions
    def _say(self, text: str, error: bool = False) -> None:
        self.msg.setText(f"<span style='color:{T.danger if error else T.text_secondary}'>{esc(text)}</span>")

    def _import(self, entry: rc.CatalogEntry | None = None) -> None:
        dlg = ImportDialog(self, self.lib, entry)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        v = dlg.values()
        self.loader.start()
        self._say("Importing and hashing…")

        def work():
            return self.lib.import_file(**v)

        def done(res) -> None:
            self.loader.stop()
            if res.id == 0:
                self._say(f"Not imported: identical to “{self.lib.get(res.duplicate_of)['rel']}” already in the library.")
            else:
                self.app.audit.record("library.import", library=self.library_name, id=res.id, source=v["source_url"])
                self._say("Imported" + (" (a duplicate of another file was kept because you asked for it)"
                                        if res.duplicate_of else "") + ".")
            self.reload()

        run_in_background(work, done, lambda e: (self.loader.stop(), self._say(f"Import failed: {e}", True)))

    def _adopt(self) -> None:
        rel = self._current_untracked()
        if not rel:
            return
        self.loader.start()

        def done(_rid) -> None:
            self.loader.stop()
            self.app.audit.record("library.adopt", library=self.library_name, path=rel)
            self._say(f"Now tracking {rel}.")
            self.reload()
        run_in_background(lambda: self.lib.adopt(rel), done, lambda e: (self.loader.stop(), self._say(str(e), True)))

    def _rename(self) -> None:
        rid = self._current_id()
        d = self.lib.get(rid) if rid else None
        if not d:
            return
        name, ok = QInputDialog.getText(self, "Rename", "New file name:", text=d["name"])
        if not ok:
            return
        try:
            self.lib.rename(rid, name)
        except (LibraryError, OSError) as e:
            self._say(str(e), True)
            return
        self.app.audit.record("library.rename", library=self.library_name, id=rid)
        self.reload()

    def _remove(self, delete: bool) -> None:
        rid = self._current_id()
        d = self.lib.get(rid) if rid else None
        if not d:
            return
        if delete:
            ok = confirm_dialog(self, "Delete file", f"Permanently delete <b>{esc(d['rel'])}</b> from disk?<br>"
                                f"({esc(str(self.lib.root))})<br>This cannot be undone.", "Delete file", danger=True)
        else:
            ok = confirm_dialog(self, "Remove from library", f"Stop tracking <b>{esc(d['rel'])}</b>?<br>The file stays "
                                "on disk and will appear under “Untracked files”.", "Remove from library")
        if ok:
            self.lib.remove(rid, delete_file=delete)
            self.app.audit.record("library.delete_file" if delete else "library.untrack", library=self.library_name, id=rid)
            self._integrity.pop(rid, None)
            self.reload()

    def _toggle_favorite(self) -> None:
        rid = self._current_id()
        d = self.lib.get(rid) if rid else None
        if d:
            self.lib.set_favorite(rid, not d["favorite"])
            self.reload()

    def _show_in_folder(self) -> None:
        rid, rel = self._current_id(), self._current_untracked()
        d = self.lib.get(rid) if rid else None
        target = (self.lib.root / (d["rel"] if d else rel)).parent if (d or rel) else self.lib.root
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(target)))

    def _verify_one(self) -> None:
        rid = self._current_id()
        if rid:
            self._run_verify([rid])

    def _verify_all(self) -> None:
        ids = [d["id"] for d in self.lib.files()]
        if ids:
            self._run_verify(ids)

    def _run_verify(self, ids: list[int]) -> None:
        self.loader.start()
        self._say(f"Verifying {len(ids)} file(s)…")

        def done(res: dict) -> None:
            self.loader.stop()
            self._integrity.update(res)
            bad = [i for i, s in res.items() if s != "ok"]
            self._say(f"Verified {len(res)} file(s): {len(res) - len(bad)} unchanged, {len(bad)} changed or missing.",
                      bool(bad))
            self.app.audit.record("library.verify", library=self.library_name, files=len(res), problems=len(bad))
            self.reload_files()
        run_in_background(lambda: {i: self.lib.verify(i) for i in ids}, done,
                          lambda e: (self.loader.stop(), self._say(f"Verification failed: {e}", True)))

    def _show_duplicates(self) -> None:
        groups = self.lib.duplicates()
        if not groups:
            self._say("No duplicate files (identical SHA-256) in the library.")
            return
        lines = [" = ".join(d["rel"] for d in g) for g in groups]
        self.details.setHtml("<h3>Duplicates</h3><ul>" + "".join(f"<li>{esc(l)}</li>" for l in lines) + "</ul>"
                             f"<p style='color:{T.text_secondary}'>Nothing is deleted automatically. Remove the copy you "
                             "do not need yourself.</p>")
        self._say(f"{len(groups)} group(s) of duplicate files found.")

    # ================================================================ catalog tab
    def _catalog_tab(self) -> QWidget:
        w = QWidget()
        lay = QHBoxLayout(w)
        lay.setContentsMargins(0, 8, 0, 0)
        self.ctable = make_table(["Entry", "Type", "License", "In library"], stretch_col=0)
        self.ctable.itemSelectionChanged.connect(self._cat_select)
        lay.addWidget(self.ctable, 3)
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        self.cdetails = QTextBrowser()
        self.cdetails.setOpenLinks(False)
        self.cdetails.anchorClicked.connect(lambda u: QDesktopServices.openUrl(u))
        rl.addWidget(self.cdetails, 1)
        self.c_open = MatrixButton("Open source page", icon_name="launch")
        self.c_open.clicked.connect(self._cat_open)
        self.c_check = MatrixButton("Check source and license…", icon_name="reset")
        self.c_check.clicked.connect(self._cat_check)
        self.c_import = MatrixButton("Import a copy I obtained…", "primary", "folder")
        self.c_import.clicked.connect(lambda: self._import(self._cat_entry()))
        self.c_gen = MatrixButton("Generate locally…", "primary")
        self.c_gen.clicked.connect(self._cat_generate)
        for x in (self.c_open, self.c_check, self.c_import, self.c_gen):
            rl.addWidget(x)
        lay.addWidget(right, 2)
        return w

    def _reload_catalog(self) -> None:
        counts: dict[str, int] = {}
        for d in self.lib.files():
            if d["entry_id"]:
                counts[d["entry_id"]] = counts.get(d["entry_id"], 0) + 1
        self.ctable.setRowCount(len(rc.CATALOG))
        for r, e in enumerate(rc.CATALOG):
            for c, v in enumerate([e.name, e.kind, e.license, str(counts.get(e.id, 0))]):
                item = QTableWidgetItem(v)
                if c == 0:
                    item.setData(Qt.ItemDataRole.UserRole, e.id)
                self.ctable.setItem(r, c, item)
        if self.ctable.currentRow() < 0:
            self.ctable.selectRow(0)
        self._cat_select()

    def _cat_entry(self) -> rc.CatalogEntry | None:
        r = self.ctable.currentRow()
        item = self.ctable.item(r, 0) if r >= 0 else None
        return rc.entry(item.data(Qt.ItemDataRole.UserRole)) if item else None

    def _cat_select(self) -> None:
        e = self._cat_entry()
        for b in (self.c_open, self.c_check, self.c_import, self.c_gen):
            b.setVisible(False)
        if not e:
            return
        self.c_open.setVisible(bool(e.source_url))
        self.c_check.setVisible(e.kind == "reference")
        self.c_import.setVisible(e.kind in ("reference", "local"))
        self.c_gen.setVisible(e.kind == "generated")
        rows = [("Type", {"reference": "Third-party reference (not bundled, not downloaded)",
                          "generated": "Generated locally from invented patterns", "local": "Supplied by you"}[e.kind]),
                ("Source", f"<a href='{esc(e.source_url)}'>{esc(e.source_url)}</a>" if e.source_url else "—"),
                ("License", esc(e.license)), ("Attribution", esc(e.attribution or "—")),
                ("License note", esc(e.license_note or "—"))]
        body = "".join(f"<tr><td style='color:{T.text_secondary}'>{k}&nbsp;</td><td>{v}</td></tr>" for k, v in rows)
        extra = ""
        if e.kind == "reference":
            extra = (f"<p style='color:{T.warning}'>Obtain this yourself, deliberately, from the source. WIFI Center does "
                     "not download it. Its content derives from real leaked credentials: treat copies as sensitive and "
                     "use them only for authorised offline testing.</p>")
        self.cdetails.setHtml(f"<h3>{esc(e.name)}</h3><p style='color:{T.text_secondary}'>{esc(e.description)}</p>"
                              f"<table cellpadding='3'>{body}</table>{extra}")

    def _cat_open(self) -> None:
        e = self._cat_entry()
        if e and e.source_url:
            QDesktopServices.openUrl(QUrl(e.source_url))
            self._say("Opened the source page in your browser. Download from there if you accept its license.")

    def _cat_check(self) -> None:
        e = self._cat_entry()
        if not e:
            return
        host = "api.github.com" if e.repo else (e.source_url.split("/")[2] if e.source_url else "the source")
        if not confirm_dialog(self, "Check source", f"Contact <b>{esc(host)}</b> to confirm the source still exists"
                              + (" and read its declared license" if e.repo else "") + "?<br>Your IP address is visible "
                              "to that site. Nothing is downloaded.", "Check source"):
            return
        self.loader.start()
        self._say("Checking…")

        def done(res: dict) -> None:
            self.loader.stop()
            self.lib.record_source_check(e.id, res)
            self.app.audit.record("library.source_check", entry=e.id, available=res.get("available"))
            extra = ""
            if res.get("license_matches") is False:
                extra = f" WARNING: the repository now declares {res['license']}, but this catalog records {e.license}. Re-read its license."
            self._say(f"{e.name}: {res.get('detail', '')}.{extra}", not res.get("available") or res.get("license_matches") is False)
            self._reload_history()
        run_in_background(lambda: LibraryService.check_source(e), done,
                          lambda err: (self.loader.stop(), self._say(f"Check failed: {err}", True)))

    def _cat_generate(self) -> None:
        e = self._cat_entry()
        if not e:
            return
        count = e.default_count
        if e.default_count:
            count, ok = QInputDialog.getInt(self, "Generate", f"How many entries ({e.name})?", e.default_count, 10, 100000)
            if not ok:
                return
        try:
            rid = self.lib.generate(e.id, count or None)
        except LibraryError as err:
            self._say(str(err), True)
            return
        self.app.audit.record("library.generate", entry=e.id, id=rid)
        self._say(f"Generated {self.lib.get(rid)['rel']} ({self.lib.get(rid)['line_count']:,} lines).")
        self.reload()

    # ================================================================ history tab
    def _history_tab(self) -> QWidget:
        self.htable = make_table(["When (UTC)", "Action", "Detail"], stretch_col=2)
        return self.htable

    def _reload_history(self) -> None:
        rows = self.lib.history()
        self.htable.setRowCount(len(rows))
        for r, h in enumerate(rows):
            for c, v in enumerate([h["ts"].replace("T", " ").removesuffix("+00:00"), h["action"], h["detail"] or ""]):
                self.htable.setItem(r, c, QTableWidgetItem(v))


def _mtime_iso(mtime: float | None) -> str | None:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(mtime, timezone.utc).isoformat(timespec="seconds") if mtime else None


# ====================================================================== documentation hub
class DocumentationPage(QWidget):
    """Official documentation and source links for every integrated tool, plus WIFI Center's own guides."""

    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app = app
        self._rows: list[tuple[str, str, str, str]] = []
        lay = QVBoxLayout(self)
        t = QLabel("Documentation")
        t.setObjectName("pageTitle")
        lay.addWidget(t)
        top = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search documentation…")
        self.search.textChanged.connect(self._fill)
        self.kind = QComboBox()
        self.kind.addItems(["All", "WIFI Center guides", "Tool documentation", "Tool source / project page"])
        self.kind.currentIndexChanged.connect(self._fill)
        top.addWidget(self.search, 2)
        top.addWidget(self.kind)
        lay.addLayout(top)
        self.table = make_table(["Title", "Type", "Location"], stretch_col=2)
        self.table.doubleClicked.connect(lambda *_: self._open())
        lay.addWidget(self.table, 1)
        row = QHBoxLayout()
        b = MatrixButton("Open", "primary", "launch")
        b.clicked.connect(self._open)
        self.msg = QLabel("Links open in your browser (or your default viewer for local files) only when you press Open.")
        self.msg.setObjectName("muted")
        row.addWidget(b)
        row.addWidget(self.msg, 1)
        lay.addLayout(row)
        self._load()
        self._fill()

    @staticmethod
    def local_docs() -> list[Path]:
        for base in (Path(__file__).resolve().parents[4] / "docs", Path("/usr/share/doc/wifi-center")):
            if base.is_dir():
                return sorted(p for p in base.iterdir() if p.suffix.lower() in (".md", ".txt", ".html"))
        return []

    def _load(self) -> None:
        for p in self.local_docs():
            self._rows.append((p.stem.replace("_", " "), "WIFI Center guides", str(p), "file"))
        for prof in PROFILES:
            self._rows.append((f"{prof.name} documentation", "Tool documentation", prof.docs_url, "url"))
            if prof.source_url != prof.docs_url:
                self._rows.append((f"{prof.name} source / project", "Tool source / project page", prof.source_url, "url"))

    def _visible(self) -> list[tuple[str, str, str, str]]:
        q = self.search.text().strip().lower()
        k = self.kind.currentText()
        return [r for r in self._rows if (k == "All" or r[1] == k) and (not q or q in r[0].lower() or q in r[2].lower())]

    def _fill(self) -> None:
        rows = self._visible()
        self.table.setRowCount(len(rows))
        for i, (title, kind, loc, _) in enumerate(rows):
            for c, v in enumerate([title, kind, loc]):
                self.table.setItem(i, c, QTableWidgetItem(v))
        self._shown = rows

    def _open(self) -> None:
        r = self.table.currentRow()
        if not (0 <= r < len(self._shown)):
            return
        title, _kind, loc, how = self._shown[r]
        QDesktopServices.openUrl(QUrl.fromLocalFile(loc) if how == "file" else QUrl(loc))
        self.msg.setText(f"Opened {title}.")

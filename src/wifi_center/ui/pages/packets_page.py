"""Packet Analysis: offline statistics for existing PCAP/PCAPNG files through TShark."""
from __future__ import annotations

import threading
from datetime import datetime, timezone

import pyqtgraph as pg
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QFileDialog, QHBoxLayout, QLabel, QPushButton, QTabWidget, QTableWidgetItem,
                               QVBoxLayout, QWidget)

from ...application.app_controller import AppController
from ...security.input_validation import ValidationError
from ...services.packet_service import PacketAnalysis, PacketError, validate_capture_path
from ...workers.task import run_in_background
from ..charts import color, make_plot, make_table
from ..widgets import human_bytes


class PacketsPage(QWidget):
    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app = app
        self.svc = app.packets
        self._cancel = threading.Event()
        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        t = QLabel("Packet Analysis")
        t.setObjectName("pageTitle")
        head.addWidget(t)
        head.addStretch(1)
        self.open_btn = QPushButton("Open capture…")
        self.open_btn.setObjectName("primary")
        self.open_btn.clicked.connect(self._open)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._cancel.set)
        head.addWidget(self.cancel_btn)
        head.addWidget(self.open_btn)
        lay.addLayout(head)
        self.banner = QLabel("")
        self.banner.setWordWrap(True)
        lay.addWidget(self.banner)
        note = QLabel("Analyzes capture files you already have (.pcap, .pcapng, .cap). WIFI Center does not capture "
                      "traffic. Use only captures you are authorized to analyze.")
        note.setObjectName("muted")
        note.setWordWrap(True)
        lay.addWidget(note)
        self.status = QLabel("")
        self.status.setObjectName("muted")
        self.status.setWordWrap(True)
        lay.addWidget(self.status)

        self.tabs = QTabWidget()
        self.summary = make_table(["Property", "Value"])
        self.proto_plot = make_plot("Packets by protocol", "", "packets")
        proto = QWidget()
        pl = QHBoxLayout(proto)
        self.proto_table = make_table(["Protocol", "Packets", "Share"])
        pl.addWidget(self.proto_plot, 3)
        pl.addWidget(self.proto_table, 2)
        self.conv = make_table(["Address A", "Address B", "Packets", "Bytes"])
        self.timeline = make_plot("Traffic over time", "seconds from first packet", "packets / s")
        self.tabs.addTab(self.summary, "Summary and metadata")
        self.tabs.addTab(proto, "Protocol distribution")
        self.tabs.addTab(self.conv, "Conversations")
        self.tabs.addTab(self.timeline, "Timeline")
        lay.addWidget(self.tabs, 1)
        self._check_tools()

    def _check_tools(self) -> None:
        if self.svc.available():
            self.banner.setText("<span style='color:#00FF66'>TShark detected.</span>")
            self.open_btn.setEnabled(True)
        else:
            self.banner.setText("<span style='color:#F2B84B'><b>TShark is not installed</b> — install it with "
                                "<code>sudo apt install tshark</code> to analyze captures.</span>")
            self.open_btn.setEnabled(False)

    def _open(self) -> None:
        name, _ = QFileDialog.getOpenFileName(self, "Open capture", "", "Captures (*.pcap *.pcapng *.cap)")
        if name:
            self.analyze(name)

    def analyze(self, path: str) -> None:
        try:
            validate_capture_path(path)
        except ValidationError as e:
            self.status.setText(f"Cannot open: {e}")
            return
        self._cancel.clear()
        self.open_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.status.setText(f"Analyzing {path}…")
        self.app.audit.record("packets.analyze", path=path)

        def work():
            return self.svc.analyze(path, cancel=self._cancel), self.svc.metadata(path)

        run_in_background(work, self._done, self._failed)

    def _failed(self, err: str) -> None:
        self.open_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.status.setText(f"Analysis failed: {err}")

    def _done(self, result) -> None:
        analysis, meta = result
        self.open_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        extra = " (cancelled — partial results)" if self._cancel.is_set() else \
            " (stopped at the packet limit — partial results)" if analysis.truncated else ""
        self.status.setText(f"Analyzed {analysis.packets:,} packets{extra}.")
        self.show_analysis(analysis, meta.values)

    # ---- rendering ----
    def show_analysis(self, a: PacketAnalysis, meta: dict[str, str]) -> None:
        first = datetime.fromtimestamp(a.first_ts, timezone.utc).isoformat(timespec="seconds") if a.first_ts else "—"
        rows = [("File", a.path), ("Packets analyzed", f"{a.packets:,}"), ("Total bytes", human_bytes(a.total_bytes)),
                ("Duration", f"{a.duration:.2f} s"), ("First packet (UTC)", first),
                ("Distinct conversations", f"{len(a.conversations):,}")] + list(meta.items())
        self.summary.setRowCount(len(rows))
        for r, (k, v) in enumerate(rows):
            self.summary.setItem(r, 0, QTableWidgetItem(k))
            self.summary.setItem(r, 1, QTableWidgetItem(v))
        self.summary.resizeColumnToContents(0)

        protos = a.protocols.most_common(15)
        self.proto_table.setRowCount(len(protos))
        for r, (p, n) in enumerate(protos):
            for c, v in enumerate([p, f"{n:,}", f"{n / a.packets * 100:.1f} %" if a.packets else ""]):
                self.proto_table.setItem(r, c, QTableWidgetItem(v))
        self.proto_plot.clear()
        if protos:
            self.proto_plot.addItem(pg.BarGraphItem(x=list(range(len(protos))), height=[n for _, n in protos],
                                                    width=0.7, brush=color(0), pen=None))
            self.proto_plot.getAxis("bottom").setTicks([[(i, p) for i, (p, _) in enumerate(protos)]])

        convs = a.top_conversations(50)
        self.conv.setRowCount(len(convs))
        for r, (x, y, n, b) in enumerate(convs):
            for c, v in enumerate([x, y, f"{n:,}", human_bytes(b)]):
                self.conv.setItem(r, c, QTableWidgetItem(v))

        self.timeline.clear()
        if a.timeline:
            end = max(a.timeline)
            xs = list(range(end + 1))
            self.timeline.addItem(pg.BarGraphItem(x=xs, height=[a.timeline.get(s, [0, 0])[0] for s in xs],
                                                  width=0.9, brush=color(1), pen=None))

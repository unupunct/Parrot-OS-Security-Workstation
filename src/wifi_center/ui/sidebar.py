"""MATRIX PRO navigation sidebar: logo, collapsible groups, animated active indicator, badges."""
from __future__ import annotations

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, QRect, QSize, Qt, QVariantAnimation, Signal
from PySide6.QtGui import QColor, QFont, QKeyEvent, QPainter
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QPushButton, QScrollArea, QVBoxLayout, QWidget)

from .design.components import Badge, LogoWidget
from .design.icons import icon_pixmap
from .design.motion import Motion
from .design.tokens import T, mix
from .navigation import NAVIGATION


class NavButton(QPushButton):
    """One navigation row: icon + title + optional badge; colour eases between idle/hover/active."""

    def __init__(self, page_id: str, title: str, tooltip: str) -> None:
        super().__init__()
        self.page_id = page_id
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(36)
        self.setToolTip(tooltip)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self._title = title
        self._mix = 0.0       # 0 idle .. 1 hover/active
        self._anim: QVariantAnimation | None = None
        self.badge = Badge("", "info", self)
        self.badge.hide()
        self.setAccessibleName(title)

    def sizeHint(self) -> QSize:  # noqa: N802
        return QSize(200, 36)

    def set_badge(self, text: str | None, level: str = "info") -> None:
        if not text:
            self.badge.hide()
            return
        self.badge.setText(text)
        self.badge.set_level(level)
        self.badge.adjustSize()
        self.badge.show()
        self._place_badge()

    def _place_badge(self) -> None:
        self.badge.move(self.width() - self.badge.width() - 12, (self.height() - self.badge.height()) // 2)

    def resizeEvent(self, e) -> None:  # noqa: N802
        super().resizeEvent(e)
        self._place_badge()

    def _ease_to(self, target: float) -> None:
        if self._anim:
            self._anim.stop()
        dur = Motion.instance().duration(140)
        if dur == 0:
            self._mix = target
            self.update()
            return
        self._anim = QVariantAnimation(self)
        self._anim.setStartValue(self._mix)
        self._anim.setEndValue(target)
        self._anim.setDuration(dur)
        self._anim.valueChanged.connect(self._set_mix)
        self._anim.start()

    def _set_mix(self, v) -> None:
        self._mix = float(v)
        self.update()

    def enterEvent(self, e) -> None:  # noqa: N802
        if not self.isChecked():
            self._ease_to(0.6)
        super().enterEvent(e)

    def leaveEvent(self, e) -> None:  # noqa: N802
        if not self.isChecked():
            self._ease_to(0.0)
        super().leaveEvent(e)

    def setChecked(self, on: bool) -> None:  # noqa: N802
        super().setChecked(on)
        self._ease_to(1.0 if on else 0.0)

    def focusInEvent(self, e) -> None:  # noqa: N802
        super().focusInEvent(e)
        self.update()

    def paintEvent(self, _e) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        active = self.isChecked()
        if self._mix > 0:
            bg = QColor(T.green)
            bg.setAlphaF((0.11 if active else 0.07) * self._mix)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(bg)
            p.drawRoundedRect(QRect(8, 2, self.width() - 16, self.height() - 4), 7, 7)
        if self.hasFocus() and not active:
            p.setPen(QColor(T.border_active))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawRoundedRect(QRect(8, 2, self.width() - 16, self.height() - 4), 7, 7)
        color = mix(T.text_secondary, T.green, self._mix) if active or self._mix else T.text_secondary
        p.drawPixmap(22, (self.height() - 18) // 2, icon_pixmap(self.page_id, color, 18, 2.0))
        p.setPen(QColor(mix(T.text_secondary, T.text, min(1.0, self._mix * 1.2))))
        f = self.font()
        f.setWeight(QFont.Weight.DemiBold if active else QFont.Weight.Normal)
        p.setFont(f)
        p.drawText(QRect(52, 0, self.width() - 100, self.height()), Qt.AlignmentFlag.AlignVCenter, self._title)


class CategorySection(QWidget):
    """Collapsible group. `setExpanded` / `isExpanded` mirror the old tree API."""

    toggled = Signal(str, bool)

    def __init__(self, title: str) -> None:
        super().__init__()
        self.title = title
        self._expanded = True
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        self.head = QPushButton()
        self.head.setCursor(Qt.CursorShape.PointingHandCursor)
        self.head.setFixedHeight(30)
        self.head.setStyleSheet("QPushButton { background: transparent; border: none; text-align: left; padding: 0 18px; }")
        hl = QHBoxLayout(self.head)
        hl.setContentsMargins(18, 0, 14, 0)
        self.label = QLabel(title)
        self.label.setObjectName("navCategory")
        self.chev = QLabel()
        self.chev.setFixedSize(14, 14)
        hl.addWidget(self.label)
        hl.addStretch(1)
        hl.addWidget(self.chev)
        for w in (self.label, self.chev):
            w.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.head.clicked.connect(lambda: self.setExpanded(not self._expanded))
        lay.addWidget(self.head)
        self.body = QWidget()
        self.body_lay = QVBoxLayout(self.body)
        self.body_lay.setContentsMargins(0, 0, 0, 4)
        self.body_lay.setSpacing(1)
        lay.addWidget(self.body)
        self._anim: QPropertyAnimation | None = None
        self._update_chevron()

    def add_button(self, b: NavButton) -> None:
        self.body_lay.addWidget(b)

    def isExpanded(self) -> bool:  # noqa: N802
        return self._expanded

    def setExpanded(self, expanded: bool, animate: bool = True) -> None:  # noqa: N802
        if expanded == self._expanded:
            return
        self._expanded = expanded
        self._update_chevron()
        full = self.body.sizeHint().height()
        dur = Motion.instance().duration(180) if animate and self.isVisible() else 0
        if self._anim:
            self._anim.stop()
        if dur == 0:
            self.body.setMaximumHeight(16777215 if expanded else 0)
            self.body.setVisible(expanded)
        else:
            self.body.setVisible(True)
            self._anim = QPropertyAnimation(self.body, b"maximumHeight", self)
            self._anim.setDuration(dur)
            self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
            self._anim.setStartValue(self.body.height() if self.body.isVisible() else 0)
            self._anim.setEndValue(full if expanded else 0)
            self._anim.finished.connect(lambda: self.body.setMaximumHeight(16777215) if expanded
                                        else self.body.setVisible(False))
            self._anim.start()
        self.toggled.emit(self.title, expanded)

    def _update_chevron(self) -> None:
        pm = icon_pixmap("chevron", T.text_muted, 14, 2.0)
        from PySide6.QtGui import QTransform
        if self._expanded:
            pm = pm.transformed(QTransform().rotate(90), Qt.TransformationMode.SmoothTransformation)
        self.chev.setPixmap(pm)


class Sidebar(QFrame):
    page_selected = Signal(str)

    def __init__(self, collapsed: list[str] | None = None, accent: str = T.green) -> None:
        super().__init__()
        self.setObjectName("sidebarPane")
        self.setMinimumWidth(236)
        self._buttons: dict[str, NavButton] = {}
        self._cats: dict[str, CategorySection] = {}
        self._current: str | None = None
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        self.logo = LogoWidget(accent)
        root.addWidget(self.logo)
        sep = QFrame()
        sep.setObjectName("navSeparator")
        root.addWidget(sep)

        self.scroll = QScrollArea()
        self.scroll.setObjectName("sidebarScroll")
        self.scroll.setWidgetResizable(True)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        inner = QWidget()
        inner.setObjectName("sidebarInner")
        self.inner_lay = QVBoxLayout(inner)
        self.inner_lay.setContentsMargins(0, 8, 0, 12)
        self.inner_lay.setSpacing(2)
        self.scroll.setWidget(inner)
        root.addWidget(self.scroll, 1)

        # luminous indicator that slides between rows
        self.indicator = QFrame(inner)
        self.indicator.setFixedWidth(3)
        self.indicator.setStyleSheet(f"background: {accent}; border-radius: 1px;")
        self.indicator.hide()
        self._ind_anim = QPropertyAnimation(self.indicator, b"geometry", self)

        collapsed = collapsed or []
        for i, cat in enumerate(NAVIGATION):
            if i:
                line = QFrame()
                line.setObjectName("navSeparator")
                line.setContentsMargins(18, 0, 18, 0)
                self.inner_lay.addWidget(line)
            section = CategorySection(cat.title)
            for it in cat.items:
                b = NavButton(it.id, it.title, it.summary)
                b.clicked.connect(lambda _=False, pid=it.id: self._clicked(pid))
                section.add_button(b)
                self._buttons[it.id] = b
            self._cats[cat.title] = section
            self.inner_lay.addWidget(section)
            if cat.title in collapsed:
                section.setExpanded(False, animate=False)
        self.inner_lay.addStretch(1)
        self.scroll.verticalScrollBar().valueChanged.connect(lambda _v: self._move_indicator(animate=False))

    # ---- selection ----
    def _clicked(self, page_id: str) -> None:
        self.select_page(page_id)

    def select_page(self, page_id: str) -> None:
        if page_id not in self._buttons:
            return
        for pid, b in self._buttons.items():
            b.setChecked(pid == page_id)
        self._current = page_id
        for cat in NAVIGATION:
            if any(i.id == page_id for i in cat.items):
                self._cats[cat.title].setExpanded(True)
        self._move_indicator(animate=True)
        self.page_selected.emit(page_id)

    def _target_rect(self) -> QRect | None:
        b = self._buttons.get(self._current or "")
        if not b or not b.isVisible():
            return None
        top_left = b.mapTo(self.indicator.parentWidget(), b.rect().topLeft())
        return QRect(0, top_left.y() + 7, 3, b.height() - 14)

    def _move_indicator(self, animate: bool = True) -> None:
        r = self._target_rect()
        if r is None:
            self.indicator.hide()
            return
        self.indicator.show()
        self.indicator.raise_()
        dur = Motion.instance().duration(220) if animate else 0
        self._ind_anim.stop()
        if dur == 0 or not self.indicator.isVisible():
            self.indicator.setGeometry(r)
            return
        self._ind_anim.setDuration(dur)
        self._ind_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._ind_anim.setStartValue(self.indicator.geometry())
        self._ind_anim.setEndValue(r)
        self._ind_anim.start()
        self.scroll.ensureWidgetVisible(self._buttons[self._current], 0, 40)  # type: ignore[index]

    def resizeEvent(self, e) -> None:  # noqa: N802
        super().resizeEvent(e)
        self._move_indicator(animate=False)

    def showEvent(self, e) -> None:  # noqa: N802
        super().showEvent(e)
        self._move_indicator(animate=False)

    # ---- state ----
    def collapsed_categories(self) -> list[str]:
        return [t for t, s in self._cats.items() if not s.isExpanded()]

    def set_badge(self, page_id: str, text: str | None, level: str = "info") -> None:
        b = self._buttons.get(page_id)
        if b:
            b.set_badge(text, level)

    def set_accent(self, accent: str) -> None:
        self.logo.set_accent(accent)
        self.indicator.setStyleSheet(f"background: {accent}; border-radius: 1px;")

    # ---- keyboard: Up/Down move between visible rows ----
    def keyPressEvent(self, e: QKeyEvent) -> None:  # noqa: N802
        if e.key() in (Qt.Key.Key_Down, Qt.Key.Key_Up):
            visible = [b for b in self._buttons.values() if b.isVisible()]
            fw = self.focusWidget()
            if fw in visible:
                i = visible.index(fw) + (1 if e.key() == Qt.Key.Key_Down else -1)
                if 0 <= i < len(visible):
                    visible[i].setFocus()
                return
        super().keyPressEvent(e)

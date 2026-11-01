"""Qt6-Oberfläche (PySide6)."""
from __future__ import annotations

import sys
import threading
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from PySide6.QtCore import QDateTime, QObject, Qt, QThread, QTimer, Signal
from PySide6.QtWidgets import (
    QApplication, QDateTimeEdit, QFileDialog, QFormLayout, QHBoxLayout, QLabel,
    QLineEdit, QMainWindow, QPlainTextEdit, QProgressBar, QPushButton,
    QTabWidget, QVBoxLayout, QWidget,
)

from .. import __version__, core, strings as S
from ..cli import _local, format_info
from ..config import Settings
from ..drand import DrandError
from ..tle import Cancelled, TleError, TleNotFound
from ..tsa import TsaError

PHASES = {"encrypt": S.PH_ENCRYPT, "decrypt": S.PH_DECRYPT,
          "timestamp": S.PH_TIMESTAMP, "hash": S.PH_HASH}


def describe_error(exc: BaseException) -> str:
    if isinstance(exc, Cancelled):
        return S.MSG_CANCELLED
    if isinstance(exc, TleNotFound):
        return S.MSG_NO_TLE.format(detail=exc)
    if isinstance(exc, DrandError):
        return S.MSG_NO_NETWORK.format(detail=exc)
    if isinstance(exc, TsaError):
        return S.MSG_TSA.format(detail=exc)
    if isinstance(exc, core.TargetInPast):
        return S.MSG_TARGET_PAST + "\n\n" + str(exc)
    # Unerwarteter Fehler: Typ und Aufrufstelle mit ausgeben, damit er sich
    # ohne Konsole (PyInstaller, windowed) eingrenzen lässt.
    tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)[-12:])
    return S.MSG_ERROR.format(detail=f"{type(exc).__name__}: {exc}") + "\n\n" + tb


class Worker(QThread):
    progress = Signal(str, int, int)
    done = Signal(object)
    failed = Signal(object)

    def __init__(self, fn: Callable, parent: QObject | None = None):
        super().__init__(parent)
        self.fn = fn
        self.cancel = threading.Event()

    def run(self) -> None:
        try:
            res = self.fn(self.cancel, lambda ph, d, t: self.progress.emit(ph, d, t))
        except BaseException as exc:  # noqa: BLE001
            self.failed.emit(exc)
        else:
            self.done.emit(res)


class DropLineEdit(QLineEdit):
    def __init__(self, placeholder: str = ""):
        super().__init__()
        self.setPlaceholderText(placeholder)
        self.setAcceptDrops(True)

    def dragEnterEvent(self, e):  # noqa: N802
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e):  # noqa: N802
        urls = e.mimeData().urls()
        if urls and urls[0].isLocalFile():
            self.setText(urls[0].toLocalFile())
            self.editingFinished.emit()


class OpPanel(QWidget):
    """Gemeinsamer Teil: Fortschritt, Abbrechen, Ergebnistext."""

    def __init__(self):
        super().__init__()
        self.worker: Worker | None = None
        self.bar = QProgressBar()
        self.bar.setVisible(False)
        self.phase = QLabel()
        self.cancel_btn = QPushButton(S.BTN_CANCEL)
        self.cancel_btn.setVisible(False)
        self.cancel_btn.clicked.connect(self._cancel)
        self.result = QPlainTextEdit()
        self.result.setReadOnly(True)

    def progress_row(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.addWidget(self.phase)
        row.addWidget(self.bar, 1)
        row.addWidget(self.cancel_btn)
        return row

    def start(self, fn, on_done, buttons: list[QPushButton]):
        self.result.clear()
        self.phase.setText(S.PH_CONNECT)
        self.bar.setRange(0, 0)
        self.bar.setVisible(True)
        self.cancel_btn.setVisible(True)
        for b in buttons:
            b.setEnabled(False)
        w = Worker(fn, self)
        w.progress.connect(self._on_progress)

        def finish():
            self.bar.setVisible(False)
            self.cancel_btn.setVisible(False)
            self.phase.clear()
            for b in buttons:
                b.setEnabled(True)
            self.worker = None

        w.done.connect(lambda r: (finish(), on_done(r)))
        w.failed.connect(lambda e: (finish(), self.on_failed(e)))
        self.worker = w
        w.start()

    def on_failed(self, exc: BaseException) -> None:
        self.result.setPlainText(describe_error(exc))

    def _on_progress(self, phase: str, done: int, total: int) -> None:
        self.phase.setText(PHASES.get(phase, phase))
        if total > 0:
            self.bar.setRange(0, 1000)
            self.bar.setValue(int(1000 * done / total))
        else:
            self.bar.setRange(0, 0)

    def _cancel(self):
        if self.worker:
            self.worker.cancel.set()


class EncryptTab(OpPanel):
    def __init__(self, settings: Settings):
        super().__init__()
        self.settings = settings
        self.src = DropLineEdit(S.DROP_HINT)
        self.src.editingFinished.connect(self._suggest_output)
        src_btn = QPushButton(S.BTN_CHOOSE)
        src_btn.clicked.connect(self._choose_src)

        self.when = QDateTimeEdit(QDateTime.currentDateTime().addDays(1))
        self.when.setCalendarPopup(True)
        self.when.setDisplayFormat("dd.MM.yyyy HH:mm")
        self.when.dateTimeChanged.connect(self._update_utc)
        self.utc = QLabel()

        self.out = QLineEdit()
        out_btn = QPushButton(S.BTN_CHOOSE)
        out_btn.clicked.connect(self._choose_out)

        self.go = QPushButton(S.BTN_ENCRYPT)
        self.go.clicked.connect(self._run)
        hint = QLabel(S.MSG_SOURCE_WARNING)
        hint.setWordWrap(True)
        hint.setStyleSheet("color: palette(mid);")

        form = QFormLayout()
        r1 = QHBoxLayout(); r1.addWidget(self.src, 1); r1.addWidget(src_btn)
        form.addRow(S.LBL_SOURCE, r1)
        r2 = QHBoxLayout(); r2.addWidget(self.when); r2.addWidget(self.utc, 1)
        form.addRow(S.LBL_TARGET, r2)
        r3 = QHBoxLayout(); r3.addWidget(self.out, 1); r3.addWidget(out_btn)
        form.addRow(S.LBL_OUTPUT, r3)

        lay = QVBoxLayout(self)
        lay.addLayout(form)
        lay.addWidget(hint)
        lay.addWidget(self.go)
        lay.addLayout(self.progress_row())
        lay.addWidget(self.result, 1)
        self._update_utc()

    def target(self) -> datetime:
        return self.when.dateTime().toPython().astimezone()

    def _update_utc(self):
        utc = self.target().astimezone(timezone.utc)
        self.utc.setText(S.LBL_TARGET_UTC.format(utc=utc.strftime("%d.%m.%Y %H:%M")))
        self._suggest_output(force=False)

    def _choose_src(self):
        fn, _ = QFileDialog.getOpenFileName(self, S.LBL_SOURCE)
        if fn:
            self.src.setText(fn)
            self._suggest_output(force=True)

    def _suggest_output(self, force: bool = True):
        src = self.src.text().strip()
        if not src:
            return
        if force or not self.out.text() or self.out.text().endswith(".pytlock"):
            name = core.default_output_name(self.target())
            self.out.setText(str(Path(src).with_name(name)))

    def _choose_out(self):
        fn, _ = QFileDialog.getSaveFileName(self, S.LBL_OUTPUT, self.out.text(),
                                            "pytlock (*.pytlock)")
        if fn:
            self.out.setText(fn)

    def _run(self):
        src = Path(self.src.text().strip())
        out = Path(self.out.text().strip())
        if not src.is_file():
            self.result.setPlainText(S.MSG_ERROR.format(detail=f"Datei nicht gefunden: {src}"))
            return
        target = self.target()
        st = self.settings

        def job(cancel, progress):
            return core.encrypt_file(src, out, target, drand=st.drand(), tle=st.tle(),
                                     tsas=st.tsas, post=st.post, anchors=st.anchors,
                                     progress=progress, cancel=cancel)

        self.start(job, self._done, [self.go])

    def _done(self, res: core.EncryptResult):
        first = min(res.stamps, key=lambda s: s.info.gen_time)
        self.result.setPlainText(S.MSG_DONE_ENCRYPT.format(
            output=res.output, unlock=_local(res.unlock_time), round=res.round,
            submitted=_local(first.info.gen_time), tsa=first.tsa_name))


class DecryptTab(OpPanel):
    def __init__(self, settings: Settings):
        super().__init__()
        self.settings = settings
        self.info: core.ContainerInfo | None = None
        self.remaining = 0
        self.unlock_text = ""
        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self._tick)

        self.src = DropLineEdit(S.DROP_HINT)
        self.src.editingFinished.connect(self._inspect)
        src_btn = QPushButton(S.BTN_CHOOSE)
        src_btn.clicked.connect(self._choose_src)
        self.details = QLabel()
        self.details.setWordWrap(True)
        self.details.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.outdir = QLineEdit()
        out_btn = QPushButton(S.BTN_CHOOSE)
        out_btn.clicked.connect(self._choose_dir)
        self.go = QPushButton(S.BTN_DECRYPT)
        self.go.clicked.connect(self._run)
        self.go.setEnabled(False)

        form = QFormLayout()
        r1 = QHBoxLayout(); r1.addWidget(self.src, 1); r1.addWidget(src_btn)
        form.addRow(S.LBL_CONTAINER, r1)
        r2 = QHBoxLayout(); r2.addWidget(self.outdir, 1); r2.addWidget(out_btn)
        form.addRow(S.LBL_OUTDIR, r2)
        lay = QVBoxLayout(self)
        lay.addLayout(form)
        lay.addWidget(self.details)
        lay.addWidget(self.go)
        lay.addLayout(self.progress_row())
        lay.addWidget(self.result, 1)

    def _choose_src(self):
        fn, _ = QFileDialog.getOpenFileName(self, S.LBL_CONTAINER, "",
                                            "pytlock (*.pytlock);;Alle Dateien (*)")
        if fn:
            self.src.setText(fn)
            self._inspect()

    def _choose_dir(self):
        d = QFileDialog.getExistingDirectory(self, S.LBL_OUTDIR, self.outdir.text())
        if d:
            self.outdir.setText(d)

    def _inspect(self):
        p = Path(self.src.text().strip())
        self.timer.stop()
        self.go.setEnabled(False)
        if not p.is_file():
            return
        if not self.outdir.text():
            self.outdir.setText(str(p.parent))

        def job(cancel, progress):
            return core.inspect(p, anchors=self.settings.anchors, progress=progress)

        def done(info: core.ContainerInfo):
            self.info = info
            text = format_info(info)
            if info.stamp_errors:
                text += "\n" + "\n".join(info.stamp_errors)
            self.details.setText(text)
            self.go.setEnabled(True)

        self.start(job, done, [self.go])

    def _run(self):
        if not self.info:
            return
        path = self.info.path
        out = Path(self.outdir.text().strip() or path.parent)
        st = self.settings

        def job(cancel, progress):
            return core.decrypt_file(path, out, drand=st.drand(), tle=st.tle(),
                                     anchors=st.anchors, progress=progress, cancel=cancel)

        self.start(job, self._done, [self.go])

    def on_failed(self, exc):
        if isinstance(exc, core.NotYet):
            self.remaining = exc.remaining_seconds
            self.unlock_text = _local(exc.unlock_time)
            self._tick(first=True)
            self.timer.start()
        else:
            super().on_failed(exc)

    def _tick(self, first: bool = False):
        # Nur Anzeige: Ausgangswert stammt vom drand-Netz, nicht von der lokalen Uhr.
        if not first:
            self.remaining = max(0, self.remaining - 1)
        self.result.setPlainText(S.MSG_NOT_YET.format(
            unlock=self.unlock_text, remaining=S.fmt_duration(self.remaining)))
        if self.remaining == 0:
            self.timer.stop()

    def _done(self, r: core.DecryptResult):
        self.result.setPlainText(S.MSG_DONE_DECRYPT.format(output=r.output, size=r.size))


class MainWindow(QMainWindow):
    def __init__(self, settings: Settings | None = None):
        super().__init__()
        settings = settings or Settings.load()
        self.setWindowTitle(f"{S.APP_TITLE}  v{__version__}")
        tabs = QTabWidget()
        self.enc = EncryptTab(settings)
        self.dec = DecryptTab(settings)
        tabs.addTab(self.enc, S.TAB_ENCRYPT)
        tabs.addTab(self.dec, S.TAB_DECRYPT)
        self.setCentralWidget(tabs)
        self.resize(720, 520)


def main() -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("pytlock")
    w = MainWindow()
    w.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())

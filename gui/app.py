"""Main GUI window. Single-file for now; split into per-tab modules later."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem, QMessageBox,
)
from PySide6.QtCore import QThread, Signal, QObject, Qt
from PySide6.QtGui import QColor

from core.discovery import expand_targets, discover
from core.models import OSFamily

# Colour palette (soft backgrounds so text stays readable).
_CONF_COLOURS = {
    "high":   QColor(200, 230, 201),   # green
    "medium": QColor(255, 236, 179),   # amber
    "low":    QColor(224, 224, 224),   # grey
}
_OS_COLOURS = {
    OSFamily.WINDOWS: QColor(187, 222, 251),   # blue
    OSFamily.UNIX:    QColor(255, 224, 178),   # orange
}


class AppState:
    """Shared data the tabs pass between each other (discovery -> access -> collect)."""
    def __init__(self):
        self.hosts = []


class ScanWorker(QObject):
    host_found = Signal(object)
    finished = Signal(int)
    error = Signal(str)             # <-- new

    def __init__(self, ips):
        super().__init__()
        self.ips = ips

    def run(self):
        try:
            discover(self.ips, progress=self.host_found.emit)
        except Exception as exc:
            self.error.emit(str(exc))
        self.finished.emit(len(self.ips))

class DiscoveryTab(QWidget):
    def __init__(self, state: AppState):
        super().__init__()
        self.state = state
        self.scanned_count = 0
        layout = QVBoxLayout(self)

        row = QHBoxLayout()
        row.addWidget(QLabel("Target(s):"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("10.10.10.100-103   ·   192.168.1.0/24   ·   single IP")
        row.addWidget(self.target_input)
        self.scan_btn = QPushButton("Scan")
        self.scan_btn.clicked.connect(self.on_scan)
        row.addWidget(self.scan_btn)
        layout.addLayout(row)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Host", "Status", "OS guess", "Confidence", "Basis"])
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)

        self.status_label = QLabel("Ready.")
        layout.addWidget(self.status_label)

    def on_scan(self):
        text = self.target_input.text().strip()
        if not text:
            return
        try:
            ips = expand_targets(text)
        except Exception as exc:
            QMessageBox.warning(self, "Invalid target", f"Could not parse that:\n{exc}")
            return

        self.scan_btn.setEnabled(False)
        self.scan_btn.setText("Scanning…")
        self.status_label.setText(f"Scanning {len(ips)} address(es)…")
        self.table.setRowCount(0)
        self.state.hosts = []

        self.thread = QThread()
        self.worker = ScanWorker(ips)
        self.worker.error.connect(lambda msg: QMessageBox.warning(self, "Scan error", msg))
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.host_found.connect(self.on_host_found)
        self.worker.finished.connect(self.on_scan_done)
        self.worker.finished.connect(self.thread.quit)
        self.thread.start()

    def on_host_found(self, host):
        self.state.hosts.append(host)
        self.add_row(host)

    def on_scan_done(self, total_scanned):
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("Scan")
        up = len(self.state.hosts)
        self.status_label.setText(f"{up} host(s) up of {total_scanned} scanned.")

    def add_row(self, h):
        r = self.table.rowCount()
        self.table.insertRow(r)

        cells = [
            h.ip,
            "up",
            h.os_guess.value,
            h.confidence,
            h.fingerprint_basis,
        ]
        for c, val in enumerate(cells):
            item = QTableWidgetItem(str(val))
            self.table.setItem(r, c, item)

        # Colour the OS-guess cell by platform.
        os_colour = _OS_COLOURS.get(h.os_guess)
        if os_colour:
            self.table.item(r, 2).setBackground(os_colour)

        # Colour the confidence cell green/amber/grey.
        conf_colour = _CONF_COLOURS.get(h.confidence)
        if conf_colour:
            self.table.item(r, 3).setBackground(conf_colour)

        # Status cell: green text for "up".
        self.table.item(r, 1).setForeground(QColor(46, 125, 50))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Remote Triage Collector")
        self.resize(600, 650)
        self.state = AppState()

        tabs = QTabWidget()
        tabs.addTab(DiscoveryTab(self.state), "1 · Discovery")
        for name in ("2 · Access", "3 · Collect", "Log"):
            page = QWidget()
            lay = QVBoxLayout(page)
            lay.addWidget(QLabel(f"{name} — coming soon"))
            tabs.addTab(page, name)
        self.setCentralWidget(tabs)


def run():
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec()
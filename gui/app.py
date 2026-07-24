"""Main GUI window. Single-file for now; split into per-tab modules later."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem, QMessageBox,
)

from core.discovery import expand_targets, discover
from PySide6.QtCore import QThread, Signal, QObject

class AppState:
    """Shared data the tabs pass between each other (discovery -> access -> collect)."""
    def __init__(self):
        self.hosts = []          # list[Host] produced by discovery

class ScanWorker(QObject):
    """Runs discovery on a background thread, emitting each host as it's found."""
    host_found = Signal(object)      # emits a Host
    finished = Signal()

    def __init__(self, ips):
        super().__init__()
        self.ips = ips

    def run(self):
        discover(self.ips, progress=self.host_found.emit)
        self.finished.emit()

class DiscoveryTab(QWidget):
    def __init__(self, state: AppState):
        super().__init__()
        self.state = state
        layout = QVBoxLayout(self)

        # --- input row: label, text box, Scan button ---
        row = QHBoxLayout()
        row.addWidget(QLabel("Target(s):"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("10.10.10.100-103   ·   192.168.1.0/24   ·   single IP")
        row.addWidget(self.target_input)
        self.scan_btn = QPushButton("Scan")
        self.scan_btn.clicked.connect(self.on_scan)
        row.addWidget(self.scan_btn)
        layout.addLayout(row)

        # --- results table ---
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Host", "Status", "OS guess", "Confidence", "Basis"])
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)

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
        self.table.setRowCount(0)
        self.state.hosts = []

        # Set up the worker on its own thread.
        self.thread = QThread()
        self.worker = ScanWorker(ips)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.host_found.connect(self.on_host_found)   # runs on UI thread
        self.worker.finished.connect(self.on_scan_done)
        self.worker.finished.connect(self.thread.quit)
        self.thread.start()

    def on_host_found(self, host):
        self.state.hosts.append(host)
        self.add_row(host)

    def on_scan_done(self):
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("Scan")

    def add_row(self, h):
        r = self.table.rowCount()
        self.table.insertRow(r)
        status = "up" if h.is_up else "down"
        os_txt = h.os_guess.value if h.is_up else "—"
        conf = h.confidence if h.is_up else "—"
        basis = h.fingerprint_basis if h.is_up else ""
        for c, val in enumerate([h.ip, status, os_txt, conf, basis]):
            self.table.setItem(r, c, QTableWidgetItem(str(val)))

    def on_scan(self):
        text = self.target_input.text().strip()
        if not text:
            return
        try:
            ips = expand_targets(text)
        except Exception as exc:
            QMessageBox.warning(self, "Invalid target", f"Could not parse that:\n{exc}")
            return

        # Show feedback, then run the (blocking) scan. processEvents lets the
        # button repaint first; the window still freezes during the scan itself
        # - that's what we fix with threading next.
        self.scan_btn.setEnabled(False)
        self.scan_btn.setText("Scanning…")
        QApplication.processEvents()
        try:
            hosts = discover(ips)
        finally:
            self.scan_btn.setEnabled(True)
            self.scan_btn.setText("Scan")

        self.state.hosts = hosts     # share with the other tabs
        self.populate(hosts)

    def populate(self, hosts):
        self.table.setRowCount(len(hosts))
        for r, h in enumerate(hosts):
            status = "up" if h.is_up else "down"
            os_txt = h.os_guess.value if h.is_up else "—"
            conf = h.confidence if h.is_up else "—"
            basis = h.fingerprint_basis if h.is_up else ""
            for c, val in enumerate([h.ip, status, os_txt, conf, basis]):
                self.table.setItem(r, c, QTableWidgetItem(str(val)))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Remote Triage Collector")
        self.resize(1000, 650)
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
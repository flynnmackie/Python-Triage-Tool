"""Main GUI window. Single-file for now; split into per-tab modules later."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem, QMessageBox,
    QComboBox, QListWidget,
)
from PySide6.QtCore import QThread, Signal, QObject, Qt
from PySide6.QtGui import QColor

from core.discovery import expand_targets, discover
from core.models import OSFamily

from core.credentials import CredentialStore
from core.models import OSFamily, CredentialProfile, CredKind, AccessState



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
        self.store = CredentialStore()      # shared credential profiles


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

# Friendly labels -> the CredKind the model expects.
_KIND_CHOICES = {
    "Windows (domain)": CredKind.DOMAIN_KERBEROS,
    "Windows (standalone)": CredKind.LOCAL_NTLM,
    "Linux (SSH)": CredKind.SSH_PASSWORD,
}


class AccessTab(QWidget):
    def __init__(self, state: AppState):
        super().__init__()
        self.state = state
        layout = QHBoxLayout(self)

        # ---- Left: host table with a profile dropdown per row ----
        left = QVBoxLayout()
        left.addWidget(QLabel("Discovered hosts"))
        self.host_table = QTableWidget(0, 5)
        self.host_table.setHorizontalHeaderLabels(
            ["Host", "OS", "Profile", "WinRM", "SSH"])
        self.host_table.horizontalHeader().setStretchLastSection(True)
        left.addWidget(self.host_table)

        btn_row = QHBoxLayout()
        self.load_btn = QPushButton("Load hosts from discovery")
        self.load_btn.clicked.connect(self.load_hosts)
        btn_row.addWidget(self.load_btn)
        self.verify_btn = QPushButton("Verify access")
        self.verify_btn.setEnabled(False)          # enabled in stage two
        btn_row.addWidget(self.verify_btn)
        left.addLayout(btn_row)
        layout.addLayout(left, 2)

        # ---- Right: credential profile creation ----
        right = QVBoxLayout()
        right.addWidget(QLabel("Create credential profile"))

        self.name_in = QLineEdit(); self.name_in.setPlaceholderText("Profile name")
        self.kind_in = QComboBox(); self.kind_in.addItems(_KIND_CHOICES.keys())
        self.domain_in = QLineEdit(); self.domain_in.setPlaceholderText("Domain (Windows domain only)")
        self.user_in = QLineEdit(); self.user_in.setPlaceholderText("Username")
        self.pass_in = QLineEdit(); self.pass_in.setPlaceholderText("Password")
        self.pass_in.setEchoMode(QLineEdit.Password)       # <-- masks input
        self.sudo_in = QLineEdit(); self.sudo_in.setPlaceholderText("Sudo password (optional, Linux)")
        self.sudo_in.setEchoMode(QLineEdit.Password)

        for w in (self.name_in, self.kind_in, self.domain_in,
                  self.user_in, self.pass_in, self.sudo_in):
            right.addWidget(w)

        self.add_profile_btn = QPushButton("Add profile")
        self.add_profile_btn.clicked.connect(self.add_profile)
        right.addWidget(self.add_profile_btn)

        right.addWidget(QLabel("Profiles"))
        self.profile_list = QListWidget()
        right.addWidget(self.profile_list)
        right.addStretch()
        layout.addLayout(right, 1)

    # ---- profile creation ----
    def add_profile(self):
        name = self.name_in.text().strip()
        user = self.user_in.text().strip()
        if not name or not user:
            QMessageBox.warning(self, "Missing fields", "Profile needs at least a name and username.")
            return
        kind = _KIND_CHOICES[self.kind_in.currentText()]
        profile = CredentialProfile(
            name=name, kind=kind, username=user,
            secret=self.pass_in.text(),
            domain=self.domain_in.text().strip() or None,
            sudo_secret=self.sudo_in.text(),
        )
        self.state.store.add(profile)
        self.refresh_profiles()
        # clear the form (but not the secret fields lingering in memory longer than needed)
        for w in (self.name_in, self.domain_in, self.user_in, self.pass_in, self.sudo_in):
            w.clear()

    def refresh_profiles(self):
        self.profile_list.clear()
        self.profile_list.addItems(self.state.store.names())
        # refresh every row's dropdown so new profiles appear
        for r in range(self.host_table.rowCount()):
            combo = self.host_table.cellWidget(r, 2)
            if combo:
                current = combo.currentText()
                combo.clear()
                combo.addItem("— none —")
                combo.addItems(self.state.store.names())
                combo.setCurrentText(current)

    # ---- host loading ----
    def load_hosts(self):
        hosts = self.state.hosts
        self.host_table.setRowCount(0)
        for h in hosts:
            r = self.host_table.rowCount()
            self.host_table.insertRow(r)
            self.host_table.setItem(r, 0, QTableWidgetItem(h.ip))
            self.host_table.setItem(r, 1, QTableWidgetItem(h.os_guess.value))
            combo = QComboBox()
            combo.addItem("— none —")
            combo.addItems(self.state.store.names())
            self.host_table.setCellWidget(r, 2, combo)     # dropdown in the Profile column
            self.host_table.setItem(r, 3, QTableWidgetItem("—"))
            self.host_table.setItem(r, 4, QTableWidgetItem("—"))
        self.verify_btn.setEnabled(len(hosts) > 0)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Remote Triage Collector")
        self.resize(600, 650)
        self.state = AppState()

        tabs = QTabWidget()
        tabs.addTab(DiscoveryTab(self.state), "1 · Discovery")
        tabs.addTab(AccessTab(self.state), "2 · Access")
        for name in ("3 · Collect", "Log"):
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
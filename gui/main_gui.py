import sys
from datetime import datetime
from pathlib import Path

# main_gui.py is in VulnHunter/gui/, so the repo root is one level up
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QComboBox, QFrame, QHBoxLayout,
    QHeaderView, QLabel, QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit,
    QPushButton, QStackedWidget, QTableWidget, QTableWidgetItem, QVBoxLayout,
    QWidget,
)

from gui.data.mock_data import (
    DISABLED_MODELS, MODEL_IDS, REPO_URL, SAMPLE_FINDINGS, SAMPLE_OUTPUT,
    SCAN_DURATION, SCAN_TOKENS, SEED_HISTORY, SEVERITY_ORDER, ScanRecord,
)
from llm_connector.conn_all_llm import LLMConnector

from gui.api_conn_page import ApiConnectorPage

STYLE = """
QWidget { color: #E6EEF8; font-size: 18px; }
QMainWindow, QWidget#root { background: #0A1424; }
QDialog, QMessageBox { background: #111E33; }
QFrame#header { background: #0F2747; border: 0; border-bottom: 1px solid #1F4E8C; }
QFrame#card { background: #111E33; border: 1px solid #243B5C; border-radius: 5px; }
QFrame#card QLabel { background: transparent; }
QPushButton#home {
    background: transparent; border: 0; color: #E6EEF8; font-size: 20px;
    font-weight: 600; padding: 0 12px;
}
QLabel#title { font-size: 24px; font-weight: 600; }
QCheckBox { background: transparent; }
QLineEdit, QComboBox {
    background: #111E33; border: 1px solid #243B5C; border-radius: 5px; padding: 8px 10px;
}
QLineEdit:focus, QComboBox:focus { border: 1px solid #38BDF8; }
QComboBox QAbstractItemView {
    background: #111E33; color: #E6EEF8; selection-background-color: #1B4B7A;
    selection-color: #E6EEF8; border: 1px solid #243B5C;
}
QPushButton {
    background: #111E33; border: 1px solid #243B5C; border-radius: 5px; padding: 9px 22px;
}
QPushButton:hover { background: #172A47; }
QPushButton:disabled { color: #7F93AD; background: #0A1424; }
QPushButton#primary { background: #38BDF8; color: #05101F; border: 0; font-weight: 600; }
QPushButton#primary:hover { background: #7DD3FC; }
QPushButton#primary:disabled { background: #243B5C; color: #7F93AD; }
QTableWidget {
    background: #111E33; border: 1px solid #243B5C; gridline-color: #243B5C;
    selection-background-color: #1B4B7A; selection-color: #E6EEF8;
}
QHeaderView::section { background: #172A47; border: 0; padding: 9px 12px; font-weight: 600; }
QPlainTextEdit { background: #08101D; border: 1px solid #243B5C; color: #E6EEF8; }
QScrollBar:vertical { background: #111E33; width: 12px; margin: 0; }
QScrollBar::handle:vertical { background: #243B5C; border-radius: 5px; min-height: 24px; }
QScrollBar:horizontal { background: #111E33; height: 12px; margin: 0; }
QScrollBar::handle:horizontal { background: #243B5C; border-radius: 5px; min-width: 24px; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
"""


MIN_WINDOW_SIZE = (1300, 700)
PREFERRED_WINDOW_SIZE = (1360, 920)


def default_window_size(screen_width, screen_height):
    """Preferred size, shrunk to fit the available screen but never below the minimum."""
    width = min(PREFERRED_WINDOW_SIZE[0], int(screen_width * 0.95))
    height = min(PREFERRED_WINDOW_SIZE[1], int(screen_height * 0.92))
    return max(width, MIN_WINDOW_SIZE[0]), max(height, MIN_WINDOW_SIZE[1])


def make_table(headers):
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.verticalHeader().setVisible(False)
    table.setSelectionBehavior(QAbstractItemView.SelectRows)
    table.setSelectionMode(QAbstractItemView.SingleSelection)
    table.setEditTriggers(QAbstractItemView.NoEditTriggers)
    table.horizontalHeader().setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
    return table


class SeverityTracker(QFrame):
    """Side panel with one count per severity tier; the top two tiers are the headline rows."""
    HEADLINE_TIERS = 2

    def __init__(self):
        super().__init__()
        self.setObjectName("card")
        self.setFixedWidth(200)
        box = QVBoxLayout(self)
        heading = QLabel("Severity")
        heading.setFont(QFont("Segoe UI", 12, QFont.DemiBold))
        box.addWidget(heading)
        self.counts = {}
        for i, name in enumerate(SEVERITY_ORDER):
            headline = i < self.HEADLINE_TIERS
            label = QLabel(name)
            count = QLabel("0")
            for w in (label, count):
                w.setFont(QFont("Segoe UI", 18 if headline else 11, QFont.DemiBold if headline else QFont.Normal))
            if headline:
                count.setStyleSheet("color: #38BDF8;")
            row = QHBoxLayout()
            row.addWidget(label)
            row.addStretch()
            row.addWidget(count)
            box.addLayout(row)
            self.counts[name] = count
        box.addStretch()

    def update_counts(self, findings):
        for name, label in self.counts.items():
            label.setText(str(sum(f.severity == name for f in findings)))


class HomePage(QWidget):
    dashboard_requested = pyqtSignal()
    stats_requested = pyqtSignal()

    def __init__(self):
        super().__init__()

        title = QLabel("VulnHunter")
        title.setFont(QFont("Segoe UI", 32, QFont.DemiBold))
        title.setAlignment(Qt.AlignCenter)

        subtitle = QLabel("Welcome to VulnGUI.")
        subtitle.setAlignment(Qt.AlignCenter)

        open_btn = QPushButton("Dashboard")
        open_btn.setObjectName("primary")
        open_btn.clicked.connect(self.dashboard_requested.emit)

        open_btn_2 = QPushButton("Stats")
        open_btn_2.setObjectName("primary")
        open_btn_2.clicked.connect(self.stats_requested.emit)


        button_row = QHBoxLayout()
        button_row.addStretch()
        button_row.addWidget(open_btn)
        button_row.addWidget(open_btn_2)
        button_row.addStretch()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.addStretch()
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addSpacing(24)
        layout.addLayout(button_row)
        layout.addStretch()


class StatsPage(QWidget):
    def __init__(self):
        super().__init__()
        title = QLabel("Vulnerabilities Burndown")
        title.setFont(QFont("Segoe UI", 32, QFont.DemiBold))
        title.setAlignment(Qt.AlignCenter)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.addWidget(title)
        layout.addStretch()

class HistoryPage(QWidget):
    new_scan = pyqtSignal()
    record_selected = pyqtSignal(int)

    def __init__(self):
        super().__init__()
        title = QLabel("Scans")
        title.setObjectName("title")
        new_btn = QPushButton("New Scan")
        new_btn.setObjectName("primary")
        new_btn.clicked.connect(lambda: self.new_scan.emit())

        top = QHBoxLayout()
        top.addWidget(title)
        top.addStretch()
        top.addWidget(new_btn)

        cards = QHBoxLayout()
        cards.setSpacing(12)
        self.card_values = {}
        for name in ("Scans", "Findings", "Verified"):
            card = QFrame()
            card.setObjectName("card")
            box = QVBoxLayout(card)
            value = QLabel("0")
            value.setFont(QFont("Segoe UI", 18, QFont.DemiBold))
            box.addWidget(value)
            box.addWidget(QLabel(name))
            self.card_values[name] = value
            cards.addWidget(card)

        self.table = make_table(
            ["Repository", "Model", "Mode", "Date", "Findings", "Tokens", "Duration"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.setColumnWidth(1, 160)
        self.table.setColumnWidth(2, 100)
        self.table.setColumnWidth(3, 150)
        self.table.setColumnWidth(4, 115)
        self.table.setColumnWidth(5, 100)
        self.table.setColumnWidth(6, 115)
        self.table.cellClicked.connect(lambda row, _col: self.record_selected.emit(row))

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        layout.addLayout(top)
        layout.addLayout(cards)
        layout.addWidget(self.table, 1)

    def refresh(self, records):
        findings = [f for rec in records for f in rec.findings]
        counts = (len(records), len(findings), sum(f.status == "Verified" for f in findings))
        for label, count in zip(self.card_values.values(), counts):
            label.setText(str(count))
        self.table.setRowCount(len(records))
        for row, rec in enumerate(records):
            values = [rec.repo, rec.model, rec.mode, rec.date, str(len(rec.findings)),
                      rec.tokens, rec.duration]
            for col, value in enumerate(values):
                self.table.setItem(row, col, QTableWidgetItem(value))


class ScanPage(QWidget):
    finished = pyqtSignal(object)  # emits a ScanRecord

    def __init__(self, sample_findings, sample_output):
        super().__init__()
        self.sample_findings = sample_findings
        self.sample_output = sample_output
        self._line_index = 0
        self._run_output = []
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._next_line)

        # Top row: repository, model, demo, scan
        self.repo = QLineEdit()
        self.repo.setPlaceholderText("GitHub URL or local path")
        self.model_box = QComboBox()
        self.model_box.addItems(list(MODEL_IDS) + [f"{m} (not available yet)" for m in DISABLED_MODELS])
        for i in range(len(MODEL_IDS), self.model_box.count()):
            self.model_box.model().item(i).setEnabled(False)
        self.model_box.setToolTip("Model used for the scan. Greyed-out models are not available yet.")
        self.repo.setToolTip("Repository to scan. Not used in demo mode.")
        self.demo = QCheckBox("Demo")
        self.demo.setToolTip("Replay sample data. No API key, network or Claude access needed.")
        self.demo.setChecked(True)
        self.scan_btn = QPushButton("Scan")
        self.scan_btn.setToolTip("Hunt: look for exploitable vulnerabilities (demo replay only).")
        self.scan_btn.setObjectName("primary")
        self.scan_btn.clicked.connect(self.start_scan)

        top = QHBoxLayout()
        top.setSpacing(10)
        top.addWidget(self.repo, 1)
        top.addWidget(self.model_box)
        top.addWidget(self.demo)
        top.addWidget(self.scan_btn)

        # Findings table
        self.table = make_table(["ID", "Severity", "Finding", "Location", "Status"])
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setColumnWidth(0, 115)
        self.table.setColumnWidth(1, 105)
        self.table.setColumnWidth(3, 290)
        self.table.setColumnWidth(4, 125)
        self.table.itemSelectionChanged.connect(self._update_buttons)
        self.tracker = SeverityTracker()
        body = QHBoxLayout()
        body.setSpacing(16)
        body.addWidget(self.table, 1)
        body.addWidget(self.tracker)

        # Actions
        self.fix_btn = QPushButton("Fix")
        self.fix_btn.setObjectName("primary")
        self.verify_btn = QPushButton("Verify")
        self.report_btn = QPushButton("Report")
        self.fix_btn.setToolTip("Fix: propose a remediation for the selected finding (not implemented yet).")
        self.verify_btn.setToolTip("Verify: check that the selected finding is actually fixed (not implemented yet).")
        self.report_btn.setToolTip("Report: export the selected finding (not implemented yet).")
        actions = QHBoxLayout()
        actions.setSpacing(10)
        for btn in (self.fix_btn, self.verify_btn, self.report_btn):
            btn.clicked.connect(lambda _checked, b=btn: self._not_implemented(b.text()))
            actions.addWidget(btn)
        actions.addStretch()

        # Output
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(QFont("Consolas", 10))

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        layout.addLayout(top)
        layout.addLayout(body, 2)
        layout.addLayout(actions)
        layout.addWidget(self.output, 1)

        self._update_buttons()

    # Page states
    def reset(self):
        """Blank page for a new scan."""
        self.timer.stop()
        self._set_inputs_editable(True)
        self.repo.clear()
        self.demo.setChecked(True)
        self._fill_table([])
        self.output.clear()
        self._update_buttons()

    def show_record(self, record):
        """Read-only view of a past scan."""
        self.timer.stop()
        self.repo.setText(record.repo)
        self.demo.setChecked(record.mode == "Demo")
        self._fill_table(record.findings)
        self.output.setPlainText("\n".join(record.output))
        self._set_inputs_editable(False)

    def _set_inputs_editable(self, editable):
        self.repo.setReadOnly(not editable)
        self.model_box.setEnabled(editable)
        self.demo.setEnabled(editable)
        self.scan_btn.setEnabled(editable)

    # Scan with LLM Connector:
    def start_scan(self):
        selected_model = self.model_box.currentText()
        repo_target = self.repo.text().strip() or REPO_URL

        # If Demo mode is unchecked, trigger the live LLMConnector route!
        if not self.demo.isChecked():
            self.output.clear()
            self.output.appendPlainText(f"Connecting to {selected_model} for live scan on: {repo_target}...\n")
            
            try:
                # 1. Initialize your unified connector with the dropdown selection
                connector = LLMConnector(selected_model)
                
                # 2. Construct your prompt/query for the vulnerability scan
                prompt = f"Perform a security vulnerability analysis on the codebase at: {repo_target}"
                
                # 3. Generate response and display it in the output text box
                response = connector.generate_response(prompt)
                self.output.appendPlainText(response)
                
            except Exception as e:
                self.output.appendPlainText(f"Error connecting to model: {str(e)}")
            return

        # Otherwise, run your existing simulated demo replay workflow
        self._fill_table([])
        self.output.clear()
        self.scan_btn.setEnabled(False)
        self._line_index = 0
        self._run_output = self._output_for_model()
        self.timer.start(500)

    def _output_for_model(self):
        model = self.model_box.currentText()
        return [line.replace("{model_id}", MODEL_IDS.get(model, model)) for line in self.sample_output]

    def _next_line(self):
        if self._line_index < len(self._run_output):
            self.output.appendPlainText(self._run_output[self._line_index])
            self._line_index += 1
            return
        self.timer.stop()
        self._fill_table(self.sample_findings)
        self.scan_btn.setEnabled(True)
        now = datetime.now()
        record = ScanRecord(
            repo=self.repo.text().strip() or REPO_URL,
            model=self.model_box.currentText(),
            mode="Demo",
            date=f"{now:%b} {now.day}, {now.year}",
            findings=list(self.sample_findings),
            output=list(self._run_output),
            tokens=SCAN_TOKENS,
            duration=SCAN_DURATION,
        )
        self.finished.emit(record)

    def _fill_table(self, findings):
        self.tracker.update_counts(findings)
        # A severity outside SEVERITY_ORDER sorts last instead of raising.
        findings = sorted(findings, key=lambda f: SEVERITY_ORDER.index(f.severity)
                          if f.severity in SEVERITY_ORDER else len(SEVERITY_ORDER))
        self.table.setRowCount(len(findings))
        for row, f in enumerate(findings):
            for col, value in enumerate([f.id, f.severity, f.title, f.location, f.status]):
                self.table.setItem(row, col, QTableWidgetItem(value))
        if findings:
            self.table.selectRow(0)

    def _update_buttons(self):
        has_selection = bool(self.table.selectionModel().selectedRows())
        for btn in (self.fix_btn, self.verify_btn, self.report_btn):
            btn.setEnabled(has_selection)

    def _not_implemented(self, name):
        QMessageBox.information(self, "VulnHunter", f"{name} is not implemented yet.")


class MainWindow(QMainWindow):
    HOME, HISTORY, SCAN, STATS = 0, 1, 2, 3

    def __init__(self):
        super().__init__()
        self.setWindowTitle("VulnHunter")
        self.setMinimumSize(*MIN_WINDOW_SIZE)
        screen = QApplication.primaryScreen().availableGeometry()
        self.resize(*default_window_size(screen.width(), screen.height()))
        self.history = list(SEED_HISTORY)  # newest first; held in memory only

        self.home_page = HomePage()
        self.history_page = HistoryPage()
        self.scan_page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
        self.stats_page = StatsPage()
        self.stack = QStackedWidget()
        self.stack.addWidget(self.home_page)
        self.stack.addWidget(self.history_page)
        self.stack.addWidget(self.scan_page)
        self.stack.addWidget(self.stats_page)
        self.home_page.stats_requested.connect(self.show_stats)

        # Shared header: one home button, centered, visible on every page
        header = QFrame()
        header.setObjectName("header")
        header.setFixedHeight(56)
        home = QPushButton("VulnHunter")
        home.setObjectName("home")
        home.setCursor(Qt.PointingHandCursor)
        home.clicked.connect(self.show_home)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(24, 0, 24, 0)
        header_layout.addStretch()
        header_layout.addWidget(home)
        header_layout.addStretch()

        root = QWidget()
        root.setObjectName("root")
        layout = QVBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(header)
        layout.addWidget(self.stack, 1)
        self.setCentralWidget(root)

        self.home_page.dashboard_requested.connect(self.show_history)
        self.history_page.new_scan.connect(self.new_scan)
        self.history_page.record_selected.connect(self.open_record)
        self.scan_page.finished.connect(self.add_record)
        self.history_page.refresh(self.history)

    def show_home(self):
        self.stack.setCurrentIndex(self.HOME)

    def show_stats(self):
        self.stack.setCurrentIndex(self.STATS)

    def show_history(self):
        self.stack.setCurrentIndex(self.HISTORY)

    def new_scan(self):
        self.scan_page.reset()
        self.stack.setCurrentIndex(self.SCAN)

    def open_record(self, row):
        self.scan_page.show_record(self.history[row])
        self.stack.setCurrentIndex(self.SCAN)

    def add_record(self, record):
        self.history.insert(0, record)
        self.history_page.refresh(self.history)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLE)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

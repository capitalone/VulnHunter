"""GUI tests on synthetic data: happy path, empty states, edge cases.

Run from the repo root:

    python -m pytest gui/tests/test_gui_synthetic.py -v   (from the repo root)

On a headless Linux machine, run with ``QT_QPA_PLATFORM=offscreen``.
No live scan, network, or Claude account is involved. These tests check that the
mock GUI behaves as designed; they do not test real VulnHunter output.
"""

from dataclasses import replace

import pytest
from PyQt5.QtWidgets import QApplication, QDialog, QMessageBox

from gui import main_gui as gui
from gui.main_gui import HistoryPage, MainWindow, ScanPage
from gui.data.mock_data import (
    DISABLED_MODELS, MODEL_IDS, SAMPLE_FINDINGS, SAMPLE_OUTPUT, SAMPLE_SNIPPETS, SEED_HISTORY,
    SEVERITY_ORDER, Finding, code_url, sample_fix, sample_snippet, split_location,
)


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    yield app


def run_demo_scan(page):
    """Drive the demo replay to completion without waiting on the timer."""
    page.start_scan()
    page.timer.stop()
    for _ in range(len(page._run_output) + 1):
        page._next_line()


def table_column(page, col):
    return [page.table.item(r, col).text() for r in range(page.table.rowCount())]


# Happy path

def test_demo_scan_fills_table_and_emits_record(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    records = []
    page.finished.connect(records.append)

    run_demo_scan(page)

    assert page.table.rowCount() == len(SAMPLE_FINDINGS)
    assert len(records) == 1
    assert records[0].mode == "Demo"
    assert records[0].findings == list(SAMPLE_FINDINGS)
    assert page.scan_btn.isEnabled()


def test_demo_scan_log_names_the_selected_model(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    page.model_box.setCurrentText("DeepSeek")
    run_demo_scan(page)
    log = page.output.toPlainText()
    assert MODEL_IDS["DeepSeek"] in log
    assert "{model_id}" not in log


def test_finished_scan_is_added_to_history_and_can_be_reopened(qapp):
    window = MainWindow()
    before = len(window.history)

    run_demo_scan(window.scan_page)

    assert len(window.history) == before + 1
    assert window.history_page.table.rowCount() == before + 1
    window.open_record(0)
    assert window.stack.currentIndex() == window.SCAN
    assert not window.scan_page.scan_btn.isEnabled()  # past scans are read only
    assert window.scan_page.table.rowCount() == len(SAMPLE_FINDINGS)


def test_seed_history_is_shown_on_startup(qapp):
    window = MainWindow()
    assert window.history_page.table.rowCount() == len(SEED_HISTORY)


# Empty states

def test_new_scan_page_is_empty_and_actions_disabled(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    page.reset()
    assert page.table.rowCount() == 0
    assert page.output.toPlainText() == ""
    for btn in (page.fix_btn, page.verify_btn, page.report_btn):
        assert not btn.isEnabled()


def test_empty_history_page(qapp):
    page = HistoryPage()
    page.refresh([])
    assert page.table.rowCount() == 0
    assert [label.text() for label in page.card_values.values()] == ["0", "0", "0"]


def test_scan_with_zero_findings(qapp):
    page = ScanPage([], SAMPLE_OUTPUT)
    run_demo_scan(page)
    assert page.table.rowCount() == 0
    assert all(label.text() == "0" for label in page.tracker.counts.values())


# Edge cases

def test_actions_enable_only_with_a_selection(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    page._fill_table(SAMPLE_FINDINGS)  # selects row 0
    assert all(b.isEnabled() for b in (page.fix_btn, page.verify_btn, page.report_btn))
    page.table.clearSelection()
    assert not any(b.isEnabled() for b in (page.fix_btn, page.verify_btn, page.report_btn))


def test_long_text_and_many_rows(qapp):
    page = ScanPage([], [])
    findings = [
        Finding(f"VULN-{i:04d}", SEVERITY_ORDER[i % len(SEVERITY_ORDER)],
                "x" * 400, "src/" + "deep/" * 40 + "file.py:1", "Open")
        for i in range(300)
    ]
    page._fill_table(findings)
    assert page.table.rowCount() == 300
    severities = table_column(page, 1)
    assert severities == sorted(severities, key=SEVERITY_ORDER.index)


def test_blank_repo_in_demo_mode_still_scans(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    page.repo.setText("   ")
    records = []
    page.finished.connect(records.append)
    run_demo_scan(page)
    assert records and records[0].repo.strip()


# Not-implemented paths

def test_unchecking_demo_takes_live_route_and_shows_errors(qapp, monkeypatch):
    # The live route calls LLMConnector. Stub it so no real request is ever made.
    calls = []

    class FakeConnector:
        def __init__(self, model_name):
            calls.append(model_name)
            raise RuntimeError("stubbed: no network in tests")

    monkeypatch.setattr(gui, "LLMConnector", FakeConnector)
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    page.demo.setChecked(False)
    page.start_scan()

    assert calls == ["Claude Opus"]
    assert "stubbed: no network in tests" in page.output.toPlainText()
    assert page.table.rowCount() == 0  # no findings are produced on the live route yet
    assert not page.timer.isActive()


def test_verify_and_report_are_not_implemented(qapp, monkeypatch):
    shown = []
    monkeypatch.setattr(QMessageBox, "information",
                        lambda *args, **kwargs: shown.append(args[2]))
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    page._fill_table([replace(f) for f in SAMPLE_FINDINGS])
    before = table_column(page, 4)

    for btn in (page.verify_btn, page.report_btn):
        btn.click()

    assert len(shown) == 2
    assert all("not implemented" in msg for msg in shown)
    assert table_column(page, 4) == before


# Model dropdown

def test_model_dropdown_enabled_and_disabled_entries(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    model = page.model_box.model()
    enabled = [page.model_box.itemText(i) for i in range(page.model_box.count())
               if model.item(i).isEnabled()]
    disabled = [page.model_box.itemText(i) for i in range(page.model_box.count())
                if not model.item(i).isEnabled()]
    assert enabled == list(MODEL_IDS)
    assert len(disabled) == len(DISABLED_MODELS)
    assert all("not available yet" in name for name in disabled)


def test_model_dropdown_selection_can_change(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    page.model_box.setCurrentText("DeepSeek")
    assert page.model_box.currentText() == "DeepSeek"


# Navigation

def test_home_navigation(qapp):
    window = MainWindow()
    assert window.stack.currentIndex() == window.HOME
    window.home_page.dashboard_requested.emit()
    assert window.stack.currentIndex() == window.HISTORY
    window.show_stats()
    assert window.stack.currentIndex() == window.STATS
    window.show_home()
    assert window.stack.currentIndex() == window.HOME


def test_default_window_size_fits_screen_but_not_below_minimum():
    min_w, min_h = gui.MIN_WINDOW_SIZE
    pref_w, pref_h = gui.PREFERRED_WINDOW_SIZE
    # Large screen: the preferred size.
    assert gui.default_window_size(2560, 1440) == (pref_w, pref_h)
    # Small screen: shrinks to fit, but never below the minimum.
    width, height = gui.default_window_size(1366, 768)
    assert min_w <= width <= pref_w and min_h <= height <= pref_h
    assert gui.default_window_size(800, 600) == (min_w, min_h)


def test_main_window_uses_minimum_size(qapp):
    window = MainWindow()
    assert (window.minimumWidth(), window.minimumHeight()) == gui.MIN_WINDOW_SIZE
    assert window.width() >= gui.MIN_WINDOW_SIZE[0]
    assert window.height() >= gui.MIN_WINDOW_SIZE[1]


def test_base_font_size_is_larger_than_original():
    # Stakeholder asked for larger text than the original 14px.
    assert "font-size: 18px" in gui.STYLE.splitlines()[1]


def test_main_window_defines_show_stats_once():
    # Guards against the duplicate definition that was removed.
    import inspect
    source = inspect.getsource(gui.MainWindow)
    assert source.count("def show_stats") == 1


# Demo usage figures

def test_demo_scan_shows_no_usage_figures(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    records = []
    page.finished.connect(records.append)
    run_demo_scan(page)
    assert (records[0].tokens, records[0].duration) == ("n/a", "n/a")


# Home page text size

def test_home_page_text_is_larger_than_the_base_font():
    assert "QWidget#homePage QLabel#homeTitle { font-size: 60px" in gui.STYLE
    assert "QWidget#homePage QPushButton { font-size: 26px" in gui.STYLE


def test_home_page_widgets_use_the_sized_object_names(qapp):
    home = gui.HomePage()
    assert home.objectName() == "homePage"
    assert {w.objectName() for w in home.findChildren(gui.QLabel)} == {"homeTitle", "homeSubtitle"}


# Per-finding actions: Fix, Accept, Ignore, View in code (all mocked)

def scan_with_findings(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    run_demo_scan(page)
    return page


def select_finding(page, finding_id):
    row = next(i for i, f in enumerate(page._rows) if f.id == finding_id)
    page.table.selectRow(row)
    return page._current_finding()


def stub_dialog(monkeypatch, result, reason_index=0, note=""):
    def fake_exec(self):
        self.reason.setCurrentIndex(reason_index)
        self.note.setPlainText(note)
        return result
    monkeypatch.setattr(gui.DecisionDialog, "exec_", fake_exec)


def test_detail_panel_shows_the_selected_finding(qapp):
    page = scan_with_findings(qapp)
    finding = select_finding(page, "VULN-005")
    assert finding.id in page.detail_heading.text()
    assert page.detail_title.text() == finding.title
    assert finding.location in page.code_link.text()
    assert page.decision_label.isHidden()


def test_detail_panel_without_selection_disables_all_actions(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    page.reset()
    assert "No finding selected" in page.detail_heading.text()
    buttons = (page.fix_btn, page.accept_btn, page.ignore_btn, page.verify_btn, page.report_btn)
    assert not any(b.isEnabled() for b in buttons)
    assert page.code_link.isHidden()


def test_fix_proposes_a_sample_fix_and_marks_the_row(qapp, monkeypatch):
    shown = []
    monkeypatch.setattr(QMessageBox, "information",
                        lambda *args, **kwargs: shown.append(args[2]))
    page = scan_with_findings(qapp)
    finding = select_finding(page, "VULN-005")
    page.fix_btn.click()

    assert finding.status == "Fix proposed"
    assert table_column(page, 4)[page._rows.index(finding)] == "Fix proposed"
    assert sample_fix(finding) in shown[0] and "Mocked" in shown[0]


def test_accept_records_reason_and_context(qapp, monkeypatch):
    stub_dialog(monkeypatch, QDialog.Accepted, reason_index=1, note="  Reviewed with the owner  ")
    page = scan_with_findings(qapp)
    finding = select_finding(page, "VULN-005")
    page.accept_btn.click()

    assert (finding.decision, finding.status) == ("Accepted", "Accepted")
    assert finding.reason == gui.ACCEPT_REASONS[1]
    assert finding.note == "Reviewed with the owner"
    assert table_column(page, 4)[page._rows.index(finding)] == "Accepted"
    assert "Reviewed with the owner" in page.decision_label.text()


def test_ignore_records_reason_and_context(qapp, monkeypatch):
    stub_dialog(monkeypatch, QDialog.Accepted, reason_index=0, note="Test code only")
    page = scan_with_findings(qapp)
    finding = select_finding(page, "VULN-006")
    page.ignore_btn.click()

    assert (finding.decision, finding.status) == ("Ignored", "Ignored")
    assert finding.reason == gui.IGNORE_REASONS[0]
    assert "Ignored: False positive" in page.decision_label.text()


def test_cancelled_decision_changes_nothing(qapp, monkeypatch):
    stub_dialog(monkeypatch, QDialog.Rejected, note="should not be saved")
    page = scan_with_findings(qapp)
    finding = select_finding(page, "VULN-005")
    before = finding.status
    page.ignore_btn.click()

    assert finding.status == before
    assert (finding.decision, finding.reason, finding.note) == ("", "", "")


def test_decisions_never_change_sample_data_or_other_scans(qapp, monkeypatch):
    stub_dialog(monkeypatch, QDialog.Accepted)
    originals = [(f.id, f.status, f.decision) for f in SAMPLE_FINDINGS]
    window = MainWindow()
    run_demo_scan(window.scan_page)
    select_finding(window.scan_page, "VULN-005")
    window.scan_page.accept_btn.click()

    assert [(f.id, f.status, f.decision) for f in SAMPLE_FINDINGS] == originals
    seeded = [f for r in window.history[1:] for f in r.findings if f.id == "VULN-005"]
    assert seeded and all(f.decision == "" for f in seeded)

    run_demo_scan(window.scan_page)  # a second scan starts clean
    assert all(f.decision == "" for f in window.scan_page._rows)


def test_decision_is_kept_when_a_past_scan_is_reopened(qapp, monkeypatch):
    stub_dialog(monkeypatch, QDialog.Accepted, note="kept")
    window = MainWindow()
    run_demo_scan(window.scan_page)
    select_finding(window.scan_page, "VULN-005")
    window.scan_page.ignore_btn.click()

    window.open_record(1)  # some other scan
    window.open_record(0)  # back to the one just decided on
    finding = select_finding(window.scan_page, "VULN-005")
    assert finding.decision == "Ignored" and finding.note == "kept"


def test_decision_dialog_lists_the_right_reasons_and_context(qapp):
    finding = replace(SAMPLE_FINDINGS[0])
    accept = gui.DecisionDialog(None, finding, "Accept")
    ignore = gui.DecisionDialog(None, finding, "Ignore")
    assert [accept.reason.itemText(i) for i in range(accept.reason.count())] == gui.ACCEPT_REASONS
    assert [ignore.reason.itemText(i) for i in range(ignore.reason.count())] == gui.IGNORE_REASONS
    assert (accept.decision, ignore.decision) == ("Accepted", "Ignored")
    assert sample_fix(finding) in accept.findChildren(gui.QLabel)[0].text()


def test_view_in_code_shows_a_sample_snippet_with_the_flagged_line(qapp, monkeypatch):
    opened = []
    monkeypatch.setattr(gui.CodeViewDialog, "exec_", lambda self: opened.append(self))
    page = scan_with_findings(qapp)
    finding = select_finding(page, "VULN-003")
    page.code_link.click()

    code = opened[0].code.toPlainText()
    _path, line = split_location(finding.location)
    assert f"> {line:>4} |" in code
    assert code_url(finding).endswith(f"#L{line}")


def test_every_sample_finding_has_a_snippet_matching_its_line():
    seeded = [f for r in SEED_HISTORY for f in r.findings]
    for finding in list(SAMPLE_FINDINGS) + seeded:
        rows = sample_snippet(finding)
        assert rows, finding.id
        _path, line = split_location(finding.location)
        assert line in [n for n, _ in rows], finding.id
    assert set(SAMPLE_SNIPPETS) >= {f.id for f in SAMPLE_FINDINGS}


def test_split_location_and_code_url():
    assert split_location("src/a.py:12") == ("src/a.py", 12)
    assert split_location("src/a.py") == ("src/a.py", 0)
    finding = Finding("X", "Low", "t", "src/a.py:12", "Open")
    assert code_url(finding).endswith("/blob/main/src/a.py#L12")
    assert code_url(replace(finding, location="src/a.py")).endswith("/blob/main/src/a.py")

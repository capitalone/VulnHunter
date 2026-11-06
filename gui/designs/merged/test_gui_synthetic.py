"""GUI tests on synthetic data: happy path, empty states, edge cases.

Run from this folder:

    python -m pytest test_gui_synthetic.py -v

On a headless Linux machine, run with ``QT_QPA_PLATFORM=offscreen``.
No live scan, network, or Claude account is involved. These tests check that the
mock GUI behaves as designed; they do not test real VulnHunter output.
"""

import pytest
from PyQt5.QtWidgets import QApplication, QMessageBox

import app as gui
from app import HistoryPage, MainWindow, ScanPage
from mock_data import (
    DISABLED_MODELS, MODEL_IDS, SAMPLE_FINDINGS, SAMPLE_OUTPUT, SEED_HISTORY,
    SEVERITY_ORDER, Finding,
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

def test_live_scan_is_not_implemented(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    page.demo.setChecked(False)
    page.start_scan()
    assert "not implemented" in page.output.toPlainText().lower()
    assert page.table.rowCount() == 0
    assert not page.timer.isActive()


def test_fix_verify_report_show_message_and_change_nothing(qapp, monkeypatch):
    shown = []
    monkeypatch.setattr(QMessageBox, "information",
                        lambda *args, **kwargs: shown.append(args[2]))
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    page._fill_table(SAMPLE_FINDINGS)
    before = table_column(page, 4)

    for btn in (page.fix_btn, page.verify_btn, page.report_btn):
        btn.click()

    assert len(shown) == 3
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

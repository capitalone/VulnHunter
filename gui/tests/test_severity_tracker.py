"""Tests for the severity tracker in the merged GUI.

Run the test with the following command:

    python -m pytest gui/tests/test_severity_tracker.py -v   (from the repo root)

On a headless Linux machine, run with ``QT_QPA_PLATFORM=offscreen``.
On Windows, no extra setup is needed. No live scan, network, or Claude account is involved: these tests use mock findings only."""

import pytest
from PyQt5.QtWidgets import QApplication

from gui.main_gui import ScanPage, SeverityTracker
from gui.data.mock_data import SEVERITY_ORDER, Finding


@pytest.fixture(scope="module")
def qapp():
    """One QApplication for the whole module (Qt only allows one)."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    yield app


def make_finding(finding_id, severity):
    return Finding(finding_id, severity, f"Finding {finding_id}",
                   "src/example.py:1", "Open")


def tracker_counts(tracker):
    return {name: label.text() for name, label in tracker.counts.items()}


def test_tracker_counts_each_tier_and_resets_on_new_list(qapp):
    tracker = SeverityTracker()

    # Tracker rows follow SEVERITY_ORDER, highest first, and start at zero.
    assert list(tracker.counts) == SEVERITY_ORDER
    assert tracker_counts(tracker) == {name: "0" for name in SEVERITY_ORDER}

    tracker.update_counts([
        make_finding("VULN-1", "High"),
        make_finding("VULN-2", "High"),
        make_finding("VULN-3", "Low"),
        make_finding("VULN-4", "High+"),
    ])
    assert tracker_counts(tracker) == {
        "High+": "1",
        "High": "2",
        "Medium": "0",
        "Low": "1",
        "Informational": "0",
    }

    # A new list replaces the old counts; it does not add to them.
    tracker.update_counts([make_finding("VULN-5", "Informational")])
    assert tracker_counts(tracker) == {
        "High+": "0",
        "High": "0",
        "Medium": "0",
        "Low": "0",
        "Informational": "1",
    }

    tracker.update_counts([])
    assert tracker_counts(tracker) == {name: "0" for name in SEVERITY_ORDER}


def test_fill_table_sorts_by_severity_and_tracker_matches_table(qapp):
    page = ScanPage([], [])

    # Deliberately out of order, including the sample data's duplicate tier.
    findings = [
        make_finding("VULN-4", "Low"),
        make_finding("VULN-1", "High+"),
        make_finding("VULN-3", "Medium"),
        make_finding("VULN-2", "High"),
        make_finding("VULN-5", "Informational"),
        make_finding("VULN-6", "High"),
    ]
    page._fill_table(findings)

    table_severities = [
        page.table.item(row, 1).text() for row in range(page.table.rowCount())
    ]
    assert table_severities == [
        "High+", "High", "High", "Medium", "Low", "Informational",
    ]
    # The table's first row is the highest-severity finding, and it is selected.
    assert page.table.item(0, 0).text() == "VULN-1"
    assert page.table.currentRow() == 0

    # The tracker on the same page agrees with what the table shows.
    assert tracker_counts(page.tracker) == {
        "High+": "1",
        "High": "2",
        "Medium": "1",
        "Low": "1",
        "Informational": "1",
    }

    # Clearing the table also clears the tracker.
    page._fill_table([])
    assert page.table.rowCount() == 0
    assert tracker_counts(page.tracker) == {name: "0" for name in SEVERITY_ORDER}


def test_unknown_severity_sorts_last_and_does_not_crash(qapp):
    page = ScanPage([], [])
    page._fill_table([make_finding("VULN-9", "Critical"), make_finding("VULN-1", "Low")])
    assert page.table.rowCount() == 2
    # The unknown tier sorts after every known tier and is not counted by the tracker.
    assert page.table.item(0, 1).text() == "Low"
    assert page.table.item(1, 1).text() == "Critical"
    assert sum(int(t) for t in tracker_counts(page.tracker).values()) == 1
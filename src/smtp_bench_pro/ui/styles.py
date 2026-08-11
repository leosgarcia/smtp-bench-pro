"""Local visual guidelines implementation for SMTP Bench Pro."""

APP_STYLESHEET = """
QMainWindow, QWidget {
    background: #111318;
    color: #E8EAED;
    font-family: Segoe UI, Arial, sans-serif;
    font-size: 10pt;
}
QMenuBar, QMenu {
    background: #171A21;
    color: #E8EAED;
}
QMenuBar::item:selected, QMenu::item:selected {
    background: #263241;
}
QGroupBox {
    border: 1px solid #2B323D;
    border-radius: 6px;
    margin-top: 12px;
    padding: 12px;
    font-weight: 600;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
}
QLineEdit, QSpinBox, QDoubleSpinBox, QTableWidget, QTextEdit, QPlainTextEdit, QTabWidget::pane {
    background: #171A21;
    color: #E8EAED;
    border: 1px solid #2B323D;
    border-radius: 4px;
    selection-background-color: #2563EB;
}
QHeaderView::section {
    background: #202631;
    color: #E8EAED;
    border: 0;
    border-right: 1px solid #2B323D;
    padding: 6px;
}
QPushButton {
    background: #303846;
    color: #F8FAFC;
    border: 1px solid #3A4556;
    border-radius: 4px;
    padding: 7px 12px;
    font-weight: 600;
}
QPushButton:hover { background: #3A4556; }
QPushButton:disabled { background: #394150; color: #9AA4B2; }
QPushButton#primaryButton {
    background: #2563EB;
    border: 1px solid #3B82F6;
    color: white;
}
QPushButton#primaryButton:hover { background: #1D4ED8; }
QPushButton#secondaryButton { background: #303846; }
QPushButton#secondaryButton:hover { background: #3A4556; }
QLabel#emptyStateTitle { font-size: 12pt; font-weight: 700; color: #F8FAFC; }
QLabel#emptyStateBody { color: #B8C0CC; }
QLabel#subtleLabel { color: #B8C0CC; }
QGroupBox#mailDnsCard {
    margin-top: 8px;
    padding: 8px;
}
QGroupBox#mailDnsCard::title { font-weight: 600; }
QLabel#mailDnsCardStatus { font-weight: 700; color: #F8FAFC; }
QLabel#mailDnsCardDetails { color: #B8C0CC; }
QProgressBar {
    background: #171A21;
    color: #E8EAED;
    border: 1px solid #2B323D;
    border-radius: 4px;
    text-align: center;
}
QProgressBar::chunk { background: #22C55E; border-radius: 3px; }
QStatusBar { background: #171A21; color: #B8C0CC; }
"""

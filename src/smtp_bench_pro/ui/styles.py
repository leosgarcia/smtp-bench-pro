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
QLineEdit, QSpinBox, QDoubleSpinBox, QTableWidget, QTextEdit, QTabWidget::pane {
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
    background: #2563EB;
    color: white;
    border: 0;
    border-radius: 4px;
    padding: 7px 12px;
    font-weight: 600;
}
QPushButton:hover { background: #1D4ED8; }
QPushButton:disabled { background: #394150; color: #9AA4B2; }
QPushButton#secondaryButton { background: #303846; }
QPushButton#secondaryButton:hover { background: #3A4556; }
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

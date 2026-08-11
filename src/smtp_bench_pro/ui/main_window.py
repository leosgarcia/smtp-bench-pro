"""Standalone main window for SMTP Bench Pro."""

from __future__ import annotations

from PySide6.QtGui import QAction
from PySide6.QtWidgets import QMainWindow

from smtp_bench_pro.ui.styles import APP_STYLESHEET
from smtp_bench_pro.ui.widgets.smtp_bench_widget import SMTPBenchWidget


class SMTPBenchMainWindow(QMainWindow):
    """Standalone shell; SMTP logic lives in SMTPBenchWidget and services."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("SMTP Bench Pro")
        self.resize(1180, 760)
        self.setStyleSheet(APP_STYLESHEET)
        self.bench_widget = SMTPBenchWidget(include_about=True)
        self.setCentralWidget(self.bench_widget)
        self._build_menu()
        self.statusBar().showMessage("Pronto")

    def _build_menu(self) -> None:
        file_menu = self.menuBar().addMenu("Arquivo")
        exit_action = QAction("Sair", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        help_menu = self.menuBar().addMenu("Ajuda")
        about_action = QAction("Sobre o SMTP Bench Pro", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _show_about(self) -> None:
        for index in range(self.bench_widget.tab_widget.count()):
            if self.bench_widget.tab_widget.tabText(index) == "Sobre":
                self.bench_widget.tab_widget.setCurrentIndex(index)
                return

    def closeEvent(self, event) -> None:  # noqa: N802
        self.bench_widget.engine.cancel_all()
        super().closeEvent(event)

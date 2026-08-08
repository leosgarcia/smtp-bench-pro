"""Input panel for SMTP benchmark requests."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QDoubleSpinBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QWidget,
)

from smtp_bench_pro.application.services import BenchmarkRequest, DEFAULT_PORTS


class ConnectionPanel(QGroupBox):
    run_requested = Signal(object)
    cancel_requested = Signal()

    def __init__(self, parent: QWidget | None = None):
        super().__init__("Conexao SMTP", parent)
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("mail.example.com")
        self.iterations_input = QSpinBox()
        self.iterations_input.setRange(1, 20)
        self.iterations_input.setValue(1)
        self.timeout_input = QDoubleSpinBox()
        self.timeout_input.setRange(1.0, 30.0)
        self.timeout_input.setSingleStep(0.5)
        self.timeout_input.setValue(3.0)
        self.timeout_input.setSuffix(" s")

        self.port_checks: dict[int, QCheckBox] = {}
        ports_widget = QWidget()
        ports_layout = QHBoxLayout(ports_widget)
        ports_layout.setContentsMargins(0, 0, 0, 0)
        for port in DEFAULT_PORTS:
            check = QCheckBox(str(port))
            check.setChecked(True)
            self.port_checks[port] = check
            ports_layout.addWidget(check)
        ports_layout.addStretch(1)

        self.run_button = QPushButton("Rodar Benchmark")
        self.cancel_button = QPushButton("Cancelar")
        self.cancel_button.setObjectName("secondaryButton")
        self.cancel_button.setEnabled(False)

        buttons = QWidget()
        buttons_layout = QHBoxLayout(buttons)
        buttons_layout.setContentsMargins(0, 0, 0, 0)
        buttons_layout.addWidget(self.run_button)
        buttons_layout.addWidget(self.cancel_button)
        buttons_layout.addStretch(1)

        form = QFormLayout(self)
        form.addRow("Servidor", self.host_input)
        form.addRow("Portas", ports_widget)
        form.addRow("Execucoes", self.iterations_input)
        form.addRow("Timeout", self.timeout_input)
        form.addRow(QLabel(""), buttons)

        self.run_button.clicked.connect(self._emit_run_request)
        self.cancel_button.clicked.connect(self.cancel_requested)

    def set_running(self, running: bool) -> None:
        self.run_button.setEnabled(not running)
        self.cancel_button.setEnabled(running)
        self.host_input.setEnabled(not running)
        self.iterations_input.setEnabled(not running)
        self.timeout_input.setEnabled(not running)
        for check in self.port_checks.values():
            check.setEnabled(not running)

    def _emit_run_request(self) -> None:
        ports = tuple(port for port, check in self.port_checks.items() if check.isChecked())
        self.run_requested.emit(
            BenchmarkRequest(
                hostname=self.host_input.text(),
                ports=ports,
                iterations=self.iterations_input.value(),
                timeout=self.timeout_input.value(),
            )
        )

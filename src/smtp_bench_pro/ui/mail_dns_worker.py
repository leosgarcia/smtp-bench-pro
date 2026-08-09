"""Qt QRunnable Worker for asynchronous Mail DNS Diagnostics."""

from __future__ import annotations

import logging
from PySide6.QtCore import QObject, QRunnable, Signal

from smtp_bench_pro.application.mail_dns_coordinator import MailDNSDiagnosticsCoordinator

logger = logging.getLogger("smtp_bench_pro.mail_dns.ui")


class MailDNSWorkerSignals(QObject):
    """Signals emitted by MailDNSDiagnosticsWorker."""

    started = Signal()
    progress = Signal(int, str)
    finished = Signal(object)  # Emits (MailDNSDiagnosticsOutcome, MailDNSRunSnapshot)
    failed = Signal(str)


class MailDNSDiagnosticsWorker(QRunnable):
    """Runs Mail DNS Diagnostics on a background worker thread."""

    def __init__(
        self,
        coordinator: MailDNSDiagnosticsCoordinator,
        raw_domain_input: str,
        run_id: int | None = None,
    ) -> None:
        super().__init__()
        self.coordinator = coordinator
        self.raw_domain_input = raw_domain_input
        self.run_id = run_id
        self.signals = MailDNSWorkerSignals()
        self._is_cancelled = False

    def cancel(self) -> None:
        """Requests cooperative cancellation of the worker."""
        self._is_cancelled = True

    def run(self) -> None:
        """Main QRunnable thread execution."""
        try:
            self.signals.started.emit()

            def on_progress(step: int, text: str) -> None:
                if not self._is_cancelled:
                    self.signals.progress.emit(step, text)

            if self._is_cancelled:
                return

            outcome, snapshot = self.coordinator.diagnose_and_persist(
                raw_domain_input=self.raw_domain_input,
                run_id=self.run_id,
                progress_callback=on_progress,
            )

            if self._is_cancelled:
                logger.info("Mail DNS Worker cancelled before completing UI emission.")
                return

            self.signals.finished.emit((outcome, snapshot))
        except Exception as exc:
            logger.exception("Error during Mail DNS Diagnostics worker execution")
            if not self._is_cancelled:
                self.signals.failed.emit(str(exc))

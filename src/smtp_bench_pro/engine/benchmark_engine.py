"""Benchmark orchestration for SMTP probes."""

from __future__ import annotations

import statistics
import threading
from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal

from smtp_bench_pro.domain.diagnostic_options import DiagnosticsOptions
from smtp_bench_pro.domain.models import SMTPServerTarget
from smtp_bench_pro.domain.results import BenchmarkRunResult, BenchmarkSummary, SMTPProbeResult
from smtp_bench_pro.engine.smtp_probe import SMTPProbe


def calculate_jitter(values: list[float]) -> float:
    """Return mean absolute delta between consecutive total latencies."""
    if len(values) < 2:
        return 0.0
    deltas = [abs(values[index] - values[index - 1]) for index in range(1, len(values))]
    return round(statistics.mean(deltas), 2)


def calculate_summary(results: list[SMTPProbeResult]) -> BenchmarkSummary | None:
    totals = [result.total_ms for result in results if result.success and result.total_ms is not None]
    if not totals:
        return None
    return BenchmarkSummary(
        min_ms=round(min(totals), 2),
        median_ms=round(statistics.median(totals), 2),
        mean_ms=round(statistics.mean(totals), 2),
        max_ms=round(max(totals), 2),
        stddev_ms=round(statistics.stdev(totals), 2) if len(totals) > 1 else 0.0,
        jitter_ms=calculate_jitter(totals),
    )


class BenchmarkWorkerSignals(QObject):
    result_ready = Signal(object)
    progress_updated = Signal(int, int)
    benchmark_finished = Signal(object)


class BenchmarkWorker(QRunnable):
    """Runs SMTP probe iterations in a background Qt worker."""

    def __init__(
        self,
        target: SMTPServerTarget,
        iterations: int,
        probe: SMTPProbe | None = None,
        diagnostics_options: DiagnosticsOptions | None = None,
    ):
        super().__init__()
        if iterations <= 0:
            raise ValueError("iterations must be greater than zero")
        self.target = target
        self.iterations = iterations
        self.probe = probe or SMTPProbe()
        self.diagnostics_options = diagnostics_options or DiagnosticsOptions()
        self.signals = BenchmarkWorkerSignals()
        self._cancelled = False
        self._lock = threading.Lock()

    def cancel(self) -> None:
        with self._lock:
            self._cancelled = True

    def is_cancelled(self) -> bool:
        with self._lock:
            return self._cancelled

    def run(self) -> None:
        results: list[SMTPProbeResult] = []
        for index in range(self.iterations):
            if self.is_cancelled():
                break
            result = self.probe.run(self.target, diagnostics_options=self.diagnostics_options)
            results.append(result)
            self.signals.result_ready.emit(result)
            self.signals.progress_updated.emit(index + 1, self.iterations)
        run_result = BenchmarkRunResult(
            target=self.target,
            iterations=self.iterations,
            results=results,
            summary=calculate_summary(results),
        )
        self.signals.benchmark_finished.emit(run_result)


class SMTPBenchmarkEngine(QObject):
    """Qt-aware benchmark engine used by the application service and UI."""

    result_ready = Signal(object)
    progress_updated = Signal(int, int)
    benchmark_finished = Signal(object)

    def __init__(self, max_threads: int | None = None, probe: SMTPProbe | None = None):
        super().__init__()
        self.thread_pool = QThreadPool.globalInstance()
        if max_threads:
            self.thread_pool.setMaxThreadCount(max_threads)
        self.probe = probe
        self._workers: list[BenchmarkWorker] = []

    def run_benchmark(
        self, target: SMTPServerTarget, iterations: int, diagnostics_options: DiagnosticsOptions | None = None
    ) -> BenchmarkWorker:
        worker = BenchmarkWorker(
            target=target, iterations=iterations, probe=self.probe, diagnostics_options=diagnostics_options
        )
        worker.signals.result_ready.connect(self.result_ready)
        worker.signals.progress_updated.connect(self.progress_updated)
        worker.signals.benchmark_finished.connect(self.benchmark_finished)
        self._workers.append(worker)
        self.thread_pool.start(worker)
        return worker

    def cancel_all(self) -> None:
        for worker in self._workers:
            worker.cancel()

from smtp_bench_pro.domain.enums import ProbeStatus, SecurityMode
from smtp_bench_pro.domain.models import SMTPServerTarget
from smtp_bench_pro.domain.results import SMTPProbeResult
from smtp_bench_pro.engine.benchmark_engine import BenchmarkWorker, calculate_jitter, calculate_summary


class FakeProbe:
    def __init__(self) -> None:
        self.calls = 0

    def run(self, target: SMTPServerTarget, **_kwargs) -> SMTPProbeResult:
        self.calls += 1
        return SMTPProbeResult(
            hostname=target.hostname,
            resolved_ip="192.0.2.1",
            port=target.port,
            security_mode=target.security_mode,
            success=True,
            status=ProbeStatus.SUCCESS,
            total_ms=float(self.calls * 10),
        )


def test_calculate_summary() -> None:
    target = SMTPServerTarget("mail.example.com", 25, SecurityMode.STARTTLS)
    results = [FakeProbe().run(target), FakeProbe().run(target)]
    results[1].total_ms = 30.0

    summary = calculate_summary(results)

    assert summary is not None
    assert summary.min_ms == 10.0
    assert summary.max_ms == 30.0
    assert summary.median_ms == 20.0
    assert calculate_jitter([10.0, 20.0, 15.0]) == 7.5


def test_worker_emits_results_synchronously(qtbot) -> None:
    target = SMTPServerTarget("mail.example.com", 25, SecurityMode.STARTTLS)
    worker = BenchmarkWorker(target, iterations=2, probe=FakeProbe())
    results = []
    finished = []
    worker.signals.result_ready.connect(results.append)
    worker.signals.benchmark_finished.connect(finished.append)

    worker.run()

    assert len(results) == 2
    assert finished[0].summary is not None

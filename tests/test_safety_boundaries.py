from pathlib import Path


def test_diagnostics_code_does_not_call_prohibited_smtp_operations() -> None:
    root = Path(__file__).resolve().parents[1] / "src" / "smtp_bench_pro"
    prohibited = ['"MAIL FROM"', '"RCPT TO"', '"DATA"', '.login(']
    scanned = "\n".join(path.read_text(encoding="utf-8") for path in root.rglob("*.py"))

    for token in prohibited:
        assert token not in scanned

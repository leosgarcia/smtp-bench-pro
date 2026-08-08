import importlib.metadata
import pkgutil

from PySide6.QtWidgets import QWidget

from smtp_bench_pro.integration.module import SMTPBenchModule


def test_module_contract(qtbot) -> None:
    module = SMTPBenchModule()

    assert module.module_id == "smtp"
    assert module.display_name == "SMTP Bench Pro"
    assert module.version == "0.2.6"
    assert module.integration_api == 1
    assert module.vendor == "WL Tech"
    assert module.capabilities == frozenset({"benchmark", "diagnostics", "history", "security_audit"})
    module.initialize()
    widget = module.create_widget()
    qtbot.addWidget(widget)
    assert isinstance(widget, QWidget)
    labels = [widget.tab_widget.tabText(index) for index in range(widget.tab_widget.count())]
    assert "Sobre" not in labels
    module.shutdown()


def test_no_core_imports_in_smtp_package() -> None:
    package = __import__("smtp_bench_pro")
    package_paths = list(package.__path__)
    violations = []
    for module_info in pkgutil.walk_packages(package_paths, prefix="smtp_bench_pro."):
        module = __import__(module_info.name, fromlist=["*"])
        source = getattr(module, "__file__", "") or ""
        if source.endswith(".py"):
            with open(source, encoding="utf-8") as handle:
                text = handle.read()
            if "benchpro_core" in text or "bench_pro_core" in text:
                violations.append(source)
    assert violations == []


def test_entry_point_declared_when_installed() -> None:
    eps = importlib.metadata.entry_points(group="benchpro.modules")
    matches = [ep for ep in eps if ep.name == "smtp"]
    if matches:
        assert matches[0].value == "smtp_bench_pro.integration.module:SMTPBenchModule"





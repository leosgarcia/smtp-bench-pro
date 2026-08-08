from smtp_bench_pro.paths import app_data_dir, database_path, logs_dir


def test_smtp_paths_are_product_scoped() -> None:
    app_path = str(app_data_dir())

    assert "WL Tech" in app_path
    assert "SMTP Bench Pro" in app_path
    assert logs_dir().parent == app_data_dir()
    assert database_path().parent == app_data_dir()

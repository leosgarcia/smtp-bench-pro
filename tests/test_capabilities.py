from smtp_bench_pro.engine.capabilities import parse_ehlo_capabilities, supports_starttls


def test_parse_multiline_ehlo_capabilities() -> None:
    capabilities = parse_ehlo_capabilities(
        [
            "250-mail.example.com",
            "250-PIPELINING",
            "250-SIZE 10240000",
            "250-AUTH LOGIN PLAIN",
            "250 STARTTLS",
        ]
    )

    assert capabilities["PIPELINING"] == []
    assert capabilities["SIZE"] == ["10240000"]
    assert capabilities["AUTH"] == ["LOGIN", "PLAIN"]
    assert supports_starttls(capabilities)

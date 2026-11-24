from src.header_parser import parse_email_header


def test_parse_sender_and_recipient():
    raw = (
        "From: sender@example.com\r\n"
        "To: receiver@example.com\r\n"
        "Subject: Test Email\r\n"
        "\r\n"
        "Hello"
    )

    result = parse_email_header(raw)

    assert result["from"] == "sender@example.com"
    assert result["to"] == "receiver@example.com"


def test_parse_subject():
    raw = (
        "From: sender@example.com\r\n"
        "Subject: Security Test\r\n"
        "\r\n"
        "Hello"
    )

    result = parse_email_header(raw)

    assert result["subject"] == "Security Test"


def test_parse_authentication_results():
    raw = (
        "From: sender@example.com\r\n"
        "Authentication-Results: mx.example.com; "
        "spf=pass; dkim=pass; dmarc=fail\r\n"
        "\r\n"
        "Hello"
    )

    result = parse_email_header(raw)

    assert result["spf"] == "PASS"
    assert result["dkim"] == "PASS"
    assert result["dmarc"] == "FAIL"

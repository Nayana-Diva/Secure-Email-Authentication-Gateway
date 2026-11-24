from src.dmarc_checker import (
    parse_dmarc_record,
    check_alignment,
    evaluate_dmarc
)


def test_parse_valid_dmarc():
    record = "v=DMARC1; p=none"
    assert parse_dmarc_record(record)["p"] == "none"


def test_invalid_dmarc_policy():
    assert parse_dmarc_record("v=DMARC1; p=invalid") is None


def test_relaxed_alignment():
    assert check_alignment(
        "mail.example.com",
        "example.com"
    ) is True


def test_strict_alignment():
    assert check_alignment(
        "mail.example.com",
        "example.com",
        "strict"
    ) is False


def test_dmarc_pass_with_aligned_spf():
    result = evaluate_dmarc(
        "example.com",
        "PASS",
        "example.com",
        "FAIL",
        "other.com",
        "v=DMARC1; p=reject"
    )

    assert result["result"] == "PASS"


def test_dmarc_fail():
    result = evaluate_dmarc(
        "example.com",
        "FAIL",
        "example.net",
        "FAIL",
        "example.net",
        "v=DMARC1; p=reject"
    )

    assert result["result"] == "FAIL"

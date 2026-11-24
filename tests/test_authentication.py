from src.authentication import authenticate_email
from src.dkim_checker import generate_keys, sign_email


def create_test_email():
    email = (
        b"From: sender@example.com\r\n"
        b"To: receiver@example.com\r\n"
        b"Subject: Gateway Integration Test\r\n"
        b"\r\n"
        b"This is a controlled security test email.\r\n"
    )

    return sign_email(email, "example.com", "test")


def test_complete_authentication_pass():
    generate_keys()

    signed_email = create_test_email()

    result = authenticate_email(
        raw_email=signed_email,
        client_ip="192.168.1.10",
        mail_from_domain="example.com",
        spf_record="v=spf1 ip4:192.168.1.10 -all",
        dmarc_record="v=DMARC1; p=reject"
    )

    assert result["independent_results"]["spf"] == "PASS"
    assert result["independent_results"]["dkim"] == "PASS"
    assert result["independent_results"]["dmarc"]["result"] == "PASS"


def test_authentication_detects_modified_email():
    generate_keys()

    signed_email = create_test_email()

    modified_email = signed_email.replace(
        b"controlled security test email",
        b"modified security test email"
    )

    result = authenticate_email(
        raw_email=modified_email,
        client_ip="192.168.1.10",
        mail_from_domain="example.com",
        spf_record="v=spf1 ip4:192.168.1.10 -all",
        dmarc_record="v=DMARC1; p=reject"
    )

    assert result["independent_results"]["dkim"] == "FAIL"
    assert result["independent_results"]["dmarc"]["result"] == "PASS"

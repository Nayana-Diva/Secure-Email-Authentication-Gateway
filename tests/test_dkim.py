from src.dkim_checker import (
    generate_keys,
    sign_email,
    verify_email
)


def test_dkim_key_generation():
    result = generate_keys()
    assert "successfully" in result


def test_dkim_signature_verification():
    generate_keys()

    email = (
        b"From: sender@example.com\r\n"
        b"To: receiver@example.com\r\n"
        b"Subject: Security Test\r\n"
        b"\r\n"
        b"This is a test email.\r\n"
    )

    signed_email = sign_email(email, "example.com", "test")

    assert verify_email(signed_email) is True


def test_modified_email_fails_verification():
    generate_keys()

    email = (
        b"From: sender@example.com\r\n"
        b"To: receiver@example.com\r\n"
        b"Subject: Security Test\r\n"
        b"\r\n"
        b"This is a test email.\r\n"
    )

    signed_email = sign_email(email, "example.com", "test")

    modified_email = signed_email.replace(
        b"This is a test email.",
        b"This email was modified."
    )

    assert verify_email(modified_email) is False

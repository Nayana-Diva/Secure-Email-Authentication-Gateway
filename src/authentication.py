import re

from src.spf_checker import check_spf
from src.dkim_checker import verify_email
from src.dmarc_checker import evaluate_dmarc
from src.header_parser import parse_email_header


def authenticate_email(
    raw_email,
    client_ip,
    mail_from_domain,
    spf_record,
    dmarc_record
):
    if isinstance(raw_email, str):
        raw_email = raw_email.encode("utf-8")

    headers = parse_email_header(raw_email)

    from_address = headers["from"]

    if "@" not in from_address:
        raise ValueError("Invalid or missing From address.")

    from_domain = from_address.rsplit("@", 1)[1].lower()

    # Independent SPF evaluation
    spf_result = check_spf(client_ip, spf_record)

    # Independent DKIM signature verification
    dkim_result = verify_email(raw_email)

    signature_match = re.search(
        rb"\bd=([^;\s]+)",
        raw_email.split(b"\r\n", 1)[0],
        re.IGNORECASE
    )

    dkim_domain = (
        signature_match.group(1).decode().lower()
        if signature_match and dkim_result
        else None
    )

    dkim_status = "PASS" if dkim_result else "FAIL"

    # Independent DMARC policy evaluation
    dmarc_result = evaluate_dmarc(
        from_domain=from_domain,
        spf_result=spf_result,
        spf_domain=mail_from_domain,
        dkim_result=dkim_status,
        dkim_domain=dkim_domain,
        record=dmarc_record
    )

    return {
        "email": headers,
        "independent_results": {
            "spf": spf_result,
            "dkim": dkim_status,
            "dmarc": dmarc_result
        },
        "reported_results": {
            "spf": headers["spf"],
            "dkim": headers["dkim"],
            "dmarc": headers["dmarc"]
        }
    }

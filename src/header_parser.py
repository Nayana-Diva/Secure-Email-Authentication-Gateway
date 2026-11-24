from email import policy
from email.parser import BytesParser
from email.utils import parseaddr


def parse_email_header(raw_email):
    if isinstance(raw_email, str):
        raw_email = raw_email.encode("utf-8")

    message = BytesParser(
        policy=policy.default
    ).parsebytes(raw_email)

    sender = parseaddr(message.get("From", ""))[1]
    recipient = parseaddr(message.get("To", ""))[1]

    authentication_results = message.get_all(
        "Authentication-Results", []
    )

    received_headers = message.get_all("Received", [])

    results = {
        "from": sender,
        "to": recipient,
        "subject": message.get("Subject", ""),
        "authentication_results": [],
        "received_headers": received_headers,
        "spf": "NOT_FOUND",
        "dkim": "NOT_FOUND",
        "dmarc": "NOT_FOUND"
    }

    for header in authentication_results:
        value = str(header)
        results["authentication_results"].append(value)

        lower_value = value.lower()

        for protocol in ("spf", "dkim", "dmarc"):
            marker = protocol + "="

            if marker in lower_value:
                import re

                match = re.search(
                    rf"\b{protocol}=(pass|fail|softfail|neutral|none|temperror|permerror)\b",
                    lower_value
                )

                if match:
                    results[protocol] = match.group(1).upper()

    return results

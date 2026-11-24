import ipaddress
import dns.resolver


def get_spf_record(domain):
    try:
        answers = dns.resolver.resolve(domain, "TXT")

        for record in answers:
            txt = "".join(
                part.decode() if isinstance(part, bytes) else part
                for part in record.strings
            )

            if txt.startswith("v=spf1"):
                return txt

        return None

    except Exception:
        return None


def check_spf(ip_address, spf_record):
    try:
        ip = ipaddress.ip_address(ip_address)
    except ValueError:
        return "INVALID_IP"

    if not spf_record:
        return "NONE"

    if not spf_record.startswith("v=spf1"):
        return "INVALID_RECORD"

    mechanisms = spf_record.split()[1:]

    for mechanism in mechanisms:
        if mechanism in ("all", "-all", "~all", "?all"):
            qualifier = mechanism[0] if mechanism != "all" else "+"
            return {
                "+": "PASS",
                "-": "FAIL",
                "~": "SOFTFAIL",
                "?": "NEUTRAL"
            }[qualifier]

        qualifier = "+"
        value = mechanism

        if mechanism[0] in "+-~?":
            qualifier = mechanism[0]
            value = mechanism[1:]

        try:
            if value.startswith("ip4:") and ip.version == 4:
                network = ipaddress.ip_network(value[4:], strict=False)

                if ip in network:
                    return {
                        "+": "PASS",
                        "-": "FAIL",
                        "~": "SOFTFAIL",
                        "?": "NEUTRAL"
                    }[qualifier]

            elif value.startswith("ip6:") and ip.version == 6:
                network = ipaddress.ip_network(value[4:], strict=False)

                if ip in network:
                    return {
                        "+": "PASS",
                        "-": "FAIL",
                        "~": "SOFTFAIL",
                        "?": "NEUTRAL"
                    }[qualifier]

        except ValueError:
            return "INVALID_RECORD"

    return "NEUTRAL"


def check_domain_spf(domain, ip_address):
    record = get_spf_record(domain)
    return {
        "domain": domain,
        "ip_address": ip_address,
        "spf_record": record,
        "result": check_spf(ip_address, record)
    }

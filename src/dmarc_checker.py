import dns.resolver


def get_dmarc_record(domain):
    dmarc_domain = f"_dmarc.{domain}"

    try:
        answers = dns.resolver.resolve(dmarc_domain, "TXT")

        for record in answers:
            txt = "".join(
                part.decode() if isinstance(part, bytes) else part
                for part in record.strings
            )

            if txt.startswith("v=DMARC1"):
                return txt

        return None

    except Exception:
        return None


def parse_dmarc_record(record):
    if not record:
        return None

    if not record.startswith("v=DMARC1"):
        return None

    policy = {}

    for item in record.split(";"):
        item = item.strip()

        if "=" in item:
            key, value = item.split("=", 1)
            policy[key.strip()] = value.strip()

    if policy.get("v") != "DMARC1":
        return None

    if policy.get("p") not in ("none", "quarantine", "reject"):
        return None

    return policy


def check_alignment(auth_domain, from_domain, mode="relaxed"):
    if not auth_domain or not from_domain:
        return False

    auth_domain = auth_domain.lower().rstrip(".")
    from_domain = from_domain.lower().rstrip(".")

    if mode == "strict":
        return auth_domain == from_domain

    return (
        auth_domain == from_domain
        or auth_domain.endswith("." + from_domain)
        or from_domain.endswith("." + auth_domain)
    )


def evaluate_dmarc(
    from_domain,
    spf_result,
    spf_domain,
    dkim_result,
    dkim_domain,
    record
):
    policy = parse_dmarc_record(record)

    if policy is None:
        return {
            "result": "NONE",
            "policy": None,
            "reason": "No valid DMARC policy found."
        }

    spf_mode = policy.get("aspf", "r")
    dkim_mode = policy.get("adkim", "r")

    spf_alignment = (
        spf_result == "PASS"
        and check_alignment(
            spf_domain,
            from_domain,
            "strict" if spf_mode == "s" else "relaxed"
        )
    )

    dkim_alignment = (
        dkim_result == "PASS"
        and check_alignment(
            dkim_domain,
            from_domain,
            "strict" if dkim_mode == "s" else "relaxed"
        )
    )

    passed = spf_alignment or dkim_alignment

    return {
        "result": "PASS" if passed else "FAIL",
        "policy": policy["p"],
        "spf_aligned": spf_alignment,
        "dkim_aligned": dkim_alignment,
        "reason": (
            "At least one aligned authentication method passed."
            if passed
            else "Neither SPF nor DKIM passed with alignment."
        )
    }

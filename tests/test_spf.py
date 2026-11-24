from src.spf_checker import check_spf


def test_authorized_ip_passes():
    record = "v=spf1 ip4:192.168.1.10 -all"
    assert check_spf("192.168.1.10", record) == "PASS"


def test_unauthorized_ip_fails():
    record = "v=spf1 ip4:192.168.1.10 -all"
    assert check_spf("192.168.1.20", record) == "FAIL"


def test_missing_record_returns_none():
    assert check_spf("192.168.1.10", None) == "NONE"


def test_softfail_policy():
    record = "v=spf1 ip4:192.168.1.10 ~all"
    assert check_spf("192.168.1.20", record) == "SOFTFAIL"


def test_invalid_ip():
    record = "v=spf1 ip4:192.168.1.10 -all"
    assert check_spf("invalid-ip", record) == "INVALID_IP"

from classifier import classify, is_private_ip


def test_classify_thresholds():
    assert classify(0, 51, 11) == "SAFE"
    assert classify(10, 51, 11) == "SAFE"
    assert classify(11, 51, 11) == "SUSPICIOUS"
    assert classify(50, 51, 11) == "SUSPICIOUS"
    assert classify(51, 51, 11) == "MALICIOUS"
    assert classify(100, 51, 11) == "MALICIOUS"


def test_private_ips():
    assert is_private_ip("10.0.0.47") is True
    assert is_private_ip("192.168.1.105") is True
    assert is_private_ip("172.16.254.12") is True
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("not-an-ip") is False

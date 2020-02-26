import pytest

from ip.convert import int2ip, ip2int, CIDR


def test_ip2int():
    assert ip2int('192.168.1.1') == 3232235777
    assert ip2int('10.0.0.0') == 167772160
    assert ip2int('176.16.0.1') == 2953838593


def test_cidr():
    assert int2ip(CIDR.from_str("192.168.0.0/24")._mask()) == "255.255.255.0"

    assert str(CIDR.from_str("192.168.0.1/24").normalized()) == "192.168.0.0/24"
    assert str(CIDR.from_str("192.168.1.0/23").normalized()) == "192.168.0.0/23"


def test_merge():
    a = CIDR.from_str("192.168.0.0/24")
    b = CIDR(ip2int("192.168.1.0"), 24)
    c = CIDR(ip2int("192.168.2.0"), 24)

    assert a.merge_with(b) == CIDR(a.prefix, 23)
    assert b.merge_with(c) is None
    assert a.merge_with(c) is None


if __name__ == '__main__':
    pytest.main()

import pytest

from ip.convert import *


def test_ip2int():
    assert ip2int('192.168.1.1') == 3232235777
    assert ip2int('10.0.0.0') == 167772160
    assert ip2int('176.16.0.1') == 2953838593


@pytest.mark.parametrize("ip", [
    "::1",
    "2a03:6921:2::",
    "2a03:6947:1800::",
    "2a01:afc0:0:2::",
    "2a03:4a80:3:ffff:ffff:ffff:ffff:ffff",
    "2a03:b600:291::3fff:ffff",
])
def test_ipv6patterns(ip):
    assert IPV6.fullmatch(ip).group("address") == ip


def test_ipv4patterns():
    m = IPV4.fullmatch('192.168.1.1')
    assert m.group("address") == "192.168.1.1"
    assert m.group("suffix") is None
    m = IPV4.fullmatch('192.168.1.1/24')
    assert m.group("address") == "192.168.1.1"
    assert m.group("suffix") == "24"


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

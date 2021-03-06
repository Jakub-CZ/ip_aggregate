from itertools import islice
from os.path import abspath, dirname, join

import pytest

from ip.convert import *

ADDRESS_FILE = join(dirname(abspath(__file__)), "..", "czsk.csv")
LIMIT_TEST_CASES = 100


def ip2int(s):
    # noinspection PyProtectedMember
    return CIDR._ip2int(s)


def int2ip(ip):
    # noinspection PyProtectedMember
    return CIDR._int2ip(ip)


def test_ip2int():
    assert ip2int('192.168.1.1') == 3232235777
    assert ip2int('10.0.0.0') == 167772160
    assert ip2int('176.16.0.1') == 2953838593


@pytest.mark.parametrize("address_suffix",
                         islice(re.findall(CIDR.IP_PATTERN, open(ADDRESS_FILE).read()), LIMIT_TEST_CASES))
def test_ipv4_ip2int2ip(address_suffix):
    ip = address_suffix[0]
    assert str(CIDR._int2ip(CIDR._ip2int(ip))) == ip


@pytest.mark.parametrize("address_suffix",
                         islice(re.findall(CIDRv6.IP_PATTERN, open(ADDRESS_FILE).read()), LIMIT_TEST_CASES))
def test_ipv6_ip2int2ip(address_suffix):
    ip = address_suffix[0]
    assert str(CIDRv6._int2ip(CIDRv6._ip2int(ip))) == ip


@pytest.mark.parametrize("ip", [
    "::1",
    "2a03:6921:2::",
    "2a03:6947:1800::",
    "2a01:afc0:0:2::",
    "2a03:4a80:3:ffff:ffff:ffff:ffff:ffff",
    "2a03:b600:291::3fff:ffff",
])
def test_ipv6patterns(ip):
    assert CIDRv6.IP_PATTERN.fullmatch(ip).group("address") == ip
    i = CIDRv6._ip2int(ip)
    assert str(CIDRv6._int2ip(i)) == ip
    assert CIDRv6.from_str(ip + "/128").ip == ip


def test_ipv4patterns():
    m = CIDR.IP_PATTERN.fullmatch('192.168.1.1')
    assert m.group("address") == "192.168.1.1"
    assert m.group("suffix") is None
    m = CIDR.IP_PATTERN.fullmatch('192.168.1.1/24')
    assert m.group("address") == "192.168.1.1"
    assert m.group("suffix") == "24"


def test_cidr():
    assert int2ip(CIDR.from_str("192.168.0.0/24")._mask()) == "255.255.255.0"
    assert CIDR.from_str("192.168.0.0/24").ip == "192.168.0.0"

    assert str(CIDR.from_str("192.168.0.1/24").normalized()) == "192.168.0.0/24"
    assert str(CIDR.from_str("192.168.1.0/23").normalized()) == "192.168.0.0/23"

    line = "2.16.25.0         ,2.16.25.255                            ,CZ\n"
    assert str(CIDR.from_str(line)) == "2.16.25.0/24"

    line = "5.39.55.24        ,5.39.55.255                            ,CZ\n"
    with pytest.raises(ValueError):
        CIDR.from_str(line)

    assert list(str(ip) for ip in CIDR.many_from_str(line)) == [
        "5.39.55.24/29",
        "5.39.55.32/27",
        "5.39.55.64/26",
        "5.39.55.128/25"]


def test_merge():
    a = CIDR.from_str("192.168.0.0/24")
    b = CIDR(ip2int("192.168.1.0"), 24)
    c = CIDR(ip2int("192.168.2.0"), 24)

    assert a.merge_with(b) == CIDR(a.prefix, 23)
    assert b.merge_with(c) is None
    assert a.merge_with(c) is None


@pytest.mark.parametrize("ip_range,expected_subnets", [
    ("192.168.1.72,192.168.1.255", ["192.168.1.72/29", "192.168.1.80/28", "192.168.1.96/27", "192.168.1.128/25"]),
    ("2.16.25.0,2.16.25.255", ["2.16.25.0/24"]),
    ("5.180.196.0,5.180.203.255", ["5.180.196.0/22", "5.180.200.0/22"]),
    ("13.32.112.0,13.32.114.255", ["13.32.112.0/23", "13.32.114.0/24"]),
])
def test__from_two_addresses(ip_range, expected_subnets):
    a, b = ip_range.split(",")
    assert list(str(ip) for ip in CIDR._from_two_addresses(ip2int(a), ip2int(b))) == expected_subnets


if __name__ == '__main__':
    pytest.main()

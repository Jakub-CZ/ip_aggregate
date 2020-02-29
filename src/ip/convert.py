import re
from collections import deque
from dataclasses import dataclass
from operator import sub

from ip import aggregate_subnets

IPV4 = re.compile(r"(?P<address>(?:\d{1,3}\.){3}\d{1,3})(?:/(?P<suffix>\d+))?")
IPV6 = re.compile(r"(?P<address>(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})(?:/(?P<suffix>\d+))?")
_IPV6_BLOCKS_OF_ZEROS = re.compile(r"(?:\W|^)0(?::0)+:?")


@dataclass
class CIDR:
    """Classless Inter-Domain Routing notation for IP address range, e.g. ``192.0.2.0/24``"""
    prefix: int
    suffix: int

    BITS = 32

    @classmethod
    def _int2ip(cls, ip: int) -> str:
        return ".".join(str((ip & ((1 << n) - 1)) >> (n - 8)) for n in (32, 24, 16, 8))

    @classmethod
    def _ip2int(cls, ip: str) -> int:
        total = 0
        for i in ip.strip().split("."):
            total = (total << 8) | int(i)
        return total

    def __repr__(self):
        return f"{self._int2ip(self.prefix)}/{self.suffix}"

    def __lt__(self, other):
        assert isinstance(other, CIDR)
        return self.prefix < other.prefix

    def __contains__(self, item):
        if isinstance(item, CIDR):
            return self.size() >= item.size() and any(
                self.__contains__(x) for x in (item.prefix, item.next_address() - 1))
        return self.prefix <= item < self.next_address()

    def _mask(self):
        shift = self.BITS - self.suffix
        return ((1 << self.BITS) - 1) >> shift << shift

    @classmethod
    def from_str(cls, s: str):
        iterator = iter(cls.many_from_str(s))
        out = next(iterator)
        try:
            extra = next(iterator)
        except StopIteration:
            return out
        else:
            raise ValueError(f"Following line produced more than one subnet: {out}, {extra}, ...\n'{s.strip()}'")

    @classmethod
    def many_from_str(cls, s: str):
        columns = s.strip().split(",")
        addresses = []
        for item in columns:
            m = IPV4.match(item)
            if m:
                ip = m.groupdict()
                address = cls._ip2int(ip["address"])
                suffix = ip["suffix"]
                if suffix:
                    return [cls(address, int(suffix))]
                # look for a 2nd address
                addresses.append(address)
                if len(addresses) == 2:
                    a, b = addresses
                    return cls._from_two_addresses(a, b)
        raise ValueError(f"Following line does not contain sufficient data:\n'{s.strip()}'\n"
                         f"parsed address expressions={[cls._int2ip(i) for i in addresses]}'")

    @classmethod
    def _from_two_addresses(cls, a: int, b: int):
        prefix = a & b
        # assert a == prefix, f"First address {int2ip(a)} != common prefix {int2ip(prefix)}"
        mask = a ^ b
        mask_length = int.bit_length(mask)
        # assert (1 << mask_length) - 1 == mask, f"Mask {mask}={bin(mask)} contains zeros"
        if a == prefix and (1 << mask_length) - 1 == mask:
            return [cls(prefix, cls.BITS - mask_length)]
        # not a proper subnet; generate list of all addresses individually and let them get aggregated at the end
        # print(f"Improper subnet {int2ip(a)} - {int2ip(b)}; range of {b - a + 1} addresses")
        return aggregate_subnets(deque(cls(ip, cls.BITS) for ip in range(a, b + 1)))

    def normalized(self):
        return CIDR(self.prefix & self._mask(), self.suffix)

    def size(self) -> int:
        """Returns number of addresses in the range"""
        return 1 << (self.BITS - self.suffix)

    def next_address(self) -> int:
        """Returns first address right AFTER this address range"""
        return self.prefix + self.size()

    def merge_with(self, other):
        if self.suffix != other.suffix:
            return None  # only same-size ranges can be merged
        x = CIDR(self.prefix, self.suffix - 1).normalized()  # smallest strict superset of address range `a`
        y = CIDR(other.prefix, other.suffix - 1).normalized()
        if x == y:
            return x
        return None


@dataclass
class CIDRv6(CIDR):
    BITS = 64

    @classmethod
    def _int2ip(cls, ip: int) -> str:
        ip = ":".join(format((ip & ((1 << n) - 1)) >> (n - 16), "x") for n in range(128, 0, -16))
        matches = [m.span() for m in re.finditer(_IPV6_BLOCKS_OF_ZEROS, ip)]
        if matches:
            start, end = max(matches, key=lambda t: -sub(*t))
            return ip[:start] + "::" + ip[end:]
        return ip

    @classmethod
    def _ip2int(cls, ip: str) -> int:
        total = 0
        separators = ip.count(":")  # this is less than 7 if IP was in abbreviated format
        ip = ip.replace("::", (9 - separators) * ":")
        assert ip.count(":") == 7
        for i in ip.split(":"):
            total = (total << 16) | int("0" + i, 16)
        return total

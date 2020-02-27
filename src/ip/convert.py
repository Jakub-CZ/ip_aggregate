import re
from dataclasses import dataclass

IP_SHIFTS = (1 << 24, 1 << 16, 1 << 8, 1)
IPV4 = re.compile(r"(?P<address>(\d{1,3}\.){3}\d{1,3})(/(?P<suffix>\d+))?")
IPV6 = re.compile(r"(?P<address>([0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})(/(?P<suffix>\d+))?")


def _dot(x, y):
    return sum(x_i * y_i for x_i, y_i in zip(x, y))


def ip2int(ip: str) -> int:
    parts = [int(i) for i in ip.strip().split(".")]
    return _dot(parts, IP_SHIFTS)


def int2ip(ip: int) -> str:
    parts = [str((ip & ((1 << n) - 1)) >> (n - 8)) for n in (32, 24, 16, 8)]
    return ".".join(parts)


@dataclass
class CIDR:
    """Classless Inter-Domain Routing notation for IP address range, e.g. ``192.0.2.0/24``"""
    prefix: int
    suffix: int

    def __repr__(self):
        return f"{int2ip(self.prefix)}/{self.suffix}"

    def __lt__(self, other):
        assert isinstance(other, CIDR)
        return self.prefix < other.prefix

    def __contains__(self, item):
        if isinstance(item, CIDR):
            return self.size() >= item.size() and any(
                self.__contains__(x) for x in (item.prefix, item.next_address() - 1))
        else:
            return self.prefix <= item < self.next_address()

    def _mask(self):
        shift = 32 - self.suffix
        return ((1 << 32) - 1) >> shift << shift

    @classmethod
    def from_str(cls, s: str):
        prefix, suffix = s.strip().split("/")
        return cls(ip2int(prefix), int(suffix))

    def normalized(self):
        return CIDR(self.prefix & self._mask(), self.suffix)

    def size(self) -> int:
        """Returns number of addresses in the range"""
        return 1 << (32 - self.suffix)

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

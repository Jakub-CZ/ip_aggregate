from collections import deque
from itertools import chain

from ip import aggregate_subnets
from ip.convert import CIDR, IPV4


def process_file(from_file, to_file):
    with open(from_file) as f:
        # TODO: count addresses first, and compare with total amount at the end
        print(f"Loading {from_file}...")
        ranges = deque(
            filter(None, chain.from_iterable(CIDR.many_from_str(line) for line in f if IPV4.match(line.strip()))))
    len_orig = len(ranges)
    print("Aggregating...")
    print(f"original ranges = {len_orig}")
    ranges = aggregate_subnets(ranges)
    len_final = len(ranges)
    print(f"aggregated ranges = {len_final} ({100 * len_final / len_orig:.2f}%)")
    with open(to_file, "w") as f:
        for x in ranges:
            f.write(f"{x}\n")
    print(f"Aggregated ranges stored in {to_file}")


if __name__ == '__main__':
    process_file(from_file="czech_ranges.txt", to_file="czech_ranges_aggregated.txt")
    process_file(from_file="czsk.csv", to_file="czsk_aggregated.txt")
    print("DONE.")

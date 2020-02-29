from collections import deque

from ip import aggregate_subnets
from ip.convert import CIDR, IPV4


def process_file(from_file, to_file):
    with open(from_file) as f:
        print(f"Loading {from_file}...")
        ranges = deque()
        len_orig = 0
        for line in f:
            line = line.strip()
            if not line:
                continue
            len_orig += 1
            if IPV4.match(line):
                ranges.extend(CIDR.many_from_str(line))
    print("Aggregating...")
    print(f"original ranges = {len_orig:n}")
    ranges = aggregate_subnets(ranges, report=True)
    len_final = len(ranges)
    print(f"aggregated ranges = {len_final:n} ({100 * len_final / len_orig:.2f}%)")
    with open(to_file, "w") as f:
        for x in ranges:
            f.write(f"{x}\n")
    print(f"Aggregated ranges stored in {to_file}")
    print()


if __name__ == '__main__':
    process_file(from_file="czech_ranges.txt", to_file="czech_ranges_aggregated.txt")
    process_file(from_file="czsk.csv", to_file="czsk_aggregated.txt")
    print("DONE.")

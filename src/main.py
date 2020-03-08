from collections import deque

from ip import aggregate_subnets
from ip.convert import CIDR, CIDRv6


def process_file(from_file, to_file):
    with open(from_file) as f:
        print(f"Loading {from_file}...")
        ranges_v4 = deque()
        ranges_v6 = deque()
        len_orig_v4 = 0
        len_orig_v6 = 0
        for line in f:
            line = line.strip()
            if not line:
                continue
            if CIDR.match(line):
                len_orig_v4 += 1
                ranges_v4.extend(CIDR.many_from_str(line))
                continue
            if CIDRv6.match(line):
                len_orig_v6 += 1
                ranges_v6.extend(CIDRv6.many_from_str(line))
                continue
            raise ValueError(f"Unprocessed line!\n'{line}'")
    print("Aggregating...")
    print(f"original v4 ranges = {len_orig_v4:n}")
    print(f"original v6 ranges = {len_orig_v6:n}")
    ranges_v4 = aggregate_subnets(ranges_v4, report=True)
    len_final_v4 = len(ranges_v4)
    if len_orig_v4:
        print(f"aggregated v4 ranges = {len_final_v4:n} ({100 * len_final_v4 / len_orig_v4:.2f}%)")
    ranges_v6 = aggregate_subnets(ranges_v6, report=True)
    len_final_v6 = len(ranges_v6)
    if len_orig_v6:
        print(f"aggregated v6 ranges = {len_final_v6:n} ({100 * len_final_v6 / len_orig_v6:.2f}%)")
    with open(to_file, "w") as f:
        for x in ranges_v4 + ranges_v6:
            f.write(f"{x}\n")
    print(f"Aggregated ranges stored in {to_file}")
    print()


if __name__ == '__main__':
    process_file(from_file="czech_ranges.txt", to_file="czech_ranges_aggregated.txt")
    process_file(from_file="czsk.csv", to_file="czsk_aggregated.txt")
    print("DONE.")

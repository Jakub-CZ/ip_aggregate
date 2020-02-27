from collections import deque

from ip.convert import CIDR

if __name__ == '__main__':
    with open("czech_ranges.txt") as f:
        ranges = deque(filter(None, (CIDR.from_str(line) for line in f if line.strip())))
    len_orig = len(ranges)
    print(f"original ranges = {len_orig}")

    while True:
        merged_ranges = deque()
        len_before = len(ranges)
        while ranges:
            a = ranges.popleft()
            if not ranges:  # `a` is the last entry
                merged_ranges.append(a)
                break
            b = ranges.popleft()
            assert a < b
            merged = a.merge_with(b)
            if merged:
                merged_ranges.append(merged)
            else:  # can't merge
                merged_ranges.append(a)
                ranges.appendleft(b)  # return `b` so that next we try to merge it with the next one
        ranges = merged_ranges
        if len(ranges) == len_before:
            break
        print(f"reduced to {len(ranges)}")

    len_final = len(ranges)
    print(f"aggregated ranges = {len_final} ({100 * len_final / len_orig:.2f}%)")
    with open("czech_ranges_aggregated.txt", "w") as f:
        for x in ranges:
            f.write(f"{x}\n")
    print("DONE.")

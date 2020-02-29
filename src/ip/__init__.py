import locale
from collections import deque
from typing import Tuple, Deque

locale.setlocale(locale.LC_ALL, '')


def filter_country(file_in: str, file_out: str, codes: Tuple[str, ...]):
    with open(file_in) as f, open(file_out, "w") as out:
        for line in f:
            if line.rstrip().endswith(codes):
                out.write(line)


def aggregate_subnets(subnets: Deque, report=False):
    while True:
        did_merge = False
        merged_subnets = deque()
        total_before = sum(subnet.size() for subnet in subnets)
        while subnets:
            a = subnets.popleft()
            if not subnets:  # `a` is the last entry
                merged_subnets.append(a)
                break
            b = subnets.popleft()
            assert a < b
            merged = a.merge_with(b)
            if merged:
                did_merge = True
                merged_subnets.append(merged)
            else:  # can't merge
                merged_subnets.append(a)
                subnets.appendleft(b)  # return `b` so that next we try to merge it with the next one
        subnets = merged_subnets
        total_after = sum(subnet.size() for subnet in subnets)
        assert total_before == total_after
        if not did_merge:
            if report:
                print(f"Total number of addresses: {total_after:n}")
            return subnets
        # print(f"reduced to {len(subnets)}")


if __name__ == '__main__':
    filter_country("dbip-country-lite-2020-02.csv", "czsk.csv", ("CZ", "SK"))

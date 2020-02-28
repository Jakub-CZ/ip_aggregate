from collections import deque
from typing import Tuple, Deque


def filter_country(file_in: str, file_out: str, codes: Tuple[str, ...]):
    with open(file_in) as f, open(file_out, "w") as out:
        for line in f:
            if line.rstrip().endswith(codes):
                out.write(line)


if __name__ == '__main__':
    filter_country("dbip-country-lite-2020-02.csv", "czsk.csv", ("CZ", "SK"))


def aggregate_subnets(subnets: Deque):
    while True:
        did_merge = False
        merged_subnets = deque()
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
        if not did_merge:
            return subnets
        # print(f"reduced to {len(subnets)}")

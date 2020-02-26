from typing import Tuple


def filter_country(file_in: str, file_out: str, codes: Tuple[str, ...]):
    with open(file_in) as f, open(file_out, "w") as out:
        for line in f:
            if line.rstrip().endswith(codes):
                out.write(line)


if __name__ == '__main__':
    filter_country("dbip-country-lite-2020-02.csv", "czsk.csv", ("CZ", "SK"))

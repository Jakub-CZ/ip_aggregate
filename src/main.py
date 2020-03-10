import argparse
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
    parser = argparse.ArgumentParser(
        description="Převede libovolné IP rozsahy na IP subnety zapsané ve formátu CIDR (např.: 1.2.3.0/24).\n"
                    "Některé netypické rozsahy musí být reprezentovány pomocí více subnetů",
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('from_file', help='jméno souboru, který obsahuje IP rozsahy; '
                                          'na každém řádku právě jeden rozsah;\n'
                                          'podporované formáty:\n'
                                          "    1.2.3.0/24\n"
                                          "    5.6.7.0  ,  5.6.7.128  ,  KOMENTÁŘ",
                        )
    parser.add_argument("destination", help="soubor pro výstup")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--to-file", "-f", action="store_true",
                       help="výstup bude zapsán do souboru specifikovaného parametrem 'destination'")
    # TODO: add --format for --to_file
    group.add_argument("--to-db", "-d", action="store_true",
                       help="výstup bude zapsán do databáze;\n"
                            "soubor s údaji potřebnými pro připojení k DB je specifikovaný parametrem 'destination'")

    args = parser.parse_args()

    destination = args.destination  # type: str
    if args.to_file:
        assert not destination.endswith(".py"), f"Pravděpodobná chyba v zadaných parametrech, " \
                                                f"výstupní soubor {destination} je Python skript!"
        process_file(from_file=args.from_file, to_file=destination)
    elif args.to_db:
        assert destination.endswith(".py"), f"Pravděpodobná chyba v zadaných parametrech, " \
                                            f" soubor {destination} musí být Python skript!"
        with open(destination) as f:
            exec(f.read())
        db_vars = {"ADDRESS", "PORT", "DB", "USER", "PASSWORD"}
        assert db_vars.issubset(locals().keys()), f"Chybí tyto hodnoty: {db_vars - locals().keys()}"
        print(f">>> Tady bude připojení k DB {locals()['ADDRESS']} jako uživatel {locals()['USER']} "
              f"heslem {locals()['PASSWORD']}")
    else:
        raise ValueError(f"Nebyla zvolena žádná známá akce;\nargs={args}")

    print("Dokončeno.")

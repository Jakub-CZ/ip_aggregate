import argparse
from collections import deque
from typing import Deque, Callable

from ip import aggregate_subnets
from ip.convert import CIDR, CIDRv6
from ip.db import create_connection, delete_and_insert_into


def write_plain_text(to_file, ranges_v4: Deque[CIDR], ranges_v6: Deque[CIDR]):
    with open(to_file, "w") as f:
        for x in ranges_v4 + ranges_v6:
            f.write(f"{x}\n")


def write_rsc(to_file, ranges_v4: Deque[CIDR], ranges_v6: Deque[CIDR]):
    with open(to_file, "w") as f:
        f.write("/ip firewall address-list\n")
        for x in ranges_v4:
            f.write(f'add address={x} comment="Czech Republic" list=Country_IP_Allows\n')
        f.write("\n")
        f.write("/ipv6 firewall address-list\n")
        for x in ranges_v6:
            f.write(f'add address={x} comment="Czech Republic" list=Country_IP_Allows\n')


def write_to_db(to_file, ranges_v4: Deque[CIDR], ranges_v6: Deque[CIDR]):
    with open(to_file) as f:
        exec(f.read())
    connection = create_connection(locals()["ADDRESS"], locals()["USER"], locals()["PASSWORD"], locals()["DB"])
    try:
        delete_and_insert_into(connection, "address_list_ipv4", ranges_v4)
        delete_and_insert_into(connection, "address_list_ipv6", ranges_v6)
    finally:
        connection.close()


def process_file(from_file, to_file: str, write_routine: Callable[[str, Deque[CIDR], Deque[CIDR]], None]):
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
    write_routine(to_file, ranges_v4, ranges_v6)
    print(f"Aggregated ranges stored in {to_file}\n")


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Převede libovolné IP rozsahy na IP subnety zapsané ve formátu CIDR (např.: 1.2.3.0/24).\n"
                    "Některé netypické rozsahy musí být reprezentovány pomocí více subnetů.",
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('from_file', help='jméno souboru, který obsahuje IP rozsahy; '
                                          'na každém řádku právě jeden rozsah;\n'
                                          'podporované formáty:\n'
                                          "    1.2.3.0/24\n"
                                          "    5.6.7.0  ,  5.6.7.128  ,  KOMENTÁŘ",
                        )
    parser.add_argument("destination", help="soubor pro výstup; "
                                            "formát výstupních dat závisí na příponě uvedeného souboru.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--to-file", "-f", action="store_true",
                       help="výstup bude zapsán do souboru specifikovaného parametrem 'destination'")
    group.add_argument("--to-db", "-d", action="store_true",
                       help="výstup bude zapsán do databáze;\n"
                            "soubor s údaji potřebnými pro připojení k DB je specifikovaný parametrem 'destination'")
    return parser.parse_args()


def cli():
    args = parse_arguments()
    destination = args.destination  # type: str
    if args.to_file:
        assert not destination.endswith(".py"), f"Pravděpodobná chyba v zadaných parametrech, " \
                                                f"výstupní soubor {destination} je Python skript!"
        write_routine = write_rsc if destination.lower().endswith(".rsc") else write_plain_text
        process_file(from_file=args.from_file, to_file=destination, write_routine=write_routine)
    elif args.to_db:
        assert destination.endswith(".py"), f"Pravděpodobná chyba v zadaných parametrech, " \
                                            f" soubor {destination} musí být Python skript!"
        with open(destination) as f:
            exec(f.read())
        db_vars = {"ADDRESS", "DB", "USER", "PASSWORD"}
        assert db_vars.issubset(locals().keys()), f"Chybí tyto hodnoty: {db_vars - locals().keys()}"
        # TODO: podpora CZ+SK
        process_file(from_file=args.from_file, to_file=destination, write_routine=write_to_db)
    else:
        raise ValueError(f"Nebyla zvolena žádná známá akce;\nargs={args}")

    print("Dokončeno.")


if __name__ == '__main__':
    cli()

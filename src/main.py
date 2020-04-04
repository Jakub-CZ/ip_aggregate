import argparse
from collections import deque
from typing import Deque, Callable

from ip import aggregate_subnets
from ip.convert import CIDR, CIDRv6
from ip.db import create_connection, insert_into


# noinspection PyUnusedLocal
def write_plain_text(to_file, ranges_v4: Deque[CIDR], ranges_v6: Deque[CIDR], do_append: bool, comment: str = None):
    with open(to_file, "a" if do_append else "w") as f:
        for x in ranges_v4 + ranges_v6:
            f.write(f"{x}\n")


def write_rsc(to_file, ranges_v4: Deque[CIDR], ranges_v6: Deque[CIDR], do_append: bool, comment: str):
    with open(to_file, "a" if do_append else "w") as f:
        f.write("/ip firewall address-list\n")
        for x in ranges_v4:
            f.write(f'add address={x} comment="{comment}" list=Country_IP_Allows\n')
        f.write("\n")
        f.write("/ipv6 firewall address-list\n")
        for x in ranges_v6:
            f.write(f'add address={x} comment="{comment}" list=Country_IP_Allows\n')
        f.write("\n")


def write_to_db(to_file, ranges_v4: Deque[CIDR], ranges_v6: Deque[CIDR], do_append: bool, comment: str):
    with open(to_file) as f:
        exec(f.read())
    connection = create_connection(locals()["ADDRESS"], locals()["USER"], locals()["PASSWORD"], locals()["DB"])
    try:
        insert_into(connection, "address_list_ipv4", ranges_v4, comment, delete_old=not do_append)
        insert_into(connection, "address_list_ipv6", ranges_v6, comment, delete_old=not do_append)
    finally:
        connection.close()


def process_file(args: argparse.Namespace, write_routine: Callable[[str, Deque[CIDR], Deque[CIDR], bool, str], None]):
    from_file = args.from_file
    to_file = args.destination
    filter_str = args.filter
    do_append = args.append
    with open(from_file) as f:
        print(f"Loading {from_file}...")
        ranges_v4 = deque()
        ranges_v6 = deque()
        len_orig_v4 = 0
        len_orig_v6 = 0
        for line in f:
            if filter_str and filter_str not in line:
                continue
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
    write_routine(to_file, ranges_v4, ranges_v6, do_append, args.comment)
    print(f"Nové IP rozsahy {'připojeny k' if do_append else 'zapsány do'} "
          f"{'DB dle' if write_routine == write_to_db else 'souboru'} {to_file}\n")


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Převede libovolné IP rozsahy na IP subnety zapsané ve formátu CIDR (např.: 1.2.3.0/24).\n"
                    "Některé netypické rozsahy musí být reprezentovány pomocí více subnetů.\n"
                    "\n"
                    "Příklad použití:\n"
                    """python3 src/main.py czsk.csv --to-db db-config.py --filter ",CZ" && """
                    """python3 src/main.py czsk.csv --to-db db-config.py --filter ",SK" --append --comment Slovakia""",
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('from_file', help='jméno souboru, který obsahuje IP rozsahy; '
                                          'na každém řádku právě jeden rozsah;\n'
                                          'podporované formáty:\n'
                                          "    1.2.3.0/24\n"
                                          "    5.6.7.0  ,  5.6.7.128  ,  KOMENTÁŘ",
                        )
    parser.add_argument("destination", help="soubor pro výstup; "
                                            "formát výstupních dat závisí na příponě uvedeného souboru.")
    parser.add_argument("--append", "-a", action="store_true",
                        help="zachová předchozí výstupní data, tedy NEpřepíše soubor, NEsmaže stará data z databáze;\n"
                             "NEkontroluje, jestli tímto nevzniknou duplicitní záznamy")
    parser.add_argument("--comment", default="Czech Republic",
                        help="komentář přidělený každému výstupnímu záznamu (výchozí hodnota: 'Czech Republic')")
    parser.add_argument("--filter",
                        help="zpracuje pouze takové vstupní řádky, které obsahují zadaný řetězec")

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
        process_file(args=args, write_routine=write_routine)
    elif args.to_db:
        assert destination.endswith(".py"), f"Pravděpodobná chyba v zadaných parametrech, " \
                                            f" soubor {destination} musí být Python skript!"
        with open(destination) as f:
            exec(f.read())
        db_vars = {"ADDRESS", "DB", "USER", "PASSWORD"}
        assert db_vars.issubset(locals().keys()), f"Chybí tyto hodnoty: {db_vars - locals().keys()}"
        # TODO: podpora CZ+SK
        process_file(args=args, write_routine=write_to_db)
    else:
        raise ValueError(f"Nebyla zvolena žádná známá akce;\nargs={args}")


if __name__ == '__main__':
    cli()

from typing import Deque

from ip.convert import CIDR

try:
    import mysql.connector
    from mysql.connector import Error
    from mysql.connector.connection import MySQLConnection
except ImportError as e:
    if e.name == "mysql":
        print("Je potřeba nainstalovat balík 'mysql-connector-python' následujícím příkazem:\n"
              "pip3 install mysql-connector-python\n")
    raise


def create_connection(host_name, user_name, user_password, database):
    print(f"Připojuji se k MySQL {host_name}, databáze {database}")
    return mysql.connector.connect(
        host=host_name,
        user=user_name,
        password=user_password,
        db=database,
        raise_on_warnings=True,
    )


FIREWALL_LIST = "Country_IP_Allows"


def delete_and_insert_into(connection: MySQLConnection, table, ip_ranges: Deque[CIDR]):
    try:
        count_where_list = f"SELECT COUNT(*) FROM {table} WHERE list = %s"
        cursor = connection.cursor()
        cursor.execute(count_where_list, (FIREWALL_LIST,))
        print(f"Z tabulky {table} bude odstraněno {cursor.fetchone()[0]} řádků.")
        cursor.close()

        delete_where_list = f"DELETE FROM {table} WHERE list = %s"
        cursor = connection.cursor()
        cursor.execute(delete_where_list, (FIREWALL_LIST,))
        cursor.close()

        insert_query = (f"INSERT INTO {table} (address, mask, list, comment, disabled) "
                        "VALUES (%s, %s, %s, %s, %s)")
        cursor = connection.cursor()
        cursor.executemany(insert_query,
                           [(ip.ip, ip.suffix, FIREWALL_LIST, "Czech Republic", 0) for ip in ip_ranges])
        connection.commit()
        cursor.close()
        print(f"Bylo vloženo {len(ip_ranges)} řádků.")
    except mysql.connector.Error:
        connection.rollback()
        raise

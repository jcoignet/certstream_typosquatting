import sqlite3
import sys

TABLE_FIELDS = 'id | domain | ip | levenshtein_ratio | untrusted_issuer | abuseipdb_score | typo_score | alert_level'


def delete_table(db_connection):
    db_connection.execute("DROP TABLE alerts")
    db_connection.commit()


def create_table(db_connection):
    db_connection.execute('''CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    domain text NOT NULL,
    ip text,
    levenshtein_ratio INT,
    issuer TEXT,
    untrusted_issuer BOOL,
    abuseipdb_score INT,
    typo_score INT,
    alert_level text
);
''')
    db_connection.commit()


def full_print_table(db_connection):
    res = db_connection.execute('SELECT * FROM alerts').fetchall()
    print(TABLE_FIELDS)
    for r in res:
        print(r)


def search_by_domain(db_connection, domain):
    res = db_connection.execute(f'SELECT * FROM alerts WHERE domain="{domain}"').fetchall()
    print(TABLE_FIELDS)
    for r in res:
        print(r)


def last_entry(db_connection):
    res = db_connection.execute('SELECT * FROM alerts').fetchone()
    print(TABLE_FIELDS)
    print(res)


def last_10_entries(db_connection):
    res = db_connection.execute('SELECT * FROM alerts ORDER BY rowid DESC limit 10').fetchall()
    print(TABLE_FIELDS)
    for r in res:
        print(r)


def search_by_level(db_connection, alert_level):
    res = db_connection.execute(f'SELECT * FROM alerts WHERE alert_level="{alert_level}"').fetchall()
    print(TABLE_FIELDS)
    for r in res:
        print(r)


def usage():
    print(f'''Usage: {__file__} COMMAND_NAME <COMMAND_ARGS>
command_name options: create_table, full_print, last, last_10, search_by_domain, search_by_level, delete_table''')


if __name__ == "__main__":
    try:
        with sqlite3.connect('typosquatting.db') as db_connection:
            args = sys.argv[1:]
            if args[0] == 'create_table':
                create_table(db_connection)
            elif args[0] == 'full_print':
                full_print_table(db_connection)
            elif args[0] == 'last':
                last_entry(db_connection)
            elif args[0] == 'last_10':
                last_10_entries(db_connection)
            elif args[0] == 'search_by_domain':
                if len(args) < 2:
                    print(f'Usage: {__file__} search_by_domain <DOMAIN_NAME>')
                else:
                    search_by_domain(db_connection, args[1])
            elif args[0] == 'search_by_level':
                if len(args) < 2:
                    print(f'Usage: {__file__} search_by_level <LEVEL_NAME>')
                else:
                    search_by_level(db_connection, args[1])
            elif args[0] == 'delete_table':
                delete_table(db_connection)
            else:
                usage()
    except IndexError:
        usage()
    except Exception as e:
        print(e)

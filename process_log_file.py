import sqlite3
import sys
import argparse


def create_tables(database):
    print("Trying to create tables")
    try:
        database.execute('''CREATE TABLE CVEEvents (date text,
                                                    time text,
                                                    severity text,
                                                    event_id integer,
                                                    hostname text,
                                                    protocol text,
                                                    cve_id text)''')

        database.execute('''CREATE TABLE AccessEvents (date text,
                                                       time text,
                                                       severity text,
                                                       event_id integer,
                                                       source_address text,
                                                       destination_address text,
                                                       user text)''')
        database.execute('''CREATE TABLE UnknownEvents (unknown_log_entry text)''')
    except sqlite3.OperationalError:
        print("Tables already exist. Continuing...")

def clean_up_before_processing(cursor):
    print("Deleting data from tables")
    cursor.execute("DELETE FROM CVEEvents")
    cursor.execute("DELETE FROM AccessEvents")
    cursor.execute("DELETE FROM UnknownEvents")

def file_processor(cursor, file_name):
    print("Processing log file")
    with open(file_name, 'r') as log_file: 
        for line in log_file:
            list_from_line = line.split()
            if len(list_from_line) == 7:
                first_3_characters_of_last_field = list_from_line[-1][0:3]
                if first_3_characters_of_last_field == "CVE":
                    cursor.execute("INSERT INTO CVEEvents VALUES (?,?,?,?,?,?,?)", tuple(list_from_line))
                else:
                    cursor.execute("INSERT INTO AccessEvents VALUES (?,?,?,?,?,?,?)", tuple(list_from_line))
            elif len(list_from_line) > 0: 
                cursor.execute("INSERT INTO UnknownEvents VALUES (?)", (line,))

def count_critical_CVEs(cursor):
    cursor.execute('''SELECT COUNT(*) FROM CVEEvents
                      WHERE severity IN ('critical', 'crit', 'CRIT')''')
    print("\nTotal number of critical CVEs: {}".format(cursor.fetchone()[0]))

def main():
    try:
        assert sys.version_info >= (3,0)
    except AssertionError:
        print("This program runs in Python 3 or higher")
        sys.exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", default='log',
                        help="name of the log file to process")
    args = parser.parse_args()
    file_name = args.file
    database_name = file_name + ".db"

    log_database = sqlite3.connect(database_name)
    log_cursor = log_database.cursor()
    create_tables(log_database)
    clean_up_before_processing(log_cursor)
    file_processor(log_cursor, file_name)
    count_critical_CVEs(log_cursor)
    log_database.commit()
    log_database.close()

if __name__ == "__main__":
    main()

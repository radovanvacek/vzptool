import sqlite3
from sqlite3 import Error


class Database:
    tls_enabled_services = """'https','pop3s','ldapssl','globalcatLDAPssl','webm-https','3par-mgmt-ssl','https-alt'
    ,'compaq-https'"""

    def __create_connection(self, db_file):
        """ create a database connection to a SQLite database """
        self.__conn = None
        try:
            self.__conn = sqlite3.connect(db_file)
            print(sqlite3.version)
        except Error as e:
            print(e)

    def __init__(self):
        self.__create_connection(r"data/pythonsqlite.db")
        self.__conn.set_trace_callback(print)  # TODO: only for debug
        # self.__drop_services()  # TODO: only for debug
        self.__create_services_table()

    def __create_table(self, create_table_sql):
        """ create a table from the create_table_sql statement
        :param create_table_sql: a CREATE TABLE statement
        :return:
        """
        try:
            cursor = self.__conn.cursor()
            cursor.execute(create_table_sql)
            self.__conn.commit()
        except Error as e:
            print(e)
            exit(3)

    def __drop_services(self):
        __drop_statement = """drop table if exists services;"""
        try:
            print("dropping services table")
            cursor = self.__conn.cursor()
            cursor.execute(__drop_statement)
            self.__conn.commit()
        except Error as e:
            print(e)
            exit(3)

    def __create_services_table(self):
        __create_services_table_sql = """CREATE TABLE IF NOT EXISTS services (
                                        _id integer AUTOINCREMEMT,
                                        _ipv4 varchar NOT NULL,
                                        _ptr varchar,
                                        _proto varchar,
                                        _port varchar NOT NULL,
                                        _type varchar,
                                        _http_unencrypted varchar,
                                        _https_ca_fingerprint varchar,
                                        _https_crt_chain varchar,
                                        _https_redir varchar,
                                        _web_or_api varchar,
                                        PRIMARY KEY(_ipv4,_port, _proto));"""
        self.__create_table(__create_services_table_sql)

    def insert_service(self, service):
        if self.__conn is None:
            self.__create_connection(r"data/pythonsqlite.db")
            if self.__conn is None:
                print("could not create DB connection, exiting")
                exit(3)
        __insert_service = """INSERT INTO services 
                                (_ipv4, _ptr, _proto, _port, _type)                                
                                VALUES ( :_ipv4,:_ptr,:_proto,:_port, :_type);"""
        try:
            cursor = self.__conn.cursor()
            cursor.execute(__insert_service, service.__dict__)
            self.__conn.commit()
        except Error as e:
            print(e)
            exit(3)

    def get_tls_enabled_host_port(self):

        if self.__conn is None:
            self.__create_connection(r"data/pythonsqlite.db")
            if self.__conn is None:
                print("could not create DB connection, exiting")
                exit(3)
        try:
            cursor = self.__conn.cursor()
            __get_tls_enabled_service_sql = "SELECT _ipv4, _port FROM services " \
                                            "WHERE   _type IN ({}) AND " \
                                            "_https_ca_fingerprint IS NULL LIMIT 1".format(self.tls_enabled_services)
            cursor.execute(__get_tls_enabled_service_sql)
            self.__conn.commit()
            return cursor.fetchall()
        except Error as e:
            print(e)
            exit(3)

    def update_cert_info(self, full_chain, root_digest, ipv4, port):

        if self.__conn is None:
            self.__create_connection(r"data/pythonsqlite.db")
            if self.__conn is None:
                print("could not create DB connection, exiting")
                exit(3)
        try:
            cursor = self.__conn.cursor()
            __update_cert_info_sql = """UPDATE services SET _https_ca_fingerprint = ? , _https_crt_chain = ? 
                    WHERE _ipv4 = ? AND _port = ?"""
            cursor.execute(__update_cert_info_sql, root_digest, full_chain, ipv4, port)
            self.__conn.commit()
        except Error as e:
            print(e)
            exit(3)
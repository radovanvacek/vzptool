import sqlite3
from sqlite3 import Error


class Database:
    tls_enabled_services = """'https','pop3s','ldapssl','globalcatLDAPssl','webm-https','3par-mgmt-ssl','https-alt'
    ,'compaq-https'"""

    https_redirect_expected = """'http'"""

    http_protocol = """'http', 'https', 'webm-https', 'https-alt','compaq-https' """

    def __create_connection(self, db_file):
        """ create a database connection to a SQLite database """
        self.__conn = None
        try:
            self.__conn = sqlite3.connect(db_file)
        except Error as e:
            print(e)

    def __init__(self, datadir):
        self._datadir = datadir
        self.__create_connection(self._datadir)
        # self.__conn.set_trace_callback(print)  # TODO: only for debug
        # self.__drop_services() # TODO: only for debug
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
                                        _ipv4 varchar NOT NULL,
                                        _ptr varchar,
                                        _proto varchar,
                                        _port varchar NOT NULL,
                                        _type varchar,
                                        _http_unencrypted varchar,
                                        _https_ca_authority_key_identifier varchar,
                                        _https_crt_issuer_rfc varchar,
                                        _https_redir boolean,
                                        _https_redir_reply varchar,
                                        _web_or_api varchar,
                                        _product varchar,
                                        _product_version varchar,
                                        PRIMARY KEY(_ipv4,_port, _proto));"""
        self.__create_table(__create_services_table_sql)

    def insert_service(self, service):
        if self.__conn is None:
            self.__create_connection(self._datadir)
            if self.__conn is None:
                print("could not create DB connection, exiting")
                exit(3)
        __insert_service = """INSERT OR IGNORE INTO services 
                                (_ipv4, _ptr, _proto, _port, _type, _product, _product_version)                                
                                VALUES ( :_ipv4,:_ptr,:_proto,:_port, :_type, :_product, :_product_version);"""
        try:
            cursor = self.__conn.cursor()
            cursor.execute(__insert_service, service.__dict__)
            self.__conn.commit()
        except Error as e:
            print(e)
            exit(3)

    def get_tls_enabled_host(self, limit, runs):

        if self.__conn is None:
            self.__create_connection(self._datadir)
            if self.__conn is None:
                print("could not create DB connection, exiting")
                exit(3)
        try:
            cursor = self.__conn.cursor()
            __get_tls_enabled_service_sql = "SELECT _ipv4, _port FROM services " \
                                            "WHERE   _type IN ({}) AND " \
                                            "_https_ca_authority_key_identifier IS NULL LIMIT {} OFFSET {}" \
                .format(self.tls_enabled_services, limit, limit * runs)
            cursor.execute(__get_tls_enabled_service_sql)
            self.__conn.commit()
            return cursor.fetchall()
        except Error as e:
            print(e)
            exit(3)

    def update_cert_info(self, authority_key_identifier, issuer_rfc, ipv4, port):

        if self.__conn is None:
            self.__create_connection(self._datadir)
            if self.__conn is None:
                print("could not create DB connection, exiting")
                exit(3)
        try:
            cursor = self.__conn.cursor()
            __update_cert_info_sql = """UPDATE services SET _https_ca_authority_key_identifier = ? , _https_crt_issuer_rfc = ? 
                    WHERE _ipv4 = ? AND _port = ?"""
            cursor.execute(__update_cert_info_sql, (authority_key_identifier, issuer_rfc, ipv4, port))
            self.__conn.commit()
        except Error as e:
            print(e)
            exit(3)

    def get_http_redirect_expected_host(self, limit, runs):

        if self.__conn is None:
            self.__create_connection(self._datadir)
            if self.__conn is None:
                print("could not create DB connection, exiting")
                exit(3)
        try:
            cursor = self.__conn.cursor()
            __get_tls_enabled_service_sql = "SELECT _ipv4, _port FROM services " \
                                            "WHERE   _type IN ({}) AND " \
                                            "_https_redir IS NULL LIMIT {} OFFSET {}" \
                .format(self.https_redirect_expected, limit, limit * runs)
            cursor.execute(__get_tls_enabled_service_sql)
            self.__conn.commit()
            return cursor.fetchall()
        except Error as e:
            print(e)
            exit(3)

    def update_redirect_status(self, ipv4, port, response, has_redirect=False):
        if self.__conn is None:
            self.__create_connection(self._datadir)
            if self.__conn is None:
                print("could not create DB connection, exiting")
                exit(3)
        try:
            cursor = self.__conn.cursor()
            __update_cert_info_sql = """UPDATE services SET _https_redir = ? , _https_redir_reply = ?\
                    WHERE _ipv4 = ? AND _port = ?"""
            cursor.execute(__update_cert_info_sql, (has_redirect, response, ipv4, port))
            self.__conn.commit()
        except Error as e:
            print(e)
            exit(3)

    def get_www_host(self, limit, runs):
        if self.__conn is None:
            self.__create_connection(self._datadir)
            if self.__conn is None:
                print("could not create DB connection, exiting")
                exit(3)
        try:
            cursor = self.__conn.cursor()
            __get_tls_enabled_service_sql = "SELECT _type, _ipv4, _port FROM services " \
                                            "WHERE   _type IN ({}) AND " \
                                            "_web_or_api IS NULL LIMIT {} OFFSET {}" \
                .format(self.http_protocol, limit, limit * runs)
            cursor.execute(__get_tls_enabled_service_sql)
            self.__conn.commit()
            return cursor.fetchall()
        except Error as e:
            print(e)
            exit(3)

    def update_web_or_api(self, ipv4, port, is_for_people):
        if self.__conn is None:
            self.__create_connection(self._datadir)
            if self.__conn is None:
                print("could not create DB connection, exiting")
                exit(3)
        try:
            cursor = self.__conn.cursor()
            __update_cert_info_sql = """UPDATE services SET _web_or_api = ? WHERE _ipv4 = ? AND _port = ?"""
            cursor.execute(__update_cert_info_sql, (is_for_people, ipv4, port))
            self.__conn.commit()
        except Error as e:
            print(e)
            exit(3)

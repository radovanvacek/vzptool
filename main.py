# This is a sample Python script.

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.

# TODO: -p data/dc10.224.x_with_ping.xml data/dc10.225_with_ping.xml data/dc10.244.x-with_ping.xml

import getopt
import sys
import xml.sax

import NmapXMLImporter
import database
from CAChecker import CAInfoUpdater
from HTTPSRedirectChecker import HTTSPRedirectChecker

data_dir = r"data/pythonsqlite.db"
db = database.Database(data_dir)
max_threads = 200
limit = 1000


def print_help():
    print("""Usage: \n -p : parse the xmls\n -c : collect certificate chains""")


def main(argv):
    opts = None
    args = None
    try:
        opts, args = getopt.getopt(argv, "hp:crd:")
    except getopt.GetoptError:
        print_help()
        exit(2)
    if not opts:
        print_help()
        exit(0)
    for opt, arg in opts:
        if opt == "-d":
            print("setting data dir to {}".format(arg))
            globals()['data_dir'] = arg
            globals()['db'] = database.Database(globals()['data_dir'])
        if opt == "-p":
            print("parsing XML files {0}".format(arg))
            parse_xml(arg)
        if opt == "-h":
            print_help()
            exit(0)
        if opt == "-c":
            # print("collecting certificate chain information")
            collect_cert_chains()
        if opt == "-r":
            # print("checking redirects to HTTPS")
            check_redirects()


def __multithreaded_exec(thread=None, getter=None, data_dir=globals()['data_dir']):
    threads = []
    runs = 1
    res = getter(limit, 0)
    while len(res):
        item = res.pop()
        while item:
            threads = list(filter(lambda x: x._is_stopped is False, threads))
            if len(threads) < max_threads:
                ipv4, port = item
                cur_thread = thread(ipv4, port, data_dir)
                threads.append(cur_thread)
                cur_thread.start()
                if len(res):
                    item = res.pop()
                else:
                    break
            else:
                for t in threads:
                    t.join()
        runs += runs
        res = getter(limit, runs)


def check_redirects():
    __multithreaded_exec(HTTSPRedirectChecker, db.get_http_redirect_expected_host)


def collect_cert_chains():
    __multithreaded_exec(CAInfoUpdater, db.get_tls_enabled_host)


def parse_xml(args):
    # create an XMLReader
    parser = xml.sax.make_parser()
    # turn off namepsaces
    parser.setFeature(xml.sax.handler.feature_namespaces, 0)

    # override the default ContextHandler
    handler = NmapXMLImporter.NmapXMLContentHandler(db)
    parser.setContentHandler(handler)
    parser.parse(args)


if __name__ == '__main__':
    main(sys.argv[1:])

# See PyCharm help at https://www.jetbrains.com/help/pycharm/

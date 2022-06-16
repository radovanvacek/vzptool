# This is a sample Python script.

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.

# TODO: -p data/dc10.224.x_with_ping.xml data/dc10.225_with_ping.xml

import getopt
import sys
import xml.sax

import NmapXMLImporter
from CAChecker import CAChecker
from database import Database

db = Database()


def print_help():
    print("""Usage: \n -p : parse the xmls\n -c : collect certificate chains""")


def main(argv):
    try:
        opts, args = getopt.getopt(argv, "hpc")
    except getopt.GetoptError:
        print_help()
        exit(2)
    if not opts:
        print_help()
        exit(0)
    for opt, arg in opts:
        if opt == "-p":
            print("parsing XML files {0}".format(args))
            parse_xml(args)
        if opt == "-h":
            print_help()
            exit(0)
        if opt == "-c":
            print("collecting certificate chain information")
            collect_cert_chains()


def collect_cert_chains():
    ipv4, port = db.get_tls_enabled_host_port()[0]
    print("collecting CA information for {}:{}".format(ipv4, port))
    ca_checker = CAChecker(db)
    ca_checker.get_cert_chain(ipv4, int(port))


def parse_xml(args):
    # create an XMLReader
    parser = xml.sax.make_parser()
    # turn off namepsaces
    parser.setFeature(xml.sax.handler.feature_namespaces, 0)

    # override the default ContextHandler
    handler = NmapXMLImporter.NmapXMLContentHandler(db)
    parser.setContentHandler(handler)
    for file in args:
        parser.parse(file)


if __name__ == '__main__':
    main(sys.argv[1:])

# See PyCharm help at https://www.jetbrains.com/help/pycharm/

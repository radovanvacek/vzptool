"""
https://stackoverflow.com/questions/19145097/
"""

import socket
from OpenSSL import SSL
import certifi


# ipv4 = 'www.google.com'
# port = 443

class CAChecker:

    def __init__(self, db):
        self._db = db

    def get_cert_chain(self, ipv4, port):
        context = SSL.Context(SSL.TLSv1_2_METHOD)
        context.load_verify_locations(certifi.where())
        conn = SSL.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        conn.settimeout(5)
        conn.connect((ipv4, port))
        conn.setblocking(1)
        conn.do_handshake()
        conn.set_tlsext_host_name(ipv4.encode())
        full_chain = ''
        last_sha1_digest = ''
        for (idx, cert) in enumerate(conn.get_peer_cert_chain()):
            full_chain += '{}. certificate in chain'.format(idx)
            full_chain += '\n'
            full_chain += '\tsubject: {0}'.format(cert.get_subject())
            full_chain += '\n'
            full_chain += '\tissuer: {0})'.format(cert.get_issuer())
            full_chain += '\n'
            full_chain += '\tfingerprint-sha1: {0}'.format(cert.digest("sha1"))
            full_chain += '\n'
            full_chain += '\tfingerprint-sha256: {0}'.format(cert.digest("sha256"))
            full_chain += '\n'
            last_sha1_digest = cert.digest("sha1")
        print(full_chain)
        conn.close()
        self._db.update_cert_info(last_sha1_digest, full_chain, ipv4, port)


# get_cert_chain('www.google.com', 443)

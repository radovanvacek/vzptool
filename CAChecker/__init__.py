"""
https://stackoverflow.com/questions/19145097/
"""

import logging
import ssl
import threading

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import ExtensionNotFound
from cryptography.x509.oid import ExtensionOID

import database


# ipv4 = 'www.google.com'
# port = 443

class CAInfoUpdater(threading.Thread):

    def __init__(self, service_type, ipv4, port, data_dir):
        super().__init__()
        self._db = None
        self._ipv4 = ipv4
        self._port = int(port)
        self._data_dir = data_dir
        self._logger = logging.getLogger(__name__)
        self._logger.setLevel(logging.DEBUG)

    def run(self, n=None):
        self._logger.info(
            "{}: collecting CA information for {}:{}".format(threading.current_thread().ident, self._ipv4, self._port))
        self._db = database.Database(self._data_dir)

        try:
            cert = ssl.get_server_certificate((self._ipv4, self._port), ssl.PROTOCOL_SSLv23)
            # conn = ssl.create_connection((self._ipv4, self._port))
            # context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            # context.set_ciphers('ALL:@SECLEVEL=1')
            # sock = context.wrap_socket(conn, server_hostname=self._ipv4)
            # cert = ssl.DER_cert_to_PEM_cert(sock.getpeercert(True))
            parsed = x509.load_pem_x509_certificate(str.encode(cert), default_backend())
            issuer = parsed.issuer.rfc4514_string()
            try:
                authority_key_identifier = parsed.extensions.get_extension_for_oid(
                    ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
                self._db.update_cert_info(authority_key_identifier.value.key_identifier.hex(), issuer, self._ipv4,
                                          self._port)
            except ExtensionNotFound as err:
                authority_key_identifier = "oid 2.5.29.35 not included in cert"
                self._db.update_cert_info(authority_key_identifier, issuer, self._ipv4,
                                          self._port)
                self._logger.error('{}'.format(threading.current_thread().ident) + ' : ' + err)
        except (ConnectionError, ssl.SSLError) as err:
            self._logger.error(
                '{} : Connection error to Host {} on port {} '.format(threading.current_thread().ident, self._ipv4,
                                                                      self._port))
            self._db.update_cert_info("SSL connect failed", '', self._ipv4,
                                      self._port)
            self._logger.error(err)

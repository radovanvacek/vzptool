"""
https://stackoverflow.com/questions/19145097/
"""

import ssl
import threading

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID

import database


# ipv4 = 'www.google.com'
# port = 443

class CAInfoUpdater(threading.Thread):

    def __init__(self, ipv4, port, data_dir):
        super().__init__()
        self._db = None
        self.ipv4 = ipv4
        self.port = int(port)
        self._data_dir = data_dir

    def run(self, n=None):
        print("{}: collecting CA information for {}:{}".format(threading.current_thread().ident, self.ipv4, self.port))
        self._db = database.Database(self._data_dir)

        try:
            cert = ssl.get_server_certificate((self.ipv4, self.port), ssl.PROTOCOL_SSLv23)
            parsed = x509.load_pem_x509_certificate(str.encode(cert), default_backend())
            issuer = parsed.issuer.rfc4514_string()
            authority_key_identifier = parsed.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
            self._db.update_cert_info(authority_key_identifier.value.key_identifier.hex(), issuer, self.ipv4, self.port)
        except ssl.SSLError as err:
            print(err)
        except ConnectionError as err:
            print('Connection error to Host {} on port {}'.format(self.ipv4, self.port))
            print(err)

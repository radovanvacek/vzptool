import threading

import requests
from urllib3.exceptions import NewConnectionError

import database


class HTTSPRedirectChecker(threading.Thread):

    def __init__(self, ipv4, port):
        super().__init__()
        self._db = None
        self._url = 'http://' + ipv4 + ':' + port
        self._ipv4 = ipv4
        self._port = port

    def run(self, n=None):
        print("{}: Checking for HTTP redirects on {}".format(threading.current_thread().ident, self._url))
        self._db = database.Database()
        try:
            response = requests.get(self._url, allow_redirects=False)
        except NewConnectionError as e:
            print('Failed to establish connection to {}'.format(self._url) + '\n' + print(e))
        if response.status_code in (301, 302):
            self._db.update_redirect_status(self._ipv4, self._port, str(response.content), True)
        else:
            self._db.update_redirect_status(ipv4=self._ipv4, port=self._port, response=str(response.content))

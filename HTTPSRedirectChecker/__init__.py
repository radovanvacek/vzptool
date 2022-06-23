import logging
import threading

import requests
from requests.exceptions import ConnectionError
from urllib3.exceptions import NewConnectionError, MaxRetryError

import database


class HTTSPRedirectChecker(threading.Thread):

    def __init__(self, service_type, ipv4, port, data_dir):
        super().__init__()
        self._db = None
        self._url = 'http://' + ipv4 + ':' + port
        self._ipv4 = ipv4
        self._port = port
        self._data_dir = data_dir
        self._logger = logging.getLogger(__name__)

    def run(self, n=None):
        self._logger.info("{}: Checking for HTTP redirects on {}".format(threading.current_thread().ident, self._url))
        self._db = database.Database(self._data_dir)
        try:
            response = requests.get(self._url, allow_redirects=False)
            if response.status_code in (301, 302) or str(response.content).find('<meta http-equiv="refresh"'):
                self._db.update_redirect_status(self._ipv4, self._port, str(response.content), True)
            else:
                self._db.update_redirect_status(ipv4=self._ipv4, port=self._port, response=str(response.content))
        except (ConnectionError, NewConnectionError, MaxRetryError) as err:
            self._logger.error(
                '{} : Connection error to Host {} on port {}'.format(threading.current_thread().ident, self._ipv4,
                                                                     self._port))
            self._logger.error('{}  : {}'.format(threading.current_thread().ident, err))
            self._db.update_redirect_status(ipv4=self._ipv4, port=self._port, response="Connection error")

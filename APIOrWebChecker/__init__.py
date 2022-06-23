import logging
import ssl
import threading

from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError
from requests.packages.urllib3.poolmanager import PoolManager
from urllib3.exceptions import NewConnectionError, MaxRetryError

import database


class MyAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block):
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       ssl_version=ssl.PROTOCOL_TLSv1)


import requests

s = requests.Session()
s.mount('https://', MyAdapter())


class APIOrWebChecker(threading.Thread):

    def __init__(self, service_type, ipv4, port, data_dir):
        super().__init__()
        self._db = None
        self._url = ('https', 'http')[service_type.find('https')] + '://' + ipv4 + ':' + port
        self._ipv4 = ipv4
        self._port = port
        self._data_dir = data_dir
        self._logger = logging.getLogger(__name__)

    def run(self, n=None):
        self._logger.info(
            "{}: Getting response after all redirects {}".format(threading.current_thread().ident, self._url))
        self._db = database.Database(self._data_dir)
        try:
            response = requests.get(self._url, verify=False)
            is_for_people = self.analyze(response)
            self._db.update_web_or_api(self._ipv4, self._port, is_for_people)
        except (ConnectionError, NewConnectionError, MaxRetryError) as err:
            self._logger.error('{} : Connection error to {}'.format(threading.current_thread().ident, self._url))
            self._logger.error('{} : {}'.format(threading.current_thread().ident, err))
            self._db.update_web_or_api(ipv4=self._ipv4, port=self._port, is_for_people="Connection error")

    def analyze(self, response):
        score = 0
        score += len(list(self.findall('<img', response)))
        score += len(list(self.findall('<script', response)))
        score += len(list(self.findall('link rel="stylesheet"', response)))
        return score

    def findall(self, p, s):
        '''Yields all the positions of
        the pattern p in the string s.'''
        i = str(s.content).find(p)
        while i != -1:
            yield i
            i = str(s.content).find(p, i + 1)

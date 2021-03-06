import xml.sax


class Service:
    @property
    def ipv4(self):
        return self._ipv4

    @ipv4.setter
    def ipv4(self, value):
        self._ipv4 = value

    @property
    def ptr(self):
        return self._ptr

    @ptr.setter
    def ptr(self, value):
        self._ptr = value

    @property
    def proto(self):
        return self._proto

    @proto.setter
    def proto(self, value):
        self._proto = value

    @property
    def port(self):
        return self._port

    @port.setter
    def port(self, value):
        self._port = value

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        self._type = value

    @property
    def httpUnencrypted(self):
        return self._httpUnencrypted

    @httpUnencrypted.setter
    def httpUnencrypted(self, value):
        self._httpUnencrypted = value

    @property
    def httpsCA(self):
        return self._httpsCA

    @httpsCA.setter
    def httpsCA(self, value):
        self._httpsCA = value

    @property
    def httpsRedir(self):
        return self._httpsRedir

    @httpsRedir.setter
    def httpsRedir(self, value):
        self._httpsRedir = value

    @property
    def webOrAPI(self):
        return self._webOrAPI

    @webOrAPI.setter
    def webOrAPI(self, value):
        self._webOrAPI = value

    @property
    def host(self):
        return self._host

    @host.setter
    def host(self, value):
        self._host = value

    @property
    def product(self):
        return self._product

    @product.setter
    def product(self, value):
        self._product = value

    @property
    def product_version(self):
        return self._product_version

    @product_version.setter
    def product_version(self, value):
        self._product_version = value

    def __init__(self):
        self._ipv4 = ''
        self._ptr = ''
        self._proto = ''
        self._port = ''
        self._type = ''
        self._httpUnencrypted = ''
        self._httpsCA = ''
        self._httpsRedir = ''
        self._authRequired = ''
        self._webOrAPI = ''
        self._product = None
        self._product_version = None


class NmapXMLContentHandler(xml.sax.ContentHandler):

    def __init__(self, db):
        self._service = None
        self.db = db

    def startElement(self, tag, attributes):
        if tag == "status" and attributes['state'] == "up":
            self._service = Service()
        elif tag == "address" and self._service is not None:
            self._service.ipv4 = attributes['addr']
        elif tag == "hostname" and attributes["type"] == "PTR" and self._service is not None:
            self._service.ptr = attributes["name"]
        elif tag == "port" and self._service is not None:
            self._service.port = attributes["portid"]
            self._service.proto = attributes["protocol"]
        elif tag == "service" and self._service is not None:
            self._service.type = attributes["name"]
            try:
                self._service.product = attributes["product"]
                self._service.product_version = attributes["version"]
            except KeyError:
                pass

    def endElement(self, tag):
        if tag == "port":
            # print(self._service.__dict__) #TODO: only for debug
            self.db.insert_service(self._service)
        elif tag == "ports":
            self._service = None

import logging
import urllib3
from napalm.base.base import NetworkDriver


class GaiaOSDriver(NetworkDriver):
    def __init__(self, hostname,
            username='',
            password='',
            timeout=10,
            optional_args=None):
        pass


    def open(self):
        pass

    def close(self):
        pass


if __name__ == '__main__':
    pass
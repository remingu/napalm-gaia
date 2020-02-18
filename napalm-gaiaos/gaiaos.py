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

    def get_users(self):
        pass

    def get_arp_table(self, vrf=""):
        pass

    def get_config(self, retrieve="all", full=False):
        pass

    def get_facts(self):
        pass

    def get_interfaces(self):
        pass

    def get_interfaces_ip(self):
        pass


if __name__ == '__main__':
    pass
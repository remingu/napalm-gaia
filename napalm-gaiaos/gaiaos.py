import logging
import urllib3
import re
import socket
from napalm.base.base import NetworkDriver


class GaiaOSDriver(NetworkDriver):
    def __init__(self, hostname,
            username='',
            password='',
            timeout=10,
            optional_args=None):
        
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.optional_args = optional_args

    def open(self):
        device_type = "checkpoint_gaia"
        self.device = self._netmiko_open(device_type, netmiko_optional_args=self.optional_args)

    def close(self):
        self._netmiko_close()
    
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

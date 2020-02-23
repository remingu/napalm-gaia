import logging
import time
import re
import socket
import napalm
from napalm.base.base import NetworkDriver
from napalm.base.exceptions import ConnectionException, SessionLockedException, \
                                   MergeConfigException, ReplaceConfigException,\
                                   CommandErrorException, ConnectionClosedException


class GaiaOSDriver(NetworkDriver):
    def __init__(self, hostname,
            username='',
            password='',
            timeout=10,
            optional_args=None):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.expert_password = ''
        self.timeout = timeout
        self.optional_args = optional_args
        if 'secret' in optional_args:
            self.expert_password = optional_args['secret']


    def open(self):
        device_type = 'checkpoint_gaia'
        self.device = self._netmiko_open(device_type, netmiko_optional_args=self.optional_args)

    def close(self):
        self._netmiko_close()
    
    def cli(self, commands: list) -> dict:
        output = {}
        try:
            if isinstance(commands, list):
                for cmd in commands:
                    if isinstance(cmd, str):
                        output[cmd] = self.device.send_command(cmd)
                    else:
                        raise TypeError(
                            'Expected <class \'str\'> not a {}'.format(
                            type(cmd)
                            ))
            else:
                raise TypeError(
                    'Expected <class \'list\'> not a {}'.format(
                        type(commands)
                        )
                    )
            return output
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))
    
    def get_users(self) -> dict:
        username_regex = (
            r'^([A-z0-9_-]{1,32})\s+(\d+)\s+(\d+)\s+([/A-z0-9_-]{1,})\s+'
            r'([./A-z0-9_-]{1,})\s+((?:[\/A-z0-9_-]+\s?)+[\/A-z0-9_-])\s+'
            r'((?:[\/A-z0-9_-]+\s?)+[\/A-z0-9_-]).+?$'
        )
        users = {}
        command = 'show users'
        output = self.device.send_command(command)
        for match in re.finditer(username_regex, output, re.M):
            users[match.group(1)] = {
                'uid': match.group(2),
                'gid': match.group(3),
                'homedir': match.group(4),
                'shell': match.group(5),
                'name': match.group(6),
                'privileges': match.group(7),
            }
        return users

    def get_arp_table(self, vrf='') -> list:
        pass

    def get_config(self, retrieve='all', full=False):
        pass

    def get_facts(self):
        pass

    def get_interfaces(self):
        pass

    def get_interfaces_ip(self):
        pass

    def _enter_expert_mode(self) -> bool:
        '''
            :return: bool
        '''
        try:
            self.rhostname = self.device.find_prompt()
            output = self.device.send_command_timing('expert')
            if 'Enter expert password:' in output:
                output += self.device.send_command_timing(self.expert_password)
                time.sleep(1)
                self.device.send_command(r'unset TMOUT')
            return self._check_expert_mode()
        except Exception as e:
            raise RuntimeError(e)



    def _exit_expert_mode(self):
        '''
            :return: bool
        '''
        if self._check_expert_mode() is True:
            self.device.send_command(r'exit')
        else:
            return False


    def _check_expert_mode(self) -> bool:
        # will break if PS1 is altered - not everything possible should be done......
        rhostname = self.device.find_prompt()
        regex = r'\[Expert@.*$'
        if re.search(regex, rhostname):
            return True
        else:
            return False


    def send_clish_cmd(self, cmd: str) -> list:
        output = self.device.send_command(cmd)
        return output


    def send_expert_cmd(self, cmd: str) -> str:
        self._enter_expert_mode()
        output = self.device.send_command(cmd)
        self._exit_expert_mode()
        return output


if __name__ == '__main__':
    pass

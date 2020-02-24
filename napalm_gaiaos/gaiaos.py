import logging
import statistics
import time
import re
import socket
import ipaddress
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
        self._exit_expert_mode()
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
        """
            Returns a dictionary with the configured users.
            The keys of the main dictionary represents the username.
            The values represent the details of the user,
            represented by the following keys:
    
                * uid (int)
                * gid (int)
                * homedir (str)
                * shell (str)
                * name (str)
                * privileges (str)
        """
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
        """
                        Get arp table information. (requires expertmode available)
                        Return a list of dictionaries having the following set of keys:
                            * interface (string)
                            * mac (string)
                            * ip (string)
                            * age (float)
                            * state (string)
                        For example::
                            [
                                {
                                    'interface' : 'eth0',
                                    'mac'       : '5c:5e:ab:da:3c:f0',
                                    'ip'        : '172.17.17.1',
                                    'age'       : 0.0
                                    'age'       : 875.0
                                    'state'     : 'REACHABLE'
                                },
                                {
                                    'interface': 'eth0',
                                    'mac'       : '66:0e:94:96:e0:ff',
                                    'ip'        : '172.17.17.2',
                                    'age'       : 0.0
                                    'state'     : 'STALE'
                                }
                            ]
                        """
        arptable_regex = ()
        commands = 'ip -statistics show'
        arptable_regex = r'^([0-9.:a-f]+)\sdev\s([a-zA-Z0-9._-]+)\slladdr\s([0-9a-f:]+)\s' \
                         r'ref\s[0-9]+\sused\s([0-9]+).*probes\s[0-9]+\s([a-zA-Z]+)*$'
        command = 'ip -stat neigh'
        arp_entries = []
        if self._enter_expert_mode() is True:
            output = self.device.send_command(command)
            self._exit_expert_mode()
        else:
            raise RuntimeError('unable to enter expertmode')
        output = str(output).split('\n')
        for line in output:
            if re.match(arptable_regex, line):
                table_entry = re.search(arptable_regex, line)
                arp_entries.append({'interface': str(table_entry.group(2)),
                                    'mac': str(table_entry.group(3)),
                                    'ip': str(table_entry.group(1)),
                                    'age': float(table_entry.group(4)),
                                    'state': str(table_entry.group(5))}
                                   )
        return arp_entries

    def get_config(self, retrieve='all', full=False):
        pass

    def get_facts(self):
        pass

    def get_interfaces(self) -> dict:
        """
        Get interface details.
            last_flapped is not implemented
            for virtual interfaces speed will return 0
        Example Output:
            {u'Vlan1': {'description': u'N/A',
                        'is_enabled': True,
                        'is_up': True,
                        'last_flapped': -1.0,
                        'mac_address': u'a493.4cc1.67a7',
                        'speed': 100,
                        'mtu': 1500},
             u'Vlan100': {'description': u'Data Network',
                          'is_enabled': True,
                          'is_up': True,
                          'last_flapped': -1.0,
                          'mac_address': u'a493.4cc1.67a7',
                          'speed': 100,
                          'mtu': 65536},
             u'Vlan200': {'description': u'Voice Network',
                          'is_enabled': True,
                          'is_up': True,
                          'last_flapped': -1.0,
                          'mac_address': u'a493.4cc1.67a7',
                          'speed': 100,
                          'mtu': 1500}}
        """
        command_options = {'state': 'is_enabled',
                           'comments': 'description',
                           'speed': 'speed',
                           'link-state': 'is_up',
                           'mac-addr': 'mac_address',
                           'mtu': 'mtu'}
        interface_table = {}
        try:
            output = self.device.send_command_timing('show interfaces\t')
            interface_list = output.split()
            time.sleep(0.2)

            for interface in interface_list:
                interface_table[interface] = {}
                interface_table[interface]['last_flapped'] = -1.0
                for cmd in command_options:
                    output = self.device.send_command(r'show interface {0} {1}'.format(interface, cmd)).split()
                    if len(output) == 1:
                        interface_table[interface][command_options[cmd]] = u''
                    else:
                        if cmd == 'speed':
                            if re.search(r'(\d+)(\D)', output[1]):
                                tmpstr = re.match(r'(\d+)(\D)', output[1])
                                interface_table[interface][command_options[cmd]] = tmpstr.group(1)
                            else:
                                interface_table[interface][command_options[cmd]] = 0
                        elif cmd == 'link-state' or cmd == 'state':
                            if output[1] == 'on':
                                interface_table[interface][command_options[cmd]] = True
                            elif output[1] == 'off':
                                interface_table[interface][command_options[cmd]] = False
                            else:
                                interface_table[interface][command_options[cmd]] = True
                        elif cmd == 'mac-addr':
                            if re.search(r'[0-9a-f:]+', output[1]) :
                                interface_table[interface][command_options[cmd]] = output[1]
                            else:
                                interface_table[interface][command_options[cmd]] = u'not configured'
                        elif cmd == 'comments':
                            interface_table[interface][command_options[cmd]] = output[1]
                        elif cmd == 'mtu':
                            interface_table[interface][command_options[cmd]] = output[1]

        except:
            pass
        return interface_table

    def get_interfaces_ip(self):
        """
                Get interface ip details.
                Returns a dict of dicts
                Example Output:
                {   u'FastEthernet8': {   'ipv4': {   u'10.66.43.169': {   'prefix_length': 22}}},
                    u'Loopback555': {   'ipv4': {   u'192.168.1.1': {   'prefix_length': 24}},
                                        'ipv6': {   u'1::1': {   'prefix_length': 64},
                                                    u'2001:DB8:1::1': {   'prefix_length': 64},
                                                    u'2::': {   'prefix_length': 64},
                                                    u'FE80::3': {   'prefix_length': 10}}},
                    u'Tunnel0': {   'ipv4': {   u'10.63.100.9': {   'prefix_length': 24}}},
                    u'Tunnel1': {   'ipv4': {   u'10.63.101.9': {   'prefix_length': 24}}},
                    u'Vlan100': {   'ipv4': {   u'10.40.0.1': {   'prefix_length': 24},
                                                u'10.41.0.1': {   'prefix_length': 24},
                                                u'10.65.0.1': {   'prefix_length': 24}}},
                    u'Vlan200': {   'ipv4': {   u'10.63.176.57': {   'prefix_length': 29}}}}
                """
        command_options = {'ipv4-address': 'ipv4', 'ipv6-address': 'ipv6'}
        interface_table = {}
        try:
            output = self.device.send_command_timing('show interfaces\t')
            interface_list = str(output).split()
            for interface in interface_list:
                interface_table[interface] = {}
                for option in command_options:
                    output = self.device.send_command(r'show interface {0} {1}'.format(interface, option))
                    tmpstr = re.match('{0}\s(.*)/(.*)'.format(option), output)
                    if tmpstr is not None:
                        if ipaddress.ip_address(tmpstr.group(1)):
                            addr = str(tmpstr.group(1))

                            prefix = int(tmpstr.group(2))
                            interface_table[interface][command_options[option]] = {}
                            interface_table[interface][command_options[option]][addr] = {'prefix_length': prefix}

        except Exception as e:
            raise Exception(e)
        return interface_table

    def _enter_expert_mode(self) -> bool:
        '''
            :return: bool
        '''
        try:
            if self._check_expert_mode() is False:
                self.device.send_command('\t')
                output = self.device.send_command_timing('expert')
                if 'Enter expert password:' in output:
                    output += self.device.send_command_timing(self.expert_password)
                    time.sleep(1)
                    self.device.find_prompt()
                    self.device.send_command(r'unset TMOUT')
            return self._check_expert_mode()
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))
        except Exception as e:
            raise RuntimeError(e)


    def _exit_expert_mode(self) -> bool:
        '''
            :return: bool
        '''
        try:
            if self._check_expert_mode() is True:
                self.device.send_command_timing(r'exit')
                time.sleep(0.5)
                self.device.send_command('\t')
                if self._check_expert_mode() is False:
                    return True
                else:
                    return False
            else:
                return True
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))
        except Exception as e:
            raise RuntimeError(e)

    def _check_expert_mode(self) -> bool:
        # will break if PS1 is altered - not everything possible should be done......
        try:
            rhostname = self.device.find_prompt()
            regex = r'\[Expert@.*$'
            if re.search(regex, rhostname):
                return True
            else:
                return False
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))

    def send_clish_cmd(self, cmd: str) -> list:
        try:
            output = self.device.send_command(cmd)
            return output
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))

    def send_expert_cmd(self, cmd: str) -> str:
        if self._enter_expert_mode() is True:
            output = self.device.send_command(cmd)
            self._exit_expert_mode()
            return output
        else:
            raise RuntimeError('unable to enter expert mode')

    def ping(self, destination: str, **kwargs) -> dict:
        """
            ping destination from device
            response times below 1ms will be treated as 1ms
        :param destination: str
        :param kwargs: dict {
            source: str <interface|ip-address>,
            ttl: int =  0 < ttl < 256,
            timeout: None - Not Supported,
            size: int = 7 < size in bytes < 65507,
            count: int = 0 < count <= 1000,
            vrf: None = VSX is not supported yet }
        :return: dict {
                    'success': {
                        'probes_sent': 5,
                        'packet_loss': 0,
                        'rtt_min': 72.158,
                        'rtt_max': 72.433,
                        'rtt_avg': 72.268,
                        'rtt_stddev': 0.094,
                        'results': [
                            {
                                'ip_address': u'1.1.1.1',
                                'rtt': 72.248
                            },
                            {
                                'ip_address': '2.2.2.2',
                                'rtt': 72.299
                            }
                        ]
                    }
                }

            OR

        {
            'error': 'unknown host 8.8.8.8.8'
        }

        """
        try:
            self.device.send_command('\t')
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))
        if self._is_valid_hostname(destination) is True:
            command = r'ping {0}'.format(destination)
            if 'source' in kwargs:
                self._validate_ping_source(kwargs['source'])
                command += ' -I {0}'.format(kwargs['source'])
            if 'ttl' in kwargs:
                self._validate_ping_ttl(kwargs['ttl'])
                command += ' -t {0}'.format(kwargs['ttl'])
            if 'size' in kwargs:
                self._validate_ping_size(kwargs['size'])
                command += ' -s {0}'.format(kwargs['size'])
            if 'count' in kwargs:
                self._validate_ping_count(kwargs['count'])
                command += ' -c {0}'.format(kwargs['count'])
            else:
                command += ' -c 5'
            output = self.device.send_command(command, delay_factor=10)
            output = str(output).split('\n')
            values = []
            re_output_rtt = r'(\d+).*time=(.*)\sms'
            re_output_rtt_unreachable = r'(.*[Uu]nreachable)'
            re_stats_rtt = '.*=\s(.*)/(.*)/(.*)/(.*)\sms'
            re_unreachable = r'.*100%\spacket\sloss.*'
            mobj = re.match(re_unreachable, output[-2])
            packets_sent = 0
            packets_lost = 0
            if mobj is not None:
                return {'error': 'unknown host {0}'.format(destination)}
            else:
                for line in output:
                    mobj = re.match(re_output_rtt, line)
                    if mobj is not None:
                        val = float(mobj.group(2))
                        values.append({ 'ip-address': destination, 'rtt': val})
                        packets_sent += 1
                    mobj = re.match(re_output_rtt_unreachable, line)
                    if mobj is not None:
                        values.append({'ip-address': destination, 'rtt': None})
                        packets_sent += 1
                        packets_lost += 1
                response = {}
                response['success'] = {}
                response['success']['results'] = []
                rttstats = re.match(re_stats_rtt, output[-1])
                response = { 'probes_sent': packets_sent,
                    'packet_loss': packets_lost,
                    'rtt_min': rttstats.group(1),
                    'rtt_max': rttstats.group(3),
                    'rtt_avg': rttstats.group(2),
                    'rtt_stddev': rttstats.group(4),
                    'results' : values
                }
                return response
        else:
            raise ValueError('invalid host format')

    def _is_valid_hostname(self, hostname) -> bool:
        if ipaddress.ip_address(hostname):
            return True
        else:
            if hostname[-1] == ".":
                # strip exactly one dot from the right, if present
                hostname = hostname[:-1]
            if len(hostname) > 253:
                return False
            labels = hostname.split(".")
            # the TLD must be not all-numeric
            if re.match(r"[0-9]+$", labels[-1]):
                return False
            allowed = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
            if all(allowed.match(label) for label in labels) is False:
                raise ValueError('invalid destination')


    def _validate_ping_source(self, source: str):
        source_interfaces = []
        try:
            output = self.device.send_command_timing('show interfaces\t')
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))
        interface_list = output.split()
        for interface in interface_list:
            output = self.device.send_command('show interface {0} ipv4-address'.format(interface))
            mobj = re.match('.*ipv4-address\s*(.*)/.*', output)
            if mobj is not None:
                source_interfaces.append(mobj.group(1))
            output = self.device.send_command('show interface {0} ipv6-address'.format(interface))
            mobj = re.match('.*ipv6-address\s*(.*)/.*', output)
            source_interfaces.append(interface)
        if source not in source_interfaces:
            raise ValueError('invalid source')

    def _validate_ping_ttl(self, ttl) -> None:
        if isinstance(ttl, int):
            if int(ttl) <= 0 or int(ttl) > 256:
                raise ValueError('invalid ttl - value out of range <1-255>')
        else:
            raise TypeError('Expected <class \'int\'> not a {}'.format(type(ttl)))

    def _validate_ping_size(self, size: int) -> None:
        if isinstance(size, int):
            if size < 7 or size > 65507:
                raise ValueError('invalid size - value out of range <1-65507>')
        else:
            raise TypeError('Expected <class \'int\'> not a {}'.format(type(size)))

    def _validate_ping_count(self, count: int) -> None:
        if isinstance(count, int):
            if count < 1 or count > 1000:
                raise ValueError('invalid count - value out of range <1-1000>')
        else:
            raise TypeError('Expected <class \'int\'> not a {}'.format(type(count)))

if __name__ == '__main__':
    pass

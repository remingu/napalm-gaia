import logging
import statistics
import time
import re
import socket
import ipaddress
import napalm
from napalm.base.base import NetworkDriver
from napalm.base.exceptions import ConnectionException, SessionLockedException,\
                                   MergeConfigException, ReplaceConfigException,\
                                   CommandErrorException, ConnectionClosedException,\
                                   ValidationException

class GaiaOSDriver(NetworkDriver):
    """
        | optional_args: dict

            * secret: <expert-password>: str

    """

    def __init__(self, hostname,
            username='',
            password='',
            timeout=10,
            optional_args=None):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.expert_password = '\n'
        self.timeout = timeout
        self.optional_args = optional_args
        if self.optional_args is not None:
            if 'secret' in optional_args:
                self.expert_password = optional_args['secret']

    def open(self):
        device_type = 'checkpoint_gaia'
        self.device = self._netmiko_open(device_type, netmiko_optional_args=self.optional_args)

    def close(self):
        self._exit_expert_mode()
        self._netmiko_close()
    
    def cli(self, commands: list) -> dict:
        """
        | Will execute a list of commands and return the output in a dictionary format.
        | Works only for cli.sh commands.

        Example::

            {
                'show version product':  'Product version Check Point Gaia R80.20',
                'show route': '''
                        Codes: C - Connected, S - Static, R - RIP, B - BGP (D - Default),
                        O - OSPF IntraArea (IA - InterArea, E - External, N - NSSA)
                        A - Aggregate, K - Kernel Remnant, H - Hidden, P - Suppressed,
                        U - Unreachable, i - Inactive

                        S         0.0.0.0/0           via 172.16.10.1, eth0, cost 0, age 57785
                        C         127.0.0.0/8         is directly connected, lo
                        C         172.16.10.0/26     is directly connected, eth0'''
            }
        """
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
    
    def get_users(self, **kwargs) -> dict:
        """
            | Returns a dictionary with the configured users.
            | The keys of the main dictionary represents the username.
            | Checkpoint uses RBAC and does not know about privilege levels
            | therefore level always returns a level of 15
            | instead a field 'privileges' was added containing additional user-role information
            |
            | ssh-keys will only fetched with option retrieve='all' (requires expert password)
            | otherwise ssh-keys will return a list containing an empty string
            | The values represent the details of the user,
            | represented by the following keys:


                * uid: int
                * gid: int
                * homedir: str
                * shell: str
                * name: str
                * privileges: str
                * sshkeys: list[str,]
                * level : 15,

            :return: dict

            example::

                {
                    'admin': {
                        'uid': '0',
                        'gid': '0',
                        'homedir': '/home/admin',
                        'shell': '/etc/cli.sh',
                        'name': 'n/a',
                        'privileges': 'Access to Expert features'},
                        'level' : 15,
                        'password' : '$1$aWTXGUmr$1r1Ls428oJg2gFwMcKJdO0'
                        'sshkeys' : ['',]}
                    'monitor':                        {
                        'uid': '102',
                        'gid': '100',
                        'homedir': '/home/monitor',
                        'shell': '/etc/cli.sh',
                        'name': 'Monitor',
                        'privileges': 'None',
                        'level' : 15,
                        'password' : '*'
                        'sshkeys' : ['',]}
                }


        """
        username_regex = (
            r'^([A-z0-9_-]{1,32})\s+(\d+)\s+(\d+)\s+([/A-z0-9_-]{1,})\s+'
            r'([./A-z0-9_-]{1,})\s+((?:[\/A-z0-9_-]+\s?)+[\/A-z0-9_-])\s+'
            r'((?:[\/A-z0-9_-]+\s?)+[\/A-z0-9_-]).+?$'
        )
        pwdhash_regex = (
            r'^[a-z]{3}\s[a-z]{4}\s([A-z][A-z0-9_-]+)\s.*hash\s(.*)$'
        )
        users = {}
        command = 'show users'
        try:
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
            command = 'show configuration user'
            output = self.device.send_command(command)
            for match in re.finditer(pwdhash_regex, output, re.M):
                users[match.group(1)]['password'] = match.group(2)
            if 'retrieve' in kwargs:
                if kwargs['retrieve'] == 'all':
                    if self._enter_expert_mode() is True:
                        files = ['authorized_keys', 'authorized_keys2']
                        for user in users:
                            users[user]['sshkeys'] = []
                            i = False
                            for file in files:
                                command = r'cat /home/{0}/.ssh/{1}'.format(user, file)
                                output = self.device.send_command(command)
                                if re.match(r'cat.*$', output) is None and re.match(r'$', output) is None:
                                    users[user]['sshkeys'].append(str(output.split('\n')))
                                    i = True
                                else:
                                    pass
                            if i is False:
                                users[user]['sshkeys'].append('')
                    else:
                        raise RuntimeError('unable to enter expert-mode')
            else:
                for user in users:
                    users[user]['sshkeys'] = ['']
            return users
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))
        except Exception as e:
            raise RuntimeError(e)

    def get_arp_table(self, vrf='') -> list:
        """
            | Get arp table information. (requires expert-password)
            | vrf is not supported.
            | Returns a list of dictionaries having the following set of keys:

                * interface: str
                * mac: str
                * ip: str
                * age: float
                * state: str

            :return: list

            example::

                [
                    {
                        'interface' : 'eth0',
                        'mac'       : '5c:5e:ab:da:3c:f0',
                        'ip'        : '172.17.17.1',
                        'age'       : 875.0,
                        'state'     : 'REACHABLE'
                    },
                    {
                        'interface': 'eth0',
                        'mac'       : '66:0e:94:96:e0:ff',
                        'ip'        : '172.17.17.2',
                        'age'       : 0.0,
                        'state'     : 'STALE'
                    }
                ]

        """

        arptable_regex = ()
        commands = 'ip -statistics show'
        arptable_regex = '^([0-9.]+)\sdev\s([A-z0-9.]+)\slladdr\s([A-z0-9:]+)\s' \
                         '(?:ref\s\d+\s|)used\s(\d+)(?:[/0-9]+\s|[/0-9]+\sprobes\s\d+\s)([A-z]+)$'
        command = 'ip -stat neigh'
        arp_entries = []
        if self._enter_expert_mode() is True:
            output = self.device.send_command(command)
            self._exit_expert_mode()
        else:
            raise RuntimeError('unable to enter expert-mode')
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
      
    def get_config(self, retrieve='all') -> dict:
        """
        | Get host configuration. Returns a string delimited with a '\n' for further parsing.
        | Configuration can be retrieved at once or as logical part.

        :return: dict

            
            For example::

                device.get_config(retrieve='user')

                {
                    'running': '
                        set user admin shell /etc/cli.sh
                        set user admin password-hash $1$aWTXGUmr$1r1Ls428oJg2gFwMcKJdO0
                        set user monitor shell /etc/cli.sh
                        set user monitor password-hash *

                    ',
                    'candidate': '',
                    'startup' : ''
                }


            Retrieve options::


                all                  - display full configuration
            
                aaa                  - display aaa configuration commands
                aggregate            - Display Route Aggregation configuration commands
                allowed-client       - Displays Allowed Clients configuration
                arp                  - Display ARP configuration commands
                as                   - Show Autonomous System Number configuration commands
                backup-scheduled     - Display scheduled backup configuration commands
                bgp                  - Display BGP configuration commands
                bonding              - display bonding configuration commands
                bootp                - Show BOOTP/DHCP Relay configuration commands
                bridging             - display bridging configuration commands
                clienv               - display CLI environment configuration commands
                command              - extended commands configuration commands
                core-dump            - Display core-dump configuration commands
                cron                 - display cron configuration commands
                dhcp-client          - display dhcp client configuration commands
                dhcp-server          - display dhcp configuration commands
                dns                  - display dns configuration commands
                domainname           - display domainname configuration commands
                edition              - display edition configuration commands
                expert-password      - Displays expert password configuration
                format               - display format configuration commands
                group                - display group configuration commands
                host                 - Display host configuration commands
                hostname             - Display hostname configuration commands
                igmp                 - Display IGMP configuration commands
                inbound-route-filter - Display Inbound Route Filter configuration commands
                installer            - installer configuration commands
                interface            - interface configuration commands
                interface-name       - Interface naming configuration commands
                iphelper             - Display IP Broadcast Helper configuration commands
                ipv6                 - Display IPv6 routing configuration commands
                ipv6-state           - Display IPv6 configuration commands
                kernel-routes        - Show configuration commands for kernel routes
                lcd                  - display lcd configuration commands
                mail-notification    - display format configuration commands
                management           - management configuration commands
                max-path-splits      - Show max-path-splits configuration commands
                message              - Display message configuration commands
                net-access           - Displays network access configuration
                netflow              - netflow configuration commands
                ntp                  - display ntp configuration commands
                ospf                 - Display OSPFv2 configuration commands
                password-controls    - display password-controls configuration commands
                pim                  - Display PIM configuration commands
                ping                 - Display ping (for static routes) configuration commands
                protocol-rank        - Show protocol ranks configuration commands
                proxy                - display proxy configuration commands
                rba                  - Display rba configuration commands
                rdisc                - Display ICMP Router Discovery configuration commands
                rip                  - Display RIP configuration commands
                route-redistribution - Display route redistribution configuration commands
                routedsyslog         - Show Routing Daemon syslog configuration commands
                routemap             - Display configuration commands for a specific Route Map
                routemaps            - Display Route Map configuration commands
                router-id            - Show Router ID configuration commands
                router-options       - Show Router Options configuration commands
                snmp                 - SNMP configuration commands
                static-mroute        - Display static multicast route configuration commands
                static-route         - Display IPv4 static route configuration commands
                syslog               - Display syslog configuration commands
                timezone             - Timezone configuration commands
                trace                - Show Trace configuration commands
                tracefile            - Show Tracefile configuration commands
                user                 - Display user configuration commands
                vpnt                 - Display VPN tunnel configuration
                web                  - Displays Web configuration

        """
        opt = retrieve.lower()
        command = 'show configuration'
        if opt != 'all':
            command += ' {}'.format(opt)
        try:
            output = self.device.send_command(command)
            retdict = {'running': output, 'candidate': '', 'startup': ''}
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))
        except Exception as e:
            RuntimeError(e)
        return retdict

    def get_firewall_policy(self, interfaces=False) -> dict:
        """
            | Gets firewall policy information. Returns a dict with the following keys.
            |    * name (str)
            |    * install_time (str)
            |    * current_conns (int)
            |    * peak_conns (int)
            |    * conns_limit (int)
            |
            | With optional parameter 'interfaces' returns nested dict with the following keys.
            |    * iftab32 (dict)
            |    * iftab64 (dict)
            |       * <interface name> (dict)
            |           * in (dict)
            |               * accept (int)
            |               * drop (int)
            |               * reject (int)
            |               * log (int)
            |           * out (dict)
            |               * accept (int)
            |               * drop (int)
            |               * reject (int)
            |               * log (int)

        :param interfaces: bool
        :return: dict

        example::
            {
              'name': 'policy',
              'install_time': 'Wed Mar  1 00:00:00 2020',
              'current_conns': '0',
              'peak_conns': '0',
              'conns_limit': '0',
              'if_tab_32': {
                'bond0': {
                  'in': {
                    'accept': '0',
                    'drop': '0',
                    'reject': '0',
                    'log': '0'
                  },
                  'out': {
                    'accept': '0',
                    'drop': '0',
                    'reject': '0',
                    'log': '0'
                  }
                }
                'if_tab_64': {
                  'bond0': {
                    'in': {
                      'accept': '0',
                      'drop': '0',
                      'reject': '0',
                      'log': '0'
                    },
                    'out': {
                      'accept': '0',
                      'drop': '0',
                      'reject': '0',
                      'log': '0'
                    }
                  }
                }
        """

        regex = r'.*\snot a FireWall-1 module'
        command = 'fw stat'
        output = self.device.send_command(command)
        if re.match(regex, output) is not None:
            raise ValueError('firewall module not enabled')
        try:
            policy_regex = r'([A-z. ]+)(?:\:)(?:\s+)([A-z0-9-_:\ ]+)'
            policy_if_regex = r'^(?:\|)([A-z0-9.]+)(?:\s+\||\|)([A-z]+)' \
                              r'(?:\s+\||\|)(?:\s+|)(\d+)(?:\s+\||\|\s+|\|)' \
                              r'(\d+)(?:\s+\||\|\s+|\|)(\d+)(?:\s+\||\|\s+|\|)(\d+)'
            command = 'cpstat -f policy fw'
            output = self.device.send_command(command)
            policy_list = []
            for match in re.finditer(policy_regex, output, re.M):
                policy_list.append(match.group(2))
            policy = {
                'name': str(policy_list[1]),
                'install_time': str(policy_list[2]),
                'current_conns': int(policy_list[3]),
                'peak_conns': int(policy_list[4]),
                'conns_limit': int(policy_list[5])
            }
            if interfaces is True:
                for match in re.finditer(policy_if_regex, output, re.M):
                    counters = {
                        'accept': int(match.group(4)),
                        'drop': int(match.group(5)),
                        'reject': int(match.group(6)),
                        'log': int(match.group(7))
                    }
                    if match.group(1) is None:
                        if match.group(2) not in policy[iftab]:
                            policy[iftab][match.group(2)] = {}
                        policy[iftab][match.group(2)][match.group(3)] = counters
                    else:
                        iftab = 'iftab64' if re.sub(r'\D', '', match.group(1)) == '64' else 'iftab32'
                        policy[iftab] = {}
            return policy
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))
        except Exception as e:
            raise RuntimeError(str(e))

    def get_interfaces(self) -> dict:

        """
                    | Get interface details.
                    | last_flapped is not implemented and will return -1.
                    | Virtual interfaces speed will return 0.

                    :return: dict

                    example::

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
                                      'mtu': 1500   }}
                """
        RE_NICDATA = {'description': re.compile('\s+comments(.*|$)'),
                      'is_enabled': re.compile('\s+state\s(.*)$'),
                      'is_up': re.compile('\s+[Ll]ink-[Ss]tate\s[Ll]ink\s(.*)$'),
                      'mac_address': re.compile('\s+[Mm]ac-[Aa]ddr\s(.*)$'),
                      'speed': re.compile('\s+[Ll]ink-[Ss]peed\s([0-9]+).*$'),
                      'mtu': re.compile('\s+[Mm]tu\s(.*)$')
                      }
        interface_table = {}
        try:
            self.device.send_command('set clienv rows 0')
            output = self.device.send_command('show interfaces all')
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))

        output = str(output).split('Interface ')
        for item in output:
            if len(item) == 0:
                output.remove(item)
        for item in output:
            item = str(item).splitlines()
            # set entry defaults
            interface_table[item[0]] = {}
            interface_table[item[0]]['is_enabled'] = False
            interface_table[item[0]]['is_up'] = False
            interface_table[item[0]]['mtu'] = 0
            interface_table[item[0]]['description'] = ''
            interface_table[item[0]]['mac_address'] = 'Not configured'
            interface_table[item[0]]['speed'] = 0
            for line in item:
                if re.match(RE_NICDATA['is_enabled'], line) is not None:
                    if re.findall(RE_NICDATA['is_enabled'], line) == 'off':
                        interface_table[item[0]]['is_enabled'] = False
                    else:
                        interface_table[item[0]]['is_enabled'] = True
                if re.match(RE_NICDATA['is_up'], line) is not None:
                    if re.findall(RE_NICDATA['is_up'], line) == 'down':
                        interface_table[item[0]]['is_up'] = False
                    else:
                        interface_table[item[0]]['is_up'] = True
                if re.match(RE_NICDATA['mtu'], line) is not None:
                    interface_table[item[0]]['mtu'] = re.findall(RE_NICDATA['mtu'], line)[0]
                if re.match(RE_NICDATA['description'], line) is not None:
                    interface_table[item[0]]['description'] = re.findall(RE_NICDATA['description'], line)[0]
                    if re.match(r'^\s+$',  interface_table[item[0]]['description']):
                        interface_table[item[0]]['description'] = ''
                if re.match(RE_NICDATA['mac_address'], line) is not None:
                    interface_table[item[0]]['mac_address'] = re.findall(RE_NICDATA['mac_address'], line)[0]
                if re.match(RE_NICDATA['mac_address'], line) is not None:
                    interface_table[item[0]]['mac_address'] = re.findall(RE_NICDATA['mac_address'], line)[0]
                if re.match(RE_NICDATA['speed'], line) is not None:
                    interface_table[item[0]]['speed'] = re.findall(RE_NICDATA['speed'], line)[0]
        return interface_table

    def get_interfaces_ip(self):
        """
            | Get interface ip details.
            | Returns a dict of dicts

            :return: dict

            example::

                {   u'FastEthernet8': {   'ipv4': {   u'10.66.43.169': {   'prefix_length': 22}}},
                    u'Loopback555': {   'ipv4': {   u'192.168.1.1': {   'prefix_length': 24}},
                                        'ipv6': {   u'1::1': {   'prefix_length': 64}}},
                    u'Tunnel0': {   'ipv4': {   u'10.63.100.9': {   'prefix_length': 24}}},
                    u'Tunnel1': {   'ipv4': {   u'10.63.101.9': {   'prefix_length': 24}}},
                    u'Vlan100': {   'ipv4': {   u'10.65.0.1': {   'prefix_length': 24}}},
                    u'Vlan200': {   'ipv4': {   u'10.63.176.57': {   'prefix_length': 29}}}}

        """
        RE_NICDATA = {'ipv4': re.compile('\s+ipv4-ad\w+\s([0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})/([0-9]{1,3})$'),
                      'ipv6': re.compile(r'\s+ipv6-(\w+-\w+-)?\w+\s(.*)/([0-9]{1,3})$')
                      }
        interface_table = {}
        try:
            self.device.send_command('set clienv rows 0')
            output = self.device.send_command('show interfaces all')
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))
        output = str(output).split('Interface ')
        for item in output:
            if len(item) == 0:
                output.remove(item)
        for item in output:
            item = str(item).splitlines()
            # set entry defaults
            for line in item:
                if re.match(RE_NICDATA['ipv4'], line) is not None:
                    if item[0] not in interface_table:
                        interface_table[item[0]] = {}
                    ip_addr = re.findall(RE_NICDATA['ipv4'], line)
                    interface_table[item[0]]['ipv4'] = {ip_addr[0][0]: {'prefix_length': ip_addr[0][1]}}
                if re.match(RE_NICDATA['ipv6'], line) is not None:
                    if item[0] not in interface_table:
                        interface_table[item[0]] = {}
                    ip_addr = re.findall(RE_NICDATA['ipv6'], line)
                    if len(ip_addr[0]) == 2:
                        interface_table[item[0]]['ipv6'] = {ip_addr[0][0]: {'prefix_length': ip_addr[0][1]}}
                    else:
                        interface_table[item[0]]['ipv6'] = {ip_addr[0][1]: {'prefix_length': ip_addr[0][2]}}
        return interface_table

    def get_virtual_systems(self) -> dict:
        """
            | Get virtual systems information.   
            | Returns a dictionary with configured virtual systems.
            | The keys of the main dictionary represents virtual system ID.
            | The values represent the detail of the  virtual system,
            | represeted by the following keys.
            |   * type (str)
            |   * name (str)
            |   * policy (str)
            |   * sic (str)
            
            :return: dict
            
            example::
                {
                  0:
                    {'
                      'type': 'VSX Gateway',
                      'name': 'dummy_vsx_gw',
                      'policy': 'dummy_policy'
                      'sic': 'Trust established'
                    }
                }
        """
        try:
            if self._check_vsx_state() is True:
                vs_regex = r'\|(.\d+)\|([A-z0-9-_]+\s.\w+)+(?:\s+\||\|)+([A-z0-9-_]+)+' \
                           r'(?:\s+\||\|)+([A-z0-9_-]+)+(?:\s+\||\|)+(.*)(?:\|)'
                command = 'cpstat -f stat vsx'
                output = self.device.send_command(command)
                vs = {}
                for match in re.finditer(vs_regex, output, re.M):
                    vs[match.group(1)] = {
                        'type': match.group(2),
                        'name': match.group(3),
                        'policy': match.group(4),
                        'sic': match.group(5)
                    }
                return vs
            else:
                raise ValidationException('VSX not enabled')
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))

    def _enter_expert_mode(self) -> bool:
        """
            :return: bool
        """
        try:
            if self._check_expert_mode() is False:
                self.device.send_command('expert', expect_string=r':')
                output = self.device.send_command_timing(self.expert_password)
                if r']#' in output:
                    self.device.set_base_prompt(r'#')
                    self.device.send_command(r'unset TMOUT')
                return self._check_expert_mode()

        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))
        except Exception as e:
            raise RuntimeError(e)

    def _exit_expert_mode(self) -> bool:
        """
            :return: bool
        """
        try:
            if self._check_expert_mode() is True:
                self.device.send_command('exit', expect_string=r'>')
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
        except Exception as e:
            raise RuntimeError(e)

    def send_clish_cmd(self, cmd: str) -> str:
        """
            send clish command

            :param cmd: str
            :return: (str)
        """
        try:
            output = self.device.send_command(cmd)
            return output
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))
        except Exception as e:
            raise RuntimeError(e)

    def send_expert_cmd(self, cmd: str) -> str:
        """
            send expert-mode command(requires expert-password)

            :param cmd: str
            :return: str
        """
        if self._enter_expert_mode() is True:
            output = self.device.send_command(cmd)
            self._exit_expert_mode()
            return output
        else:
            raise RuntimeError('unable to enter expert mode')

    def ping(self, destination: str, **opts) -> dict:
        """
            | ping destination from device
            | vsx/vrf is currently not supported, neither is setting timeout

            :param destination: str
            :param opts: dict

            | opts:

                * source: (<interface|ip-address>: str)
                * ttl: (1-255: int)
                * timeout: None
                * vrf: None
                * size: (8-65507: int)
                * count: (1-1000: int)

            example::

                {
                'source': 'eth0',
                'ttl': 30,
                'timeout': None,
                'size': 1500,
                'count': 10,
                'vrf': None
                }

            :return: dict

            example::

                {
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
                                'ip_address': u'1.1.1.1',
                                'rtt': 72.299
                            }
                        ]
                    }
                }

            OR::

                {
                    'error': 'unknown host 8.8.8.8'
                }

        """

        try:
            self.device.send_command('\t')
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))
        if self._is_valid_hostname(destination) is True:
            command = r'ping {0}'.format(destination)
            if 'source' in opts:
                self._validate_ping_source(opts['source'])
                command += ' -I {0}'.format(opts['source'])
            if 'ttl' in opts:
                self._validate_ping_ttl(opts['ttl'])
                command += ' -t {0}'.format(opts['ttl'])
            if 'size' in opts:
                self._validate_ping_size(opts['size'])
                command += ' -s {0}'.format(opts['size'])
            if 'count' in opts:
                self._validate_ping_count(opts['count'])
                command += ' -c {0}'.format(opts['count'])
            else:
                command += ' -c 5'
            output = self.device.send_command(command, delay_factor=10)
            output = str(output).split('\n')
            values = []
            re_output_rtt = r'(\d+).*time=(.*)\sms'
            re_output_rtt_unreachable = r'(.*[Uu]nreachable)'
            re_stats_rtt = r'.*=\s(.*)/(.*)/(.*)/(.*)\sms'
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

    def get_facts(self, **kwargs):
        """



            Returns a dictionary containing the following information:
             * uptime - Uptime of the device in seconds.
             * vendor - Manufacturer of the device.
             * model - Device model.
             * hostname - Hostname of the device
             * fqdn - Fqdn of the device
             * os_version - String with the OS version running on the device.
             * serial_number - Serial number of the device
             * interface_list - List of the interfaces of the device
            Example::
                {
                'uptime': 151005.57332897186,
                'vendor': u'Arista',
                'os_version': u'4.14.3-2329074.gaatlantarel',
                'serial_number': u'SN0123A34AS',
                'model': u'vEOS',
                'hostname': u'eos-router',
                'fqdn': u'eos-router',
                'interface_list': [u'Ethernet2', u'Management1', u'Ethernet1', u'Ethernet3']
                }


        :param kwargs:
        :return:
        """
        retdict = {}
        interfaces = str(self.device.send_command('show interfaces')).split('\n')

        # uptime requires conversion to seconds -> output format follows pattern:
        #   " 1 year 1 month 1 day 1 hour 5 minutes"
        # unused fields will be omitted
        #   (i.e. " 1 day 1 hour 5 minutes")
        # need to doublecheck with realworld deployments(to less uptime in lab)
        # disable meanwhile and set to zero
        uptime = float(0)
        hostname = self.device.send_command('show hostname')
        dns_suffix = self.device.send_command('show dns suffix')
        if re.match('$', dns_suffix) is None:
            fqdn = hostname + '.' + dns_suffix
        else:
            fqdn = hostname
        output = self.device.send_command('show version product')
        output = re.match('.*(Check Point Gaia R\d+\.\d+)\s*$', output)
        if output is not None:
            os_version = output.group(1)
            output = self.device.send_command('show version os kernel')
            output = re.match('OS\skernel\sversion\s(.*)$', output)
            if output is not None:
                os_version += ' - Kernel: ' + output.group(1)
        else:
            os_version = 'unknown'
        # sn - behaviour differs  openserver/virtual appliance require ('expert::dmidecode -t system')
        # appliances work with('clish::cpstat -os'). platform check required (use uuid if sn is 'none'?)
        # set sn to empty string meanwhile
        #
        output = self.device.send_command('cpstat os')
        retdict['model'] = 'unknown'
        for line in str(output).split('\n'):
            if re.match(r'Appliance\sName.*$', line) is not None:
                retdict['model'] = re.match(r'Appliance\sName:\s*(.*)$', line).group(1)
        sn = ''
        vendor = ''
        retdict['uptime'] = uptime
        retdict['os_version'] = os_version
        retdict['serial_number'] = sn
        retdict['vendor'] = vendor
        retdict['hostname'] = hostname
        retdict['fqdn'] = fqdn
        retdict['interface_list'] = interfaces
        return retdict

    def _is_valid_hostname(self, hostname) -> bool:
        if ipaddress.ip_address(hostname):
            return True
        else:
            if hostname[-1] == ".":
                hostname = hostname[:-1]
            if len(hostname) > 253:
                return False
            labels = hostname.split(".")
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
            mobj = re.match(r'.*ipv4-address\s*(.*)/.*', output)
            if mobj is not None:
                source_interfaces.append(mobj.group(1))
            output = self.device.send_command('show interface {0} ipv6-address'.format(interface))
            mobj = re.match(r'.*ipv6-address\s*(.*)/.*', output)
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

    def _check_vsx_state(self) -> bool:
        """
            :return: bool
        """
        vsx_regex = r'^\|.\d+\|'
        command = 'cpstat -f stat vsx'
        try:
            output = self.device.send_command(command)
            if re.search(vsx_regex, output, re.M):
                return True
            else:
                return False
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))
    
    def _set_virtual_system(self, vsid: int) -> bool:
        """
            | Switch to VSX context. Raises RuntimeError if failed.
            
            :return: bool
        """
        try:
            if self._check_vsx_state() is True:
                if self._check_expert_mode() is True:
                    command = 'vsenv {}'.format(vsid)
                else:
                    command = 'set virtual-system {}'.format(vsid)
                vsid_regex = r'(?<=:){}'.format(vsid)
                expect_regex = r'(?<=:)\d+'
                output = self.device.send_command(command, expect_regex)
                if re.search(vsid_regex, output):
                    return True
                else:
                    raise CommandErrorException('cannot access virtual-system')
            else:
                raise ValidationException('VSX not enabled')
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))

    ##########################################################################################
    # """                               the tbd section                                  """ #
    ##########################################################################################

    def get_bgp_config(self, **kwargs):
        """
            not implemented yet

        :param kwargs:
        :return:
        """
        raise NotImplementedError

    def get_bgp_neighbors(self):
        """
            not implemented yet

        :param kwargs:
        :return:
        """
        raise NotImplementedError

    def get_bgp_neighbors_detail(self, **kwargs):
        """
            not implemented yet

        :param kwargs:
        :return:
        """
        raise NotImplementedError

    def get_environment(self):
        """
            not implemented yet

        :param kwargs:
        :return:
        """
        raise NotImplementedError

    def get_interfaces_counters(self):
        """
            not implemented yet

        :param kwargs:
        :return:
        """
        raise NotImplementedError

    def get_ipv6_neighbors_table(self):
        """
            not implemented yet

        :param kwargs:
        :return:
        """
        raise NotImplementedError

    def get_lldp_neighbors(self):
        """
            not implemented yet

        :param kwargs:
        :return:
        """
        raise NotImplementedError

    def get_lldp_neighbors_detail(self, **kwargs):
        """
            not implemented yet

        :param kwargs:
        :return:
        """
        raise NotImplementedError

    def get_mac_address_table(self):
        """
            not implemented yet

        :param kwargs:
        :return:
        """
        raise NotImplementedError

    def get_network_instances(self, **kwargs):
        """
            not implemented yet

        :param kwargs:
        :return:
        """
        raise NotImplementedError

    def get_ntp_peers(self):
        """
            not implemented yet

        :param kwargs:
        :return:
        """
        raise NotImplementedError

    def get_ntp_servers(self):
        """
            not implemented yet

        :param kwargs:
        :return:
        """
        raise NotImplementedError

    def get_ntp_stats(self):
        """
            not implemented yet

        :param kwargs:
        :return:
        """
        raise NotImplementedError

    def get_optics(self):
        """
            not implemented yet

        :param kwargs:
        :return:
        """
        raise NotImplementedError

    def get_probes_config(self):
        """
            not implemented yet

        :param kwargs:
        :return:
        """
        raise NotImplementedError

    def get_probes_results(self):
        """
            not implemented yet

        :param kwargs:
        :return:
        """
        raise NotImplementedError

    def get_route_to(self, **kwargs):
        """
            not implemented yet

        :param kwargs:
        :return:
        """
        raise NotImplementedError

    def get_snmp_information(self):
        """
            not implemented yet

        :param kwargs:
        :return:
        """
        raise NotImplementedError

    def is_alive(self):
        """
            not implemented yet

        :param kwargs:
        :return:
        """
        raise NotImplementedError

    def traceroute(self, **kwargs):
        """
            not implemented yet

        :param kwargs:
        :return:
        """
        raise NotImplementedError

    def load_template(self, **kwargs):
        """
            not implemented yet

        :param kwargs:
        :return:
        """
        raise NotImplementedError

    def compliance_report(self, **kwargs):
        """
            not implemented yet

        :param kwargs:
        :return:
        """
        raise NotImplementedError

    def commit_config(self, **kwargs):
        """
            not implemented yet

        :param kwargs:
        :return:
        """
        raise NotImplementedError

    def compare_config(self):
        """
            not implemented yet

        :param kwargs:
        :return:
        """
        raise NotImplementedError

    def load_merge_candidate(self,  **kwargs):
        """
            not implemented yet

        :param kwargs:
        :return:
        """
        raise NotImplementedError

    def load_replace_candidate(self, **kwargs):
        """
            not implemented yet

        :param kwargs:
        :return:
        """
        raise NotImplementedError

    def rollback(self):
        """
            not implemented yet

        :param kwargs:
        :return:
        """
        raise NotImplementedError


if __name__ == '__main__':
    pass

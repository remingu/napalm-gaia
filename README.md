# napalm-gaia

CheckPoint GaiaOS driver-plugin for NAPALM (Network Automation and Programmability Abstraction Layer with Multivendor support) python library.<br> 
Certain commands will require expert password. <br>
Please note that the cli mode supports only clish commands.<br>
This driver is not slightly feature complete. 
(You can send atomic commands using send_clish_cmd() and send_expert_cmd() methods.)


## install
 
we're preparing pypi deployment at the moment, meanwhile you can install testpackages via easy_install.

## documentation

(https://napalm-gaia.readthedocs.io/en/latest)

## simple test
    #!/usr/bin/env python3
    from napalm import get_network_driver    
    
    driver = get_network_driver('gaiaos')   
    optional_args = {'secret': 'expert-password'}
    device = driver('1.1.1.1', 'username', 'password', optional_args=optional_args)
    device.open()    
    vals = device.get_users()    
    print(vals)
    vals = device.send_clish_cmd('show asset all')
    print(vals)
    vals = device.send_expert_cmd('uname -a')
    print(vals)    
    device.close()
    

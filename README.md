# napalm-gaia

CheckPoint Gaia driver-plugin for NAPALM (Network Automation and Programmability Abstraction Layer with Multivendor support) python library 
Certain commands require expert mode accessible.

## install
 
we're preparing pypi deployment at the moment, meanwhile you can install testpackages via easy_install or rpm/dpkg.<br>




## simple test
    #!/usr/bin/env python3
    from napalm import get_network_driver
    
    optional_args = {'secret': 'expert-password'}
    driver = get_network_driver('gaiaos')   
    device = driver('1.1.1.1', 'username', 'password', optional_args=optional_args)
    device.open()    
    vals = device.get_users()
    device.close()
    print(vals)

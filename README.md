# napalm-gaia

CheckPoint Gaia driver-plugin for NAPALM (Network Automation and Programmability Abstraction Layer with Multivendor support) python library 


## simple test
    #!/usr/bin/env python3
    from napalm import get_network_driver
    
    
    driver = get_network_driver('gaiaos')   
    device = driver('1.1.1.1', 'username', 'password')
    device.open()    
    vals = device.func()
    device.close()
    print(vals)
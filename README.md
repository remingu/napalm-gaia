# napalm-gaia

CheckPoint Gaia driver-plugin for NAPALM (Network Automation and Programmability Abstraction Layer with Multivendor support) python library 

## install
 
we're preparing pypi deployment at the moment, meanwhile you can install testpackages via easy_install or rpm.<br>
If you're on *.deb based distributions you can use 'alien' to convert the rpm to deb and then install it via apt or dpkg.



## simple test
    #!/usr/bin/env python3
    from napalm import get_network_driver
    
    
    driver = get_network_driver('gaiaos')   
    device = driver('1.1.1.1', 'username', 'password')
    device.open()    
    vals = device.func()
    device.close()
    print(vals)
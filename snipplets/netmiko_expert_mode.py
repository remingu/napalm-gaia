from netmiko import ConnectHandler

device = {'device_type': 'checkpoint_gaia', 'host': '<X.X.X.X>', 'username': '<uid>', 'password': '<pwd>'}
conn = ConnectHandler(**device)
tmpstr = conn.send_command_timing('expert')
if 'Enter expert password:' in tmpstr:
    tmpstr += conn.send_command_timing('<enable_password>')
output = conn.find_prompt()
print(output)
output = conn.send_command('ip neigh show')
print(output)
conn.send_command('exit')
output = conn.find_prompt()
print(output)
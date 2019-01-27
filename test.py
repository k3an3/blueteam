from blueteam.backends import SSHBackend, LocalBackend
from blueteam.modules import Host

sb = SSHBackend(host='www.team40.isucdc.com')
lb = LocalBackend()
lh = Host(lb)
sh = Host(sb)

command = 'ls'
print(sb.run_command(command))
print(lb.run_command(command))
print(sb.read_file('/etc/hosts'))
print(lb.read_file('/etc/hosts'))
print(sb.glob('/tmp'))
print(lb.glob('/tmp'))
"""
for host, output in b.run_command('whoami'):
    print("[{}] {}".format(host, output))

for host, output in b.read_file('/etc/passwd'):
    print("[{}] {}".format(host, output))

for host, output in b.glob('/etc/sudoers.d/*'):
    print(host, output)

for host, output in b.run_command('ls /etc/sudoers{,.d/*}'):
    print("[{}] {}".format(host, output))
h = Host(b)
print(h.parse_sudo())
"""

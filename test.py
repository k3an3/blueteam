from blueteam.backends import SSHBackend
from blueteam.modules import Host

b = SSHBackend(hosts=['www.team40.isucdc.com',
                      'db1.team40.isucdc.com',
                      'db2.team40.isucdc.com',
                      'db3.team40.isucdc.com',
                      'db4.team40.isucdc.com',
                      'db5.team40.isucdc.com'], keyfile=None)
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

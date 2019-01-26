import collections
import subprocess
import sys
from typing import List

import colorful
import psutil as psutil

from blueteam.backends import Backend, LocalBackend


class Host:
    def __init__(self, backend: Backend):
        self.backend = backend
        self.sudo = []
        self.cron = []
        self.debsums = []
        self.processes = {}
        self.dpkg = {}

    def combine_files(self, *patterns: List[str]):
        for p in patterns:
            for f in self.backend.glob(p):
                for line in self.backend.read_file(f):
                    line = line.rstrip()
                    if line and not line.startswith('#'):
                        yield line

    def parse_sudo(self):
        for line in self.combine_files('/etc/sudoers{,.d/*}'):
            if line.startswith("Defaults"):
                self.sudo.append(line)
            else:
                self.sudo.append(colorful.yellow(line))

    def parse_cron(self):
        for line in self.combine_files('/etc/cron{tab,.*/*}', '/var/spool/cron/crontabs/*'):
            self.cron.append(line)

    def run_debsums(self):
        for line in self.backend.run('debsums -ac'):
            self.debsums.append(line)

    def get_processes(self):
        for proc in psutil.process_iter(attrs=['pid', 'ppid', 'name', 'exe',
                                               'cmdline', 'terminal', 'connections',
                                               'username', 'create_time']):
            self.processes[proc.pid] = proc.info

    def _print_process(self, pid: int):
        p = self.processes.get(pid)
        if p:
            print("{:7}{:6}{:6} ".format(p['username'][:7], p['pid'],
                                            p['ppid']), end='')
        else:
            print(pid, ">???")

    def _print_cmdline(self, p):
        cmdline = ' '.join(p['cmdline'])
        print(cmdline[:50] if p['cmdline'] else p['name'],
              '...' if len(cmdline) > 50 else '', "'" + p['exe'])

    # Stolen from psutil
    def _print_tree(self, parent, tree, indent=''):
        try:
            p = self.processes[parent]
        except KeyError:
            pass
        else:
            self._print_cmdline(p)
        if parent not in tree:
            return
        children = tree[parent][:-1]
        for child in children:
            self._print_process(child)
            sys.stdout.write(indent + "\\_ ")
            self._print_tree(child, tree, indent + "| ")
        child = tree[parent][-1]
        self._print_process(child)
        sys.stdout.write(indent + "\\_ ")
        self._print_tree(child, tree, indent + "  ")

    def get_package_name(self, pkg: str):
        try:
            p = self.dpkg[pkg]
        except KeyError:
            p = self.backend.run_command('dpkg -S {}'.format(pkg))[0].rstrip()
            self.dpkg[pkg] = p
        return p

    # Stolen from psutil
    def pstree(self):
        tree = collections.defaultdict(list)
        for pid, p in self.processes.items():
            try:
                tree[p['ppid']].append(pid)
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                pass
        # on systems supporting PID 0, PID 0's parent is usually 0
        if 0 in tree and 0 in tree[0]:
            tree[0].remove(0)
        self._print_tree(min(tree), tree)


if __name__ == '__main__':
    b = LocalBackend()
    h = Host(b)
    # h.parse_sudo()
    # h.parse_cron()
    for l in h.sudo:
        print(l)
    for l in h.cron:
        print(l)
    h.get_processes()
    # h.print_pstree()
    h.pstree()

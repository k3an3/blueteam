import collections
import os
import sys
from multiprocessing import Queue
from typing import List

import colorful
import psutil as psutil

from blueteam.backends import Backend


class Host:
    def __init__(self, backend: Backend, debsums: bool = True):
        self.backend = backend
        self.sudo = []
        self.cron = []
        self.debsums = []
        self.processes = {}
        self.dpkg = {}
        self.pid = os.getpid()
        self._tasks = [self.parse_sudo, self.parse_cron]
        self.uidmap = {}
        if debsums:
            self._tasks.append(self.run_debsums)
        self.q = Queue()

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
        for line in self.backend.run_command('debsums -ac').split('\n'):
            self.debsums.append("{} ({})".format(line, colorful.cyan(self.get_package_name(line).rstrip())))

    def get_processes(self):
        for pid, proc in self.backend.get_processes():
            pkg = self.get_package_name(proc['exe'])
            self.processes[pid] = {**proc, 'pkg': pkg,
                                   'verify': proc['exe'] not in self.debsums}

    @staticmethod
    def _is_kthread(p):
        return 2 in (p['pid'], p['ppid'])

    def _print_process(self, pid: int):
        p = self.processes.get(pid)
        color = colorful.red if not p['pkg'] and not self._is_kthread(p) else colorful.green
        if p:
            print("{:7}{:6}{:6} {:3} {:5}{:30} ".format(p['username'][:7], p['pid'],
                                                        p['ppid'], colorful.yellow(len(p['connections'])),
                                                        color('dpkg:' if not self._is_kthread(p) else ''),
                                                        p['pkg'] or ''), end='')
        else:
            print(pid, ">???")

    def _print_cmdline(self, p):
        cmdline = ' '.join(p['cmdline'])
        print(cmdline[:50] if p['cmdline'] else p['name'],
              '...' if len(cmdline) > 50 else '',
              colorful.white(p['exe']),
              colorful.white_on_blue('(blueteam)') if self._is_parent(p['pid']) else '')

    def _is_parent(self, pid: int):
        pid = int(pid)
        if not pid:
            return False
        if pid == self.pid:
            return True
        return self._is_parent(self.processes[pid]['ppid'])

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

    def get_package_name(self, path: str):
        if path:
            try:
                p = self.dpkg[path]
            except KeyError:
                p = self.backend.run_command('dpkg -S {}'.format(path))
                try:
                    p = p.split(":")[0]
                except AttributeError:
                    p = p[0].split(":")[0]
                self.dpkg[path] = p
            return p

    def run_all(self):
        for task in self._tasks:
            print("Running", task.__name__)
            task()
        print(colorful.black_on_white('SUDO FILES ' + 69 * '='))
        for line in self.sudo:
            print(line)
        print(colorful.black_on_white('CRON FILES ' + 69 * '='))
        for line in self.cron:
            print(line)

    # Stolen from psutil
    def pstree(self):
        tree = collections.defaultdict(list)
        for pid, p in self.processes.items():
            tree[p['ppid']].append(pid)
        # on systems supporting PID 0, PID 0's parent is usually 0
        if 0 in tree and 0 in tree[0]:
            tree[0].remove(0)
        self._print_tree(min(tree), tree)

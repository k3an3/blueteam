import collections
import os
import re
import sys
from multiprocessing import Queue
from typing import List

import colorful

from blueteam.backends import Backend


class Host:
    def __init__(self, backend: Backend, cron: bool = True, debsums: bool = True, pkg: bool = True, kthreads: bool = True,
                 q: Queue = None):
        self.backend = backend
        self.sudo = []
        self.cron = []
        self.debsums = []
        self.users = []
        self.processes = {}
        self.dpkg = {}
        self.pid = os.getpid()
        self._tasks = [self.parse_sudo, self.get_login_users, self.get_processes]
        self.uidmap = {}
        if debsums:
            self._tasks.append(self.run_debsums)
        if cron:
            self._tasks.append(self.parse_cron)
        self.q = q
        self.pkg = pkg
        self.kthreads = kthreads

    def __str__(self):
        return self.backend.host

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
                self.sudo.append(str(colorful.yellow(line)))

    def parse_cron(self):
        for line in self.combine_files('/etc/cron{tab,.*/*}', '/var/spool/cron/crontabs/*'):
            self.cron.append(line)

    def run_debsums(self):
        for line in self.backend.run_command('debsums -ac').split('\n'):
            self.debsums.append("{} ({})".format(line, str(colorful.cyan(self.get_package_name(line).rstrip()))))

    def get_processes(self):
        for pid, proc in self.backend.get_processes():
            pkg = self.get_package_name(proc['exe']) if self.pkg else ''
            self.processes[pid] = {**proc, 'pkg': pkg,
                                   'verify': proc['exe'] not in self.debsums}

    @staticmethod
    def _is_kthread(p):
        return 2 in (p['pid'], p['ppid'])

    def _print_process(self, pid: int):
        p = self.processes.get(pid)
        color = colorful.red if not p['pkg'] and not self._is_kthread(p) else colorful.green
        if p and (self.kthreads or not self._is_kthread(p)):
            print("{:9}{:6}{:6} {:4} {:5}{:30} ".format((p['username'] or 'unk')[:8] + ('+' if len(p['username'] or 'unk') > 8 else ''),
                                                        p['pid'], p['ppid'],
                                                        str(colorful.yellow(int(len(p['connections'])))),
                                                        str(color('dpkg:' if self.pkg and not self._is_kthread(p) else '')),
                                                        p['pkg'] or ''), end='')
        else:
            print(pid, ">???")

    def _print_cmdline(self, p):
        cmdline = p['cmdline']
        if type(cmdline) == list:
            cmdline = ' '.join(p['cmdline'])
        print(cmdline[:50] if p['cmdline'] else p['name'],
              '...' if len(cmdline) > 50 else '',
              colorful.white(p['exe']) if p['exe'] else colorful.white_on_red('(missing)') if not self._is_kthread(
                  p) else '',
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
        parent = int(parent)
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

    def get_login_users(self):
        passwd = self.backend.read_file('/etc/passwd')
        shadow = self.backend.read_file('/etc/shadow')
        for i, line in enumerate(passwd):
            if line:
                if not line.startswith('root') and re.match(r'^[\w-]+:.:(0:\d+|\d+:0):.*$', line):
                    self.users.append(line)
                elif not shadow[i].split(":")[1] in ('*', '!', '!!'):
                    user = line.split(':')[0]
                    h = shadow[i].split(":")[1]
                    rest = ':'.join(line.split(":")[2:])
                    self.users.append("{}:{}:{}".format(user, h, rest))

    def get_package_name(self, path: str):
        if path:
            try:
                p = self.dpkg[path]
            except KeyError:
                p = self.backend.run_command('dpkg -S {}'.format(path))
                if p:
                    try:
                        p = p.split(":")[0]
                    except AttributeError:
                        p = p[0].split(":")[0]
                    self.dpkg[path] = p
                    return p

    def run_all(self):
        for task in self._tasks:
            print(colorful.white_on_black(str(self) + " running " + task.__name__))
            task()
        print(colorful.green_on_black(str(self) + " is done."))

    # Stolen from psutil
    def pstree(self):
        tree = collections.defaultdict(list)
        for pid, p in self.processes.items():
            try:
                tree[int(p['ppid'])].append(pid)
            except ValueError:
                pass
        # on systems supporting PID 0, PID 0's parent is usually 0
        if 0 in tree and 0 in tree[0]:
            tree[0].remove(0)
        self._print_tree(min(tree), tree)

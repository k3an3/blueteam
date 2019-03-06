import ast
import os
import socket
from abc import ABC, abstractmethod
from concurrent.futures import as_completed
from concurrent.futures.thread import ThreadPoolExecutor
from glob import glob
from os import cpu_count
from subprocess import run

import paramiko
import psutil
from braceexpand import braceexpand


class Backend(ABC):
    @abstractmethod
    def run_command(self, command: str):
        pass

    @abstractmethod
    def read_file(self, path: str):
        pass

    @abstractmethod
    def glob(self, glob: str):
        pass

    @abstractmethod
    def get_processes(self):
        pass

    @abstractmethod
    def get_connections(self):
        pass

    @abstractmethod
    def getpid(self):
        pass

    @abstractmethod
    def getuid(self):
        pass

    @abstractmethod
    def walk(self):
        pass

    @abstractmethod
    def real_path(self):
        pass


class SSHBackend(Backend):
    def __init__(self, host: str, port: int = 22, user: str = 'root', password: str = None,
                 keyfile: str = None, sudo: str = None):
        self.host = host
        self.sudo = sudo
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(host, port, user, password, key_filename=keyfile)

    def get_connections(self):
        pass

    def real_path(self, path: str):
        return self.remote_python('import os; print os.path.realpath("{}")'.format(path))[0]

    def get_processes(self):
        results = []
        with ThreadPoolExecutor(max_workers=cpu_count() + 1) as executor:
            for p in self.glob('/proc/*'):
                p = p.split('/')[-1]
                try:
                    p = int(p)
                except ValueError:
                    continue
                results.append(executor.submit(self._get_process, p))
        for res in as_completed(results):
            try:
                r = res.result()[1]
            except Exception as e:
                continue
            yield r['pid'], r

    def user_from_id(self, id: int):
        for line in self.run_command('getent passwd'):
            line = line.split(":")
            if int(line[2]) == int(id):
                return line[0]

    def getpid(self):
        return int(self.remote_python('import os; print os.getppid()')[0])

    def getuid(self):
        return int(self.remote_python('import os; print os.getuid()')[0])

    def remote_python(self, command: str):
        python_command = 'python -c "{}"'.format(command.replace('"', '\\"'))
        return self.run_command(python_command)

    def glob(self, path: str):
        result = []
        for p in braceexpand(path):
            result += self.remote_python('from glob import glob\nfor line in glob("{}"): print line'.format(p))
        return result

    def run_command(self, command: str):
        if self.sudo:
            command = "sudo -S -p '' " + command
        stdin, stdout, stderr = self.ssh.exec_command(command)
        if self.sudo and not isinstance(self.sudo, bool):
            stdin.write(self.sudo + "\n")
            stdin.flush()
        res = []
        for line in stdout.readlines():
            res.append(line.rstrip())
        return res

    def read_file(self, path: str):
        return self.remote_python('print open("{}").read()'.format(path))

    def walk(self, dir):
        return ast.literal_eval(self.remote_python('import os; print list(os.walk("{}"))'.format(dir))[0])

    def _get_process(self, p: int):
        try:
            stat = self.read_file('/proc/{}/stat'.format(p))[0]
        except IndexError:
            return
        try:
            exe = self.run_command('readlink /proc/{}/exe'.format(p))[0].rstrip()
        except IndexError:
            exe = ''
        name = stat.split('(')[1].split(')')[0]
        ppid = int(stat.split(')')[1].split()[1])
        cmdline = self.read_file('/proc/{}/cmdline'.format(p))[0].replace('\x00', ' ')
        data = {'pid': p, 'name': name, 'ppid': ppid,
                'exe': exe,
                'cmdline': cmdline,
                'connections': '',
                'username': self.user_from_id(
                    self.run_command('grep Uid /proc/{}/status'.format(p))[0].split()[1])}
        return p, data


class LocalBackend(Backend):
    def __init__(self):
        self.host = "localhost"
        self.sudo = False

    def getpid(self):
        return os.getpid()

    def getuid(self):
        return os.getuid()

    @staticmethod
    def get_processes():
        for proc in psutil.process_iter(attrs=['pid', 'ppid', 'name', 'exe',
                                               'cmdline', 'terminal', 'connections',
                                               'username', 'create_time']):
            yield proc.pid, proc.info

    def real_path(self, path: str):
        return os.path.realpath(path)

    # https://github.com/giampaolo/psutil/blob/master/scripts/netstat.py
    def get_connections(self):
        res = []
        AD = "-"
        AF_INET6 = getattr(socket, 'AF_INET6', object())
        proto_map = {
            (socket.AF_INET, socket.SOCK_STREAM): 'tcp',
            (AF_INET6, socket.SOCK_STREAM): 'tcp6',
            (socket.AF_INET, socket.SOCK_DGRAM): 'udp',
            (AF_INET6, socket.SOCK_DGRAM): 'udp6',
        }
        templ = "%-5s %-50s %-50s %-13s %-6s %s"
        proc_names = {}
        for p in psutil.process_iter(attrs=['pid', 'name']):
            proc_names[p.info['pid']] = p.info['name']
        for c in psutil.net_connections(kind='inet'):
            laddr = "%s:%s" % c.laddr
            raddr = ""
            if c.raddr:
                raddr = "%s:%s" % c.raddr
            res.append(templ % (
                proto_map[(c.family, c.type)],
                laddr,
                raddr or AD,
                c.status,
                c.pid or AD,
                proc_names.get(c.pid, '?')[:15],
            ))
        return res

    def read_file(self, path: str):
        result = []
        with open(path) as f:
            for line in f.readlines():
                result.append(line.rstrip())
        return result

    def glob(self, path: str):
        result = []
        for p in braceexpand(path):
            result += glob(p)
        return result

    def run_command(self, command: str):
        return run(command, shell=True, capture_output=True).stdout.decode().split('\n')

    def walk(self, dir):
        return os.walk(dir)

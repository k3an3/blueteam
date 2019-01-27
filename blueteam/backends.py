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


class SSHBackend(Backend):
    def __init__(self, host: str, port: int = 22, user: str = 'root', password: str = None,
                 keyfile: str = None):
        self.host = host
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(host, port, user, password, key_filename=keyfile)

    def get_processes(self):
        results = []
        with ThreadPoolExecutor(max_workers=cpu_count() + 1) as executor:
            for p in self.glob('/proc/'):
                p = p.split('/')[-1]
                try:
                    p = int(p)
                except ValueError:
                    continue
                results.append(executor.submit(_get_process, self.ssh, p))
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

    def remote_python(self, command: str):
        python_command = 'python -c "{}"'.format(command.replace('"', '\\"'))
        return self.run_command(python_command)

    def glob(self, glob: str):
        return self.run_command('ls {}'.format(glob))

    def run_command(self, command: str):
        _, stdout, _ = self.ssh.exec_command(command)
        res = []
        for line in stdout.readlines():
            res.append(line.rstrip())
        return res

    def read_file(self, path: str):
        return self.remote_python('print open("{}").read()'.format(path))


class LocalBackend(Backend):
    def get_processes(self):
        for proc in psutil.process_iter(attrs=['pid', 'ppid', 'name', 'exe',
                                               'cmdline', 'terminal', 'connections',
                                               'username', 'create_time']):
            yield proc.pid, proc.info

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


class NullSSHBackend(SSHBackend):
    def __init__(self, ssh):
        self.ssh = ssh


def _get_process(ssh, p: int):
    backend = NullSSHBackend(ssh)
    try:
        stat = backend.read_file('/proc/{}/stat'.format(p))[0]
    except IndexError:
        return
    try:
        exe = backend.run_command('readlink /proc/{}/exe'.format(p))[0].rstrip()
    except IndexError:
        exe = ''
    name = stat.split('(')[1].split(')')[0]
    ppid = int(stat.split(')')[1].split()[1])
    data = {'pid': p, 'name': name, 'ppid': ppid,
            'exe': exe,
            'cmdline': backend.read_file('/proc/{}/cmdline'.format(p))[0],
            'connections': '',
            'username': backend.user_from_id(
                backend.run_command('grep Uid /proc/{}/status'.format(p))[0].split()[1])}
    return p, data

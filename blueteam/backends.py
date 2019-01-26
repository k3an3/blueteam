from abc import ABC, abstractmethod
from glob import glob
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
        for p in self.glob('/proc/*'):
            try:
                p = int(p.rstrip())
            except ValueError:
                continue
            try:
                stat = self.read_file('/proc/{}/stat'.format(p))[0].split()
            except IndexError:
                continue
            try:
                exe = self.run_command('readlink /proc/{}/exe'.format(p))[0].rstrip()
            except IndexError:
                exe = ''
            data = {'pid': p, 'name': stat[1][1:-1], 'ppid': stat[3],
                    'exe': exe,
                    'cmdline': self.read_file('/proc/{}/cmdline'.format(p))[0].rstrip()[:-1],
                    'connections': '',
                    'username': self._user_from_id(
                        self.run_command('grep Uid /proc/{}/status'.format(p))[0].split()[1])}
            yield p, data

    def _user_from_id(self, id: int):
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
        return stdout.readlines()

    def read_file(self, path: str):
        return self.remote_python('print open("{}").read()'.format(path))


class LocalBackend(Backend):
    def get_processes(self):
        for proc in psutil.process_iter(attrs=['pid', 'ppid', 'name', 'exe',
                                               'cmdline', 'terminal', 'connections',
                                               'username', 'create_time']):
            yield proc.pid, proc.info

    def read_file(self, path: str):
        with open(path) as f:
            return f.readlines()

    def glob(self, path: str):
        result = []
        for p in braceexpand(path):
            result += glob(p)
        return result

    def run_command(self, command: str):
        return run(command, shell=True, capture_output=True).stdout.decode()

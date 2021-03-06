import argparse
import getpass
import os
import re
import subprocess
import sys
from multiprocessing import cpu_count, Pool

import colorful
import pkg_resources

from blueteam.backends import LocalBackend, SSHBackend
from blueteam.modules import Host


def get_version():
    try:
        return 'v' + pkg_resources.require("blueteam")[0].version
    except pkg_resources.DistributionNotFound:
        try:
            return 'v' + subprocess.run(['git', 'describe', '--tags', 'HEAD'],
                                        check_output=True).stdout.decode('UTF-8')
        except:
            return ''


def handle_run(host: str, args, sudo=None, key_pass=None):
    r = re.split(r'((\w+)@)?([.\w]+)(:(\d+))?', host)
    b = SSHBackend(host=r[3], user=r[2], port=r[5] or 22, keyfile=args.keyfile, sudo=sudo, passphrase=key_pass)
    h = Host(b, cron=not args.no_cron, debsums=not args.skip_debsums,
             pkg=not args.no_pkg, kthreads=not args.no_kthread,
             file_sentry=args.file_sentry)
    if args.ps:
        h.get_processes()
    else:
        h.run_all()
    del h.backend.ssh
    return h


def handle_results(host: Host):
    print(colorful.white_on_green("RESULTS FOR " + str(host)))
    if host.sudo:
        print(colorful.white_on_blue("SUDO FOR " + str(host)))
        for s in host.sudo:
            print(s)
    if host.cron:
        print(colorful.white_on_blue("CRON FOR " + str(host)))
        for c in host.cron:
            print(c)
    if host.debsums:
        print(colorful.white_on_blue("DEBSUMS FOR " + str(host)))
        for d in host.debsums:
            print(d)
    if host.users:
        print(colorful.white_on_blue("LOGIN USERS FOR " + str(host)))
        for user in host.users:
            print(colorful.red(user))
    if host.processes:
        print(colorful.white_on_blue("PSTREE FOR " + str(host)))
        host.pstree()
    if host.connections:
        print(colorful.white_on_blue("NETWORK FOR " + str(host)))
        templ = "%-5s %-50s %-50s %-13s %-6s %s"
        print(templ % (
            "Proto", "Local address", "Remote address", "Status", "PID",
            "Program name"))
        for line in sorted(host.connections):
            if '127.0.0.1' in line or '::1:' in line:
                line = colorful.green(line)
            elif '0.0.0.0' in line or ':::' in line:
                line = colorful.yellow(line)
            print(line)
    if host.files:
        print(colorful.white_on_blue("FILE SENTRY FOR " + str(host)))
        for f in sorted(host.files):
            print(f)


def cli():
    parser = argparse.ArgumentParser(description='Scan machine for threats.')
    parser.add_argument('-d', '--skip-debsums', action='store_true', help="Don't run debsums. "
                                                                          "Helpful if debsums not "
                                                                          "installed or takes "
                                                                          "too long.")
    parser.add_argument('-n', '--no-cron', action='store_true', help="Don't print cron.")
    parser.add_argument('-c', '--no-pkg', action='store_true', help="Don't match processes to "
                                                                    "packages. Quicker.")
    parser.add_argument('-k', '--no-kthread', action='store_true', help="Don't print kthreads in "
                                                                        "process list.")
    parser.add_argument('-p', '--ps', action='store_true', help='Only perform pstree.')
    parser.add_argument('-a', '--passphrase', action='store_true', help='Prompt for SSH key passphrase.')
    parser.add_argument('-s', '--sudo', action='store_true', help='Prompt for sudo password.')
    parser.add_argument('-w', '--workers', default=cpu_count() + 1, type=int, dest='processes',
                        help='Number of processes to use for SSH hosts.')
    parser.add_argument('hosts', metavar='[user@]host[:port]', nargs='*', help='SSH hosts to run on.')
    parser.add_argument('-i', '--identity', dest='keyfile', help='SSH identity file to use.')
    parser.add_argument('-f', '--file-sentry', action='store_true', help='Run the file sentry.')
    args = parser.parse_args()

    print(colorful.white_on_blue("blueteam " + get_version()))

    if args.hosts:
        hosts = []
        sudo_pass = None
        key_pass = None
        if args.passphrase:
            if not args.keyfile:
                print("Must specify a keyfile!")
                sys.exit(0)
            key_pass = getpass.getpass("Passphrase for SSH keyfile:")
        if args.sudo:
            sudo_pass = getpass.getpass("[sudo] password for remote host:")
        with Pool(processes=args.processes) as pool:
            for host in args.hosts:
                print(colorful.black_on_white("STARTING " + host))
                p = pool.apply_async(handle_run, args=(host, args, sudo_pass, key_pass))
                hosts.append(p)
            for r in hosts:
                r.wait()
                handle_results(r.get())
    else:
        if os.getuid():
            print(colorful.white_on_red("Must be run as root to do local. Exiting..."))
            sys.exit(0)
        b = LocalBackend()
        h = Host(b, cron=not args.no_cron, debsums=not args.skip_debsums,
                 pkg=not args.no_pkg, kthreads=not args.no_kthread,
                 file_sentry=args.file_sentry)
        if args.ps:
            h.get_processes()
            h.pstree()
        else:
            h.run_all()
            handle_results(h)
    print(colorful.white_on_green("Done."))


if __name__ == '__main__':
    cli()

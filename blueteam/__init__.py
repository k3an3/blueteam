import argparse
import os
import subprocess

import colorful
import pkg_resources
from blueteam.modules import Host

from blueteam.backends import LocalBackend


def get_version():
    try:
        return 'v' + pkg_resources.require("blueteam")[0].version
    except pkg_resources.DistributionNotFound:
        try:
            return 'v' + subprocess.run(['git', 'describe', '--tags', 'HEAD'],
                                        check_output=True).stdout.decode('UTF-8')
        except:
            return ''


def cli():
    parser = argparse.ArgumentParser(description='Scan machine for threats.')
    parser.add_argument('-d', '--skip-debsums', dest='skip_debsums', action='store_true', help="Don't run debsums. "
                                                                                               "Helpful if debsums not "
                                                                                               "installed or takes "
                                                                                               "too long.")
    parser.add_argument('-p', '--ps', dest='ps', action='store_true', help='Only perform pstree.')
    parser.add_argument('hosts', metavar='[user@]host[:port]', default=None, nargs='*', help='SSH hosts to run on.')
    args = parser.parse_args()

    if os.getuid():
        print(colorful.white_on_red("Must be run as root. Exiting..."))
        raise SystemExit
    print(colorful.white_on_blue("blueteam " + get_version()))

    if args.hosts:
        pass
    else:
        b = LocalBackend()
        h = Host(b, debsums=not args.skip_debsums)
        if args.ps:
            h.get_processes()
            h.pstree()
        else:
            h.run_all()
    print(colorful.green("Done."))


if __name__ == '__main__':
    cli()

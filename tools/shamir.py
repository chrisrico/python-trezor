#!/usr/bin/python
import os
import argparse
import re
import json

from binascii import hexlify, unhexlify
from bitcoin.deterministic import bip32_master_key
from mnemonic import Mnemonic
from secretsharing import SecretSharer
from subprocess import Popen, PIPE, STDOUT


def parse_args(commands):
    parser = argparse.ArgumentParser(description='Commandline tool for Trezor devices.')
    parser.add_argument('-l', '--language', default='english', choices=['english', 'japanese'])
    parser.add_argument('-j', '--json', action='store_true', help="Prints result as json object")

    cmdparser = parser.add_subparsers(title='Available commands')

    for cmd in commands._list_commands():
        func = object.__getattribute__(commands, cmd)

        try:
            arguments = func.arguments
        except AttributeError:
            arguments = ((('params',), {'nargs': '*'}),)

        item = cmdparser.add_parser(cmd, help=func.help)
        for arg in arguments:
            item.add_argument(*arg[0], **arg[1])

        item.set_defaults(func=func)
        item.set_defaults(cmd=cmd)

    return parser.parse_args()


class SSSS(object):
    SPLIT_EXECUTABLE = 'ssss-split'
    COMBINE_EXECUTABLE = 'ssss-combine'

    SPLIT_PATTERN = re.compile('\d+-[0-9a-fA-F]+')
    COMBINE_PATTERN = re.compile('Resulting secret: ([0-9a-fA-F]+)')

    @classmethod
    def execute(cls, cmd, data):
        """
        :rtype : str
        """
        p = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=STDOUT)
        stdout, stderr = p.communicate(data)
        if p.returncode:
            raise RuntimeError('%s exited with code %s' % (cmd[0], p.returncode))
        return stdout

    @classmethod
    def split_secret(cls, secret, threshold, shares, token=None):
        cmd = [cls.SPLIT_EXECUTABLE, '-t', str(threshold), '-n', str(shares), '-x']
        if token:
            cmd.extend(['-w', token])
        output = cls.execute(cmd, secret)
        shares = cls.SPLIT_PATTERN.findall(output)
        if not shares:
            raise RuntimeError(output)
        return shares

    @classmethod
    def recover_secret(cls, shares):
        cmd = [cls.COMBINE_EXECUTABLE, '-t', str(len(shares)), '-x']
        output = cls.execute(cmd, os.linesep.join(shares))
        match = cls.COMBINE_PATTERN.match(output)
        if not match:
            raise RuntimeError(output)
        return match.group(1)


class Commands(object):
    @classmethod
    def _list_commands(cls):
        return [x for x in dir(cls) if not x.startswith('_')]

    @staticmethod
    def _normalize(args):
        m = Mnemonic(args.language)
        mnemonic = ' '.join(args.mnemonic)
        if not m.check(mnemonic):
            raise Exception('Invalid mnemonic checksum')
        return mnemonic, m

    def split_mnemonic(self, args):
        mnemonic, _ = self._normalize(args)
        return SecretSharer.split_secret(hexlify(mnemonic), args.threshold, args.shares)

    split_mnemonic.help = 'Uses secret-sharing module to split mnemonic into shares'
    split_mnemonic.arguments = [
        (('-t', '--threshold'), {'type': int, 'required': True}),
        (('-n', '--shares'), {'type': int, 'required': True}),
        (('mnemonic',), {'nargs': '+'})
    ]

    def recover_mnemonic(self, args):
        return unhexlify(SecretSharer.recover_secret(args.shares[:args.threshold]))

    recover_mnemonic.help = 'Uses secret-sharing module to recover mnemonic from shares'
    recover_mnemonic.arguments = [
        (('-t', '--threshold'), {'type': int, 'required': True}),
        (('shares',), {'nargs': '+'})
    ]

    def split_seed(self, args):
        mnemonic, m = self._normalize(args)
        seed = hexlify(m.to_seed(mnemonic, args.passphrase))
        return SSSS.split_secret(seed, args.threshold, args.shares)

    split_seed.help = "Uses ssss binaries to split mnemonic's seed into shares"
    split_seed.arguments = split_mnemonic.arguments
    split_seed.arguments.append((('-p', '--passphrase'), {'default': ''}))

    def recover_seed(self, args):
        seed = SSSS.recover_secret(args.shares[:args.threshold])
        return bip32_master_key(unhexlify(seed))

    recover_seed.help = 'Uses ssss binaries to recover seed from shares'
    recover_seed.arguments = recover_mnemonic.arguments


def main():
    args = parse_args(Commands)

    res = args.func(Commands(), args)

    if args.json:
        print json.dumps(res, sort_keys=True, indent=4)
    else:
        print res


if __name__ == '__main__':
    main()

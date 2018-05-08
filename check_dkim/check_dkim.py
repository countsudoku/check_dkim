#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys

import dns.resolver
import dns.rdatatype

from . import Nagios_output
from . import RSAPubkey
from . import Domainkey, DKIMException


def main():
    """ Main entry point of the check_dkim commandline tool """
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--domain', action='store', required=True,
                        help='the domain to check')
    parser.add_argument('-s', '--selector', action='store', required=True,
                        help='the selector for the domainkey')
    parser.add_argument('-k', '--keyfile', action='store',
                        help='the private-key file, which has to match the pub key in DNS')
    args = parser.parse_args()

    try:
        nagios = Nagios_output('DKIM')

        try:
            domainkey = Domainkey.get_domainkey_from_dns(domain=args.domain, selector=args.selector)
        except dns.resolver.NXDOMAIN:
            return nagios.write(
                'critical',
                'can\'t find domainkey for selector {selector} and domain {domain}'.format(
                    selector=args.selector,
                    domain=args.domain,
                    ))
        except DKIMException as err:
            return nagios.write('critical', str(err))

        if args.keyfile is not None:
            try:
                with open(args.keyfile, 'rb') as keyfile:
                    private_key = keyfile.read()
                keyfile_public_key = RSAPubkey.extract_pubkey(private_key)
                dns_public_key = domainkey.key
                if dns_public_key == keyfile_public_key:
                    return nagios.write('ok', 'DKIM is there and private key match public key')
                else:
                    return nagios.write('critical', 'DKIM public key doesn\'t match private key')
            except FileNotFoundError:
                return nagios.write('critical', 'File {file} not readable'.format(file=args.keyfile))
        else:
            return nagios.write('ok', 'DKIM key is there')

    except Exception as err:
        name = err.__class__.__name__
        msg = str(err)
        return nagios.write( 'critical', '{type}: {msg}'.format(
            type=name,
            msg=msg,
            ))

if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import subprocess
from base64 import b64decode

import dns.resolver
import dns.rdatatype

from . import Nagios_out

DKIM_DNS_TAGS = {
    'v' : 'version',
    'g' : 'granularity',
    'h' : 'acceptable_hash_algorithm',
    'k' : 'key_type',
    'n' : 'notes',
    'p' : 'public_key',
    's' : 'service_type',
    't' : 'flags',
    }

DKIM_DNS_TAGS_DEFAULTS = {
    'version' : 'DKIM1',
    'granularity': '*',
    'key_type': 'rsa',
    'service_type' : '*',
    }

class DKIMException(Exception):
    pass


def parse_domainkey(s):
    domainkey_fields = [field.split('=', 1) for field in s.split('; ')]
    domainkey_data = { DKIM_DNS_TAGS[field[0]]: field[1] for field in domainkey_fields}
    if 'public_key' not in domainkey_data:
        raise DKIMException('no public key found in domainkey data')
    return dict(domainkey_data, **DKIM_DNS_TAGS_DEFAULTS)

def get_domainkey_from_dns(domain, selector):
    answer = dns.resolver.query(
        '{selector:s}._domainkey.{domain:s}'.format(
            selector=selector,
            domain=domain,
            ),
        dns.rdatatype.TXT)
    if len(answer) != 1:
        raise DKIMException(
            'more then one DKIM key found for selector {selector} and domain {domain}'.format(
                selector=selector,
                domain=domain,
            ))
    domainkey_string = answer[0].to_text().strip('\'"')

    return parse_domainkey(domainkey_string)

def get_pubkey(private_key_file):
    with open(private_key_file, 'rb') as f:
        priv_key = f.read()
    pubkey = subprocess.check_output(
        ['openssl', 'rsa', '-pubout', '-outform', 'der'],
        input=priv_key,
        stderr=subprocess.DEVNULL
        )
    return pubkey

def compare_pubkeys(dns_domainkey_data, keyfile):
    if dns_domainkey_data['key_type'].lower() != 'rsa':
        raise TypeError(
            'Currently only RSA keys are suported, but domainkey has key type {key_type}'.format(
                key_type=dns_domainkey_data['key_type'],
                ))
    pubkey_from_keyfile = get_pubkey(keyfile)
    pubkey_from_dns = b64decode(dns_domainkey_data['public_key'])
    return pubkey_from_keyfile == pubkey_from_dns


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--domain', action='store', required=True,
                        help='the domain to check')
    parser.add_argument('-s', '--selector', action='store', required=True,
                        help='the selector for the domainkey')
    parser.add_argument('-k', '--keyfile', action='store',
                        help='the private-key file, which has to match the pub key in DNS')
    args = parser.parse_args()

    try:
        nagios = Nagios_out('DKIM')

        try:
            domainkey_data = get_domainkey_from_dns(domain=args.domain, selector=args.selector)
        except dns.resolver.NXDOMAIN:
            nagios.write(
                'critical',
                'can\'t find domainkey for selector {selector} and domain {domain}'.format(
                    selector=args.selector,
                    domain=args.domain,
                    ))
        except DKIMException as err:
            nagios.write('critical', str(err))

        if args.keyfile is not None:
            try:
                if compare_pubkeys(domainkey_data, args.keyfile):
                    nagios.write('ok', 'DKIM is there and private key match public key')
                else:
                    nagios.write('critical', 'DKIM public key doesn\'t match private key')
            except FileNotFoundError:
                nagios.write('critical', 'File {file} not readable'.format(file=args.keyfile))
            except subprocess.CalledProcessError as err:
                nagios.write(
                    'critical', 'File {file} isn\'t a private key file'.format(file=args.keyfile))
        else:
            nagios.write('ok', 'DKIM key is there')

    except Exception as err:
        name = err.__class__.__name__
        msg = str(err)
        nagios.write( 'critical', '{type}: {msg}'.format(
            type=name,
            msg=msg,
            ))

if __name__ == "__main__":
    main()

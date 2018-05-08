#!/usr/bin/env python
# -*- coding: utf-8 -*-

import dns.resolver
import dns.rdatatype

from . import RSAPubkey

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


class Domainkey(object):
    """ a representation of a DKIM domainkey

    Args:
        key: The key data of the domainkey
        params (dict):
    """
    def __init__(self, key=None, params=None):
        self._params = None
        self.params = params

        self._key = None
        if  key is not None:
            self.key = key

    @property
    def key(self):
        """ the public key of the domain key """
        if self._key is None:
            raise ValueError('domainkey not initalized')
        return self._key

    @key.setter
    def key(self, pubkey):
        self._key = RSAPubkey(pubkey)

    @property
    def params(self):
        """ metadata of the domain key """
        return self._params

    @params.setter
    def params(self, p):
        if p is None:
            self._params = DKIM_DNS_TAGS_DEFAULTS
        else:
            for tag in p:
                if tag.lower() not in DKIM_DNS_TAGS.values():
                    raise ValueError("{tag} is not a valid domainkey tag!".format(tag=tag))
            params = dict(p, **DKIM_DNS_TAGS_DEFAULTS)

            if params['key_type'].lower() != 'rsa':
                raise TypeError(
                    'Currently only RSA keys are suported, but domainkey has key type {key_type}'.format(
                        key_type=params['key_type'],
                        ))
            self._params = params


    @classmethod
    def parse_domainkey(cls, s):
        """ parse the raw DNS domainkey and return a dict

        Args:
            s (str): the raw domainkey string

        Returns:
            dict: the parsed data
        """
        domainkey_fields = [field.split('=', 1) for field in s.split('; ')]
        domainkey_data = { DKIM_DNS_TAGS[field[0]]: field[1] for field in domainkey_fields}
        if 'public_key' not in domainkey_data:
            raise DKIMException('no public key found in domainkey data')

        params = {key:value
                  for key, value in domainkey_data.items()
                  if key != 'public_key'
                 }
        key = domainkey_data['public_key']
        return cls(key, params)

    @classmethod
    def get_domainkey_from_dns(cls, domain, selector):
        """ query the domainkey via DNS and return the data

        Args:
            domain (str): the domain of the key
            selector (str): the selector used for DKIM

        Returns:
            dict: data of the domainkey
        """
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
        return cls.parse_domainkey(domainkey_string)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from base64 import b64decode, b64encode
from Crypto.PublicKey import RSA

class RSAPubkey(object):
    """ represents a RSA public key

    Args:
        pubkey (str, bytes): the pubkey
    """
    def __init__(self, pubkey):
        self._pubkey = bytes()
        self.pubkey = pubkey

    def __str__(self):
        """ returns a base64 encoded pubkey string """
        return str(b64encode(self.pubkey))

    @property
    def pubkey(self):
        """ returns a byte object of the pubkey """
        return self._pubkey

    @pubkey.setter
    def pubkey(self, pubkey):
        if isinstance(pubkey, bytes):
            self._pubkey = pubkey
        elif isinstance(pubkey, str):
            self._pubkey = b64decode(pubkey)
        else:
            raise TypeError('only string and bytes are allowed as public key')

    def __eq__(self, other):
        return self.pubkey == other.pubkey

    @classmethod
    def extract_pubkey(cls, private_key):
        """ extract the public key from a private key

        Args:
            private_key (str): private key

        Returns:
            Pubkey: public key

        Raises:
            ValueError: When private_key isn't a private key
        """
        private_key = RSA.importKey(private_key)
        if not private_key.has_private():
            raise ValueError('Key is not a private key!')
        public_key = private_key.publickey()
        return cls(public_key.exportKey(format='DER'))

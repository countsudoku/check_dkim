#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .Severity import Severity
from .Nagios_out import Nagios_out
from .RSAPubkey import RSAPubkey

with open('version.txt', 'rb') as version_file:
    __version__ = version_file.read().strip().decode()

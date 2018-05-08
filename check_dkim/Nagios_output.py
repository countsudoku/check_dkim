#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from . import Severity

class Nagios_output(object):
    def __init__(self, name=''):
        self.name = name

    def write(self, severity, msg):
        s = Severity(severity)
        output = '{name} {severity} - {msg}'.format(
            name=self.name,
            severity=str(s).upper(),
            msg=msg,
            )
        print(output)
        sys.exit(int(s))

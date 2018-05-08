#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from . import Severity

class Nagios_output(object):
    def __init__(self, name='', writer=print):
        self.name = name
        self.writer = writer

    def write(self, severity, msg):
        s = Severity(severity)
        output = '{name} {severity} - {msg}'.format(
            name=self.name,
            severity=str(s).upper(),
            msg=msg,
            )
        self.writer(output)
        return int(s)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from . import Severity

class Nagios_output(object):
    """ writes a nagios compatible output

    Args:
        name (str): a general prefix for the output
        writer (function): a function to write the result string
    """
    def __init__(self, name='', writer=print):
        self.name = name
        self.writer = writer

    def write(self, severity, msg):
        """ writes the msg

        Args:
            severity (str, int): the severity of the output
            msg (str): the message to write

        Returns:
            int: the return code for nagios
        """
        s = Severity(severity)
        output = '{name} {severity} - {msg}'.format(
            name=self.name,
            severity=str(s).upper(),
            msg=msg,
            )
        self.writer(output)
        return int(s)

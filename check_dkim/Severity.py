#!/usr/bin/env python
# -*- coding: utf-8 -*-

from functools import total_ordering
from collections import OrderedDict

@total_ordering
class Severity(object):
    """ This class represents a nagios like Severity.

    Args:
        severity: :py:obj:`int`, :py:obj:`str`
            A string or integer which represents the wanted severity.
    """
    # Map of severities, ordered from good to very bad
    _severity_map = OrderedDict([
        ('ok', 0),
        ('warning', 1),
        ('critical', 2),
        ('unknown', 3),
    ])
    severities = tuple(_severity_map.keys())
    def __init__(self, severity):
        if isinstance(severity, str):
            try:
                self._severity_map[severity.lower()]
            except KeyError:
                raise KeyError('Unknown severity string: {s}'.format(s=severity))
            else:
                self._severity = severity
        elif isinstance(severity, int):
            try:
                idx = tuple(Severity._severity_map.values()).index(severity)
            except ValueError:
                idx = 3
            self._severity = Severity.severities[idx]

    def __str__(self):
        return self._severity

    def __int__(self):
        return self._severity_map[self._severity]

    def __lt__(self, other):
        self_idx = self.severities.index(self._severity)
        other_idx = self.severities.index(other._severity)
        return self_idx < other_idx

    def __eq__(self, other):
        return self._severity == other._severity

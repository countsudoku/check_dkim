#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

from check_dkim import __version__

setup(
    packages=find_packages(),
    name='check_dkim',
    version=__version__,
    author='Moritz C. K. U. Schneider',
    description='Nagios monitoring script to check DKIM DNS records.',
    install_requires=['dnspython'],
    url='https://github.com/countsudoku/check_dkim',
    entry_points={
        'console_scripts': [
            'check_dkim = check_dkim.check_dkim:main',
        ],
    },
)

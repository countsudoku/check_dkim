#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

from check_dkim import __version__

with open('requirements.txt', 'rb') as f:
    requirements = [ package.decode().strip('\n') for package in f.readlines() if package ]

setup(
    packages=find_packages(),
    name='check_dkim',
    version=__version__,
    author='Moritz C. K. U. Schneider',
    description='Nagios monitoring script to check DKIM DNS records.',
    install_requires=requirements,
    url='https://github.com/countsudoku/check_dkim',
    entry_points={
        'console_scripts': [
            'check_dkim = check_dkim.check_dkim:main',
        ],
    },
)

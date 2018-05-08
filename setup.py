#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ast
import os.path

from setuptools import setup, find_packages

def get_version(filepath, name):
    """ get version from another python file without importing it

    Args:
        filepath (str): the file with the version
        name (str): the variable name of the version string

    Returns:
        the version string
    """
    with open(filepath, 'rb') as f:
        version_code = next(
            line for line in f.readlines() if line.strip().startswith(name.encode()))
    return ast.parse(version_code).body[0].value.s

with open('requirements.txt', 'rb') as f:
    requirements = [ package.decode().strip('\n') for package in f.readlines() if package ]

__version__ = get_version(
    os.path.join(os.path.dirname(__file__), 'check_dkim/__init__.py'),
    '__version__'
    )

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

#!/usr/bin/python
# -*- coding: utf-8 -*-
from os import path

from setuptools import setup

this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.md'), 'r') as f:
    long_description = f.read()

setup(
    name='pypdns',
    version='1.4',
    author='Raphaël Vinot',
    author_email='raphael.vinot@circl.lu',
    maintainer='Raphaël Vinot',
    url='https://github.com/CIRCL/PyPDNS',
    project_urls={
        'Documentation': 'http://pymisp.readthedocs.io',
        'Source': 'https://github.com/MISP/PyMISP',
        'Tracker': 'https://github.com/MISP/PyMISP/issues',
    },
    description='Python API for PDNS.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    packages=['pypdns'],
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Telecommunications Industry',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
        'Topic :: Internet',
    ],
    install_requires=['requests-cache'],
)

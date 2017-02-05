#!/usr/bin/env python

from setuptools import setup

setup(
    name='get_trust_anchor',
    version='0.1',
    description='DNSSEC Trust Anchor Tools',
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3'
    ],
    url='https://github.com/iana-org/get_trust_anchor/',
    scripts=[
        'get_trust_anchor.py'
    ]
)

#!/usr/bin/env python

import os
from setuptools import find_packages, setup


with open(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='emcrypten',
    version='0.1.0',
    description='Multi-recipient encryption in Python',
    long_description=long_description,
    long_description_content_type='text/markdown',
    license='MIT',
    author='Santtu Pajukanta',
    author_email='santtu@pajukanta.fi',
    url='http://github.com/con2/emcrypten',
    packages = find_packages(exclude=["tests"]),
    zip_safe=True,
    entry_points={
        'console_scripts': [
            'emcrypten = emcrypten.__main__:main',
        ]
    },
    install_requires=["cryptography"],
    tests_require=["pytest"],
    setup_requires=["pytest-runner"],
)

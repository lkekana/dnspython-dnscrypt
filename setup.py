# /usr/bin/env python3
#
# Copyright (C) 2017 Brian Hartvigsen
# Copyright (C) 2025 Lesedi Kekana
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
# OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

from distutils.core import setup

version = '2.1.0'

setup(name='dnscrypt',
    version=version,
    maintainer='Brian Hartvigsen and Lesedi Kekana',
    maintainer_email='bhartvigsen@opendns.com / lesedikekana84@gmail.com',
    description='dnspython compatible DNSCrypt Resolver',
    url="https://github.com/lkekana/dnspython-dnscrypt",
    long_description=open('README.rst').read(),
    license='ISC',
    packages=['dnscrypt'],
    install_requires=[
        'dnspython >= 2.7.0',
        'PyNaCl >= 1.5.0',
        'cffi == 1.17.1',
        'pycparser == 2.22',
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9"
    ])

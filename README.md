# Emcrypten – Multi-recipient encryption in Python

## DO NOT USE THIS LIBRARY!

Cryptography should be left to cryptography professionals. Until this library has been properly audited by such professionals, it should be deemed unfit for any use.

Particularly we use the `asymmetric` encryption primitives of `cryptography.hazmat`.

## Purpose

Consider a system that has users called Alice, Bob and Carol. Alice wants to save `confidential_data: bytes` so that it can later be opened by themself and Bob only, but not Carol, let alone Malice.

Let Alice and Bob have private keys encrypted with their login passwords. Now Alice constructs a `KeySet` containing the public keys of themself and Bob, and then does `key_set.encrypt(confidential_data)`.

What is returned is an `EncryptedValue`, containing `confidential_data` encrypted using a symmetrical encryption key that is in turn encrypted using asymmetrical encryption with both Alice's and Bob's keys.

For a complete example, see `tests/test_keyset.py`.

## Getting started

    pip install -e .

    pip install pytest
    pytest

## License

    The MIT License (MIT)

    Copyright © 2020 Santtu Pajukanta

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.

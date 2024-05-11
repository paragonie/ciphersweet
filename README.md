# CipherSweet

[![Build Status](https://github.com/paragonie/ciphersweet/actions/workflows/ci.yml/badge.svg)](https://github.com/paragonie/ciphersweet/actions)
[![Static Analysis](https://github.com/paragonie/ciphersweet/actions/workflows/psalm.yml/badge.svg)](https://github.com/paragonie/ciphersweet/actions)
[![Latest Stable Version](https://poser.pugx.org/paragonie/ciphersweet/v/stable)](https://packagist.org/packages/paragonie/ciphersweet)
[![Latest Unstable Version](https://poser.pugx.org/paragonie/ciphersweet/v/unstable)](https://packagist.org/packages/paragonie/ciphersweet)
[![License](https://poser.pugx.org/paragonie/ciphersweet/license)](https://packagist.org/packages/paragonie/ciphersweet)
[![Downloads](https://img.shields.io/packagist/dt/paragonie/ciphersweet.svg)](https://packagist.org/packages/paragonie/ciphersweet)

**CipherSweet** is a backend library developed by [Paragon Initiative Enterprises](https://paragonie.com)
for implementing [searchable field-level encryption](https://paragonie.com/blog/2017/05/building-searchable-encrypted-databases-with-php-and-sql).

**Requires PHP 8.1 or newer**.

If you want to use CipherSweet on an older version of PHP (5.5+), use 
[CipherSweet v3](https://github.com/paragonie/ciphersweet/tree/v3.x).

Before adding searchable encryption support to your project, make sure you understand
the [appropriate threat model](https://adamcaudill.com/2016/07/20/threat-modeling-for-applications/)
for your use case. At a minimum, you will want your application and database
server to be running on separate cloud instances / virtual machines.
(Even better: Separate bare-metal hardware.)

CipherSweet is available under the very permissive [ISC License](https://github.com/paragonie/ciphersweet/blob/master/LICENSE)
which allows you to use CipherSweet in any of your PHP projects, commercial
or noncommercial, open source or proprietary, at no cost to you.

## CipherSweet Features at a Glance

* Encryption that targets the 256-bit security level
  (using [AEAD](https://tonyarcieri.com/all-the-crypto-code-youve-ever-written-is-probably-broken) modes
  with extended nonces to minimize users' rekeying burden).
* **Compliance-Specific Protocol Support.** Multiple backends to satisfy a
  diverse range of compliance requirements. More can be added as needed:
  * `BoringCrypto` uses [libsodium](https://download.libsodium.org/doc/), the de
    facto standard encryption library for software developers.
    [Algorithm details](https://ciphersweet.paragonie.com/security#moderncrypto).
  * `FIPSCrypto` only uses the cryptographic algorithms covered by the
    FIPS 140-3 recommendations to avoid auditing complexity.
    [Algorithm details](https://ciphersweet.paragonie.com/security#fipscrypto).
* **Key separation.** Each column is encrypted with a different key, all of which are derived from
  your master encryption key using secure key-splitting algorithms.
* **Key management integration.** CipherSweet supports integration with Key
  Management solutions for storing and retrieving the master encryption key.
* **Searchable Encryption.** CipherSweet uses
  [blind indexing](https://paragonie.com/blog/2017/05/building-searchable-encrypted-databases-with-php-and-sql#solution-literal-search)
  with the fuzzier and Bloom filter strategies to allow fast ciphertext search
  with [minimal data leakage](https://ciphersweet.paragonie.com/php/blind-index-planning). 
  * Each blind index on each column uses a distinct key from your encryption key
    and each other blind index key.
  * This doesn't allow for `LIKE` operators or regular expression searching, but
    it does allow you to index transformations (e.g. substrings) of the plaintext,
    hashed under a distinct key.
* **Adaptability.** CipherSweet has a database- and product-agnostic design, so
  it should be easy to write an adapter to use CipherSweet in any PHP-based
  software.
* **File/stream encryption.** CipherSweet has an API for encrypting files (or
  other PHP streams) that provides authenticated encryption that defeats TOCTOU
  attacks with minimal overhead. [Learn more](https://ciphersweet.paragonie.com/internals/file-encryption).

## Installing CipherSweet

Use Composer.

```bash
composer require paragonie/ciphersweet:^4
```

If you're intending to use CipherSweet on an older version of PHP, use the v3 branch:

```bash
composer require paragonie/ciphersweet:^3
```

## Using CipherSweet

Please refer to **[the documentation](https://ciphersweet.paragonie.com)**
to learn how to use CipherSweet.

Security experts may be interested in [the security properties of our design](https://ciphersweet.paragonie.com/security).

### Integration Support

Please feel free to [create an issue](https://github.com/paragonie/ciphersweet/issues/new)
if you'd like to integrate CipherSweet with your software.

## CipherSweet in Other Languages

* [JavaScript (Node.js)](https://github.com/paragonie/ciphersweet-js)

## Why "CipherSweet"?

CipherSweet was originally intended for use in [SuiteCRM](https://github.com/salesagility/SuiteCRM)
(a fork of the SugarCRM Community Edition) and related products, although
there is nothing preventing its use in other products.

Therefore, we opted for a pun on "ciphersuite" that pays homage to the
open source heritage of the project we designed this library for.

If the wordplay is too heavy, feel free to just call it "Sweet", or juxtapose
the two component nouns and call it "SweetCipher" in spoken conversation.

## Support Contracts

If your company uses this library in their products or services, you may be
interested in [purchasing a support contract from Paragon Initiative Enterprises](https://paragonie.com/enterprise).

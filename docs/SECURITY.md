# Security Properties and Thread Model for CipherSweet

## Table of Contents

* [Table of Contents](#table-of-contents)
* [Threat Model](#threat-model)
  * [Attacker Capabilities](#attacker-capabilities)
* [Security Properties of CipherSweet](#security-properties-of-ciphersweet)
  * [Encryption](#encryption)
  * [Blind Indexes](#blind-indexes)
  * [Cryptographic Secrets](#cryptographic-secrets)
* [Design Rationale](#design-rationale)
* [Informal Security Analysis](#informal-security-analysis)
  * [FIPSCrypto](#fipscrypto)
    * [FIPSCrypto Encryption](#fipscrypto-encryption)
    * [FIPSCrypto Fast Blind Indexes](#fipscrypto-fast-blind-indexes)
    * [FIPSCrypto Slow Blind Indexes](#fipscrypto-slow-blind-indexes)
  * [ModernCrypto](#moderncrypto)
    * [ModernCrypto Encryption](#moderncrypto-encryption)
    * [ModernCrypto Fast Blind Indexes](#moderncrypto-fast-blind-indexes)
    * [ModernCrypto Slow Blind Indexes](#moderncrypto-slow-blind-indexes)
  * [CipherSweet](#ciphersweet)
    * [Blind Index Information Leaks](#blind-index-information-leaks)

## Threat Model

The core assumption of CipherSweet's security is that the attacker only sees:

* Ciphertexts
* Blind indexes

This implies that the database server is on one piece of physical hardware, and
the application that access the database is on a separate piece of physical
hardware, and the keys never get transmitted to the database server.
 
Anyone who violates this assumption is playing fast-and-loose with side-channels
and RDBMS exploits that allow local file disclosure. Keep your keys secret;
don't trust the RDBMS.

### Attacker Capabilities

The weakest attackers are assumed to have read-only access to the SQL database
in question (i.e. via SQL injection of an existing SELECT query, but not through
arbitrary queries).

Some attackers **MAY** have read-write access to the database. 

Some attackers **MAY** use the application legitimately (i.e. as a normal user)
and encrypt chosen plaintexts to attempt to attack both the encryption and the
blind indexes.

## Security Properties of CipherSweet

### Encryption

CipherSweet exclusively uses extended-nonce AEAD modes for symmetric-key
encryption. Nonces are sourced from the kernel's CSPRNG (e.g. `/dev/urandom`).

### Blind Indexes

A blind index is:

* A deterministic one-way hash of the plaintext
* Truncated to a specified number of bits
* Treated as a Bloom filter for database lookups

A blind index can be:

* Be the output of a key derivation function rather than a hash-based message
  authentication function (i.e. PBKDF2-SHA384 instead of HMAC-SHA384)
* Functional indexes (by applying domain-specific transformations to the 
  plaintext before it encounters the final hash/KDF function)

A blind index doesn't necessarily need to be calculated over the entire message.
You can have as many blind indexes as you want on a given field.

### Cryptographic Secrets

Cryptography secrets (i.e. encryption keys) are [derived](internals/01-key-heirarchy.svg)
from the master cryptography key. No two fields will (with overwhelming
probability) share the same encryption key, provided [some assumptions hold true](#informal-security-analysis).
No two blind index fields will either.

## Design Rationale

We designed CipherSweet with the following criteria in mind:

1. [Indistinguishability](indistinguishability.png) (image from
   [this talk](https://youtu.be/LhSB98nZllk?t=545) by Tony Arcieri's talk
   which covers different topics in encrypted database implementations).
2. Resistant to chosen-ciphertext attacks.
3. Built using only the tools available to software developers today.
4. Performance.

This may sound like a rehash of the CIA triad. After all:

* Indistinguishability is important for **confidentiality**.
* Chosen-ciphertext attack resistance implies **integrity**.
* Performance and tooling are two different kinds of **availability** concerns.

However, there are subtle consequences to this set of requirements.

First, it means that we can't use **deterministic encryption** (e.g. AES-SIV
with the nonce set to the SHA256 hash of the plaintext), since it is not, by
definition, indistinguishable when the same plaintext is encrypted twice.

Additionally, we can't use any of the academic designs (Order-Preserving
Encryption, Lattices) since they aren't available in the cryptography
libraries that most developers already have installed today.

Furthermore, even if the academic designs landed in OpenSSL and/or libsodium
today, the only encrypted database designs that meet our distinguishability
requirements are roughly a million times too slow. We need performance.

Our approach can be abbreviated as:

1. Use non-deterministic, extended-nonce AEAD ciphers for encryption.
2. Use truncated, keyed hash functions (or KDFs) of the plaintext to create
   deterministic outputs that can be used in SELECT queries.

You can accomplish indistinguishability (even against chosen-ciphertext
attacks) with an AEAD cipher as described above, using high-performance
symmetric-key cryptography. We aso chose very fast hash and secure hash
functions in our designs. 

Finally, every cryptography primitive we used is available in OpenSSL or
libsodium, or is a standard construction of widely-available primitives.

Our design does **not** aim to provide full-text searching or allow the
database to order ciphertexts.

## Informal Security Analysis

Given the security of CipherSweet depends largely on the security of the
backend being used, we must first establish the security properties of each
backend before we can describe the security properties of CipherSweet itself.

### FIPSCrypto

1. The operating system's CSPRNG (hence, kCSPRNG)
2. [SHA384](https://tools.ietf.org/html/rfc6234)
3. [HMAC](https://tools.ietf.org/html/rfc2104) with a secure hash function
4. [HKDF](https://tools.ietf.org/html/rfc5869)
5. [AES](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf) in
   [counter mode](https://csrc.nist.gov/publications/detail/sp/800-38a/final)
   with 256-bit keys (AES-CTR-256), followed by HMAC-SHA384
   ([Encrypt-then-MAC](https://moxie.org/blog/the-cryptographic-doom-principle/)).
   Decryption requires validating the MAC first, which is done in constant-time. 
6. [PBKDF2](https://tools.ietf.org/html/rfc2898) with SHA384 (optional, for slow blind indexes)

If we assume that HKDF is a secure key-splitting function [as used](internals/01-key-heirarchy.svg)
in CipherSweet (i.e. with HMAC-SHA384, and domain separation constants),
then our key hierarchy is also secure. Furthermore, related-key
attacks can be obviated from the threat model.

#### FIPSCrypto Encryption

The best real-world attacks against AES-256-CTR require a nonce to be reused
condition, which allows attackers to recover plaintext messages.
 
> AES nonces are always 16 bytes long (due to its 128-bit block size), but we can
create an extended nonce construction by using an additional 256-bit random
HKDF salt (generated from the kCSPRNG) to derive a subkey for each message.
This is exactly what CipherSweet's FIPSCrypto provider does. 
>
> Thus, even if a nonce collision occurs, it will happen under a different AES
key. You will have to encrypt 2^128 messages in order to have a 50% chance of a
single HKDF salt collision, in addition to the 2^64 messages needed for a 50%
chance of a random nonce collision.
>
> At this threshold, due to the pigeonhole principle, we would expect a 16 byte
block of the keystream to repeat long before a nonce/key pair repeats.

By using an Encrypt-then-HMAC construction and verifying MACs in constant-time
(as per [the encryption documentation](internals/03-encryption.md)), we side-step
chosen-ciphertext attacks (assuming HMAC-SHA384 remains secure).

Additionally, the AES and HMAC keys are derived from a single key through
HKDF-SHA384. You cannot provide independent keys for each step in the process.

#### FIPSCrypto Fast Blind Indexes

Each blind index has a distinct key, provided by HKDF-HMAC-SHA256.

Fast blind indexes calculate a hash using HMAC-SHA384, then truncates the
output to a desired number of bits (zero-padding the remaining bits in the
last byte).

As long as SHA384 is a secure hash function and HMAC constructions are also
secure, then the security of HMAC-SHA384 follows.

The security of fast blind indexes can be inferred from the security of
HMAC-SHA384.

#### FIPSCrypto Slow Blind Indexes

Each slow blind index has a distinct key, provided by HKDF-HMAC-SHA256.

Slow blind indexes calculate a hash using PBKDF2-SHA384, then truncates the
output to a desired number of bits (zero-padding the remaining bits in the
last byte).

The purpose of a slow blind index is to make attacks more expensive (e.g.
for slightly smaller keyspaces). We use PBKDF2-SHA384 for slow indexes.

Because PBKDF2 uses HMAC iteratively, the worst case security of a slow
blind index is to be as secure as a fast blind index.

### ModernCrypto

1. The operating system's CSPRNG (hence, kCSPRNG)
2. [BLAKE2b](https://tools.ietf.org/html/rfc7693)
3. [HMAC](https://tools.ietf.org/html/rfc2104) with a secure hash function
4. [HKDF](https://tools.ietf.org/html/rfc5869)
5. [XChaCha20-Poly1305](https://datatracker.ietf.org/doc/draft-arciszewski-xchacha/),
   which is derived from [XSalsa](https://cr.yp.to/snuffle/xsalsa-20081128.pdf) and
   [ChaCha20-Poly1305](https://tools.ietf.org/html/rfc7539) 
6. [Argon2id](https://github.com/P-H-C/phc-winner-argon2)
   (optional, for slow blind indexes)

If we assume that HKDF is a secure key-splitting function [as used](internals/01-key-heirarchy.svg)
in CipherSweet (i.e. with BLAKE2b, and domain separation constants),
then our key hierarchy is also secure. Furthermore, related-key
attacks can be obviated from the threat model.

#### ModernCrypto Encryption

The best real-world attacks against XChaCha20-Poly1305 require a nonce-reuse
condition. However, given its 24 byte nonce (generated from the kCSPRNG), you
have to encrypt 2^96 messages in order to have a 50% chance of a single nonce
collision.

#### ModernCrypto Fast Blind Indexes

Each blind index has a distinct key, provided by HKDF-HMAC-SHA256.

Fast blind indexes calculate a hash using keyed BLAKE2b, then truncates
the output to a desired number of bits (zero-padding the remaining bits in
the last byte).

The security of fast blind indexes can be inferred from the security of
keyed BLAKE2b hashes.

#### ModernCrypto Slow Blind Indexes

Each slow blind index has a distinct key, provided by HKDF-HMAC-SHA256.

Slow blind indexes calculate a hash using Argon2id, where the blind index
key is the Argon2 salt, then truncates the output to a desired number of bits
(zero-padding the remaining bits in the last byte).

The security of fast blind indexes can be inferred from the security of
Argon2id as a key derivation function.  

### CipherSweet

It should be clear that, with either backend, the same rough security
properties hold true:

* You can encrypt more than 2^64 messages safely without worring about a
  nontrivial chance of nonce reuse.
* Each blind index has a distinct key, from which other keys cannot be derived
  by an attacker who can guess one. The cost of such an attack is significantly
  larger than 2^100.
* Fast blind index outputs are calculated from secure cryptographic hash
  functions with a preimage resistance, which has an attack cost that exceeds
  2^100.
* Slow blind index outputs are calculated from secure KDFs, which has an attack
  cost that exceeds 2^100.

The encryption protocols are straightforward and merit no further discussion.
Of interest to analysts here is the overall construction of blind indexes and
information leakage.

#### Blind Index Information Leaks

Encrypted fields have a one-to-many relationship with blind indexes. Blind
index inputs are *derived* from the plaintext, through user-defined transforms.
After being processed by the final cryptographic algorithm, the output is
truncated. This achieves two desirable properties:

1. It reduces the overall storage requirements for the outputs of a given blind
   index. 
2. The hash outputs become a Bloom filter, rather than fingerprints of the
   plaintext.

Bloom filters allows false positives (i.e. by partial hash collisions on the
non-truncated part of the hash), but not false negatives. Thus, these prefix
collisions cease to be collisions that reveal duplicate plaintexts. 
Instead, we call them **coincidences**.

Coincidences can still be dangerous. If you have a large number (e.g. 100)
distinct blind indexes on a single encrypted field, and two rows have an
identical set of blind index outputs, you can infer that their plaintexts
are identical.

So long as the probability of false positives is sufficient, attackers cannot
use blind index coincidences to prove that two ciphertexts were the result of
duplicate plaintext inputs.

Generally, users should minimize the number and output length of each blind
index. The more indexes you create, the more confidence an attacker gains.
Larger indexes are also more useful than shorter indexes.

The exact formula to determine safer upper bounds for the amount of information
that one can safely leak without conclusively revealing duplicate plaintexts
(i.e. allowing the attacker to rule out false positives) can be derived as
follows:

* Let **L_i** be the number of bits in the blind index output
* Let **K_i** be the keyspace of the input domain (in bits)
* Let **R** be the number of encrypted records that use this blind index
* The probability of a coincidence for a given blind index is
  `2^-(min(L_i, K_i))`
* The number of coincidences (**C**) you can expect for each plaintext can be 
  obtained through simple multiplication. A summation of the exponent is
  quicker to calculate, and yields an equivalent result.

Thus:

    C = R / 2^-(sum(min(L_i, K_i))) 

...or, alternatively:

```php
<?php
/**
 * @param array $indexes
 * @param int $R
 * @return float
 */
function coincidenceCount(array $indexes, $R)
{
    $exponent = 0;
    $count = count($indexes);
    for ($i = 0; $i < $count; ++$i) {
        $exponent += min($indexes[$i]['L'] ,$indexes[$i]['K']);
    }
    return (float) max(1, $R) / pow(2, $exponent);
}

/* Usage example: */
$indexes = [
    ['L' => 16, 'K' => 24],
    ['L' => 8, 'K' => PHP_INT_MAX]
];
var_dump(coincidenceCount($indexes, 1 << 31)); // float(128)
var_dump(coincidenceCount($indexes, 1 << 24)); // float(1)
var_dump(coincidenceCount($indexes, 1 << 16)); // float(0.00390625)
```

Our recommendation is to ensure that you always have a **C** value of 2 or
higher for your expected value of **R**. This means reducing the values of
**L** appropriately.

On the other side, if **C** is larger than the square root of **R**, then
there is no marginal benefit of using blind indexes at all.

In short, one should always aim for `2 <= C < sqrt(R)`, for any given value
of R.

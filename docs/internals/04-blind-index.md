# Blind Indexing

A blind index is calculated by using hash functions and/or
key-stretching algorithms of the plaintext, using [an appropriate key](01-key-hierarchy.md).

Blind indexes come in two modes (slow, fast). Both variants accept a
parameter called the "bit length", which affects the truncation length
of the resulting cryptographic output. Additionally, if truncated to a
bit length that is not an even multiple of 8, it will clear the least
significant bits in the trailing byte.

## FIPSCrypto

* Fast: PBKDF2-SHA384 with 1 iteration
  * Accepts three arguments:
    1. The plaintext
    2. The key for this blind index
    3. The bit length
* Slow: PBKDF2-SHA384 with a tunable number of iterations (default:
  50,000).
  * Accepts four arguments:
    1. The plaintext
    2. The key for this blind index
    3. The bit length
    4. An array of configuration options that can override the number of
       iterations for this particular index.

## ModernCrypto

* Fast: BLAKE2b
  * Accepts three arguments:
    1. The plaintext
    2. The key for this blind index
    3. The bit length
* Slow: Argon2id (memlimit = 32MB, opslimit = 4)
  * Accepts four arguments:
    1. The plaintext
    2. The key for this blind index
    3. The bit length
    4. An array of configuration options that can override the Argon2id
       paramters for this particular index.

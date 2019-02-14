# File Encryption

Since version 1.9.0, CipherSweet has provided an `EncryptedFile` API that provides
authenticated encryption, password-based encryption, and resistance against race
condition attacks.

## Algorithm Overview

### Authenticated Encryption

Relevant API methods:

* `EncryptedFile::decryptFile()`
* `EncryptedFile::decryptStream()`
* `EncryptedFile::encryptFile()`
* `EncryptedFile::encryptStream()`

The file encryption key is derived in the same ways as the field encryption
key in `EncryptedField`, with two constants for the table name
(`special__file__encryption`) and column name (`special__file__ciphersweet`).

The file format and cryptography protocols depend on the backend being used.

### Password-Based Authenticated Encryption

Relevant API methods:

* `EncryptedFile::decryptFileWithPassword()`
* `EncryptedFile::decryptStreamWithPassword()`
* `EncryptedFile::encryptFileWithPassword()`
* `EncryptedFile::encryptStreamWithPassword()`

The `WithPassword` API methods do **NOT** rely on the `KeyProvider`. Instead,
they derive a per-file encryption key based on the password and a randomly
generated 16-byte salt.

For FIPSCrypto, the key is derived using PBKDF2-SHA384 with 100,000 iterations.

For ModernCrypto, the key is derived using Argon2id with the `_INTERACTIVE`
libsodium constants.

## Encrypted File Format

### FIPSCrypto

Encrypting a file with the `FIPSCrypto` backend introduces a 117 byte overhead
on top of the original file size.

* Header (`fips:`): `[0-4]` (5 bytes)
* HMAC-SHA384 tag: `[5-52]` (48 bytes)
* PBKDF2 salt (NUL bytes if not password-encrypted): `[53-68]` (16 bytes)
* HKDF-SHA384 salt: `[69-100]` (32 bytes)
* AES-CTR nonce: `[101-116]` (16 bytes)
* Ciphertext: `[117-EOF]` (Remainder of file)

The HMAC-SHA384 tag covers the header, PBKDF2 salt, HKDF-SHA384 salt, AES-CTR
nonce, and the ciphertext.

### ModernCrypto

Encrypting a file with the `ModernCrypto` backend introduces a 61 byte overhead
on top of the original file size.

* Header (`nacl:`): `[0-4]` (5 bytes)
* Poly1305 tag: `[5-20]` (16 bytes)
* Argon2 salt (NUL bytes if not password-encrypted): `[21-36]` (16 bytes)
* XChaCha20 nonce: `[37-60]` (24 bytes)
* Ciphertext: `[61-EOF]` (Remainder of file)

The Poly1305 tag covers the header, Argon2 salt, XChaCha20 nonce, and the
ciphertext.

## Race Conditions
 
### Race Condition Threat

Let's say you're storing your encrypted files in a folder controlled by a
cloud storage provider (e.g. Dropbox).

If Dropbox suddenly became malicious and wanted to attack the integrity of
your files, they could attack a naively-implemented decryption routine like
so:

1. Wait until you've verified the authentication tag of the entire file.
2. Replace the ciphertext with data of their own choosing.

This is called a race condition: You're racing against a security control,
and if you win, you can bypass it. (Normally this requires microsecond
precision to pull off effectively.)

### Race Condition Mitigation

When decrypting a file in memory, `EncryptedFile` will first verify the
authentication tag of the file's contents before it even attempts to
decrypt the file. (In adherence with the cryptographic doom principle.)

On its first pass of the ciphertext, for each "chunk" (parametrized in the
`EncryptedFile` constructor, default: 8192 bytes), a truncated HMAC of the
previous chunks and the current chunk will be stored in memory.

After verifying the entire file's authentication tag, `EncryptedFile` will
begin to process each chunk of ciphertext in the following way:

1. Read a chunk from the encrypted file.
2. Verify the truncated HMAC of the current chunk is still valid. Throw an
   exception if anything goes wrong.
3. Decrypt the chunk.
4. Write plaintext to the output stream.
5. If you run out of ciphertext and there are still chunks in memory, throw
   an exception (mitigate truncation attacks).

This effectively mitigates the race condition vulnerability without ballooning
the file size. Instead, there is a slight memory cost during decryption).
 
Additionally, it allows each computer to decide on its own memory cost by
selecting a different chunk size without affecting the authentication tags
or file size. 

## Prior Art - Security Design

CipherSweet's `EncryptedFile` API is not the first file encryption utility to
solve the same threat model. See also:

* [Defuse Security's PHP Encryption Library](https://github.com/defuse/php-encryption)
* [Paragon Initiative Enterprises' Halite library](https://github.com/paragonie/halite)

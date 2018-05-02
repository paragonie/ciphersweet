# Key Hierarchy in CipherSweet

CipherSweet uses a series of key expansion/splitting techniques to turn
a single key (which is handled by the `KeyProvider` object and may be
sourced from third-party key management services) into:

* One distinct encryption key for each encrypted field on each table.
* Many distinct keys for calculating blind indexes, one for each index
  on each encrypted field on each table.

At a super high-level, the picture looks like this:

![Key Hierarchy](https://cdn.rawgit.com/paragonie/ciphersweet/internals/docs/internals/01-key-heirarchy.svg)

Where:

* C1 is the byte `0xB4` repeated 32 times.
* C2 is the byte `0x7E` repeated 32 times.

The constants C1 and C2 were chosen to have a Hamming distance of 4
between them, and are used to achieve domain separation for secure
key splitting.

The `Field Enc. Key` in the above diagram is the **Field Encryption Key**,
which allows data to be securely encrypted or decrypted in the database.

The `Index Root Key` in the above diagram is the root key for each
blind index on the field. Each index's corresponding key is calculated
by taking the HMAC-SHA256 of the packed table name, field name,
and index name as the message, and the `Index Root Key` as the HMAC key.

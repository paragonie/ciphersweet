# Key Hierarchy in CipherSweet

CipherSweet uses a series of key expansion/splitting techniques to turn
a single key (which is handled by the `KeyProvider` object and may be
sourced from third-party key management services) into:

* One distinct encryption key for each encrypted field on each table.
* Many distinct keys for calculating blind indexes, one for each index
  on each encrypted field on each table.

At a super high-level, the picture looks like this:

![Key Hierarchy](https://cdn.rawgit.com/paragonie/ciphersweet/master/docs/internals/01-key-heirarchy.svg)

Where:

* C1 is the byte `0xB4` repeated 32 times.
* C2 is the byte `0x7E` repeated 32 times.

The constants C1 and C2 were chosen to have a Hamming distance of 32*4 = 128b
between them, and are used to achieve domain separation for secure
key splitting.

The `Field Enc. Key` in the above diagram is the **Field Encryption Key**,
which allows data to be securely encrypted or decrypted in the database.

The `Index Root Key` in the above diagram is the root key for each
blind index on the field. Each index's corresponding key is calculated
by taking the HMAC-SHA256 of the packed table name, field name,
and index name as the message, and the `Index Root Key` as the HMAC key,
and truncating the result to 32 bytes.

### Why were 0xB4 and 0x7E selected?

The primary purpose of these two byte values was to achieve a simple
property called **domain separation**, which helps side-step accidental
misuse of cryptographic secrets.

As long as two distinct constants were used, this property is achieved.
`0x01` and `0x02` would have been sufficient for satisfying this
security goal. Any further design decision would not weaken this
security goal.

However, consider that [the security proof for HMAC](https://cseweb.ucsd.edu/~mihir/papers/kmd5.pdf)
made it clear that a high Hamming distance between the padding values
was desirable.

Indeed, a 2012 paper on [generic related-key attacks for HMAC](https://eprint.iacr.org/2012/684.pdf)
demonstrated that poor choice in padding constants could make their attacks
significantly more powerful.

This led us to choose padding constants with a high Hamming distance per
byte (4, as per HMAC), but distinct from the HMAC padding constants.

* `0x7E` in binary is `0111 1110`, which is symmetric.
* `0xB4` is `1101 0100`, which is asymmetric, and unlike the HMAC constants,
  has its highest bit set to `1`.

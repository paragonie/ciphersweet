# Packing

## CipherSweet's Multi-Part Message Packing Protocol

The packing algorithm is similar to the one used in [PASETO](https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Common.md#authentication-padding),
with one departure: The length that precedes the packed payload is only
32 bits long.

This was designed to mitigate canonicalization attacks, which are only
relevant depending on how you feed data into your MAC.

### Authentication Padding

**LE32()** encodes a 32-bit unsigned integer into a little-endian
binary string. The most significant bit MUST be cleared for interoperability
with programming languages that do not have unsigned integer support.

**LE64()** encodes a 64-bit unsigned integer into a little-endian
binary string. The most significant bit MUST be cleared for interoperability
with programming languages that do not have unsigned integer support.

**cipherSweetPack()** accepts an array of strings (usually denoted as
`array<int, string>` in docblocks to signify integer keys, but in
other languages, `string[]` is preferred; in the PHP community
they're synonymous). (This is implemented as `Util::pack()` in our
implementation.)

The first 8 bytes of the output will be the number of pieces. Typically
this is a small number (3 or 4). This is calculated by `LE64()` of the
size of the array.

Next, for each piece provided, the length of the piece is encoded via
`LE64()` and prefixed to each piece before concatenation.

An implementation may look like this:

```javascript
function LE32(n) {
    var str = '';
    for (var i = 0; i < 4; ++i) {
        if (i === 3) {
            // Clear the MSB for interoperability
            n &= 127;
        }
        str += String.fromCharCode(n & 255);
        n = n >>> 8;
    }
    return str;
}
function LE64(n) {
    var str = '';
    for (var i = 0; i < 8; ++i) {
        if (i === 7) {
            // Clear the MSB for interoperability
            n &= 127;
        }
        str += String.fromCharCode(n & 255);
        n = n >>> 8;
    }
    return str;
}
function cipherSweetPack(pieces) {
    if (!Array.isArray(pieces)) {
        throw TypeError('Expected an array.');
    }
    var count = pieces.length;
    var output = LE32(count);
    for (var i = 0; i < count; i++) {
        output += LE64(pieces[i].length);
        output += pieces[i];
    }
    return output;
}
```

As a consequence:

* `cipherSweetPack([])` will always return `"\x00\x00\x00\x00"`
* `cipherSweetPack([''])` will always return
  `"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"`
* `cipherSweetPack(['test'])` will always return
  `"\x01\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00test"`
* `cipherSweetPack('test')` will throw a `TypeError`

As a result, you cannot create a collision with only a partially
controlled plaintext. Either the number of pieces will differ, or the
length of one of the fields (which is prefixed to the input you can
provide) will differ, or both.

Due to the length being expressed as an unsigned 64-bit integer, it
remains infeasible to generate/transmit enough data to create an integer
overflow.

The number of pieces should always be smaller than 2^31 (about 2
billion).

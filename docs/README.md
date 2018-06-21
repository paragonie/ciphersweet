# Using CipherSweet

## Setting up CipherSweet at Run-Time

### Select Your Backend

First, you'll need to decide if you have any strict operational requirements for
your encryption. This mostly boils down to whether or not you need all
encryption to be FIPS 140-2 compliant or not, in which case, you'll need to use
the `FIPSCrypto` backend.

If you aren't sure, the answer is that you probably don't, and feel free to use
`ModernCrypto` instead.

```php
<?php
use ParagonIE\CipherSweet\Backend\FIPSCrypto;
use ParagonIE\CipherSweet\Backend\ModernCrypto;

$fips = new FIPSCrypto(); // Use only FIPS 140-2 algorithms
$nacl = new ModernCrypto(); // Uses libsodium
```

### Define your Key Provider

After you choose your backend, you'll need a KeyProvider. We provide a few
out-of-the-box, but we also provide an interface that can be used to integrate
with any key management service in your code.

The simplest example of this is the `StringProvider`, which accepts a
string containing your encryption key:

```php
<?php
use ParagonIE\ConstantTime\Hex;
use ParagonIE\CipherSweet\Backend\ModernCrypto;
use ParagonIE\CipherSweet\KeyProvider\StringProvider;

$provider = new StringProvider(
    new ModernCrypto(),
    // Example key, chosen randomly, hex-encoded:
    '4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc'
);
```

You can pass a raw binary string, hex-encoded string, or
base64url-encoded string to the second parameter of the `StringProvider`
constructor, provided the decoded key is 256 bits.

Attempting to pass a key of an invalid size (i.e. not 256-bit) will
result in a `CryptoOperationException` being thrown. The recommended
way to generate a key is:

```php
<?php
use ParagonIE\ConstantTime\Hex;

var_dump(Hex::encode(random_bytes(32)));
```

### Start Your Engines

Once you have these two, you can actually start the engine (`CipherSweet`).
Building on the previous code example:

```php
<?php
use ParagonIE\ConstantTime\Hex;
use ParagonIE\CipherSweet\Backend\ModernCrypto;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\KeyProvider\StringProvider;

$provider = new StringProvider(
    new ModernCrypto(),
    // Example key, chosen randomly, hex-encoded:
    '4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc'
);

$engine = new CipherSweet($provider);
```

If you're using FIPSCrypto instead of ModernCrypto, you just need to pass
it once to the `KeyProvider` and the rest is handled for you.

```php
<?php
use ParagonIE\ConstantTime\Hex;
use ParagonIE\CipherSweet\Backend\ModernCrypto;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\KeyProvider\StringProvider;

$provider = new StringProvider(
    new FIPSCrypto(),
    // Example key, chosen randomly, hex-encoded:
    '4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc'
);
$engine = new CipherSweet($provider);
```

## Basic CipherSweet Usage

Once you have an engine in play, you can start defining encrypted fields and
defining one or more **blind index** to be used for fast search operations.

### EncryptedField

This will primarily involve the `EncryptedField` class (as well as one or more
instances of `BlindIndex`), mostly:

* `$encryptedField->prepareForStorage()`
* `$encryptedField->getBlindIndex()`
* `$encryptedField->getAllBlindIndexes()`
* `$encryptedField->encryptValue()`
* `$encryptedField->decryptValue()`

For example, the following code encrypts a user's social security number and
then creates two blind indexes: One for a literal search, the other only
matches the last 4 digits.

```php
<?php
use ParagonIE\CipherSweet\BlindIndex;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\EncryptedField;
use ParagonIE\CipherSweet\Transformation\LastFourDigits;

/** @var CipherSweet $engine */
$ssn = (new EncryptedField($engine, 'contacts', 'ssn'))
    // Add a blind index for the "last 4 of SSN":
    ->addBlindIndex(
        new BlindIndex(
            // Name (used in key splitting):
            'contact_ssn_last_four',
            // List of Transforms: 
            [new LastFourDigits()],
            // Bloom filter size (bits)
            16
        )
    )
    // Add a blind index for the full SSN:
    ->addBlindIndex(
        new BlindIndex(
            'contact_ssn', 
            [],
            32
        )
    );

// Some example parameters:
$contactInfo = [
    'name' => 'John Smith',
    'ssn' => '123-45-6789',
    'email' => 'foo@example.com'
];

/** 
 * @var string $ciphertext
 * @var array<string, string> $indexes
 */
list ($ciphertext, $indexes) = $ssn->prepareForStorage($contactInfo['ssn']);
```

Every time you run the above code, the `$ciphertext` will be randomized, but the
array of blind indexes will remain the same.

Each blind index returns an array with two values: `type` and `value`. The value
is calculated from the plaintext. The `type` is a key derived form the table
name, field name, and index name.
 
The `type` indicator is handy if you're storing all your blind indexes in a
separate table rather than in an additional column in the same table. In the
latter case, you only need the `value` string for each index.

```
var_dump($ciphertext, $indexes);
/*
string(73) "nacl:jIRj08YiifK86YlMBfulWXbatpowNYf4_vgjultNT1Tnx2XH9ecs1TqD59MPs67Dp3ui"
array(2) {
  ["contact_ssn_last_four"]=>
  array(2) {
    ["type"]=>
    string(13) "3dywyifwujcu2"
    ["value"]=>
    string(4) "8058"
  }
  ["contact_ssn"]=>
  array(2) {
    ["type"]=>
    string(13) "2iztg3wbd7j5a"
    ["value"]=>
    string(8) "311314c1"
  }
}
*/
```

You can now use these values for inserting/updating records into your database.

To search the database at a later date, use `getAllBlindIndexes()` or `getBlindIndex()`:

```php
<?php
use ParagonIE\CipherSweet\BlindIndex;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\EncryptedField;
use ParagonIE\CipherSweet\Transformation\LastFourDigits;

/** @var CipherSweet $engine */
$ssn = (new EncryptedField($engine, 'contacts', 'ssn'))
    // Add a blind index for the "last 4 of SSN":
    ->addBlindIndex(
        new BlindIndex(
            // Name (used in key splitting):
            'contact_ssn_last_four',
            // List of Transforms: 
            [new LastFourDigits()],
            // Bloom filter size (bits)
            16
        )
    )
    // Add a blind index for the full SSN:
    ->addBlindIndex(
        new BlindIndex(
            'contact_ssn', 
            [],
            32
        )
    );

// Use these values in search queries:
$indexes = $ssn->getAllBlindIndexes('123-45-6789');
$lastFour = $ssn->getBlindIndex('123-45-6789', 'contact_ssn_last_four');
```

Which should result in the following (for the example key):

```
var_dump($lastFour);
/*
array(2) {
  ["type"]=>
  string(13) "3dywyifwujcu2"
  ["value"]=>
  string(4) "8058"
}
*/

var_dump($indexes);
/*
array(2) {
  ["contact_ssn_last_four"]=>
  array(2) {
    ["type"]=>
    string(13) "3dywyifwujcu2"
    ["value"]=>
    string(4) "8058"
  }
  ["contact_ssn"]=>
  array(2) {
    ["type"]=>
    string(13) "2iztg3wbd7j5a"
    ["value"]=>
    string(8) "311314c1"
  }
}
*/
```

### EncryptedRow

An alternative approach for datasets with multiple encrypted rows and/or
[encrypted boolean fields](https://github.com/paragonie/ciphersweet/blob/master/docs/solutions/01-boolean.md)
is the `EncryptedRow` API, which looks like this:

```php
<?php
use ParagonIE\CipherSweet\BlindIndex;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\CompoundIndex;
use ParagonIE\CipherSweet\EncryptedRow;
use ParagonIE\CipherSweet\Transformation\LastFourDigits;

/** @var CipherSweet $engine */
// Define two fields (one text, one boolean) that will be encrypted
$row = (new EncryptedRow($engine, 'contacts'))
    ->addTextField('ssn')
    ->addBooleanField('hivstatus');

// Add a normal Blind Index on one field:
$row->addBlindIndex(
    'ssn',
    new BlindIndex(
        'contact_ssn_last_four',
        [new LastFourDigits()],
        32 // 32 bits = 4 bytes
    )
);

// Create/add a compound blind index on multiple fields:
$row->addCompoundIndex(
    (
        new CompoundIndex(
            'contact_ssnlast4_hivstatus',
            ['ssn', 'hivstatus'],
            32, // 32 bits = 4 bytes
            true // fast hash
        )
    )->addTransform('ssn', new LastFourDigits())
);

// Notice: You're passing an entire array at once, not a string
$prepared = $row->prepareRowForStorage([
    'extraneous' => true,
    'ssn' => '123-45-6789',
    'hivstatus' => false
]);

var_dump($prepared);
/*
array(2) {
  [0]=>
  array(3) {
    ["extraneous"]=>
    bool(true)
    ["ssn"]=>
    string(73) "nacl:wVMElYqnHrGB4hU118MTuANZXWHZjbsd0uK2N0Exz72mrV8sLrI_oU94vgsWlWJc84-u"
    ["hivstatus"]=>
    string(61) "nacl:ctWDJBn-NgeWc2mqEWfakvxkG7qCmIKfPpnA7jXHdbZ2CPgnZF0Yzwg="
  }
  [1]=>
  array(2) {
    ["contact_ssn_last_four"]=>
    array(2) {
      ["type"]=>
      string(13) "3dywyifwujcu2"
      ["value"]=>
      string(8) "805815e4"
    }
    ["contact_ssnlast4_hivstatus"]=>
    array(2) {
      ["type"]=>
      string(13) "nqtcc56kcf4qg"
      ["value"]=>
      string(8) "cbfd03c0"
    }
  }
}
*/
```

With the `EncryptedRow` API, you can encrypt a subset of all of the fields
in a row, and create compound blind indexes based on multiple pieces of
data in the dataset rather than a single field, without writing a ton of
glue code.

## Using CipherSweet with a Database 

CipherSweet is database-agnostic, so you'll need to write some code that
uses CipherSweet behind-the-scenes to encrypt data before storing it in a
database, query the database based on blind indexes, and then use CipherSweet
to decrypt the results.

See also: the **[examples](https://github.com/paragonie/ciphersweet/tree/master/docs/examples)**
directory.

## Solutions for Common Problems with Searchable Encryption

See also: the **[solutions](https://github.com/paragonie/ciphersweet/tree/master/docs/solutions)**
directory.

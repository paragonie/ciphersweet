# Using CipherSweet

## Table of Contents

* [Using CipherSweet](https://github.com/paragonie/ciphersweet/tree/master/docs)
  * **Table of Contents** (You are here)
  * [Understanding CipherSweet's Features and Limitations](#understanding-ciphersweets-features-and-limitations)
  * [Setting up CipherSweet at Run-Time](#setting-up-ciphersweet-at-run-time)
    * [Select Your Backend](#select-your-backend)
    * [Define your Key Provider](#define-your-key-provider)
    * [Start Your Engines](#start-your-engines)
  * [Basic CipherSweet Usage](#basic-ciphersweet-usage)
    * [`EncryptedField`](#encryptedfield)
    * [`EncryptedRow`](#encryptedrow)
      * [`EncryptedRow` with a `CompoundIndex` using a custom Transform of Multiple Fields](#encryptedrow-with-a-compoundindex-using-a-custom-transform-of-multiple-fields)
      * [Using the Old API to Create a Congruent Result](#using-the-old-api-to-create-a-congruent-result)
    * [`EncryptedMultiRows`](#encryptedmultirows)
      * [`EncryptedMultiRows` with AAD](#encryptedmultirows-with-aad)
  * [Blind Index Planning](#blind-index-planning)
  * [Key/Backend Rotation](#keybackend-rotation)
    * [`FieldRotator`](#fieldrotator)
    * [`RowRotator`](#rowrotator)
    * [`MultiRowsRotator`](#multirowsrotator)
  * [`EncryptedFile`](#encryptedfile)
* [Security Properties and Thread Model for CipherSweet](SECURITY.md)
* [CipherSweet Examples](https://github.com/paragonie/ciphersweet/tree/master/docs/examples)
  (Look here if you seek runnable example code for common integrations)
* [CipherSweet Internals](https://github.com/paragonie/ciphersweet/tree/master/docs/internals)
  (Look here if you seek to port CipherSweet to another language)
  * [Key Hierarchy](https://github.com/paragonie/ciphersweet/blob/master/docs/internals/01-key-hierarchy.md)
  * [Packing](https://github.com/paragonie/ciphersweet/blob/master/docs/internals/02-packing.md)
  * [Field-Level Encryption](https://github.com/paragonie/ciphersweet/blob/master/docs/internals/03-encryption.md)
  * [Blind Indexing](https://github.com/paragonie/ciphersweet/blob/master/docs/internals/04-blind-index.md)
  * [File Encryption](https://github.com/paragonie/ciphersweet/blob/master/docs/internals/05-file-encryption.md)
* [Solutions for Common Problems with Searchable Encryption](https://github.com/paragonie/ciphersweet/tree/master/docs/solutions)

## Understanding CipherSweet's Features and Limitations

CipherSweet is an implementation of [PIE's searchable encryption design](https://paragonie.com/blog/2017/05/building-searchable-encrypted-databases-with-php-and-sql),
which combines semantically secure authenticated encryption with "blind indexes"
of the plaintext.

At a super high level overview:

* Ciphertexts (encrypted messages) are indistinguishable from each other.
* Blind indexes offer limited searching capabilities.
  * They don't support `LIKE` operators or regular expressions.
* Each blind index is one-way (a.k.a. irreversible) and can be created
  on the plaintext itself, or a **transformation** of the plaintext. 
  Example transformations include:
  * Last four numeric digits of the plaintext
  * First letter of the plaintext
  * All-lowercase representation of the plaintext
* CipherSweet also supports **compound indexes**, which combine multiple fields
  together before applying the cryptographic hash function.
  * This allows you to create an index on "first initial" + "last name".
  * It's recommended to use compound indexes for sensitive boolean fields.
    * For example: Indexing your users' HIV status by itself would be a huge
      HIPAA violation risk. However, if you index "HIV status + last 4 digits
      of social security number", an attacker can't just look at the blind
      indexes and immediately deduce the value of this boolean field.
* If you add too many blind indexes to your data, you may allow attackers who
  know some plaintexts to be able to deduce facts about the decrypted value of
  other ciphertexts.
     * We refer to these deductive strategies as "crossword puzzle attacks"
       because the same sort of analytical skills used to solve crossword 
       puzzles can be employed to learn facts about the unencryptable data.
     * Solution: Use blind indexes sparingly.
* Each blind index is intended to be truncated and used as a [Bloom filter](https://en.wikipedia.org/wiki/Bloom_filter)
  when searching.
  * How much you truncate each index depends on how many duplicates / false positives
    you wish your application to tolerate.
  * Shorter indexes will result in more duplicates, but will be less useful for
    attackers trying to perform crossword puzzle attacks on the blind indexes.
* It's okay to only encrypt some fields and not create blind indexes on them,
  so long as your application doesn't need to use those values in SELECT queries.

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

There is no need to pass `ModernCrypto` or `FIPSCrypto` multiple times.

```php
<?php
use ParagonIE\CipherSweet\Backend\FIPSCrypto;
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
 * @var array<string, array<string, string>> $indexes
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
    string(4) "2acb"
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

Since version 1.10.0, you can call `setFlatIndexes(true)` on any `EncryptedField`, `EncryptedRow`,
and `EncryptedMultiRows` object to only get the flat version.

```php
/** 
 * @var string $ciphertext
 * @var array<string, string> $indexes
 */
list ($ciphertext, $indexes) = $ssn->prepareForStorage($contactInfo['ssn']);
var_dump($ciphertext, $indexes);
/*
string(73) "nacl:jIRj08YiifK86YlMBfulWXbatpowNYf4_vgjultNT1Tnx2XH9ecs1TqD59MPs67Dp3ui"
array(2) {
  ["contact_ssn_last_four"]=>
  string(4) "2acb"
  ["contact_ssn"]=>
  string(8) "311314c1"
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

```php
var_dump($lastFour);
/*
array(2) {
  ["type"]=>
  string(13) "3dywyifwujcu2"
  ["value"]=>
  string(4) "2acb"
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
    string(4) "2acb"
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

#### EncryptedField with AAD

Since version 1.6.0, both `EncryptedField::encryptValue()` and
`EncryptedField::prepareForStorage()` allow an optional string to be passed to
the second parameter, which will be included in the authentication tag on the
ciphertext. It will **NOT** be stored in the ciphertext.

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
      string(8) "2acbcd1c"
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

Since version 1.10.0, you can call `setFlatIndexes(true)` on any `EncryptedField`, `EncryptedRow`,
and `EncryptedMultiRows` object to only get the flat version.

```php
// Use flat indexes
$row->setFlatIndexes(true);

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
    string(8) "2acbcd1c"
    ["contact_ssnlast4_hivstatus"]=>
    string(8) "cbfd03c0"
  }
}
*/
```

#### EncryptedRow with a CompoundIndex using a custom Transform of Multiple Fields

Since **version 1.5.0**, it's possible to quickly create a compound
index that uses a transformation that combines multiple fields into one
output string.

Following the previous example:

```php
<?php
use ParagonIE\CipherSweet\BlindIndex;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\CompoundIndex;
use ParagonIE\CipherSweet\Contract\RowTransformationInterface;
use ParagonIE\CipherSweet\EncryptedRow;
use ParagonIE\CipherSweet\Transformation\LastFourDigits;

/**
 * Class FirstInitialLastName
 */
class FirstInitialLastName implements RowTransformationInterface
{
    /**
     * @param array $input
     * @param int $layer
     *
     * @return array|string
     * @throws \Exception
     */
    public function processArray(array $input, $layer = 0)
    {
        if (!\is_array($input)) {
            throw new \TypeError('Compound Transformation expects an array');
        }
        return \strtolower($input['first_name'][0] . $input['last_name']);
    }

    /**
     * Implementations can define their own prototypes, but
     * this should almost always operate on a string, and must
     * always return a string.
     *
     * @param mixed $input
     * @return string
     * @throws \Exception
     */
    public function __invoke($input)
    {
        return $this->processArray($input);
    }
}

/** @var CipherSweet $engine */
$row = (new EncryptedRow($engine, 'contacts'))
    ->addTextField('first_name')
    ->addTextField('last_name')
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

// Notice the ->addRowTransform() method:
$row->addCompoundIndex(
    $row->createCompoundIndex(
        'contact_first_init_last_name',
        ['first_name', 'last_name'],
        64, // 64 bits = 8 bytes
        true
    )->addRowTransform(new FirstInitialLastName())
);

$prepared = $row->prepareRowForStorage([
    'first_name' => 'Jane',
    'last_name' => 'Doe',
    'extraneous' => true,
    'ssn' => '123-45-6789',
    'hivstatus' => false
]);

var_dump($prepared);
/*
array(2) {
  [0]=>
  array(5) {
    ["first_name"]=>
    string(141) "fips:fCCyMZOUMA95S3efKWEgL8Zq7RNYo7vX0pXZl3Ls1iM8k0ST_3y2VpeQQO4BET0EABkVUhnRvIbWXM-MA2gJw6uv1jvoR0nJwiRaHJOAknwvoKT-coHYJuwUT2v_qDAvZVbvdA=="
    ["last_name"]=>
    string(137) "fips:AIJniZTOIaehOUE5fA8PnvUdQSGs24YhTK5bQO3T8wI7a_t11k_Ah5SnlAqjUEXeX-_PpvlbPapqagApxS4_QFjn74xc1IG3e8SaUi8wemxjl-udPWg0xML0wANsTQMCp3EE"
    ["extraneous"]=>
    bool(true)
    ["ssn"]=>
    string(149) "fips:oP6DuYYErL-lZqfgX1pOfjTJHzCNtx8w5ZBrT78sypnc5waFd7K-9Qu0-GojHFXqnlJe5Cvj9x1doooR6ijy1fIKle5JpzjZeSe0nbJP44atuNJqDg6JMkTSLsNylaQoULxEHR5mFTcAKOA="
    ["hivstatus"]=>
    string(137) "fips:3QGNnjNPZTFNoSC4kKEWfevvcSQ1hRWhWrc9agh9PVPvWesJeZCwskFakeCFAB_5zSSRbKgGXFMlIk-2lJphJrl5OuHBmCSeB_E_mBU931k4rHfz3_OP-rGnB8H9CAfVpw=="
  }
  [1]=>
  array(3) {
    ["contact_ssn_last_four"]=>
    array(2) {
      ["type"]=>
      string(13) "idlzpypmia6qu"
      ["value"]=>
      string(8) "a88e74ad"
    }
    ["contact_ssnlast4_hivstatus"]=>
    array(2) {
      ["type"]=>
      string(13) "dozudszz2yu5k"
      ["value"]=>
      string(8) "417daacf"
    }
    ["contact_first_init_last_name"]=>
    array(2) {
      ["type"]=>
      string(13) "w6dsrxbathjze"
      ["value"]=>
      string(16) "81f9316ceccea014"
    }
  }
}
*/
```

The above snippet defines a custom implementation of 
`RowTransformationInterface` that appends the first initial
and the last name.

Note: You can achieve the same overall effect (but not the same
hash output) using the default CompoundIndex.

#### Using the Old API to Create a Congruent Result

```php
<?php
use ParagonIE\CipherSweet\BlindIndex;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\Transformation\AlphaCharactersOnly;
use ParagonIE\CipherSweet\Transformation\FirstCharacter;
use ParagonIE\CipherSweet\Transformation\Lowercase;
use ParagonIE\CipherSweet\Transformation\LastFourDigits;
use ParagonIE\CipherSweet\EncryptedRow;

/** @var CipherSweet $engine */
$row = (new EncryptedRow($engine, 'contacts'))
    ->addTextField('first_name')
    ->addTextField('last_name')
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

// Notice the ->addRowTransform() method:
$row->addCompoundIndex(
    $row->createCompoundIndex(
        'contact_first_init_last_name',
        ['first_name', 'last_name'],
        64, // 64 bits = 8 bytes
        true
    )
    ->addTransform('first_name', new AlphaCharactersOnly())
    ->addTransform('first_name', new Lowercase())
    ->addTransform('first_name', new FirstCharacter())
    ->addTransform('last_name', new AlphaCharactersOnly())
    ->addTransform('last_name', new Lowercase())
);

$prepared = $row->prepareRowForStorage([
    'contactid' => 123456,
    'first_name' => 'Jane',
    'last_name' => 'Doe',
    'extraneous' => true,
    'ssn' => '123-45-6789',
    'hivstatus' => false
]);

var_dump($prepared);
/*
array(2) {
  [0]=>
  array(6) {
    ["contactid"]=>
    int(123456)
    ["first_name"]=>
    string(141) "fips:32kSOVcY9IIX5rxoVhxSWMQs-PPl8XwPOPzD4sPA50_HAiD-ylCvoW_-vAEHtIp-o2p_M_9lxTRzmBa8U--g471Uipks2njotKwzFstqYiXwX80cdAsFYDazmvrs2TIOnKrX-w=="
    ["last_name"]=>
    string(137) "fips:MVPhhMtbgi14ofY8gsiI96PL3xv2-nbJRdJnkeXaZVA_ctGW_-1_Q-WsRCjZLVghykIMxdRYd5uNh-u39-dFufb2OmyP7r9_GCIM0OpAiqrjxEDezfLEMpdg5liaGKiNkx3x"
    ["extraneous"]=>
    bool(true)
    ["ssn"]=>
    string(149) "fips:laANliGoATw0HBWc8RbdE_sZ5gIFmRMvLP2ai6OgSapNZNIofsVO349Ui18FCggy8VoPtaIAjillR5uvxOJ_LtNdr2GtBikUXNkmlu2il7XCeQn41vs5u_kcZwFh6vFPvLGrDLXuDRV89zk="
    ["hivstatus"]=>
    string(137) "fips:Czzax6VDFGDIFuyCrRtU_K3EjYOaBDyPMkGDzZD8MFx03uzVPS77mjF5GNCR_0TGunCZsZbkDF5_R9O1PfZCA0GuSS4uBI34LBNx_c3Yn9LWJXt1K_R886qLCI6xmacaew=="
  }
  [1]=>
  array(2) {
    ["contact_ssn_last_four"]=>
    array(2) {
      ["type"]=>
      string(13) "idlzpypmia6qu"
      ["value"]=>
      string(8) "a88e74ad"
    }
    ["contact_first_init_last_name"]=>
    array(2) {
      ["type"]=>
      string(13) "w6dsrxbathjze"
      ["value"]=>
      string(16) "32ee2a30de9ef264"
    }
  }
}
*/
```

In both instances, we create a blind index on "jdoe" given a first name
of "John" and a last name of "Doe".

#### EncryptedRow with AAD

Since version 1.6.0, you can now use a separate plaintext column (e.g. primary
or foreign key) as additional authenticated data.
 
This binds the ciphertext to a specific row, thereby preventing an attacker
capable of replacing ciphertexts and using legitimate app access to decrypt
ciphertexts they wouldn't otherwise have access to.

```php
$row->setAadSourceField('first_name', 'contactid');
```

This can also be included during the table instantiation:

```php
<?php
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\EncryptedRow;

/** @var CipherSweet $engine */
$row = (new EncryptedRow($engine, 'contacts'))
    ->addTextField('first_name', 'contact_id');
    /* ... */
```

### EncryptedMultiRows

Since version 1.6.0, CipherSweet also provided a multi-row abstraction
to make it easier to manage heavily-normalized databases.

When working with `EncryptedMultiRows`, your arrays should be formatted
as follows:

```php
$input = [
    'table1' => [
        'column1' => 'value',
        'columnB' => 123456,
        // ...
    ],
    'table2' => [ /* ... */ ],
    // ...
];
```

For example:

```php
<?php

use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\Transformation\AlphaCharactersOnly;
use ParagonIE\CipherSweet\Transformation\FirstCharacter;
use ParagonIE\CipherSweet\Transformation\Lowercase;
use ParagonIE\CipherSweet\Backend\FIPSCrypto;
use ParagonIE\CipherSweet\KeyProvider\StringProvider;
use ParagonIE\CipherSweet\EncryptedMultiRows;

$provider = new StringProvider(
    new FIPSCrypto(),
    // Example key, chosen randomly, hex-encoded:
    'a981d3894b5884f6965baea64a09bb5b4b59c10e857008fc814923cf2f2de558'
);
$engine = new CipherSweet($provider);
$rowSet = (new EncryptedMultiRows($engine))
    ->addTextField('contacts', 'first_name')
    ->addTextField('contacts', 'last_name')
    ->addFloatField('contacts', 'latitude')
    ->addFloatField('contacts', 'longitude')
    ->addTextField('foobar', 'test');

$rowSet->addCompoundIndex(
    'contacts',
    $rowSet->createCompoundIndex(
        'contacts',
        'contact_first_init_last_name',
        ['first_name', 'last_name'],
        64, // 64 bits = 8 bytes
        true
    )
        ->addTransform('first_name', new AlphaCharactersOnly())
        ->addTransform('first_name', new Lowercase())
        ->addTransform('first_name', new FirstCharacter())
        ->addTransform('last_name', new AlphaCharactersOnly())
        ->addTransform('last_name', new Lowercase())
);


$prepared = $rowSet->prepareForStorage([
    'contacts' => [
        'contactid' => 12345,
        'first_name' => 'Jane',
        'last_name' => 'Doe',
        'latitude' => 52.52,
        'longitude' => -33.106,
        'extraneous' => true
    ],
    'foobar' => [
        'foobarid' => 23,
        'contactid' => 12345,
        'test' => 'paragonie'
    ]
]);

var_dump($prepared);
```

This will produce something similar to the following output:

```
array(2) {
  [0]=>
  array(2) {
    ["contacts"]=>
    array(6) {
      ["contactid"]=>
      int(12345)
      ["first_name"]=>
      string(141) "fips:8NSLNDWxN4u7OeN_v5ahnt-tgTNqrarsdhPwhMFT4uqtMsELj5L1D7KhukM1OSOKdwtgytiaut3-1kvtP8eSiIH8bQLidw3MwUFQ0JaxvNldI7rzVKeMP3yp4UVSrJZNH89nvQ=="
      ["last_name"]=>
      string(137) "fips:uk9FtD5HvXY4Fe8_ibXF32FurmV8WvAUVSWUPVhOcfmHNC-nol7EnNjdQ5vBG2HQmpeRaTjSE5QZNZ9TQGeK-HgaO3V_MCVQDTtN2u9-3HR4ehSFjn8rHbGt31Ygrh4CV6WV"
      ["latitude"]=>
      string(145) "fips:HE1PQoMso4FBu_rJWk0adWnp9i6HSBXQbf3QaHp1cw8-tOCDSm3rjiE1zIIrUmKarprPRzCTzb2BxdiXVg3RNsLH8iSko0ZmXSXhTa51XoEByxaH9fvAILpXttIfk8rsSXoIKgvMfcY="
      ["longitude"]=>
      string(145) "fips:4gwnipUOws0kLW9gLmIgUNOM65ba1SVkibxILmJOpCbvw3853v_AaEGD-PO3b0fNwVnD6zbWdpovtHblAlXX2iOUvfqgrnwO21vPcYt8FaFkT706-_ZvbRioooL7NwFBqvJJWpiTnhA="
      ["extraneous"]=>
      bool(true)
    }
    ["foobar"]=>
    array(3) {
      ["foobarid"]=>
      int(23)
      ["contactid"]=>
      int(12345)
      ["test"]=>
      string(145) "fips:vnoJ6rIEBBMLCvXMt4gke8CT6PomgAExNufTZUrpPd3rp9y28jgopmXA7w8reqVe3SfE6KhRvN-lt5GQhzR1miQPVaIVq2V6D1i4eZCSKQDBmJ7PTAYuigNd9DPSL4qW3OAOtvagJ4Lc"
    }
  }
  [1]=>
  array(2) {
    ["contacts"]=>
    array(1) {
      ["contact_first_init_last_name"]=>
      array(2) {
        ["type"]=>
        string(13) "w6dsrxbathjze"
        ["value"]=>
        string(16) "546b1ffd1f83c37a"
      }
    }
    ["foobar"]=>
    array(0) {
    }
  }
}
```

#### EncryptedMultiRows with AAD

Since version 1.6.0, you can now use a separate plaintext column (e.g. primary
or foreign key) as additional authenticated data.
 
This binds the ciphertext to a specific row, thereby preventing an attacker
capable of replacing ciphertexts and using legitimate app access to decrypt
ciphertexts they wouldn't otherwise have access to.

```php
$rowSet->setAadSourceField('contacts', 'first_name', 'contactid');
```

This can also be included during the table instantiation:

```php
<?php
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\EncryptedMultiRows;

/** @var CipherSweet $engine */
$rowSet = (new EncryptedMultiRows($engine))
    ->addTextField('contacts', 'first_name', 'contactid');
    /* ... */
```

### Blind Index Planning

Since version 1.7.0, CipherSweet includes a **planner** to assist developers in
determining the safe sizes for an additional blind index on an encrypted field.

Using the planner is straightforward:

```php
<?php
use ParagonIE\CipherSweet\Planner\FieldIndexPlanner;

# First, instantiate the planner for a given field
$planner = new FieldIndexPlanner();

# How many rows do you anticipate?
$planner->setEstimatedPopulation(50000);

# Next, add some information about existing fields
$planner->addExistingIndex('name_goes_here', 4, 16);
// ... etc.

$recommended = $planner->recommend();
var_dump($recommended);
```

This code snippet should yield the following:

```
array(2) {
  ["min"]=>
  int(4)
  ["max"]=>
  int(11)
}
```

How to interpret this data:

If you make the additional index larger than `11`, you [introduce the risk of leaking data](SECURITY.md#blind-index-information-leaks).

If you make it lower than `4`, you'll have a lot of false positives and it
really would not be worth creating this blind index.

If your additional index has a limited keyspace, you can pass the number of
bits to the `recommend()` method to include this in the calculation.

Furthermore, you can use `recommendLow()` to only get the lower number, and
`recommendHigh()` to only get the higher number.

**Note:** If there is no safe value for an additional index, the `recommend`
methods will throw a `PlannerException`.

### Key/Backend Rotation

Since version 1.8.0, CipherSweet aims to make key rotation and/or backend migration
as pain-free as possible.

To use these APIs, first instantiate two `CipherSweet` instances.
They can have different backends (e.g. FIPSCrypto to ModernCrypto),
different keys, or both.

#### `FieldRotator`

```php
<?php
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\KeyRotation\FieldRotator;
use ParagonIE\CipherSweet\EncryptedField;

/**
 * @var string $ciphertext
 * @var CipherSweet $old
 * @var CipherSweet $new
 */
$oldField = new EncryptedField($old, 'contacts', 'ssn');
$newField = new EncryptedField($new, 'contacts', 'ssn');

$rotator = new FieldRotator($oldField, $newField);
if ($rotator->needsReEncrypt($ciphertext)) {
    list($ciphertext, $indices) = $rotator->prepareForUpdate($ciphertext);
}
```

You can optionally also provide additional authenticated data to this API, like so:

```php
if ($rotator->needsReEncrypt($ciphertext, 'old AAD')) {
    list($ciphertext, $indices) = $rotator->prepareForUpdate($ciphertext, 'old AAD', 'new AAD');
}
```

The end result will be re-encrypted, and the ciphertext tag will be tied to `"new AAD"`.

#### `RowRotator`

```php
<?php
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\KeyRotation\RowRotator;
use ParagonIE\CipherSweet\EncryptedRow;

/**
 * @var array<string, string> $ciphertext
 * @var CipherSweet $old
 * @var CipherSweet $new
 */
$oldRow = new EncryptedRow($old, 'contacts');
$newRow = new EncryptedRow($new, 'contacts');

$rotator = new RowRotator($oldRow, $newRow);
if ($rotator->needsReEncrypt($ciphertext)) {
    list($ciphertext, $indices) = $rotator->prepareForUpdate($ciphertext);
}
```

#### `MultiRowsRotator`

```php
<?php
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\KeyRotation\MultiRowsRotator;
use ParagonIE\CipherSweet\EncryptedMultiRows;

/**
 * @var array<string, array<string, string>> $ciphertext
 * @var CipherSweet $old
 * @var CipherSweet $new
 */
$oldMultiRows = new EncryptedMultiRows($old);
$newMultiRows = new EncryptedMultiRows($new);

$rotator = new MultiRowsRotator($oldMultiRows, $newMultiRows);
if ($rotator->needsReEncrypt($ciphertext)) {
    list($ciphertext, $indices) = $rotator->prepareForUpdate($ciphertext);
}
```

## `EncryptedFile`

Since version 1.9.0, CipherSweet has provided an `EncryptedFile` API that provides
authenticated encryption, password-based encryption, and resistance against race
condition attacks.

### Using `EncryptedFile` in your Projects

First, instantiate the `EncryptedFile` class by passing your engine to the
constructor, like so:

```php
<?php
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\EncryptedFile;

/** @var CipherSweet $engine */
$encFile = new EncryptedFile($engine);
```

Now that you have an `EncryptedFile` object, you can use it to encrypt files on
disk or PHP streams.

```php
<?php
use ParagonIE\CipherSweet\EncryptedFile;
/** @var EncryptedFile $encFile */

// Encrypting a file with CipherSweet
$encFile->encryptFile(
    '/tmp/super-secret', 
    '/tmp/super-secret.enc'
);

// Encrypting a stream with CipherSweet
$input = \fopen('/tmp/super-secret', 'rb');
$output = \fopen('php://temp', 'wb');
$encFile->encryptStream($input, $output);
```

The above functions will use the key provider and backend from your `CipherSweet`
object to encrypt each file.

Decryption is a congruent operation:

```php
<?php
use ParagonIE\CipherSweet\EncryptedFile;
/** @var EncryptedFile $encFile */

// Decrypting a file with CipherSweet
if ($encFile->isFileEncrypted('/tmp/super-secret.enc')) {
    $encFile->decryptFile(
        '/tmp/super-secret.enc',
        '/tmp/super-secret.dec'
    );
}

// Decrypting a stream with CipherSweet
$input = \fopen('/tmp/super-secret.enc', 'rb');
$output = \fopen('php://temp', 'wb');
if ($encFile->isStreamEncrypted($input)) {
    $encFile->decryptStream($input, $output);
}
```

The `isFileEncrypted()` and `isStreamEncrypted()` methods return `TRUE` only if
this file was encrypted with the same backend as the current engine.

If you'd rather encrypt each file with a password rather than a local key, you
can use the `*WithPassword()` API instead:

```php
<?php
use ParagonIE\CipherSweet\EncryptedFile;
/** @var EncryptedFile $encFile */

$password = 'correct horse battery staple';

// Encrypting a file with CipherSweet
$encFile->encryptFileWithPassword(
    '/tmp/super-secret',
    '/tmp/super-secret.enc',
    $password
);

// Encrypting a stream with CipherSweet
$input = \fopen('/tmp/super-secret', 'rb');
$output = \fopen('php://temp', 'wb');
$encFile->encryptStreamWithPassword($input, $output, $password);

// Decrypting a file with CipherSweet
if ($encFile->isFileEncrypted('/tmp/super-secret.enc')) {
    $encFile->decryptFileWithPassword(
        '/tmp/super-secret.enc',
        '/tmp/super-secret.dec',
        $password
    );
}

// Decrypting a stream with CipherSweet
$input = \fopen('/tmp/super-secret.enc', 'rb');
$output = \fopen('php://temp', 'wb');
if ($encFile->isStreamEncrypted($input)) {
    $encFile->decryptStreamWithPassword($input, $output, $password);
}
```

Please be aware that encrypting with a password does **NOT** use your local
encryption key.

To learn more about how `EncryptedFile` was designed and implemented, please
refer to the [internal documentation](https://github.com/paragonie/ciphersweet/blob/master/docs/internals/05-file-encryption.md).

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

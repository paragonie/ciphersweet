# Using CipherSweet

## Table of Contents

* [Using CipherSweet](https://github.com/paragonie/ciphersweet/tree/master/docs)
  * **Table of Contents** (You are here)
  * [Setting up CipherSweet at Run-Time](#setting-up-ciphersweet-at-run-time)
    * [Select Your Backend](#select-your-backend)
    * [Define your Key Provider](#define-your-key-provider)
    * [Start Your Engines](#start-your-engines)
  * [Basic CipherSweet Usage](#basic-ciphersweet-usage)
    * [`EncryptedField`](#encryptedfield)
    * [`EncryptedRow`](#encryptedrow)
      * [`EncryptedRow` with a `CompoundIndex` using a custom Transform of Multiple Fields](#encryptedrow-with-a-compoundindex-using-a-custom-transform-of-multiple-fields)
      * [Using the Old API to Create a Congruent Result](#using-the-old-api-to-create-a-congruent-result)
* [CipherSweet Examples](https://github.com/paragonie/ciphersweet/tree/master/docs/examples)
  (Look here if you seek runnable example code for common integrations)
* [CipherSweet Internals](https://github.com/paragonie/ciphersweet/tree/master/docs/internals)
  (Look here if you seek to port CipherSweet to another language)
  * [Key Hierarchy](https://github.com/paragonie/ciphersweet/blob/master/docs/internals/01-key-hierarchy.md)
  * [Packing](https://github.com/paragonie/ciphersweet/blob/master/docs/internals/02-packing.md)
  * [Field-Level Encryption](https://github.com/paragonie/ciphersweet/blob/master/docs/internals/03-encryption.md)
  * [Blind Indexing](https://github.com/paragonie/ciphersweet/blob/master/docs/internals/04-blind-index.md)
* [Solutions for Common Problems with Searchable Encryption](https://github.com/paragonie/ciphersweet/tree/master/docs/solutions)

## Understanding CipherSweet's Features and Limitations

CipherSweet is an implementation of [PIE's searchable encryption design](https://paragonie.com/blog/2017/05/building-searchable-encrypted-databases-with-php-and-sql),
which combines semantically secure authenticated encryption with "blind indexes"
of the plaintext.

At a super high level overview:

* Ciphertexts (encrypted messages) are indistinguishable from each other.
* Blind indexes offer limited searching capabilities.
* It doesn't support `LIKE` operators or regular expressions.
* Each blind index uses, at its core, a one-way cryptographic hash function.
* Each blind index can be created on the plaintext itself, or a **transformation**
  of the plaintext. Example transformations include:
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

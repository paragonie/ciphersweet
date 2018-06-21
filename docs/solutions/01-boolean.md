# Encrypting and Searching with Boolean Fields

While searchable encryption is straightforward with text inputs, boolean
data (TRUE or FALSE; sometimes also NULL) presents unique challenges.

In general, it is not possible to protect a boolean field **in isolation**
while still being able to search on it, since there are only 2 (or 3, if
NULL is allowed) possible inputs.

For example, if you're storing HIV status as a boolean by studying the
blind index and observing that ~90% of people have one value and the
rest have another value, attackers can make an intelligent guess on
which records are TRUE and which are FALSE based entirely on context and
statistics.

However, all is not doomed. We provide a few tools that can be used to
minimize data leaks.

## CipherSweet Features for Protecting Boolean Fields

### EncryptedRow

The simplest solution is to use `EncryptedRow` instead of `EncryptedField`.

Instead of operating on naked string data, `EncryptedRow` operates on a
one-dimensional associative array. Fields will be encrypted in-place and
compound blind indexes (i.e. a blind index constructed of multiple fields
at once) are much easier to use.

For example:

```php
<?php
use ParagonIE\CipherSweet\Backend\FIPSCrypto;
use ParagonIE\CipherSweet\Backend\ModernCrypto;
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
```

In the above example, since the `contact_ssnlast4_hivstatus` blind index
depends on the last 4 digits of the contact's social security number AND
the boolean hivstatus field, it has a keyspace larger than 1 bit, and
thus leaks less information via hash collisions.

### EncryptedField

Safely storing boolean fields with the `EncryptedField` API, rather than
the `EncryptedRow` API, is possible but requires a bit more glue code.

#### Util::boolToChr() and Util::chrToBool()

CipherSweet provides a congruent method for compacting a nullable boolean
into one character

#### The Compound Transformation

The first rule for protect boolean fields is to **never create a blind index
on a boolean field in isolation.**

Instead, consider using the `Compound` transformation to combine
multiple values together.

#### Example Snippet

This code assumes an abstract `$dbh` object that supports an API that
looks like this:

* `insert(string $table, array $fieldToValueMap): bool`
* `search(string $table, array $conditions): array<int, array<string, mixed>>`

```php
<?php
use ParagonIE\CipherSweet\KeyProvider\StringProvider;
use ParagonIE\CipherSweet\Backend\ModernCrypto;
use ParagonIE\CipherSweet\BlindIndex;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\EncryptedField;
use ParagonIE\CipherSweet\Transformation\Compound;
use ParagonIE\CipherSweet\Transformation\LastFourDigits;
use ParagonIE\CipherSweet\Util;

$provider = new StringProvider(
    new ModernCrypto(),
    // Example key, chosen randomly, hex-encoded:
    '4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc'
);

/** @var CipherSweet $engine */
$engine = new CipherSweet($provider);

$field = (new EncryptedField($engine, 'contacts', 'hivstatus'))
    // Add a blind index for HIV status and the "last 4 of SSN":
    ->addBlindIndex(
        new BlindIndex(
            // Name (used in key splitting):
            'contact_hivstatus_ssn',
            // List of Transforms:
            [new Compound()],
            // Bloom filter size (bits)
            16
        )
    );

$lastFour = new LastFourDigits();

// Storage
$ciphertext = $field->encryptValue(Util::boolToChr($hivStatus));
$index = $field->getBlindIndex(
    [$hivStatus, $lastFour($lastFourSSN)],
    'contact_hivstatus_ssn'
);
$dbh->insert('contacts', [
    'hivstatus' => $ciphertext,
    'contact_hivstatus_ssn' => $index
]);

// Retrieval
$lookup = $field->getBlindIndex(
    [$givenHIVStatus, $lastFour($givenLastFourSSN)],
    'contact_hivstatus_ssn'
);
$results = $dbh->search('contacts', ['contact_hivstatus_ssn' => $lookup]);
foreach ($results as $result) {
    $status = Util::chrToBool(
        $field->decryptValue($result['hivstatus'])
    );
    // ... Do whatever else with the results
}
```

# Example: Getting Data Into and Out of the Database

The following example uses [Latitude](https://github.com/shadowhand/latitude)
and [EasyDB](https://github.com/paragonie/easydb) (required PHP 7.1+):

```php
<?php
use ParagonIE\CipherSweet\BlindIndex;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\EncryptedField;
use ParagonIE\CipherSweet\Transformation\LastFourDigits;
use ParagonIE\EasyDB\EasyDB;
use Latitude\QueryBuilder\Engine\CommonEngine;
use Latitude\QueryBuilder\QueryFactory;
use function Latitude\QueryBuilder\field;

/** @var CipherSweet $engine */
$ssnField = (new EncryptedField($engine, 'contacts', 'ssn'))
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

# INSERTING A NEW RECORD:
/**
 * @var string $ciphertext
 * @var array<string, string> $indexes
 */
list ($ciphertext, $indexes) = $ssnField->prepareForStorage($contactInfo['ssn']);
/** @var EasyDB $db */
$db->insert(
    'contacts',
    [
        'name' => $contactInfo['name'],
        'email' => $contactInfo['email'],
        'ssn' => $ciphertext,
        'ssn_idx' => $indexes['contact_ssn'],
        'ssn_last_four_idx' => $indexes['contact_ssn_last_four']
    ]
);

# SEARCHING AND DECRYPTING:
$indexValue = $ssnField->getBlindIndex($contactInfo['ssn'], 'contact_ssn_last_four');

/** @var QueryFactory $factory */
$factory = new QueryFactory(new CommonEngine());
$query = $factory
    ->select('id', 'name', 'email', 'ssn')
    ->from('contacts')
    ->where(field('ssn_last_four_idx')->eq($indexValue['value']))
    ->compile();

$results = $db->safeQuery($query->sql(), $query->params());
foreach ($results as $row) {
    $decryptedSSN = $ssnField->decryptValue($row['ssn']);
    if (\hash_equals($contactInfo['ssn'], $decryptedSSN)) {
        // Found record:
        var_dump([
            'name' => $row['name'],
            'email' => $row['email']
        ]);
    }
}
```

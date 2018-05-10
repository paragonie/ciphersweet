# Example: Getting Data Into and Out of the Database

The following example uses the PDO extension using the MySQL driver.

```php
<?php
use ParagonIE\CipherSweet\BlindIndex;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\EncryptedField;
use ParagonIE\CipherSweet\Transformation\LastFourDigits;
use ParagonIE\CipherSweet\KeyProvider\StringProvider;
use ParagonIE\CipherSweet\Backend\ModernCrypto;

$pdo = new PDO(
    'mysql:host=127.0.0.1:3306;dbname=testdb;charset=utf8',
    'username',
    'password',
    [
        PDO::ATTR_EMULATE_PREPARES => false,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
    ]
);

$createTableQuery = '
CREATE TABLE IF NOT EXISTS contacts (
    id int(10) unsigned NOT NULL AUTO_INCREMENT,
    name varchar(40) NOT NULL,
    email varchar(40) NOT NULL,
    ssn text NOT NULL,
    ssn_idx varchar(40) NOT NULL,
    ssn_last_four_idx varchar(4) NOT NULL,
    PRIMARY KEY (id)
) ENGINE=InnoDB;
';

$pdo->query($createTableQuery);

$provider = new StringProvider(
    new ModernCrypto(),
    // Example key, chosen randomly, hex-encoded:
    '4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc'
);

/** @var CipherSweet $engine */
$engine = new CipherSweet($provider);

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

$insertQuery = 'INSERT INTO contacts (name, email, ssn, ssn_idx, ssn_last_four_idx) VALUES (:name, :email, :ssn, :ssn_idx, :ssn_last_four_idx);';
$stmt = $pdo->prepare($insertQuery);
$stmt->bindValue('name', $contactInfo['name'], PDO::PARAM_STR);
$stmt->bindValue('email', $contactInfo['email'], PDO::PARAM_STR);
$stmt->bindValue('ssn', $ciphertext, PDO::PARAM_STR);
$stmt->bindValue('ssn_idx', $indexes['contact_ssn']['value'], PDO::PARAM_STR);
$stmt->bindValue('ssn_last_four_idx', $indexes['contact_ssn_last_four']['value'], PDO::PARAM_STR);
$stmt->execute();

# SEARCHING AND DECRYPTING:
$indexValue = $ssnField->getBlindIndex($contactInfo['ssn'], 'contact_ssn_last_four');

$selectQuery = 'SELECT id, name, email, ssn FROM contacts WHERE ssn_last_four_idx = :ssn_last_four_idx';
$stmt = $pdo->prepare($selectQuery);
$stmt->bindValue('ssn_last_four_idx', $indexValue['value'], PDO::PARAM_STR);
$stmt->execute();
$results = $stmt->fetchAll();

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

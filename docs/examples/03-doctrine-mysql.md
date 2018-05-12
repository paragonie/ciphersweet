# Example: Getting Data Into and Out of the Database

The following example uses the Doctrine ORM using PDO with the MySQL driver.

Firstly we need an entity:

```php
<?php
class Contact
{
    private $id;
    private $name;
    private $email;
    private $ssn;
    private $ssn_idx;
    private $ssn_last_four_idx;

    public function __construct(
        string $name,
        string $email,
        string $ssn
    )
    {
        $this->name = $name;
        $this->email = $email;
        $this->ssn = $ssn;
    }

    public function name()
    {
        return $this->name;
    }

    public function email()
    {
        return $this->email;
    }

    public function ssn()
    {
        return $this->ssn;
    }

    public function withIndexes(string $ssn_idx, string $ssn_last_four_idx)
    {
        $new = clone $this;
        $new->ssn_idx = $ssn_idx;
        $new->ssn_last_four_idx = $ssn_last_four_idx;

        return $new;
    }
}

```

And some entity configuration:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<doctrine-mapping xmlns="http://doctrine-project.org/schemas/orm/doctrine-mapping"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="http://doctrine-project.org/schemas/orm/doctrine-mapping
                          http://www.doctrine-project.org/schemas/orm/doctrine-mapping.xsd">

    <entity name="Contact" table="contacts">
        <id name="id" type="integer" column="id">
            <generator strategy="AUTO" />
        </id>
        <field name="name" column="name" type="string" length="50" nullable="true" unique="true" />
        <field name="email" column="email" type="string" column-definition="CHAR(32) NOT NULL" />
        <field name="ssn" column="ssn" type="text" />
        <field name="ssn_idx" column="ssn_idx" type="text" />
        <field name="ssn_last_four_idx" column="ssn_last_four_idx" type="text" />
    </entity>
</doctrine-mapping>
```

```php
<?php
use ParagonIE\CipherSweet\BlindIndex;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\EncryptedField;
use ParagonIE\CipherSweet\Transformation\LastFourDigits;
use ParagonIE\CipherSweet\KeyProvider\StringProvider;
use ParagonIE\CipherSweet\Backend\ModernCrypto;
use Doctrine\ORM\Tools\Setup;
use Doctrine\ORM\EntityManager;

require "/path/to/Entity.php";

$config = new \Doctrine\DBAL\Configuration();

$dbParams = array(
    'dbname'   => 'testdb',
    'user'     => 'username',
    'password' => 'password',
    'host'     => '127.0.0.1',
    'driver'   => 'pdo_mysql',
    'port'     => 3306,
    'charset'  => 'utf8'
);

$isDevMode = true;

$config = Setup::createAnnotationMetadataConfiguration([], $isDevMode);
$driver = new \Doctrine\ORM\Mapping\Driver\XmlDriver(["/path/to/dcm-xml-files"]);
$config->setMetadataDriverImpl($driver);

$entityManager = EntityManager::create($dbParams, $config);

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

$entityManager->getConnection()->query($createTableQuery);

$provider = new StringProvider(
    new ModernCrypto(),
    // Example key, chosen randomly, hex-encoded:
    ParagonIE\ConstantTime\Hex::encode(random_bytes(32))
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

$contact = new Contact($contactInfo['name'], $contactInfo['email'], $ciphertext);
$contact = $contact->withIndexes(
    $indexes['contact_ssn']['value'],
    $indexes['contact_ssn_last_four']['value']
);

$entityManager->persist($contact);
$entityManager->flush();

# SEARCHING AND DECRYPTING:
$indexValue = $ssnField->getBlindIndex($contactInfo['ssn'], 'contact_ssn_last_four');

$repository = $entityManager->getRepository('Contact');
$results = $repository->findBy(
    [
        'ssn_last_four_idx' => $indexValue['value']
    ]
);

foreach ($results as $contact) {
    $decryptedSSN = $ssnField->decryptValue($contact->ssn());
    if (\hash_equals($contactInfo['ssn'], $decryptedSSN)) {
        // Found record:
        var_dump([
            'name' => $contact->name(),
            'email' => $contact->email()
        ]);
    }
}
```

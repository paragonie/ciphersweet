<?php
namespace ParagonIE\CipherSweet\Tests;

use ParagonIE\CipherSweet\Backend\FIPSCrypto;
use ParagonIE\CipherSweet\Backend\ModernCrypto;
use ParagonIE\CipherSweet\BlindIndex;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\EncryptedRow;
use ParagonIE\CipherSweet\Exception\ArrayKeyException;
use ParagonIE\CipherSweet\Exception\BlindIndexNameCollisionException;
use ParagonIE\CipherSweet\Exception\BlindIndexNotFoundException;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;
use ParagonIE\CipherSweet\Exception\InvalidCiphertextException;
use ParagonIE\CipherSweet\JsonFieldMap;
use ParagonIE\CipherSweet\Transformation\LastFourDigits;
use ParagonIE\ConstantTime\Binary;
use PHPUnit\Framework\TestCase;
use ParagonIE\CipherSweet\Tests\Transformation\FirstInitialLastName;

/**
 * Class EncryptedRowTest
 * @package ParagonIE\CipherSweet\Tests
 */
class EncryptedRowTest extends TestCase
{
    use CreatesEngines;

    /**
     * @var CipherSweet $fipsEngine
     */
    protected $fipsEngine;

    /**
     * @var CipherSweet $naclEngine
     */
    protected $naclEngine;

    /**
     * @var CipherSweet $naclEngine
     */
    protected $brngEngine;

    /**
     * @var CipherSweet $fipsRandom
     */
    protected $fipsRandom;

    /**
     * @var CipherSweet $naclRandom
     */
    protected $naclRandom;

    /**
     * @var CipherSweet $naclRandom
     */
    protected $brngRandom;

    /**
     * @before
     * @throws CryptoOperationException
     */
    public function before()
    {
        $this->fipsEngine = $this->createFipsEngine('4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc');
        $this->naclEngine = $this->createModernEngine('4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc');
        $this->brngEngine = $this->createBoringEngine('4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc');

        $this->fipsRandom = $this->createFipsEngine();
        $this->naclRandom = $this->createModernEngine();
        $this->brngRandom = $this->createBoringEngine();
    }

    /**
     * @throws ArrayKeyException
     * @throws CryptoOperationException
     * @throws \SodiumException
     */
    public function testSimpleEncrypt()
    {
        $eF = (new EncryptedRow($this->fipsRandom, 'contacts'));
        $eM = (new EncryptedRow($this->naclRandom, 'contacts'));
        $eF->addTextField('message');
        $eM->addTextField('message');

        $message = 'This is a test message: ' . \random_bytes(16);
        $row     = [
            'message' => $message
        ];

        $fCipher = $eF->encryptRow($row);
        $mCipher = $eM->encryptRow($row);

        $this->assertSame(
            FIPSCrypto::MAGIC_HEADER,
            Binary::safeSubstr($fCipher['message'], 0, 5)
        );
        $this->assertSame(
            ModernCrypto::MAGIC_HEADER,
            Binary::safeSubstr($mCipher['message'], 0, 5)
        );

        $this->assertSame($row, $eF->decryptRow($fCipher));
        $this->assertSame($row, $eM->decryptRow($mCipher));
    }

    /**
     * @throws ArrayKeyException
     * @throws CryptoOperationException
     * @throws \SodiumException
     */
    public function testEncryptWithAAD()
    {
        $eFwithout = (new EncryptedRow($this->fipsRandom, 'contacts'));
        $eMwithout = (new EncryptedRow($this->naclRandom, 'contacts'));
        $eFwithout->addTextField('message');
        $eMwithout->addTextField('message');

        $eF = (new EncryptedRow($this->fipsRandom, 'contacts'));
        $eM = (new EncryptedRow($this->naclRandom, 'contacts'));
        $eF->addTextField('message', 'id');
        $eM->addTextField('message', 'id');

        $message = 'This is a test message: ' . \random_bytes(16);
        $row     = [
            'id' => 123,
            'message' => $message
        ];
        $row2     = [
            'id' => 124,
            'message' => $message
        ];

        $fCipher = $eF->encryptRow($row);
        $mCipher = $eM->encryptRow($row);
        $fCipher2 = $eF->encryptRow($row2);
        $mCipher2 = $eM->encryptRow($row2);
        $fCipherWithAD = $eFwithout->encryptRow($row);
        $mCipherWithAD = $eMwithout->encryptRow($row);
        $fCipherWithAD2 = $eFwithout->encryptRow($row2);
        $mCipherWithAD2 = $eMwithout->encryptRow($row2);


        try {
            $eF->decryptRow($fCipherWithAD);
            $this->fail('AAD was permitted when ciphertext had none');
        } catch (\Exception $ex) {
            $this->assertInstanceOf(InvalidCiphertextException::class, $ex);
        }
        if (PHP_VERSION_ID !== 70300) { // PHP bug #77297
            try {
                $eM->decryptRow($mCipherWithAD);
                $this->fail('AAD was permitted when ciphertext had none');
            } catch (\Exception $ex) {
                $this->assertInstanceOf('SodiumException', $ex);
            }
        }

        try {
            $eFwithout->decryptRow($fCipher);
            $this->fail('AAD stripping was permitted');
        } catch (\Exception $ex) {
            $this->assertInstanceOf(InvalidCiphertextException::class, $ex);
        }
        if (PHP_VERSION_ID !== 70300) { // PHP bug #77297
            try {
                $eMwithout->decryptRow($mCipher);
                $this->fail('AAD stripping was permitted');
            } catch (\Exception $ex) {
                $this->assertInstanceOf('SodiumException', $ex);
            }
        }
        try {
            $fCipher2['id'] = $row['id'];
            $eFwithout->decryptRow($fCipher2);
            $this->fail('AAD stripping was permitted');
        } catch (\Exception $ex) {
            $this->assertInstanceOf(InvalidCiphertextException::class, $ex);
        }
        if (PHP_VERSION_ID !== 70300) { // PHP bug #77297
            try {
                $mCipher2['id'] = $row['id'];
                $eMwithout->decryptRow($mCipher2);
                $this->fail('AAD stripping was permitted');
            } catch (\Exception $ex) {
                $this->assertInstanceOf('SodiumException', $ex);
            }
        }
        try {
            $fCipherWithAD2['id'] = $row['id'];
            $eF->decryptRow($fCipherWithAD2);
            $this->fail('AAD stripping was permitted');
        } catch (\Exception $ex) {
            $this->assertInstanceOf(InvalidCiphertextException::class, $ex);
        }
        if (PHP_VERSION_ID !== 70300) { // PHP bug #77297
            try {
                $mCipherWithAD2['id'] = $row['id'];
                $eM->decryptRow($mCipherWithAD2);
                $this->fail('AAD stripping was permitted');
            } catch (\Exception $ex) {
                $this->assertInstanceOf('SodiumException', $ex);
            }
        }
    }

    /**
     * @throws ArrayKeyException
     * @throws BlindIndexNotFoundException
     * @throws CryptoOperationException
     * @throws \SodiumException
     */
    public function testGetIndexFromPartialInfo()
    {
        $row = [
            'ssn' => '123-45-6789',
            'hivstatus' => true
        ];
        $eF = $this->getExampleRow($this->fipsEngine, true);
        $eF
            ->setFlatIndexes(true)
            ->addTextField('extraneous'); // We aren't providing this one in $row.

        $indexes = $eF->getAllBlindIndexes($row);
        $this->assertEquals('a88e74ada916ab9b', $indexes['contact_ssn_last_four']);
        $this->assertEquals('9c3d53214ab71d7f', $indexes['contact_ssnlast4_hivstatus']);

        $this->assertSame(
            'a88e74ada916ab9b',
            $eF->getBlindIndex('contact_ssn_last_four', $row)
        );

        if (\ParagonIE_Sodium_Compat::crypto_pwhash_is_available()) {
            $eM = $this->getExampleRow($this->naclEngine, true);
            $eM
                ->setFlatIndexes(true)
                ->addTextField('extraneous'); // We aren't providing this one in $row.

            $indexes = $eM->getAllBlindIndexes($row);
            $this->assertEquals('2acbcd1c7c55c1db', $indexes['contact_ssn_last_four']);
            $this->assertEquals('1b8c1e1f8e122bd3', $indexes['contact_ssnlast4_hivstatus']);
        }
    }

    /**
     * @throws CryptoOperationException
     * @throws ArrayKeyException
     * @throws \SodiumException
     */
    public function testGetAllIndexes()
    {
        $row = [
            'extraneous' => 'this is unecnrypted',
            'ssn' => '123-45-6789',
            'hivstatus' => true
        ];
        $eF = $this->getExampleRow($this->fipsEngine, true);

        $indexes = $eF->getAllBlindIndexes($row);
        $this->assertEquals('a88e74ada916ab9b', $indexes['contact_ssn_last_four']['value']);
        $this->assertEquals('9c3d53214ab71d7f', $indexes['contact_ssnlast4_hivstatus']['value']);
    }
    /**
     * @throws CryptoOperationException
     * @throws ArrayKeyException
     * @throws \SodiumException
     */
    public function testGetAllIndexesFlat()
    {
        $row = [
            'extraneous' => 'this is unecnrypted',
            'ssn' => '123-45-6789',
            'hivstatus' => true
        ];
        $eF = $this->getExampleRow($this->fipsEngine, true);
        $eF->setFlatIndexes(true);

        $indexes = $eF->getAllBlindIndexes($row);
        $this->assertEquals('a88e74ada916ab9b', $indexes['contact_ssn_last_four']);
        $this->assertEquals('9c3d53214ab71d7f', $indexes['contact_ssnlast4_hivstatus']);

        $this->assertEquals(
            'xbobk6kf7kqcm',
            $eF->getBlindIndexType('contacts', 'contact_ssn_last_four')
        );
        $this->assertEquals(
            'dozudszz2yu5k',
            $eF->getCompoundIndexType('contact_ssnlast4_hivstatus')
        );
    }

    /**
     * @throws ArrayKeyException
     * @throws CryptoOperationException
     * @throws \SodiumException
     */
    public function testEncrypt()
    {
        $row = [
            'extraneous' => 'this is unecnrypted',
            'ssn' => '123-45-6789',
            'hivstatus' => true
        ];
        $eF = $this->getExampleRow($this->fipsRandom, true);
        $eM = $this->getExampleRow($this->naclRandom, true);

        /** @var EncryptedRow $engine */
        foreach ([$eM, $eF] as $engine) {
            $store = $engine->encryptRow($row);
            $this->assertSame($store['extraneous'], $row['extraneous']);
            $this->assertNotSame($store['ssn'], $row['ssn']);
            $this->assertNotSame($store['hivstatus'], $row['hivstatus']);
        }
    }

    /**
     * @throws CryptoOperationException
     * @throws \ParagonIE\CipherSweet\Exception\ArrayKeyException
     * @throws \SodiumException
     */
    public function testPrepareForStorage()
    {
        $eF = $this->getExampleRow($this->fipsRandom, true);
        $flat = $this->getExampleRow($this->fipsRandom, true);
        $flat->setFlatIndexes(true);

        $rows = [
            [
                'ssn' => '111-11-1111',
                'hivstatus' => false
            ],
            [
                'ssn' => '123-45-6789',
                'hivstatus' => false
            ],
            [
                'ssn' => '999-99-6789',
                'hivstatus' => false
            ],
            [
                'ssn' => '123-45-1111',
                'hivstatus' => true
            ],
            [
                'ssn' => '999-99-1111',
                'hivstatus' => true
            ],
            [
                'ssn' => '123-45-6789',
                'hivstatus' => true
            ]
        ];
        foreach ($rows as $row) {
            list($store, $indexes) = $eF->prepareRowForStorage($row);
            $this->assertTrue(\is_array($store));
            $this->assertTrue(\is_string($store['ssn']));
            $this->assertTrue(\is_string($store['hivstatus']));
            $this->assertNotSame($row['ssn'], $store['ssn']);
            $this->assertNotSame($row['hivstatus'], $store['hivstatus']);
            $this->assertTrue(\is_array($indexes));

            list($store, $indexes) = $flat->prepareRowForStorage($row);
            $this->assertTrue(\is_array($store));
            $this->assertTrue(\is_string($store['ssn']));
            $this->assertTrue(\is_string($store['hivstatus']));
            $this->assertNotSame($row['ssn'], $store['ssn']);
            $this->assertNotSame($row['hivstatus'], $store['hivstatus']);
            $this->assertTrue(\is_array($indexes));
        }
    }

    /**
     * @param CipherSweet $backend
     * @param bool $longer
     * @param bool $fast
     *
     * @return EncryptedRow
     */
    public function getExampleRow(
        CipherSweet $backend,
        $longer = false,
        $fast = false
    ) {
        $row = (new EncryptedRow($backend, 'contacts'))
            ->addTextField('ssn')
            ->addBooleanField('hivstatus');

        $row->addBlindIndex(
            'ssn',
            new BlindIndex(
            // Name (used in key splitting):
                'contact_ssn_last_four',
                // List of Transforms:
                [new LastFourDigits()],
                // Output length (bytes)
                $longer ? 64 : 16,
                $fast
            )
        );
        $row->createCompoundIndex(
            'contact_ssnlast4_hivstatus',
            ['ssn', 'hivstatus'],
            $longer ? 64 : 16,
            $fast
        );
        return $row;
    }

    /**
     * @throws ArrayKeyException
     * @throws CryptoOperationException
     * @throws BlindIndexNotFoundException
     * @throws \SodiumException
     */
    public function testRowTransform()
    {
        $row = (new EncryptedRow($this->fipsRandom, 'users'))
            ->addTextField('first_name')
            ->addTextField('last_name');
        $row->addCompoundIndex(
            $row->createCompoundIndex(
                'first_init_last_name',
                ['first_name', 'last_name'],
                64,
                true
            )->addRowTransform(new FirstInitialLastName())
        );
        $this->assertEquals(
            $row->getAllBlindIndexes(['first_name' => 'John', 'last_name' => 'Smith']),
            $row->getAllBlindIndexes(['first_name' => 'Jane', 'last_name' => 'Smith'])
        );
        $this->assertNotEquals(
            $row->getAllBlindIndexes(['first_name' => 'John', 'last_name' => 'Smith']),
            $row->getAllBlindIndexes(['first_name' => 'Ryan', 'last_name' => 'Smith'])
        );
        $this->assertNotEquals(
            $row->getAllBlindIndexes(['first_name' => 'John', 'last_name' => 'Smith']),
            $row->getAllBlindIndexes(['first_name' => 'Jane', 'last_name' => 'Doe'])
        );
        $row->addCompoundIndex($row->createCompoundIndex(
            'full_name',
            ['first_name', 'last_name'],
            64,
            true
        ));
        $this->assertEquals(
            $row->getBlindIndex('first_init_last_name', ['first_name' => 'John', 'last_name' => 'Smith']),
            $row->getBlindIndex('first_init_last_name', ['first_name' => 'Jane', 'last_name' => 'Smith'])
        );
        $this->assertNotEquals(
            $row->getBlindIndex('full_name', ['first_name' => 'John', 'last_name' => 'Smith']),
            $row->getBlindIndex('full_name', ['first_name' => 'Jane', 'last_name' => 'Smith'])
        );
    }

    public function engineProvider()
    {
        if (!isset($this->fipsEngine)) {
            $this->before();
        }
        return [
            [$this->fipsEngine],
            [$this->fipsRandom],
            [$this->naclEngine],
            [$this->naclRandom],
            [$this->brngEngine],
            [$this->brngRandom]
        ];
    }

    /**
     * @dataProvider engineProvider
     */
    public function testJsonField(CipherSweet $engine)
    {
        $eR = new EncryptedRow($engine, 'foo');
        $eR->addJsonField('bar', new JsonFieldMap());
        $this->assertInstanceOf(JsonFieldMap::class, $eR->getJsonFieldMap('bar'));

        $null = $eR->encryptRow(['bar' => ['test' => true]]);
        $this->assertSame(['bar' => '{"test":true}'], $null);

        $eR->getJsonFieldMap('bar')
            ->addTextField('baz');

        $plaintext = ['bar' => ['baz' => 'abdefg', 'qux' => 1234]];
        $some = $eR->encryptRow($plaintext);
        $array = json_decode($some['bar'], true);
        $this->assertStringStartsWith(
            $engine->getBackend()->getPrefix(),
            $array['baz']
        );
        $this->assertSame(1234, $array['qux']);
        $this->assertSame($plaintext, $eR->decryptRow($some));
    }
}

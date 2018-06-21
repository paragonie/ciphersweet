<?php
namespace ParagonIE\CipherSweet\Tests;

use ParagonIE\CipherSweet\Backend\FIPSCrypto;
use ParagonIE\CipherSweet\Backend\ModernCrypto;
use ParagonIE\CipherSweet\BlindIndex;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\EncryptedRow;
use ParagonIE\CipherSweet\Exception\ArrayKeyException;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;
use ParagonIE\CipherSweet\KeyProvider\StringProvider;
use ParagonIE\CipherSweet\Transformation\LastFourDigits;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\ConstantTime\Hex;
use PHPUnit\Framework\TestCase;

/**
 * Class EncryptedRowTest
 * @package ParagonIE\CipherSweet\Tests
 */
class EncryptedRowTest extends TestCase
{
    /**
     * @var CipherSweet $fipsEngine
     */
    protected $fipsEngine;

    /**
     * @var CipherSweet $naclEngine
     */
    protected $naclEngine;

    /**
     * @var CipherSweet $fipsRandom
     */
    protected $fipsRandom;

    /**
     * @var CipherSweet $naclRandom
     */
    protected $naclRandom;

    /**
     * @throws CryptoOperationException
     */
    public function setUp()
    {
        $fips = new FIPSCrypto();
        $nacl = new ModernCrypto();

        $this->fipsEngine = new CipherSweet(
            new StringProvider(
                $fips,
                Hex::decode(
                    '4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc'
                )
            )
        );
        $this->naclEngine = new CipherSweet(
            new StringProvider(
                $nacl,
                Hex::decode(
                    '4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc'
                )
            )
        );

        $this->fipsRandom = new CipherSweet(
            new StringProvider(
                $fips,
                \random_bytes(32)
            )
        );
        $this->naclRandom = new CipherSweet(
            new StringProvider(
                $nacl,
                \random_bytes(32)
            )
        );
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
        $this->assertEquals('abd9497d226601a2', $indexes['contact_ssn_last_four']['value']);
        $this->assertEquals('9c3d53214ab71d7f', $indexes['contact_ssnlast4_hivstatus']['value']);
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
        }
    }

    /**
     * @param CipherSweet $backend
     * @param bool $longer
     * @param bool $fast
     *
     * @return EncryptedRow
     * @throws BlindIndexNameCollisionException
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
}

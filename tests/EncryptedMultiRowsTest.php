<?php
namespace ParagonIE\CipherSweet\Tests;

use ParagonIE\CipherSweet\BlindIndex;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\EncryptedMultiRows;
use ParagonIE\CipherSweet\Backend\FIPSCrypto;
use ParagonIE\CipherSweet\Backend\ModernCrypto;
use ParagonIE\CipherSweet\Exception\InvalidCiphertextException;
use ParagonIE\CipherSweet\KeyProvider\StringProvider;
use ParagonIE\CipherSweet\Transformation\Lowercase;
use ParagonIE\ConstantTime\Hex;
use PHPUnit\Framework\TestCase;

/**
 * Class EncryptedMultiRowsTest
 * @package ParagonIE\CipherSweet\Tests
 */
class EncryptedMultiRowsTest extends TestCase
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
     * @throws \Exception
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

    public function testEncryptedMultiRowsSetup()
    {
        $engines = [$this->fipsEngine, $this->fipsRandom, $this->naclEngine, $this->naclRandom];
        foreach ($engines as $engine) {
            $mr = (new EncryptedMultiRows($engine))
                ->addTable('foo')
                ->addTable('bar');
            $this->assertSame(['foo', 'bar'], $mr->listTables(), 'Tables test 1');

            $mr->addTextField('foo', 'column1');
            $mr->addBooleanField('foo', 'column2');
            $this->assertSame(['foo', 'bar'], $mr->listTables(), 'Tables test 2');

            $mr->addIntegerField('baz', 'column1');
            $this->assertSame(['foo', 'bar', 'baz'], $mr->listTables(), 'Tables test 3');

            $eR = $mr->getEncryptedRowObjectForTable('foo');
            $this->assertSame(['column1', 'column2'], $eR->listEncryptedFields(), 'Encrypted fields test 1');

            $eR = $mr->getEncryptedRowObjectForTable('bar');
            $this->assertSame([], $eR->listEncryptedFields(), 'Encrypted fields test 2');

            $eR = $mr->getEncryptedRowObjectForTable('baz');
            $this->assertSame(['column1'], $eR->listEncryptedFields(), 'Encrypted fields test 2');
        }
    }

    /**
     * @return EncryptedMultiRows
     */
    public function getMultiRows()
    {
        $mr = (new EncryptedMultiRows($this->fipsEngine))
            ->addTable('foo')
            ->addTable('bar');
        $mr->addIntegerField('foo', 'column1')
            ->addTextField('foo', 'column2')
            ->addBooleanField('foo', 'column3');
        $mr->addIntegerField('bar', 'column1');
        $mr->addIntegerField('baz', 'column1');

        $mr->addBlindIndex(
            'foo',
            'column2',
            (new BlindIndex('foo_column2_idx', [new Lowercase()], 32, true))
        );
        return $mr;
    }

    /**
     * @throws \ParagonIE\CipherSweet\Exception\ArrayKeyException
     * @throws \ParagonIE\CipherSweet\Exception\CryptoOperationException
     * @throws \SodiumException
     */
    public function testUsage()
    {
        $mr = $this->getMultiRows();

        $rows = [
            'foo' => [
                'id' => 123456,
                'column1' => 654321,
                'column2' => 'paragonie',
                'column3' => true,
                'extra' => 'test'
            ],
            'bar' => [
                'id' => 554353,
                'foo_id' => 123456,
                'column1' => 654321
            ],
            'baz' => [
                'id' => 3174521,
                'foo_id' => 123456,
                'column1' => 654322
            ]
        ];
        list($outRow, $indexes) = $mr->prepareForStorage($rows);
        $decrypted = $mr->decryptManyRows($outRow);
        $this->assertNotSame($outRow, $decrypted, 'prepareForStorage() encryption');
        $this->assertSame($rows, $decrypted, 'prepareForStorage() decryption');
        $this->assertEquals($indexes, [
            'foo' => [
                'foo_column2_idx' => [
                    'type' => 'vxb6t3nzfqqv2',
                    'value' => '65b71d96'
                ]
            ],
            'bar' => [],
            'baz' => []
        ], 'prepareForStorage() indices');

        $decrypt2 = $mr->decryptManyRows($outRow);
        $this->assertSame($decrypted, $decrypt2, 'Both decryption APIs must produce the same output');

        $indexes2 = $mr->getAllBlindIndexes($rows);
        $this->assertSame($indexes, $indexes2, 'Both blind index APIs must produce the same output');

        // Additional authenticated data (sourced from ID column)
        $mr2 = $this->getMultiRows()
            ->setAadSourceField('foo', 'column1', 'id');
        $outRow2 = $mr2->encryptManyRows($rows);
        $decrypted2 = $mr2->decryptManyRows($outRow2);

        $this->assertSame($rows, $decrypted2, 'Decryption must be the same');
        try {
            $mr->decryptManyRows($outRow2);
            $this->fail('AAD stripping was permitted');
        } catch (\Exception $ex) {
            $this->assertInstanceOf(InvalidCiphertextException::class, $ex);
        }
        try {
            $mr2->decryptManyRows($outRow);
            $this->fail('AAD stripping was permitted');
        } catch (\Exception $ex) {
            $this->assertInstanceOf(InvalidCiphertextException::class, $ex);
        }
    }
}

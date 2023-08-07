<?php
namespace ParagonIE\CipherSweet\Tests;

use ParagonIE\CipherSweet\BlindIndex;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\EncryptedMultiRows;
use ParagonIE\CipherSweet\Exception\ArrayKeyException;
use ParagonIE\CipherSweet\Exception\CipherSweetException;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;
use ParagonIE\CipherSweet\Exception\InvalidCiphertextException;
use ParagonIE\CipherSweet\JsonFieldMap;
use ParagonIE\CipherSweet\Transformation\Lowercase;
use PHPUnit\Framework\TestCase;
use SodiumException;

/**
 * Class EncryptedMultiRowsTest
 * @package ParagonIE\CipherSweet\Tests
 */
class EncryptedMultiRowsTest extends TestCase
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
     * @var CipherSweet $boringEngine
     */
    protected $boringEngine;

    /**
     * @var CipherSweet $fipsRandom
     */
    protected $fipsRandom;

    /**
     * @var CipherSweet $naclRandom
     */
    protected $naclRandom;

    /**
     * @var CipherSweet $boringRandom
     */
    protected $boringRandom;

    /**
     * @beforeClass
     * @before
     * @throws \Exception
     */
    public function before()
    {
        $this->fipsEngine = $this->createFipsEngine('4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc');
        $this->naclEngine = $this->createModernEngine('4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc');
        $this->boringEngine = $this->createBoringEngine('4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc');

        $this->fipsRandom = $this->createFipsEngine();
        $this->naclRandom = $this->createModernEngine();
        $this->boringRandom = $this->createBoringEngine();
    }

    public function testFlatInherits()
    {
        $engines = [$this->fipsEngine, $this->fipsRandom, $this->naclEngine, $this->naclRandom];
        foreach ($engines as $engine) {
            $mr = (new EncryptedMultiRows($engine, true))
                ->addTable('foo')
                ->addTable('bar');

            foreach ($mr->listTables() as $table) {
                $this->assertSame(
                    $mr->getTypedIndexes(),
                    $mr->getEncryptedRowObjectForTable($table)->getTypedIndexes()
                );
            }
        }
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
    public function getMultiRows($engine = null)
    {
        if (empty($engine)) {
            $engine = $this->fipsEngine;
        }
        $mr = (new EncryptedMultiRows($engine))
            ->addTable('foo')
            ->addTable('bar');
        $mr->addIntegerField('foo', 'column1')
            ->addTextField('foo', 'column2')
            ->addBooleanField('foo', 'column3');
        $mr->addIntegerField('bar', 'column1');
        $mr->addIntegerField('baz', 'column1');

        $map = (new JsonFieldMap())
            ->addTextField('qux')
            ->addIntegerField('quux');

        $mr->addJsonField('foo', 'column4', $map);

        $mr->addBlindIndex(
            'foo',
            'column2',
            (new BlindIndex('foo_column2_idx', [new Lowercase()], 32, true))
        );
        return $mr;
    }

    /**
     * @throws ArrayKeyException
     * @throws CryptoOperationException
     * @throws CipherSweetException
     * @throws SodiumException
     */
    public function testUsage()
    {
        $mr = $this->getMultiRows();
        $rows = $this->getDummyPlaintext();

        $mr->setTypedIndexes(true);
        list($outRow, $indexes) = $mr->prepareForStorage($rows);
        $decrypted = $mr->decryptManyRows($outRow);
        $this->assertIsNotArray($outRow['foo']['column4'], 'column4 not encrypted');
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

    private function getDummyPlaintext()
    {
        return [
            'foo' => [
                'id' => 123456,
                'column1' => 654321,
                'column2' => 'paragonie',
                'column3' => true,
                'column4' => ['qux' => 'paragon', 'quux' => 1234],
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
    }

    /**
     * @dataProvider engineProvider
     *
     * @throws ArrayKeyException
     * @throws CryptoOperationException
     * @throws CipherSweetException
     * @throws SodiumException
     */
    public function testXAllEngines(CipherSweet $engine = null)
    {
        $mr = $this->getMultiRows($engine);
        $rows = $this->getDummyPlaintext();

        $mr->setTypedIndexes(true);
        list($outRow, $indexes) = $mr->prepareForStorage($rows);
        $decrypted = $mr->decryptManyRows($outRow);
        $this->assertIsNotArray($outRow['foo']['column4'], 'column4 not encrypted');
        $this->assertNotSame($outRow, $decrypted, 'prepareForStorage() encryption');
        $this->assertSame($rows, $decrypted, 'prepareForStorage() decryption');

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
            [$this->boringEngine],
            [$this->boringRandom]
        ];
    }

    /**
     * @dataProvider engineProvider
     */
    public function testFieldsAreNotSwappable(CipherSweet $engine): void
    {
        $eR = new EncryptedMultiRows($engine);
        $eR
            ->addOptionalTextField('foo', 'field1')
            ->addOptionalTextField('foo', 'field2');

        $plain = ['foo' => ['field1' => 'example', 'field2' => 'message']];
        $encrypted = $eR->encryptManyRows($plain);
        $swapped = [];
        [$swapped['foo']['field1'], $swapped['foo']['field2']] = [$encrypted['foo']['field2'], $encrypted['foo']['field1']];
        // Sanity check: Did we actually swap them?
        $this->assertSame($swapped['foo']['field2'], $encrypted['foo']['field1']);
        $this->assertSame($swapped['foo']['field1'], $encrypted['foo']['field2']);

        // Is decryption successful still?
        $decrypted = $eR->decryptManyRows($encrypted);
        $this->assertSame($plain['foo']['field1'], $decrypted['foo']['field1']);
        $this->assertSame($plain['foo']['field2'], $decrypted['foo']['field2']);

        // Okay, let's decryptRow() on the swapped values. This must throw.
        try {
            $eR->decryptManyRows($swapped);
            $this->fail('Expected decryptRow() to fail.');
        } catch (CipherSweetException|SodiumException) {
        }
    }

    /**
     * @dataProvider engineProvider
     */
    public function testOptionalFields(CipherSweet $engine): void
    {
        $eR = new EncryptedMultiRows($engine);
        $eR
            ->addOptionalBooleanField('foo', 'bar')
            ->addOptionalFloatField('foo', 'baz')
            ->addOptionalIntegerField('foo', 'qux')
            ->addOptionalTextField('foo', 'quux');

        $null = ['foo' => ['bar' => null, 'baz' => null, 'qux' => null, 'quux' => null]];
        $encrypted = $eR->encryptManyRows($null);
        $this->assertSame($null, $encrypted);

        // Boolean fields treat NULl as a value. Optional booleans do not.
        $eR->addBooleanField('foo', 'testing');
        $null['foo']['testing'] = null;
        $encrypted = $eR->encryptManyRows($null);
        $this->assertNotSame($null, $encrypted);

    }
}

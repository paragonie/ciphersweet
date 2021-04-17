<?php
namespace ParagonIE\CipherSweet\Tests\Rotator;

use ParagonIE\CipherSweet\BlindIndex;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\EncryptedMultiRows;
use ParagonIE\CipherSweet\Exception\ArrayKeyException;
use ParagonIE\CipherSweet\Exception\BlindIndexNameCollisionException;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;
use ParagonIE\CipherSweet\Exception\InvalidCiphertextException;
use ParagonIE\CipherSweet\KeyRotation\MultiRowsRotator;
use ParagonIE\CipherSweet\Tests\CreatesEngines;
use ParagonIE\CipherSweet\Transformation\Lowercase;
use PHPUnit\Framework\TestCase;

/**
 * Class RowRotatorTest
 * @package ParagonIE\CipherSweet\Tests\Rotator
 */
class MultiRowsRotatorTest extends TestCase
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
     * @var CipherSweet $fipsRandom
     */
    protected $fipsRandom;

    /**
     * @var CipherSweet $naclRandom
     */
    protected $naclRandom;

    /**
     * @before
     * @throws ArrayKeyException
     * @throws CryptoOperationException
     */
    public function before()
    {
        $this->fipsRandom = $this->createFipsEngine();
        $this->naclRandom = $this->createModernEngine();
    }

    /**
     * @throws ArrayKeyException
     * @throws BlindIndexNameCollisionException
     * @throws CryptoOperationException
     * @throws InvalidCiphertextException
     * @throws \SodiumException
     */
    public function testFipsToNacl()
    {
        $eF = $this->getExampleMultiRows($this->fipsRandom);
        $eM = $this->getExampleMultiRows($this->naclRandom);

        $message = 'This is a test message: ' . \random_bytes(16);
        $rows = [
            'foo' => [
                'column1' => 12345,
                'column2' => $message,
                'column3' => false,
                'column4' => 'testing'
            ],
            'bar' => [
                'column1' => 45,
                'extraneous' => 'test'
            ],
            'baz' => [
                'column1' => 67,
                'extraneous' => true
            ]
        ];
        $rotator = new MultiRowsRotator($eF, $eM);
        $fCipher = $eF->encryptManyRows($rows);
        $mCipher = $eM->encryptManyRows($rows);

        $this->assertTrue($rotator->needsReEncrypt($fCipher));
        $this->assertFalse($rotator->needsReEncrypt($mCipher));
    }

    /**
     * @param CipherSweet $backend
     * @param bool $longer
     * @param bool $fast
     *
     * @return EncryptedMultiRows
     * @throws BlindIndexNameCollisionException
     */
    public function getExampleMultiRows(CipherSweet $backend)
    {

        $mr = (new EncryptedMultiRows($backend))
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
}

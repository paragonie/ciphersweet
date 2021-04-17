<?php
namespace ParagonIE\CipherSweet\Tests\Rotator;

use ParagonIE\CipherSweet\BlindIndex;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\EncryptedRow;
use ParagonIE\CipherSweet\Exception\ArrayKeyException;
use ParagonIE\CipherSweet\Exception\BlindIndexNameCollisionException;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;
use ParagonIE\CipherSweet\Exception\InvalidCiphertextException;
use ParagonIE\CipherSweet\KeyRotation\RowRotator;
use ParagonIE\CipherSweet\Tests\CreatesEngines;
use ParagonIE\CipherSweet\Transformation\LastFourDigits;
use PHPUnit\Framework\TestCase;

/**
 * Class RowRotatorTest
 * @package ParagonIE\CipherSweet\Tests\Rotator
 */
class RowRotatorTest extends TestCase
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
        $eF = $this->getExampleRow($this->fipsRandom);
        $eM = $this->getExampleRow($this->naclRandom);

        $message = 'This is a test message: ' . \random_bytes(16);
        $rows = [
            [
                'ssn' => '111-11-1111',
                'message' => $message,
                'hivstatus' => false
            ],
            [
                'ssn' => '123-45-6789',
                'message' => $message,
                'hivstatus' => false
            ],
            [
                'ssn' => '999-99-6789',
                'message' => $message,
                'hivstatus' => false
            ],
            [
                'ssn' => '123-45-1111',
                'message' => $message,
                'hivstatus' => true
            ],
            [
                'ssn' => '999-99-1111',
                'message' => $message,
                'hivstatus' => true
            ],
            [
                'ssn' => '123-45-6789',
                'message' => $message,
                'hivstatus' => true
            ]
        ];
        $rotator = new RowRotator($eF, $eM);
        foreach ($rows as $row) {
            $fCipher = $eF->encryptRow($row);
            $mCipher = $eM->encryptRow($row);

            $this->assertTrue($rotator->needsReEncrypt($fCipher));
            $this->assertFalse($rotator->needsReEncrypt($mCipher));
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

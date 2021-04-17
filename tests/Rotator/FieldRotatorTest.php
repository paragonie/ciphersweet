<?php
namespace ParagonIE\CipherSweet\Tests\Rotator;

use ParagonIE\CipherSweet\BlindIndex;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\EncryptedField;
use ParagonIE\CipherSweet\Exception\ArrayKeyException;
use ParagonIE\CipherSweet\Exception\BlindIndexNameCollisionException;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;
use ParagonIE\CipherSweet\Exception\InvalidCiphertextException;
use ParagonIE\CipherSweet\KeyRotation\FieldRotator;
use ParagonIE\CipherSweet\Tests\CreatesEngines;
use ParagonIE\CipherSweet\Transformation\LastFourDigits;
use PHPUnit\Framework\TestCase;

/**
 * Class FieldRotatorTest
 * @package ParagonIE\CipherSweet\Tests\Rotator
 */
class FieldRotatorTest extends TestCase
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
     * @throws BlindIndexNameCollisionException
     * @throws CryptoOperationException
     * @throws InvalidCiphertextException
     */
    public function testFipsToNacl()
    {
        $eF = $this->getExampleField($this->fipsRandom);
        $eM = $this->getExampleField($this->naclRandom);

        $message = 'This is a test message: ' . \random_bytes(16);
        $fCipher = $eF->encryptValue($message);
        $mCipher = $eM->encryptValue($message);

        $rotator = new FieldRotator($eF, $eM);
        $this->assertTrue($rotator->needsReEncrypt($fCipher));
        $this->assertFalse($rotator->needsReEncrypt($mCipher));
    }

    /**
     * @param CipherSweet $backend
     * @param bool $longer
     * @param bool $fast
     *
     * @return EncryptedField
     * @throws BlindIndexNameCollisionException
     * @throws CryptoOperationException
     */
    public function getExampleField(CipherSweet $backend, $longer = false, $fast = false)
    {
        return (new EncryptedField($backend, 'contacts', 'ssn'))
            // Add a blind index for the "last 4 of SSN":
            ->addBlindIndex(
                new BlindIndex(
                // Name (used in key splitting):
                    'contact_ssn_last_four',
                    // List of Transforms:
                    [new LastFourDigits()],
                    // Output length (bytes)
                    $longer ? 64 : 16,
                    $fast
                )
            )
            ->addBlindIndex(
                new BlindIndex(
                // Name (used in key splitting):
                    'contact_ssn_last_4',
                    // List of Transforms:
                    [new LastFourDigits()],
                    // Output length (bytes)
                    $longer ? 64 : 16,
                    $fast
                )
            )
            // Add a blind index for the full SSN:
            ->addBlindIndex(
                new BlindIndex(
                    'contact_ssn',
                    [],
                    $longer ? 128 : 32,
                    $fast
                )
            );
    }
}

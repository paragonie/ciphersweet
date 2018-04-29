<?php
namespace ParagonIE\CipherSweet\Tests;

use ParagonIE\CipherSweet\Backend\FIPSCrypto;
use ParagonIE\CipherSweet\Backend\ModernCrypto;
use ParagonIE\CipherSweet\BlindIndex;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\EncryptedField;
use ParagonIE\CipherSweet\Exception\ArrayKeyException;
use ParagonIE\CipherSweet\Exception\BlindIndexNameCollisionException;
use ParagonIE\CipherSweet\Exception\BlindIndexNotFoundException;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;
use ParagonIE\CipherSweet\KeyProvider\ArrayProvider;
use ParagonIE\CipherSweet\Transformation\LastFourDigits;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\ConstantTime\Hex;
use PHPUnit\Framework\TestCase;


/**
 * Class EncryptedFieldTest
 * @package ParagonIE\CipherSweet\Tests
 */
class EncryptedFieldTest extends TestCase
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
     * @throws ArrayKeyException
     * @throws CryptoOperationException
     */
    public function setUp()
    {
        $fips = new FIPSCrypto();
        $nacl = new ModernCrypto();

        $this->fipsEngine = new CipherSweet(
            new ArrayProvider(
                $fips,
                [
                    ArrayProvider::INDEX_SYMMETRIC_KEY => Hex::decode(
                        '4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc'
                    )
                ]
            )
        );
        $this->naclEngine = new CipherSweet(
            new ArrayProvider(
                $nacl,
                [
                    ArrayProvider::INDEX_SYMMETRIC_KEY => Hex::decode(
                        '4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc'
                    )
                ]
            )
        );

        $this->fipsRandom = new CipherSweet(
            new ArrayProvider(
                $fips,
                [
                    ArrayProvider::INDEX_SYMMETRIC_KEY => \random_bytes(32)
                ]
            )
        );
        $this->naclRandom = new CipherSweet(
            new ArrayProvider(
                $nacl,
                [
                    ArrayProvider::INDEX_SYMMETRIC_KEY => \random_bytes(32)
                ]
            )
        );
    }

    /**
     * @throws BlindIndexNameCollisionException
     * @throws CryptoOperationException
     */
    public function testEncrypt()
    {
        $eF = $this->getExampleField($this->fipsRandom);
        $eM = $this->getExampleField($this->naclRandom);

        $message = 'This is a test message: ' . \random_bytes(16);
        $fCipher = $eF->encryptValue($message);
        $mCipher = $eM->encryptValue($message);

        $this->assertSame(
            FIPSCrypto::MAGIC_HEADER,
            Binary::safeSubstr($fCipher, 0, 5)
        );
        $this->assertSame(
            ModernCrypto::MAGIC_HEADER,
            Binary::safeSubstr($mCipher, 0, 5)
        );

        $this->assertSame($message, $eF->decryptValue($fCipher));
        $this->assertSame($message, $eM->decryptValue($mCipher));
    }

    /**
     * @throws BlindIndexNameCollisionException
     * @throws BlindIndexNotFoundException
     * @throws CryptoOperationException
     */
    public function testFIPSBlindIndex()
    {
        $ssn = $this->getExampleField($this->fipsEngine);

        $this->assertEquals(
            ['type' => 'idlzpypmia6qu', 'value' => 'f7bb'],
            $ssn->getBlindIndex('111-11-1111', 'contact_ssn_last_four')
        );
        $this->assertEquals(
            ['type' => 'idlzpypmia6qu', 'value' => '38dc'],
            $ssn->getBlindIndex('111-11-2222', 'contact_ssn_last_four')
        );
        $this->assertEquals(
            ['type' => 'idlzpypmia6qu', 'value' => 'e6c4'],
            $ssn->getBlindIndex('123-45-6788', 'contact_ssn_last_four')
        );
        $this->assertEquals(
            ['type' => 'idlzpypmia6qu', 'value' => 'abd9'],
            $ssn->getBlindIndex('123-45-6789', 'contact_ssn_last_four')
        );
        $this->assertEquals(
            ['type' => 'stfodrsbpd4ls', 'value' => 'ee10e07b'],
            $ssn->getBlindIndex('invalid guess 123', 'contact_ssn')
        );
        $this->assertEquals(
            ['type' => 'stfodrsbpd4ls', 'value' => '9a15fe14'],
            $ssn->getBlindIndex('123-45-6789', 'contact_ssn')
        );

        $random = $this->getExampleField($this->fipsRandom, true);
        $this->assertNotEquals(
            ['type' => 'stfodrsbpd4ls', 'value' => 'ee10e07b213a922075a6ada22514528c'],
            $random->getBlindIndex('123-45-6789', 'contact_ssn')
        );
    }

    /**
     * @throws BlindIndexNameCollisionException
     * @throws BlindIndexNotFoundException
     * @throws CryptoOperationException
     */
    public function testModernBlindIndex()
    {
        $ssn = $this->getExampleField($this->naclEngine);
        $this->assertEquals(
            ['type' => '3dywyifwujcu2', 'value' => 'f50e'],
            $ssn->getBlindIndex('111-11-1111', 'contact_ssn_last_four')
        );
        $this->assertEquals(
            ['type' => '3dywyifwujcu2', 'value' => '702f'],
            $ssn->getBlindIndex('111-11-2222', 'contact_ssn_last_four')
        );
        $this->assertEquals(
            ['type' => '3dywyifwujcu2', 'value' => '5953'],
            $ssn->getBlindIndex('123-45-6788', 'contact_ssn_last_four')
        );
        $this->assertEquals(
            ['type' => '3dywyifwujcu2', 'value' => '8058'],
            $ssn->getBlindIndex('123-45-6789', 'contact_ssn_last_four')
        );
        $this->assertEquals(
            ['type' => '2iztg3wbd7j5a', 'value' => '499db508'],
            $ssn->getBlindIndex('invalid guess 123', 'contact_ssn')
        );
        $this->assertEquals(
            ['type' => '2iztg3wbd7j5a', 'value' => '311314c1'],
            $ssn->getBlindIndex('123-45-6789', 'contact_ssn')
        );

        $random = $this->getExampleField($this->naclRandom, true);
        $this->assertNotEquals(
            ['type' => '2iztg3wbd7j5a', 'value' => '499db5085e715c2f167c1e2c02f1c80f'],
            $random->getBlindIndex('123-45-6789', 'contact_ssn')
        );
    }

    /**
     * @param CipherSweet $backend
     * @param bool $longer
     *
     * @return EncryptedField
     * @throws BlindIndexNameCollisionException
     * @throws CryptoOperationException
     */
    public function getExampleField(CipherSweet $backend, $longer = false)
    {
        $fast = (
            $backend instanceof ModernCrypto
                &&
            !\ParagonIE_Sodium_Compat::crypto_pwhash_is_available()
        );

        return (new EncryptedField($backend, 'contacts', 'ssn'))
            // Add a blind index for the "last 4 of SSN":
            ->addBlindIndex(
                new BlindIndex(
                // Name (used in key splitting):
                    'contact_ssn_last_four',
                    // List of Transforms:
                    [new LastFourDigits()],
                    // Output length (bytes)
                    $longer ? 8 : 2,
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
                    $longer ? 8 : 2,
                    $fast
                )
            )
            // Add a blind index for the full SSN:
            ->addBlindIndex(
                new BlindIndex(
                    'contact_ssn',
                    [],
                    $longer ? 16 : 4,
                    $fast
                )
            );
    }
}

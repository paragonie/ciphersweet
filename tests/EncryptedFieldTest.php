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
use ParagonIE\CipherSweet\Exception\InvalidCiphertextException;
use ParagonIE\CipherSweet\Transformation\LastFourDigits;
use ParagonIE\ConstantTime\Binary;
use PHPUnit\Framework\TestCase;

/**
 * Class EncryptedFieldTest
 * @package ParagonIE\CipherSweet\Tests
 */
class EncryptedFieldTest extends TestCase
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
        $this->fipsEngine = $this->createFipsEngine('4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc');
        $this->naclEngine = $this->createModernEngine('4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc');

        $this->fipsRandom = $this->createFipsEngine();
        $this->naclRandom = $this->createModernEngine();
    }

    public function testConstructor()
    {
        $encField = new EncryptedField($this->naclEngine, 'test',  'field', true);
        $this->assertTrue($encField->getTypedIndexes(), 'Constructor argument not handled correctly');
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

        $aad = 'Test AAD: ' . \random_bytes(32);
        $fCipherWithAD = $eF->encryptValue($message, $aad);
        $mCipherWithAD = $eM->encryptValue($message, $aad);

        $this->assertSame($message, $eF->decryptValue($fCipherWithAD, $aad));
        $this->assertSame($message, $eM->decryptValue($mCipherWithAD, $aad));

        try {
            $eF->decryptValue($fCipher, $aad);
            $this->fail('AAD was permitted when ciphertext had none');
        } catch (\Exception $ex) {
            $this->assertInstanceOf(InvalidCiphertextException::class, $ex);
        }
        if (PHP_VERSION_ID !== 70300) { // PHP bug #77297
            try {
                $eM->decryptValue($mCipher, $aad);
                $this->fail('AAD was permitted when ciphertext had none');
            } catch (\Exception $ex) {
                $this->assertInstanceOf('SodiumException', $ex);
            }
        }
        try {
            $eF->decryptValue($fCipherWithAD);
            $this->fail('AAD stripping was permitted');
        } catch (\Exception $ex) {
            $this->assertInstanceOf(InvalidCiphertextException::class, $ex);
        }
        if (PHP_VERSION_ID !== 70300) { // PHP bug #77297
            try {
                $eM->decryptValue($mCipherWithAD);
                $this->fail('AAD stripping was permitted');
            } catch (\Exception $ex) {
                $this->assertInstanceOf('SodiumException', $ex);
            }
        }
    }

    /**
     * @throws BlindIndexNameCollisionException
     * @throws BlindIndexNotFoundException
     * @throws CryptoOperationException
     */
    public function testFIPSBlindIndex()
    {
        $ssn = $this->getExampleField($this->fipsEngine);
        $ssn->setTypedIndexes(true);

        $this->assertEquals(
            ['type' => 'idlzpypmia6qu', 'value' => '334b'],
            $ssn->getBlindIndex('111-11-1111', 'contact_ssn_last_four')
        );
        $this->assertEquals(
            ['type' => 'idlzpypmia6qu', 'value' => '7947'],
            $ssn->getBlindIndex('111-11-2222', 'contact_ssn_last_four')
        );
        $this->assertEquals(
            ['type' => 'idlzpypmia6qu', 'value' => 'd5ac'],
            $ssn->getBlindIndex('123-45-6788', 'contact_ssn_last_four')
        );
        $this->assertEquals(
            ['type' => 'idlzpypmia6qu', 'value' => 'a88e'],
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
    public function testFIPSBlindIndexFast()
    {
        $ssn = $this->getExampleField($this->fipsEngine, false, true);
        $ssn->setTypedIndexes(true);

        $this->assertEquals(
            ['type' => 'idlzpypmia6qu', 'value' => '924b'],
            $ssn->getBlindIndex('111-11-1111', 'contact_ssn_last_four')
        );
        $this->assertEquals(
            ['type' => 'idlzpypmia6qu', 'value' => 'be3b'],
            $ssn->getBlindIndex('111-11-2222', 'contact_ssn_last_four')
        );
        $this->assertEquals(
            ['type' => 'idlzpypmia6qu', 'value' => '3cd3'],
            $ssn->getBlindIndex('123-45-6788', 'contact_ssn_last_four')
        );
        $this->assertEquals(
            ['type' => 'idlzpypmia6qu', 'value' => '4bb1'],
            $ssn->getBlindIndex('123-45-6789', 'contact_ssn_last_four')
        );
        $this->assertEquals(
            ['type' => 'stfodrsbpd4ls', 'value' => '256e1182'],
            $ssn->getBlindIndex('invalid guess 123', 'contact_ssn')
        );
        $this->assertEquals(
            ['type' => 'stfodrsbpd4ls', 'value' => 'd2a774dc'],
            $ssn->getBlindIndex('123-45-6789', 'contact_ssn')
        );

        $random = $this->getExampleField($this->fipsRandom, true, true);
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
    public function testFIPSBlindIndexFlatAndFast()
    {
        $ssn = $this->getExampleField($this->fipsEngine, false, true);

        $this->assertEquals(
            '924b',
            $ssn->getBlindIndex('111-11-1111', 'contact_ssn_last_four')
        );
        $this->assertEquals(
            'be3b',
            $ssn->getBlindIndex('111-11-2222', 'contact_ssn_last_four')
        );
        $this->assertEquals(
            '3cd3',
            $ssn->getBlindIndex('123-45-6788', 'contact_ssn_last_four')
        );
        $this->assertEquals(
            '4bb1',
            $ssn->getBlindIndex('123-45-6789', 'contact_ssn_last_four')
        );
        $this->assertEquals(
            '256e1182',
            $ssn->getBlindIndex('invalid guess 123', 'contact_ssn')
        );
        $this->assertEquals(
            'd2a774dc',
            $ssn->getBlindIndex('123-45-6789', 'contact_ssn')
        );

        $this->assertEquals(
            'idlzpypmia6qu',
            $ssn->getBlindIndexType('contact_ssn_last_four')
        );
        $this->assertEquals(
            'stfodrsbpd4ls',
            $ssn->getBlindIndexType('contact_ssn')
        );

        $random = $this->getExampleField($this->fipsRandom, true, true);
        $this->assertNotEquals(
            'ee10e07b213a922075a6ada22514528c',
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
        if (!\ParagonIE_Sodium_Compat::crypto_pwhash_is_available()) {
            $this->markTestSkipped('libsodium not installed');
            return;
        }
        $ssn = $this->getExampleField($this->naclEngine);
        $ssn->setTypedIndexes(true);
        $this->assertEquals(
            ['type' => '3dywyifwujcu2', 'value' => '32ae'],
            $ssn->getBlindIndex('111-11-1111', 'contact_ssn_last_four')
        );
        $this->assertEquals(
            ['type' => '3dywyifwujcu2', 'value' => 'e538'],
            $ssn->getBlindIndex('111-11-2222', 'contact_ssn_last_four')
        );
        $this->assertEquals(
            ['type' => '3dywyifwujcu2', 'value' => '8d1a'],
            $ssn->getBlindIndex('123-45-6788', 'contact_ssn_last_four')
        );
        $this->assertEquals(
            ['type' => '3dywyifwujcu2', 'value' => '2acb'],
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
     * @throws BlindIndexNameCollisionException
     * @throws BlindIndexNotFoundException
     * @throws CryptoOperationException
     */
    public function testModernBlindIndexFast()
    {
        $ssn = $this->getExampleField($this->naclEngine, false, true);
        $ssn->setTypedIndexes(true);
        $this->assertEquals(
            ['type' => '3dywyifwujcu2', 'value' => '7843'],
            $ssn->getBlindIndex('111-11-1111', 'contact_ssn_last_four')
        );
        $this->assertEquals(
            ['type' => '3dywyifwujcu2', 'value' => 'd246'],
            $ssn->getBlindIndex('111-11-2222', 'contact_ssn_last_four')
        );
        $this->assertEquals(
            ['type' => '3dywyifwujcu2', 'value' => '4882'],
            $ssn->getBlindIndex('123-45-6788', 'contact_ssn_last_four')
        );
        $this->assertEquals(
            ['type' => '3dywyifwujcu2', 'value' => '92c8'],
            $ssn->getBlindIndex('123-45-6789', 'contact_ssn_last_four')
        );
        $this->assertEquals(
            ['type' => '2iztg3wbd7j5a', 'value' => 'b6fd11a1'],
            $ssn->getBlindIndex('invalid guess 123', 'contact_ssn')
        );
        $this->assertEquals(
            ['type' => '2iztg3wbd7j5a', 'value' => '30c7cc68'],
            $ssn->getBlindIndex('123-45-6789', 'contact_ssn')
        );

        $random = $this->getExampleField($this->naclRandom, true, true);
        $this->assertNotEquals(
            ['type' => '2iztg3wbd7j5a', 'value' => '499db5085e715c2f167c1e2c02f1c80f'],
            $random->getBlindIndex('123-45-6789', 'contact_ssn')
        );
    }

    /**
     * @throws BlindIndexNameCollisionException
     * @throws BlindIndexNotFoundException
     * @throws CryptoOperationException
     */
    public function testModernBlindIndexFlatAndFast()
    {
        $ssn = $this->getExampleField($this->naclEngine, false, true);
        $this->assertEquals(
            '7843',
            $ssn->getBlindIndex('111-11-1111', 'contact_ssn_last_four')
        );
        $this->assertEquals(
            'd246',
            $ssn->getBlindIndex('111-11-2222', 'contact_ssn_last_four')
        );
        $this->assertEquals(
            '4882',
            $ssn->getBlindIndex('123-45-6788', 'contact_ssn_last_four')
        );
        $this->assertEquals(
            '92c8',
            $ssn->getBlindIndex('123-45-6789', 'contact_ssn_last_four')
        );
        $this->assertEquals(
            'b6fd11a1',
            $ssn->getBlindIndex('invalid guess 123', 'contact_ssn')
        );
        $this->assertEquals(
            '30c7cc68',
            $ssn->getBlindIndex('123-45-6789', 'contact_ssn')
        );

        $this->assertEquals(
            '3dywyifwujcu2',
            $ssn->getBlindIndexType('contact_ssn_last_four')
        );
        $this->assertEquals(
            '2iztg3wbd7j5a',
            $ssn->getBlindIndexType('contact_ssn')
        );

        $random = $this->getExampleField($this->naclRandom, true, true);
        $this->assertNotEquals(
            '499db5085e715c2f167c1e2c02f1c80f',
            $random->getBlindIndex('123-45-6789', 'contact_ssn')
        );
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

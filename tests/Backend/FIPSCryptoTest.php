<?php
namespace ParagonIE\CipherSweet\Tests\Backend;

use ParagonIE\CipherSweet\Backend\FIPSCrypto;
use ParagonIE\CipherSweet\KeyProvider\ArrayProvider;
use ParagonIE\CipherSweet\KeyProvider\RandomProvider;
use PHPUnit\Framework\TestCase;

/**
 * Class FIPSCryptoTest
 * @package ParagonIE\CipherSweet\Tests
 */
class FIPSCryptoTest extends TestCase
{
    /**
     * @throws \Exception
     */
    public function testEncrypt()
    {
        $fips = new FIPSCrypto();
        $keyProvider = new ArrayProvider($fips, [
            ArrayProvider::INDEX_SYMMETRIC_KEY => random_bytes(32)
        ]);

        $message = 'This is just a test message';
        $cipher = $fips->encrypt($message, $keyProvider->getSymmetricKey());
        $decrypted = $fips->decrypt($cipher, $keyProvider->getSymmetricKey());

        $this->assertSame($message, $decrypted);
    }

    /**
     * @throws \Exception
     */
    public function testPublicEncrypt()
    {
        $fips = new FIPSCrypto();
        $randomProvider = new RandomProvider($fips);

        $privateKey = $randomProvider->getSecretKey();
        $publicKey = $privateKey->getPublicKey();

        $message = 'This is just a test message';
        $cipher = $fips->publicEncrypt($message, $publicKey);
        $decrypted = $fips->privateDecrypt($cipher, $privateKey);

        $this->assertSame($message, $decrypted);
    }

    /**
     * @throws \Exception
     */
    public function testSign()
    {
        $fips = new FIPSCrypto();
        $randomProvider = new RandomProvider($fips);

        $privateKey = $randomProvider->getSecretKey();
        $publicKey = $privateKey->getPublicKey();

        $message = 'This is just a test message';
        $signature = $fips->sign($message, $privateKey);
        $this->assertTrue($fips->verify($message, $publicKey, $signature));
    }
}

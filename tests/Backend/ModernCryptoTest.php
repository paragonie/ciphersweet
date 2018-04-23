<?php
namespace ParagonIE\CipherSweet\Tests\Backend;

use ParagonIE\CipherSweet\Backend\ModernCrypto;
use ParagonIE\CipherSweet\KeyProvider\ArrayProvider;
use ParagonIE\CipherSweet\KeyProvider\RandomProvider;
use PHPUnit\Framework\TestCase;

/**
 * Class ModernCryptoTest
 * @package ParagonIE\CipherSweet\Tests
 */
class ModernCryptoTest extends TestCase
{
    /**
     * @throws \Exception
     */
    public function testEncrypt()
    {
        $nacl = new ModernCrypto();
        $keyProvider = new ArrayProvider($nacl, [
            ArrayProvider::INDEX_SYMMETRIC_KEY => random_bytes(32)
        ]);

        $message = 'This is just a test message';
        $cipher = $nacl->encrypt($message, $keyProvider->getSymmetricKey());
        $decrypted = $nacl->decrypt($cipher, $keyProvider->getSymmetricKey());

        $this->assertSame($message, $decrypted);
    }

    /**
     * @throws \Exception
     */
    public function testPublicEncrypt()
    {
        $nacl = new ModernCrypto();
        $randomProvider = new RandomProvider($nacl);

        $privateKey = $randomProvider->getSecretKey();
        $publicKey = $privateKey->getPublicKey();

        $message = 'This is just a test message';
        $cipher = $nacl->publicEncrypt($message, $publicKey);
        $decrypted = $nacl->privateDecrypt($cipher, $privateKey);

        $this->assertSame($message, $decrypted);
    }

    /**
     * @throws \Exception
     */
    public function testSign()
    {
        $nacl = new ModernCrypto();
        $randomProvider = new RandomProvider($nacl);

        $privateKey = $randomProvider->getSecretKey();
        $publicKey = $privateKey->getPublicKey();

        $message = 'This is just a test message';
        $signature = $nacl->sign($message, $privateKey);
        $this->assertTrue($nacl->verify($message, $publicKey, $signature));
    }
}

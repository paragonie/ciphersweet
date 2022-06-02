<?php
namespace ParagonIE\CipherSweet\Tests\Backend;

use ParagonIE\CipherSweet\Backend\BoringCrypto;
use ParagonIE\CipherSweet\KeyProvider\StringProvider;
use PHPUnit\Framework\TestCase;

/**
 * Class BoringCryptoTest
 * @package ParagonIE\CipherSweet\Tests
 */
class BoringCryptoTest extends TestCase
{
    /**
     * @throws \Exception
     */
    public function testEncrypt()
    {
        $nacl = new BoringCrypto();
        $keyProvider = new StringProvider(random_bytes(32));

        $message = 'This is just a test message';
        $cipher = $nacl->encrypt($message, $keyProvider->getSymmetricKey());
        $decrypted = $nacl->decrypt($cipher, $keyProvider->getSymmetricKey());

        $this->assertSame($message, $decrypted);
    }

    public function testBlindIndexSlowEmpty()
    {
        $brng = new BoringCrypto();
        $keyProvider = new StringProvider(random_bytes(32));

        $raw = $brng->blindIndexSlow('', $keyProvider->getSymmetricKey(), 32);
        $this->assertNotEmpty($raw);
    }
}

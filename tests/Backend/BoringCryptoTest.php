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
        $brng = new BoringCrypto();
        $keyProvider = new StringProvider(random_bytes(32));

        $message = 'This is just a test message';
        $cipher = $brng->encrypt($message, $keyProvider->getSymmetricKey());
        $decrypted = $brng->decrypt($cipher, $keyProvider->getSymmetricKey());

        $this->assertSame($message, $decrypted);
    }

    public function testBlindIndexFastEmpty()
    {
        $brng = new BoringCrypto();
        $keyProvider = new StringProvider(random_bytes(32));

        $raw = $brng->blindIndexFast('', $keyProvider->getSymmetricKey(), 32);
        $this->assertNotEmpty($raw);
    }

    public function testBlindIndexSlowEmpty()
    {
        $brng = new BoringCrypto();
        $keyProvider = new StringProvider(random_bytes(32));

        $raw = $brng->blindIndexSlow('', $keyProvider->getSymmetricKey(), 32);
        $this->assertNotEmpty($raw);
    }
}

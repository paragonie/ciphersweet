<?php
namespace ParagonIE\CipherSweet\Tests\Backend;

use ParagonIE\CipherSweet\Backend\FIPSCrypto;
use ParagonIE\CipherSweet\KeyProvider\StringProvider;
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
        $keyProvider = new StringProvider(random_bytes(32));

        $message = 'This is just a test message';
        $cipher = $fips->encrypt($message, $keyProvider->getSymmetricKey());
        $decrypted = $fips->decrypt($cipher, $keyProvider->getSymmetricKey());

        $this->assertSame($message, $decrypted);
    }

    public function testBlindIndexFastEmpty()
    {
        $fips = new FIPSCrypto();
        $keyProvider = new StringProvider(random_bytes(32));

        $raw = $fips->blindIndexFast('', $keyProvider->getSymmetricKey(), 32);
        $this->assertNotEmpty($raw);
    }

    public function testBlindIndexSlowEmpty()
    {
        $fips = new FIPSCrypto();
        $keyProvider = new StringProvider(random_bytes(32));

        $raw = $fips->blindIndexSlow('', $keyProvider->getSymmetricKey(), 32);
        $this->assertNotEmpty($raw);
    }
}

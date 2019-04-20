<?php
namespace ParagonIE\CipherSweet\Tests\Backend;

use ParagonIE\CipherSweet\Backend\ModernCrypto;
use ParagonIE\CipherSweet\KeyProvider\StringProvider;
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
        $keyProvider = new StringProvider(random_bytes(32));

        $message = 'This is just a test message';
        $cipher = $nacl->encrypt($message, $keyProvider->getSymmetricKey());
        $decrypted = $nacl->decrypt($cipher, $keyProvider->getSymmetricKey());

        $this->assertSame($message, $decrypted);
    }
}

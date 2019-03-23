<?php
namespace ParagonIE\CipherSweet\Tests\KeyProvider;

use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\KeyProvider\StringProvider;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Hex;
use PHPUnit\Framework\TestCase;

/**
 * Class StringProviderTest
 * @package ParagonIE\CipherSweet\Tests\KeyProvider
 */
class StringProviderTest extends TestCase
{

    /**
     * @throws \ParagonIE\CipherSweet\Exception\CryptoOperationException
     */
    public function testHappyPath()
    {
        $symmetric = \random_bytes(32);

        $provider = new StringProvider($symmetric);
        $this->assertInstanceOf(SymmetricKey::class, $provider->getSymmetricKey());

        $hex = new StringProvider(Hex::encode($symmetric));
        $this->assertSame(
            Hex::encode($provider->getSymmetricKey()->getRawKey()),
            Hex::encode($hex->getSymmetricKey()->getRawKey()),
            'Hex-encoded keys are not producing the same result'
        );
        $b64 = new StringProvider(Base64UrlSafe::encode($symmetric));
        $this->assertSame(
            Hex::encode($provider->getSymmetricKey()->getRawKey()),
            Hex::encode($b64->getSymmetricKey()->getRawKey()),
            'B64-encoded keys are not producing the same result'
        );
    }
}

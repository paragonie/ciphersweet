<?php
namespace ParagonIE\CipherSweet\Tests\KeyProvider;

use ParagonIE\CipherSweet\KeyProvider\ArrayProvider;
use ParagonIE\ConstantTime\Hex;
use PHPUnit\Framework\TestCase;

/**
 * Class ArrayProviderTest
 * @package ParagonIE\CipherSweet\Tests\KeyProvider
 */
class ArrayProviderTest extends TestCase
{
    /**
     * @throws \ParagonIE\CipherSweet\Exception\ArrayKeyException
     * @throws \ParagonIE\CipherSweet\Exception\CryptoOperationException
     */
    public function testHappyPath()
    {
        $random = random_bytes(32);

        $provider = new ArrayProvider([
            ArrayProvider::INDEX_SYMMETRIC_KEY =>
                $random
        ]);

        $this->assertSame(
            Hex::encode($random),
            Hex::encode($provider->getSymmetricKey()->getRawKey())
        );
    }
}

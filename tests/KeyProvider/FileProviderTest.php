<?php
namespace ParagonIE\CipherSweet\Tests\KeyProvider;

use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\KeyProvider\FileProvider;
use ParagonIE\ConstantTime\Base32;
use PHPUnit\Framework\TestCase;

/**
 * Class FileProviderTest
 * @package ParagonIE\CipherSweet\Tests\KeyProvider
 */
class FileProviderTest extends TestCase
{
    /**
     * @var string $prefix
     */
    private $prefix;

    /**
     * @before
     * @throws \SodiumException
     */
    public function before()
    {
        $this->prefix = Base32::encodeUnpadded(random_bytes(16));

        $symmetric = \random_bytes(32);
        \file_put_contents(
            __DIR__ . '/files/' . $this->prefix . '.symmetric',
            $symmetric
        );
    }

    /**
     * @afterClass
     */
    public function afterClass()
    {
        \unlink(__DIR__ . '/files/' . $this->prefix . '.symmetric');
    }

    /**
     * @throws \ParagonIE\CipherSweet\Exception\KeyProviderException
     */
    public function testHappyPath()
    {
        $provider = new FileProvider(
            __DIR__ . '/files/' . $this->prefix . '.symmetric'
        );

        $this->assertInstanceOf(SymmetricKey::class, $provider->getSymmetricKey());
    }
}

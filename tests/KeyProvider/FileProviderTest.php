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
    private $symmetric;


    /**
     * @before
     * @throws \SodiumException
     */
    public function before()
    {
        $this->prefix = Base32::encodeUnpadded(random_bytes(16));

        $this->symmetric = \random_bytes(32);
        \file_put_contents(
            __DIR__ . '/files/' . $this->prefix . '.symmetric',
            $this->symmetric
        );

        // save hashed ranbom bytes as hash
        \file_put_contents(
            __DIR__ . '/files/' . $this->prefix . '.symmetric.hash',
            trim(bin2hex($this->symmetric))
        );

        // save hashed random bytes as hash with whitelines
        \file_put_contents(
            __DIR__ . '/files/' . $this->prefix . '.symmetric.hash.whitelines',
            bin2hex($this->symmetric)."\n"
        );
    }

    /**
     * @afterClass
     */
    public function afterClass()
    {
        \unlink(__DIR__ . '/files/' . $this->prefix . '.symmetric');
        \unlink(__DIR__ . '/files/' . $this->prefix . '.symmetric.hash');
        \unlink(__DIR__ . '/files/' . $this->prefix . '.symmetric.hash.whitelines');

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
        $this->assertSame($provider->getSymmetricKey()->getRawKey(), $this->symmetric);
    }

       /**
     * @throws \ParagonIE\CipherSweet\Exception\KeyProviderException
     */
    public function testHashedPassword()
    {
        $provider = new FileProvider(
            __DIR__ . '/files/' . $this->prefix . '.symmetric.hash'
        );

        $this->assertInstanceOf(SymmetricKey::class, $provider->getSymmetricKey());
        $this->assertSame($provider->getSymmetricKey()->getRawKey(), $this->symmetric);

    }

       /**
     * @throws \ParagonIE\CipherSweet\Exception\KeyProviderException
     */
    public function testHashedPasswordWithWhitelines()
    {
        $provider = new FileProvider(
            __DIR__ . '/files/' . $this->prefix . '.symmetric.hash.whitelines'
        );

        $this->assertInstanceOf(SymmetricKey::class, $provider->getSymmetricKey());
        $this->assertSame($provider->getSymmetricKey()->getRawKey(), $this->symmetric);
    }
}

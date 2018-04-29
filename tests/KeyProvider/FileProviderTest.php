<?php
namespace ParagonIE\CipherSweet\Tests\KeyProvider;

use ParagonIE\CipherSweet\Backend\Key\AsymmetricPublicKey;
use ParagonIE\CipherSweet\Backend\Key\AsymmetricSecretKey;
use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\Backend\ModernCrypto;
use ParagonIE\CipherSweet\KeyProvider\FileProvider;
use ParagonIE\ConstantTime\Base32;
use ParagonIE\ConstantTime\Hex;
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
     * @throws \SodiumException
     */
    public function setUp()
    {
        $this->prefix = \rtrim(Base32::encode(random_bytes(16)), '=');

        $symmetric = \random_bytes(32);
        \file_put_contents(
            __DIR__ . '/files/' . $this->prefix . '.symmetric',
            $symmetric
        );
        $keypair = \ParagonIE_Sodium_Compat::crypto_sign_keypair();

        \file_put_contents(
            __DIR__ . '/files/' . $this->prefix . '.secret',
            \ParagonIE_Sodium_Compat::crypto_sign_secretkey($keypair)
        );

        \file_put_contents(
            __DIR__ . '/files/' . $this->prefix . '.public',
            \ParagonIE_Sodium_Compat::crypto_sign_publickey($keypair)
        );
    }

    public function tearDown()
    {
        \unlink(__DIR__ . '/files/' . $this->prefix . '.symmetric');
        \unlink(__DIR__ . '/files/' . $this->prefix . '.secret');
        \unlink(__DIR__ . '/files/' . $this->prefix . '.public');
        parent::tearDown();
    }

    /**
     * @throws \ParagonIE\CipherSweet\Exception\KeyProviderException
     */
    public function testHappyPath()
    {
        $backend = new ModernCrypto();
        $provider = new FileProvider(
            $backend,
            __DIR__ . '/files/' . $this->prefix . '.symmetric',
            __DIR__ . '/files/' . $this->prefix . '.secret',
            __DIR__ . '/files/' . $this->prefix . '.public'
        );

        $this->assertInstanceOf(SymmetricKey::class, $provider->getSymmetricKey());
        $this->assertInstanceOf(AsymmetricSecretKey::class, $provider->getSecretKey());
        $this->assertInstanceOf(AsymmetricPublicKey::class, $provider->getPublicKey());

        // Since these two were part of the same keypair, this should work:
        $this->assertSame(
            Hex::encode($provider->getPublicKey()->getRawKey()),
            Hex::encode($provider->getSecretKey()->getPublicKey()->getRawKey())
        );
    }
}

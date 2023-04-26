<?php
namespace ParagonIE\CipherSweet\Tests;

use ParagonIE\CipherSweet\Backend\BoringCrypto;
use ParagonIE\CipherSweet\Backend\FIPSCrypto;
use ParagonIE\CipherSweet\Backend\ModernCrypto;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\Exception\CipherSweetException;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;
use ParagonIE\CipherSweet\KeyProvider\StringProvider;
use ParagonIE\ConstantTime\Hex;
use PHPUnit\Framework\TestCase;
use SodiumException;

/**
 * Class CipherSweetTest
 * @package ParagonIE\CipherSweet\Tests
 */
class CipherSweetTest extends TestCase
{
    /**
     * @throws \ParagonIE\CipherSweet\Exception\ArrayKeyException
     * @throws CryptoOperationException
     */
    public function testBasicAPI()
    {
        $fips = new FIPSCrypto();
        $nacl = new ModernCrypto();

        $random = \random_bytes(32);
        $provider = new StringProvider($random);

        $fipsEngine = new CipherSweet($provider, $fips);
        $naclEngine = new CipherSweet($provider, $nacl);

        $this->assertInstanceOf(FIPSCrypto::class, $fipsEngine->getBackend());
        $this->assertInstanceOf(ModernCrypto::class, $naclEngine->getBackend());

        foreach ([$fipsEngine, $naclEngine] as $e) {
            $this->assertNotEquals(
                Hex::encode($e->getBlindIndexRootKey('foo', 'bar')->getRawKey()),
                Hex::encode($e->getFieldSymmetricKey('foo', 'bar')->getRawKey()),
                'Domain separation did not prevent a collision?' .
                "\n" . 'Class: ' . \get_class($e) . "\n" . 'Random: ' . Hex::encode($random)
            );
            $this->assertNotEquals(
                Hex::encode($e->getFieldSymmetricKey('foo', 'bar')->getRawKey()),
                Hex::encode($e->getFieldSymmetricKey('foo', 'baz')->getRawKey()),
                'Assertion that bar !== baz failed (getFieldSymmetricKey collision?)' .
                "\n" . 'Class: ' . \get_class($e) . "\n" . 'Random: ' . Hex::encode($random)
            );
            $this->assertNotEquals(
                Hex::encode($e->getBlindIndexRootKey('foo', 'bar')->getRawKey()),
                Hex::encode($e->getBlindIndexRootKey('foo', 'baz')->getRawKey()),
                'Assertion that bar !== baz failed (getBlindIndexRootKey collision?)' .
                "\n" . 'Class: ' . \get_class($e) . "\n" . 'Random: ' . Hex::encode($random)
            );
            try {
                $this->assertNotEquals(
                    Hex::encode($e->getIndexTypeColumn('foo', 'bar', 'baz')),
                    Hex::encode($e->getIndexTypeColumn('test', '1234', 'quux'))
                );
            } catch (\Exception $ex) {
                \trigger_error(
                    'getIndexTypeColumn collision:' .
                    "\n" . 'Class: ' . \get_class($e) . "\n" . 'Random: ' . Hex::encode($random),
                    E_USER_WARNING
                );
                // Collision chance of 1 in 4 billion
                $this->assertNotEquals(
                    Hex::encode($e->getIndexTypeColumn('fon', 'baq', 'bay')),
                    Hex::encode($e->getIndexTypeColumn('tesu', '1235', 'quuy')),
                    'getIndexTypeColumn collision:' .
                    "\n" . 'Class: ' . \get_class($e) . "\n" . 'Random: ' . Hex::encode($random)
                );
            }
        }
    }

    public function engineProvider(): array
    {
        $random = \random_bytes(32);
        $provider = new StringProvider($random);
        return [
            [new CipherSweet($provider, new FIPSCrypto())],
            [new CipherSweet($provider, new ModernCrypto())],
            [new CipherSweet($provider, new BoringCrypto())],
        ];
    }

    /**
     * @dataProvider engineProvider
     * @param CipherSweet $engine
     * @return void
     *
     * @throws CipherSweetException
     * @throws CryptoOperationException
     * @throws SodiumException
     */
    public function testExtensionKey(CipherSweet $engine): void
    {
        $ext1 = $engine->getExtensionKey('foo', 'bar');
        $ext2 = $engine->getExtensionKey("foo\x03\x00\x00\x00\x00\x00\x00\x00bar");
        $this->assertNotSame(
            sodium_bin2hex($ext1->getRawKey()),
            sodium_bin2hex($ext2->getRawKey()),
            'Key derivation is not resistant to canonicalization issues'
        );
    }
}

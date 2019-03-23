<?php
namespace ParagonIE\CipherSweet\Tests;

use ParagonIE\CipherSweet\Backend\FIPSCrypto;
use ParagonIE\CipherSweet\Backend\ModernCrypto;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\Contract\BackendInterface;
use ParagonIE\CipherSweet\KeyProvider\ArrayProvider;
use ParagonIE\ConstantTime\Hex;
use PHPUnit\Framework\TestCase;

/**
 * Class CipherSweetTest
 * @package ParagonIE\CipherSweet\Tests
 */
class CipherSweetTest extends TestCase
{
    public function testDefaultBackend()
    {
        $this->assertInstanceOf(
            BackendInterface::class,
            CipherSweet::getDefaultBackend()
        );
    }

    /**
     * @throws \ParagonIE\CipherSweet\Exception\ArrayKeyException
     * @throws \ParagonIE\CipherSweet\Exception\CryptoOperationException
     */
    public function testBasicAPI()
    {
        $fips = new FIPSCrypto();
        $nacl = new ModernCrypto();
        $random = \random_bytes(32);

        $fipsEngine = new CipherSweet(
            new ArrayProvider(
                [
                    ArrayProvider::INDEX_SYMMETRIC_KEY => $random
                ]
            ),
            $fips
        );
        $naclEngine = new CipherSweet(
            new ArrayProvider(
                [
                    ArrayProvider::INDEX_SYMMETRIC_KEY => $random
                ]
            ),
            $nacl
        );

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
}

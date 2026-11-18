<?php
namespace ParagonIE\CipherSweet\Tests;

use ParagonIE\CipherSweet\Backend\BoringCrypto;
use ParagonIE\CipherSweet\Backend\FIPSCrypto;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\EncryptedField;
use ParagonIE\CipherSweet\Exception\CipherSweetException;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;
use ParagonIE\CipherSweet\Exception\InvalidCiphertextException;
use ParagonIE\CipherSweet\KeyProvider\StringProvider;
use PHPUnit\Framework\Attributes\DataProvider;
use ParagonIE\ConstantTime\Hex;
use PHPUnit\Framework\TestCase;
use ParagonIE\CipherSweet\AAD;

class AADTest extends TestCase
{
    public function testLegacyBehavior(): void
    {
        $aad1 = AAD::literal('foo');
        $aad2 = AAD::field('bar');

        $this->assertTrue($aad1->getLegacy());
        $this->assertTrue($aad2->getLegacy());

        $this->assertSame('foo', $aad1->canonicalize());
        $this->assertSame('baz', $aad2->canonicalize(['bar' => 'baz']));
    }

    public function testMerge(): void
    {
        $aad1 = AAD::literal('foo');
        $aad2 = AAD::field('bar');
        $aad3 = $aad1->merge($aad2);

        $this->assertSame(
            '0200000000000000010000000000000001000000000000000300000000000000626172030000000000000062617a0300000000000000666f6f',
            Hex::encode($aad3->canonicalize(['bar' => 'baz'])),
            'Canonical encoding'
        );

        $aad4 = AAD::literal('baz');
        $aad5 = $aad3->addLiteral('baz');
        $aad6 = $aad5->merge($aad4);
        $this->assertSame($aad5->canonicalize(), $aad6->canonicalize());
    }

    public function testCollapse(): void
    {
        $aad = new AAD(['foo', 'bar', 'baz'], ['apple', 'pear']);
        $collapsed = $aad->getCollapsed([
            'foo' => 'banana',
            'bar' => 'pineapple',
            'baz' => 'blueberry'
        ]);
        $fields = $collapsed->getFieldNames();
        $this->assertCount(0, $fields);
        $literals = $collapsed->getLiterals();
        $this->assertCount(5, $literals);
    }

    public function testFieldOrder(): void
    {
         $this->assertSame(
             '02000000000000000200000000000000000000000000000005000000000000006170706c65030000000000000031323305000000000000007a656272610300000000000000313232',
             Hex::encode((new AAD(['zebra', 'apple']))->canonicalize(['zebra' => '122', 'apple' => '123'])),
             'Keys must be sorted'
         );
    }

    public static function backends(): array
    {
        return [[BoringCrypto::class], [FIPSCrypto::class]];
    }

    /**
     * @throws CryptoOperationException
     * @throws CipherSweetException
     */
    #[DataProvider('backends')]
    public function testZeroAadCannotBeStripped(string $backendClass): void
    {
        $engine = new CipherSweet(new StringProvider(str_repeat('K', 32)), new $backendClass());
        $field = new EncryptedField($engine, 'records', 'secret');
        $ciphertext = $field->encryptValue('private data', '0');
        self::assertSame('private data', $field->decryptValue($ciphertext, '0'));
        $this->expectException($backendClass === BoringCrypto::class ? \SodiumException::class : InvalidCiphertextException::class);
        $field->decryptValue($ciphertext, '');
    }
}

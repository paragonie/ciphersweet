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
    public function testConstructorDefaults(): void
    {
        $aad = new AAD();
        $this->assertSame([], $aad->getFieldNames());
        $this->assertSame([], $aad->getLiterals());
        $this->assertFalse($aad->getLegacy());
        $this->assertSame(str_repeat("\0", 24), $aad->canonicalize());
    }

    public function testEmptyLegacyInputs(): void
    {
        foreach ([new AAD([], [], true), AAD::literal(''), AAD::field('')] as $aad) {
            $this->assertTrue($aad->getLegacy());
            $this->assertSame([], $aad->getFieldNames());
            $this->assertSame([], $aad->getLiterals());
            $this->assertSame('', $aad->canonicalize());
        }
    }

    public function testLegacyInputsWithNonzeroArrayKeys(): void
    {
        $this->assertSame('value', (new AAD([7 => 'field'], [], true))->canonicalize(['field' => 'value']));
        $this->assertSame('literal', (new AAD([], [7 => 'literal'], true))->canonicalize());
    }

    public function testCanonicalLiteralOrder(): void
    {
        $aad = new AAD([], ['z', 'a']);
        $this->assertSame(
            '02000000000000000000000000000000020000000000000001000000000000006101000000000000007a',
            Hex::encode($aad->canonicalize())
        );
        $this->assertSame(['a', 'z'], $aad->getLiterals());
    }

    public function testCollapseSortsAndDeduplicatesLiterals(): void
    {
        $aad = new AAD(['z', 'missing', 'a'], ['pear', 'apple']);
        $collapsed = $aad->getCollapsed(['z' => 'banana', 'a' => 'apple']);
        $this->assertNotSame($aad, $collapsed);
        $this->assertSame([], $collapsed->getFieldNames());
        $this->assertSame(['apple', 'banana', 'pear'], $collapsed->getLiterals());
        $this->assertFalse($collapsed->getLegacy());
        $this->assertSame(['pear', 'apple'], $aad->getLiterals());
    }

    public function testMergePreservesInputs(): void
    {
        $left = new AAD(['a'], ['first'], true);
        $right = new AAD(['a', 'b'], ['first', 'second'], true);
        $merged = $left->merge($right);
        $this->assertNotSame($left, $merged);
        $this->assertSame(['a'], $left->getFieldNames());
        $this->assertSame(['first'], $left->getLiterals());
        $this->assertTrue($left->getLegacy());
        $this->assertSame(['a', 'b'], $merged->getFieldNames());
        $this->assertSame(['first', 'second'], $merged->getLiterals());
        $this->assertFalse($merged->getLegacy());
        $this->assertSame(['a', 'b'], $right->getFieldNames());
        $this->assertSame(['first', 'second'], $right->getLiterals());
        $this->assertTrue($right->getLegacy());
    }

    public function testFactoriesCloneExistingAad(): void
    {
        $aad = new AAD(['field'], ['literal']);
        foreach ([AAD::field($aad), AAD::literal($aad)] as $copy) {
            $this->assertNotSame($aad, $copy);
            $this->assertEquals($aad, $copy);
            $copy->addFieldName('other')->addLiteral('extra');
            $this->assertSame(['field'], $aad->getFieldNames());
            $this->assertSame(['literal'], $aad->getLiterals());
        }
    }


    public function testFluentAdditionsDeduplicate(): void
    {
        $aad = new AAD();
        $this->assertSame($aad, $aad->addFieldName('field'));
        $this->assertSame($aad, $aad->addFieldName('field'));
        $this->assertSame($aad, $aad->addLiteral('literal'));
        $this->assertSame($aad, $aad->addLiteral('literal'));
        $this->assertSame(['field'], $aad->getFieldNames());
        $this->assertSame(['literal'], $aad->getLiterals());
    }

    public function testCanonicalizationCastsScalarValues(): void
    {
        $numbers = new AAD(['field'], [123]);
        $strings = new AAD(['field'], ['123']);
        $this->assertSame(
            $strings->canonicalize(['field' => '456']),
            $numbers->canonicalize(['field' => 456])
        );
    }

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

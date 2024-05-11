<?php
namespace ParagonIE\CipherSweet\Tests;

use ParagonIE\ConstantTime\Hex;
use PHPUnit\Framework\TestCase;
use ParagonIE\CipherSweet\AAD;

/**
 * @covers AAD
 */
class AADTest extends TestCase
{
    public function testLegacyBehavior(): void
    {
        $aad1 = AAD::literal('foo');
        $aad2 = AAD::field('bar');

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
}

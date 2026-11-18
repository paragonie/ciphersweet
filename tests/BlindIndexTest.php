<?php
namespace ParagonIE\CipherSweet\Tests;

use ParagonIE\CipherSweet\BlindIndex;
use ParagonIE\CipherSweet\FastBlindIndex;
use ParagonIE\CipherSweet\Transformation\DigitsOnly;
use PHPUnit\Framework\TestCase;

/**
 * Class BlindIndexTest
 * @package ParagonIE\CipherSweet\Tests
 */
class BlindIndexTest extends TestCase
{
    public function testConstructorDefaults(): void
    {
        foreach ([new BlindIndex('default'), new FastBlindIndex('default')] as $index) {
            $this->assertSame('default', $index->getName());
            $this->assertSame(256, $index->getFilterBitLength());
            $this->assertSame($index instanceof FastBlindIndex, $index->getFastHash());
            $this->assertSame([], $index->getHashConfig());
            $this->assertSame("unchanged\0", $index->getTransformed("unchanged\0"));
        }
    }

    public function testConstructorConfiguration(): void
    {
        foreach ([BlindIndex::class, FastBlindIndex::class] as $class) {
            $index = new $class('custom', [new DigitsOnly()], 128, true, ['opslimit' => 5]);
            $this->assertSame('custom', $index->getName());
            $this->assertSame(128, $index->getFilterBitLength());
            $this->assertTrue($index->getFastHash());
            $this->assertSame(['opslimit' => 5], $index->getHashConfig());
            $this->assertSame('123', $index->getTransformed('a1b2c3'));
        }
    }

    public function testAddTransformationReturnsSameIndex(): void
    {
        $index = new BlindIndex('digits');
        $this->assertSame($index, $index->addTransformation(new DigitsOnly()));
        $this->assertSame('123', $index->getTransformed('a1b2c3'));
    }

    public function testFastIndexRejectsSlowHashing(): void
    {
        $this->expectException(\ParagonIE\CipherSweet\Exception\CipherSweetException::class);
        new FastBlindIndex('slow', [], 256, false);
    }

    public function testBlindIndex()
    {
        $digits = new BlindIndex('test', [new DigitsOnly()]);
        $this->assertEquals('12345', $digits->getTransformed('1a2b3?c4d5e'));
    }

    public function testFastBlindIndex()
    {
        $digits = new FastBlindIndex('test', [new DigitsOnly()]);
        $this->assertEquals('12345', $digits->getTransformed('1a2b3?c4d5e'));
        $this->assertSame(true, $digits->getFastHash());
    }
}

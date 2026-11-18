<?php
namespace ParagonIE\CipherSweet\Tests;

use ParagonIE\CipherSweet\CompoundIndex;
use ParagonIE\CipherSweet\Exception\CipherSweetException;
use ParagonIE\CipherSweet\FastCompoundIndex;
use ParagonIE\CipherSweet\Transformation\LastFourDigits;
use PHPUnit\Framework\TestCase;

/**
 * Class CompoundIndexTest
 * @package ParagonIE\CipherSweet\Tests
 */
class CompoundIndexTest extends TestCase
{
    public function testConstructorDefaults(): void
    {
        foreach ([new CompoundIndex('default'), new FastCompoundIndex('default')] as $index) {
            $this->assertSame('default', $index->getName());
            $this->assertSame([], $index->getColumns());
            $this->assertSame(256, $index->getFilterBitLength());
            $this->assertSame($index instanceof FastCompoundIndex, $index->getFastHash());
            $this->assertSame([], $index->getHashConfig());
            $this->assertSame([], $index->getRowTransforms());
            $this->assertSame([], $index->getTransforms('unknown'));
            $this->assertSame('[]', $index->getPacked(['unused' => 'ignored']));
        }
    }

    public function testConstructorConfiguration(): void
    {
        foreach ([CompoundIndex::class, FastCompoundIndex::class] as $class) {
            $index = new $class('custom', ['ssn'], 128, true, ['opslimit' => 5]);
            $this->assertSame('custom', $index->getName());
            $this->assertSame(['ssn'], $index->getColumns());
            $this->assertSame(128, $index->getFilterBitLength());
            $this->assertTrue($index->getFastHash());
            $this->assertSame(['opslimit' => 5], $index->getHashConfig());
            $this->assertSame($index, $index->addTransform('ssn', new LastFourDigits()));
            $this->assertSame(
                '{"ssn":"0400000000000000Njc4OQ=="}',
                $index->getPacked(['ssn' => '123-45-6789', 'unused' => 'ignored'])
            );
            $this->assertSame('[]', $index->getPacked(['unused' => 'ignored']));
        }
    }

    public function testCompounderIsShared(): void
    {
        $this->assertSame(CompoundIndex::getCompounder(), CompoundIndex::getCompounder());
    }

    public function testFastIndexRejectsSlowHashing(): void
    {
        $this->expectException(CipherSweetException::class);
        new FastCompoundIndex('slow', [], 256, false);
    }

    /**
     * @throws \Exception
     */
    public function testCompoundIndex()
    {
        $cIdx = new CompoundIndex(
            'ssn_hivstatus',
            ['ssn', 'hivstatus'],
            32,
            true
        );
        $cIdx->addTransform('ssn', new LastFourDigits());
        $packed = $cIdx->getPacked([
            'ssn' => '123-45-6789',
            'hivstatus' => true
        ]);
        $this->assertSame(
            '{"ssn":"0400000000000000Njc4OQ==","hivstatus":true}',
            $packed
        );
        $packed = $cIdx->getPacked([
            'ssn' => '123-45-6789',
            'hivstatus' => false
        ]);
        $this->assertSame(
            '{"ssn":"0400000000000000Njc4OQ==","hivstatus":false}',
            $packed
        );
    }
    public function testFastCompoundIndex()
    {
        $cIdx = new FastCompoundIndex(
            'ssn_hivstatus',
            ['ssn', 'hivstatus'],
            32
        );
        $cIdx->addTransform('ssn', new LastFourDigits());
        $packed = $cIdx->getPacked([
            'ssn' => '123-45-6789',
            'hivstatus' => true
        ]);
        $this->assertSame(
            '{"ssn":"0400000000000000Njc4OQ==","hivstatus":true}',
            $packed
        );
        $packed = $cIdx->getPacked([
            'ssn' => '123-45-6789',
            'hivstatus' => false
        ]);
        $this->assertSame(
            '{"ssn":"0400000000000000Njc4OQ==","hivstatus":false}',
            $packed
        );
    }
}

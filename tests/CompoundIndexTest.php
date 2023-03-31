<?php
namespace ParagonIE\CipherSweet\Tests;

use ParagonIE\CipherSweet\CompoundIndex;
use ParagonIE\CipherSweet\FastCompoundIndex;
use ParagonIE\CipherSweet\Transformation\LastFourDigits;
use PHPUnit\Framework\TestCase;

/**
 * Class CompoundIndexTest
 * @package ParagonIE\CipherSweet\Tests
 */
class CompoundIndexTest extends TestCase
{
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

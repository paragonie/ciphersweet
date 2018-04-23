<?php
namespace ParagonIE\CipherSweet\Tests;

use ParagonIE\CipherSweet\BlindIndex;
use ParagonIE\CipherSweet\Transformation\DigitsOnly;
use PHPUnit\Framework\TestCase;

/**
 * Class BlindIndexTest
 * @package ParagonIE\CipherSweet\Tests
 */
class BlindIndexTest extends TestCase
{
    public function testBlindIndex()
    {
        $digits = new BlindIndex('test', [new DigitsOnly()]);
        $this->assertEquals('12345', $digits->getTransformed('1a2b3?c4d5e'));
    }
}

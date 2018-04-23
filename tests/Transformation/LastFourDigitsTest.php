<?php
namespace ParagonIE\CipherSweet\Tests\Transformation;

use ParagonIE\CipherSweet\Contract\TransformationInterface;
use ParagonIE\CipherSweet\Transformation\LastFourDigits;

/**
 * Class LowercaseTest
 * @package ParagonIE\CipherSweet\Tests\Transformation
 */
class LastFourDigitsTest extends GenericTransfomationCase
{
    /**
     * @return TransformationInterface
     */
    protected function getTransformation()
    {
        return new LastFourDigits();
    }

    /**
     * @return array<int, array<int, string>>
     */
    protected function getTestCases()
    {
        return [
            ['apple', '0000'],
            ['1', '0001'],
            ['12', '0012'],
            ['123', '0123'],
            ['1234', '1234'],
            ['12345', '2345'],
            ['123456', '3456'],
            ['123-456-7890', '7890']
        ];
    }
}

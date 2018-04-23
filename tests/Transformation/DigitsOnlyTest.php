<?php
namespace ParagonIE\CipherSweet\Tests\Transformation;

use ParagonIE\CipherSweet\Contract\TransformationInterface;
use ParagonIE\CipherSweet\Transformation\DigitsOnly;

/**
 * Class LowercaseTest
 * @package ParagonIE\CipherSweet\Tests\Transformation
 */
class DigitsOnlyTest extends GenericTransfomationCase
{
    /**
     * @return TransformationInterface
     */
    protected function getTransformation()
    {
        return new DigitsOnly();
    }

    /**
     * @return array<int, array<int, string>>
     */
    protected function getTestCases()
    {
        return [
            ['13375p34k 15 4cc3p74813', '1337534154374813'],
            ['apple', ''],
            ['1', '1'],
            ['12', '12'],
            ['123', '123'],
            ['1234', '1234'],
            ['12345', '12345'],
            ['123456', '123456'],
            ['123-456-7890', '1234567890']
        ];
    }
}

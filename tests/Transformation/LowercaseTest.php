<?php
namespace ParagonIE\CipherSweet\Tests\Transformation;

use ParagonIE\CipherSweet\Contract\TransformationInterface;
use ParagonIE\CipherSweet\Transformation\Lowercase;

/**
 * Class LowercaseTest
 * @package ParagonIE\CipherSweet\Tests\Transformation
 */
class LowercaseTest extends GenericTransfomationCase
{
    /**
     * @return TransformationInterface
     */
    protected function getTransformation()
    {
        return new Lowercase();
    }

    /**
     * @return array<int, array<int, string>>
     */
    protected function getTestCases()
    {
        return [
            ['APPLE', 'apple'],
            ["This is a Test String with whitespace\n", "this is a test string with whitespace\n"]
        ];
    }
}

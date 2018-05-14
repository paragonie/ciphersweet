<?php
namespace ParagonIE\CipherSweet\Tests\Transformation;

use ParagonIE\CipherSweet\Contract\TransformationInterface;
use ParagonIE\CipherSweet\Transformation\Compound;

/**
 * Class LowercaseTest
 * @package ParagonIE\CipherSweet\Tests\Transformation
 */
class CompoundTest extends GenericTransfomationCase
{
    /**
     * @return TransformationInterface
     */
    protected function getTransformation()
    {
        return new Compound();
    }

    /**
     * @return array<int, array<int, string>>
     */
    protected function getTestCases()
    {
        return [
            [['test'], '["0400000000000000dGVzdA=="]'],
            [['test', 'test2'], '["0400000000000000dGVzdA==","0500000000000000dGVzdDI="]'],
            [['test' => 'test2'], '{"test":"0500000000000000dGVzdDI="}']
        ];
    }
}

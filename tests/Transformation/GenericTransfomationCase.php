<?php
namespace ParagonIE\CipherSweet\Tests\Transformation;

use ParagonIE\CipherSweet\Contract\TransformationInterface;
use PHPUnit\Framework\TestCase;

/**
 * Class GenericTransfomationCase
 * @package ParagonIE\CipherSweet\Tests\Transformation
 */
abstract class GenericTransfomationCase extends TestCase
{
    /**
     * @return TransformationInterface
     */
    abstract protected function getTransformation();

    /**
     * @return array<int, array<int, string>>
     */
    abstract protected function getTestCases();

    public function testHappyPath()
    {
        $tf = $this->getTransformation();
        $testCases = $this->getTestCases();
        foreach ($testCases as $i => $testCase) {
            list ($input, $expected) = $testCase;
            $this->assertEquals(
                $expected,
                $tf($input)
            );
        }
    }
}

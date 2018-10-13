<?php
namespace ParagonIE\CipherSweet\Tests\Transformation;
use ParagonIE\CipherSweet\Contract\RowTransformationInterface;

/**
 * Class FirstInitialLastName
 * @package ParagonIE\CipherSweet\Tests
 */
class FirstInitialLastName implements RowTransformationInterface
{
    /**
     * @param array $input
     * @param int $layer
     *
     * @return array|string
     * @throws \Exception
     */
    public function processArray(array $input, $layer = 0)
    {
        if (!\is_array($input)) {
            throw new \TypeError('Compound Transformation expects an array');
        }
        return (string) \json_encode($this->processArray($input));

    }

    /**
     * Implementations can define their own prototypes, but
     * this should almost always operate on a string, and must
     * always return a string.
     *
     * @param mixed $input
     * @return string
     */
    public function __invoke($input)
    {
        return \strtolower($input['first_name'][0] . $input['last_name']);
    }
}
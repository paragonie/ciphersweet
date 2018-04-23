<?php
namespace ParagonIE\CipherSweet\Transformation;

use ParagonIE\CipherSweet\Contract\TransformationInterface;

/**
 * Class Lowercase
 * @package ParagonIE\CipherSweet\Transformation
 */
class Lowercase implements TransformationInterface
{
    /**
     * Returns the lowercase representation of the input string.
     *
     * @param string $input
     * @return string
     */
    public function __invoke($input)
    {
        return \strtolower($input);
    }
}

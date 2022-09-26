<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\Transformation;

use ParagonIE\CipherSweet\Contract\TransformationInterface;
use ParagonIE\ConstantTime\Binary;

/**
 * Class FirstCharacter
 * @package ParagonIE\CipherSweet\Transformation
 */
class FirstCharacter implements TransformationInterface
{
    /**
     * Returns the lowercase representation of the input string.
     *
     * @param string $input
     * @return string
     */
    public function __invoke(
        #[\SensitiveParameter]
        mixed $input
    ): string {
        if (Binary::safeStrlen($input) < 1) {
            return '';
        }
        return $input[0];
    }
}

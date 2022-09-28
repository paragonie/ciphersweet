<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\Transformation;

use ParagonIE\CipherSweet\Contract\TransformationInterface;

/**
 * Class AlphaNumericCharactersOnly
 * @package ParagonIE\CipherSweet\Transformation
 */
class AlphaNumericCharactersOnly implements TransformationInterface
{
    /**
     * Strips off any non-alphanumeric characters (including periods and commas).
     *
     * @param string $input
     * @return string
     */
    public function __invoke(
        #[\SensitiveParameter]
        mixed $input
    ): string {
        return \preg_replace('/[^a-z0-9]/i', '', $input);
    }
}

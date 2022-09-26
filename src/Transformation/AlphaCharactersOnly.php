<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\Transformation;

use ParagonIE\CipherSweet\Contract\TransformationInterface;

/**
 * Class AlphaCharactersOnly
 * @package ParagonIE\CipherSweet\Transformation
 */
class AlphaCharactersOnly implements TransformationInterface
{
    /**
     * Strips off any non-numeric characters (including periods and commas).
     *
     * @param string $input
     * @return string
     */
    public function __invoke(
        #[\SensitiveParameter]
        mixed $input
    ): string {
        return \preg_replace('/[^A-Za-z]/', '', $input);
    }
}

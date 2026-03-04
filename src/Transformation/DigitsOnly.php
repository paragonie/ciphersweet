<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\Transformation;

use ParagonIE\CipherSweet\Contract\TransformationInterface;

/**
 * Class DigitsOnly
 * @package ParagonIE\CipherSweet\Transformation
 */
class DigitsOnly implements TransformationInterface
{
    /**
     * Strips off any non-numeric characters (including periods and commas).
     *
     * @param string $input
     * @return string
     */
    #[\Override]
    public function __invoke(
        #[\SensitiveParameter]
        mixed $input
    ): string
    {
        return (string) \preg_replace('/[^0-9]/', '', $input);
    }
}

<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\Transformation;

use ParagonIE\ConstantTime\Binary;
use ParagonIE\CipherSweet\Contract\TransformationInterface;

/**
 * Class LastFourDigits
 * @package ParagonIE\CipherSweet\Transformation
 */
class LastFourDigits implements TransformationInterface
{
    /**
     * Returns the last 4 digits (e.g. for a social security or credit card
     * number). If less then 4 digits are available, it will pad them with 0
     * characters to the left.
     *
     * 1234567890 => 7890
     * 123        => 0123
     *
     * @param string $input
     * @return string
     */
    public function __invoke(
        #[\SensitiveParameter]
        mixed $input
    ): string {
        $input = \preg_replace('/[^0-9]/', '', $input);
        $input = \str_pad($input, 4, '0', STR_PAD_LEFT);
        return Binary::safeSubstr($input, -4, 4);
    }
}

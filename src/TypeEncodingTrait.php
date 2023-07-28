<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet;

use SodiumException;

trait TypeEncodingTrait
{
    /**
     * Convert data from decrypted ciphertext into the intended data type
     * (i.e. the format of the original plaintext before being converted).
     *
     * @throws SodiumException
     */
    protected function convertFromString(string $data, string $type): int|string|float|bool|null
    {
        return match ($type) {
            Constants::TYPE_OPTIONAL_BOOLEAN, Constants::TYPE_BOOLEAN =>
                Util::chrToBool($data),
            Constants::TYPE_OPTIONAL_FLOAT, Constants::TYPE_FLOAT =>
                Util::stringToFloat($data),
            Constants::TYPE_OPTIONAL_INT, Constants::TYPE_INT =>
                Util::stringToInt($data),
            default => $data,
        };
    }

    /**
     * Convert multiple data types to a string prior to encryption.
     *
     * The main goals here are:
     *
     * 1. Convert several data types to a string.
     * 2. Leak no information about the original value in the
     *    output string length.
     *
     * @throws SodiumException
     */
    protected function convertToString(int|string|float|bool|null $data, string $type): string
    {
        switch ($type) {
            // Will return a 1-byte string:
            case Constants::TYPE_OPTIONAL_BOOLEAN:
            case Constants::TYPE_BOOLEAN:
                if (!\is_null($data) && !\is_bool($data)) {
                    $data = !empty($data);
                }
                return Util::boolToChr($data);
            // Will return a fixed-length string:
            case Constants::TYPE_OPTIONAL_FLOAT:
            case Constants::TYPE_FLOAT:
                if (!\is_float($data)) {
                    throw new \TypeError('Expected a float');
                }
                return Util::floatToString($data);
            // Will return a fixed-length string:
            case Constants::TYPE_OPTIONAL_INT:
            case Constants::TYPE_INT:
                if (!\is_int($data)) {
                    throw new \TypeError('Expected an integer');
                }
                return Util::intToString($data);
            // Will return the original string, untouched:
            default:
                return (string) $data;
        }
    }
}
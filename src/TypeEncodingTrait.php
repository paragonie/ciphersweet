<?php

namespace ParagonIE\CipherSweet;

use SodiumException;

trait TypeEncodingTrait
{
    /**
     * Convert data from decrypted ciphertext into the intended data type
     * (i.e. the format of the original plaintext before being converted).
     *
     * @param string $data
     * @param string $type
     * @return int|string|float|bool|null
     * @throws SodiumException
     */
    protected function convertFromString($data, $type)
    {
        switch ($type) {
            case Constants::TYPE_BOOLEAN:
                return Util::chrToBool($data);
            case Constants::TYPE_FLOAT:
                return Util::stringToFloat($data);
            case Constants::TYPE_INT:
                return Util::stringToInt($data);
            default:
                return (string) $data;
        }
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
     * @param int|string|float|bool|null $data
     * @param string $type
     * @return string
     * @throws SodiumException
     */
    protected function convertToString($data, $type)
    {
        switch ($type) {
            // Will return a 1-byte string:
            case Constants::TYPE_BOOLEAN:
                if (!\is_null($data) && !\is_bool($data)) {
                    $data = !empty($data);
                }
                return Util::boolToChr($data);
            // Will return a fixed-length string:
            case Constants::TYPE_FLOAT:
                if (!\is_float($data)) {
                    throw new \TypeError('Expected a float');
                }
                return Util::floatToString($data);
            // Will return a fixed-length string:
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
<?php
namespace ParagonIE\CipherSweet\Contract;

use ParagonIE\CipherSweet\Exception\InvalidCiphertextException;

/**
 * Class KeyRotation
 * @package ParagonIE\CipherSweet
 */
interface KeyRotationInterface
{

    /**
     * @param string|array<string, string> $ciphertext
     * @return bool
     * @throws InvalidCiphertextException
     */
    public function needsReEncrypt($ciphertext = '');

    /**
     * @param string|array<string, string> $values
     * @return array
     */
    public function prepareForUpdate($values);
}

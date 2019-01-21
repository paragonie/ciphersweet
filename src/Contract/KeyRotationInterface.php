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
     * @param string $ciphertext
     * @return bool
     * @throws InvalidCiphertextException
     */
    public function needsReEncrypt($ciphertext = '');

    /**
     * @param string|array $values
     * @return array
     */
    public function prepareForUpdate($values);
}

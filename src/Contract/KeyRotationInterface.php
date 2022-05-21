<?php
declare(strict_types=1);
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
    public function needsReEncrypt(string|array $ciphertext = ''): bool;

    /**
     * @param string|array<string, string> $values
     * @return array
     */
    public function prepareForUpdate(string|array $values): array;
}

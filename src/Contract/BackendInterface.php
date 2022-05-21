<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\Contract;

use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\Constants;

/**
 * Interface BackendInterface
 * @package ParagonIE\CipherSweet\Contract
 */
interface BackendInterface
{
    public function encrypt(string $plaintext, SymmetricKey $key, string $aad = ''): string;

    public function decrypt(string $ciphertext, SymmetricKey $key, string $aad = ''): string;

    public function blindIndexFast(
        string $plaintext,
        SymmetricKey $key,
        ?int $bitLength = null
    ): string;

    public function blindIndexSlow(
        string $plaintext,
        SymmetricKey $key,
        ?int $bitLength = null,
        array $config = []
    ): string;

    public function getIndexTypeColumn(
        string $tableName,
        string $fieldName,
        string $indexName
    ): string;

    /**
     * @param string $password
     * @param string $salt
     * @return SymmetricKey
     */
    public function deriveKeyFromPassword(
        string $password,
        string $salt
    ): SymmetricKey;

    /**
     * @param resource $inputFP
     * @param resource $outputFP
     * @param SymmetricKey $key
     * @param int $chunkSize
     * @return bool
     */
    public function doStreamDecrypt(
        $inputFP,
        $outputFP,
        SymmetricKey $key,
        int $chunkSize = 8192
    ): bool;

    /**
     * @param resource $inputFP
     * @param resource $outputFP
     * @param SymmetricKey $key
     * @param int $chunkSize
     * @param string $salt
     * @return bool
     */
    public function doStreamEncrypt(
        $inputFP,
        $outputFP,
        SymmetricKey $key,
        int $chunkSize = 8192,
        string $salt = Constants::DUMMY_SALT
    ): bool;

    /**
     * @return int
     */
    public function getFileEncryptionSaltOffset(): int;

    /**
     * @return string
     */
    public function getPrefix(): string;
}

<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\Contract;

use ParagonIE\CipherSweet\AAD;
use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\Constants;

/**
 * Interface BackendInterface
 * @package ParagonIE\CipherSweet\Contract
 */
interface BackendInterface
{
    public function encrypt(
        #[\SensitiveParameter]
        string $plaintext,
        #[\SensitiveParameter]
        SymmetricKey $key,
        #[\SensitiveParameter]
        string $aad = ''
    ): string;

    public function decrypt(
        #[\SensitiveParameter]
        string $ciphertext,
        #[\SensitiveParameter]
        SymmetricKey $key,
        #[\SensitiveParameter]
        string $aad = '')
    : string;

    public function blindIndexFast(
        #[\SensitiveParameter]
        string $plaintext,
        #[\SensitiveParameter]
        SymmetricKey $key,
        #[\SensitiveParameter]
        ?int $bitLength = null
    ): string;

    public function blindIndexSlow(
        #[\SensitiveParameter]
        string $plaintext,
        #[\SensitiveParameter]
        SymmetricKey $key,
        ?int $bitLength = null,
        array $config = []
    ): string;

    public function getIndexTypeColumn(
        #[\SensitiveParameter]
        string $tableName,
        #[\SensitiveParameter]
        string $fieldName,
        #[\SensitiveParameter]
        string $indexName
    ): string;

    /**
     * @param string $password
     * @param string $salt
     * @return SymmetricKey
     */
    public function deriveKeyFromPassword(
        #[\SensitiveParameter]
        string $password,
        #[\SensitiveParameter]
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
        int $chunkSize = 8192,
        ?AAD $aad = null
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
        string $salt = Constants::DUMMY_SALT,
        ?AAD $aad = null
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

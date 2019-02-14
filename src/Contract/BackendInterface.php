<?php
namespace ParagonIE\CipherSweet\Contract;

use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;

/**
 * Interface BackendInterface
 * @package ParagonIE\CipherSweet\Contract
 */
interface BackendInterface
{
    /**
     * @param string $plaintext
     * @param SymmetricKey $key
     * @param string $aad       Additional authenticated data
     * @return string
     */
    public function encrypt($plaintext, SymmetricKey $key, $aad = '');

    /**
     * @param string $ciphertext
     * @param SymmetricKey $key
     * @param string $aad       Additional authenticated data
     * @return string
     */
    public function decrypt($ciphertext, SymmetricKey $key, $aad = '');

    /**
     * @param string $plaintext
     * @param SymmetricKey $key
     * @param int|null $bitLength
     *
     * @return string
     */
    public function blindIndexFast(
        $plaintext,
        SymmetricKey $key,
        $bitLength = null
    );

    /**
     * @param string $plaintext
     * @param SymmetricKey $key
     * @param int|null $bitLength
     * @param array $config
     *
     * @return string
     */
    public function blindIndexSlow(
        $plaintext,
        SymmetricKey $key,
        $bitLength = null,
        array $config = []
    );

    /**
     * @param string $tableName
     * @param string $fieldName
     * @param string $indexName
     * @return string
     */
    public function getIndexTypeColumn($tableName, $fieldName, $indexName);

    /**
     * @param string $password
     * @param string $salt
     * @return SymmetricKey
     */
    public function deriveKeyFromPassword($password, $salt);

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
        $chunkSize = 8192
    );

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
        $chunkSize = 8192,
        $salt = Constants::DUMMY_SALT
    );

    /**
     * @return int
     */
    public function getFileEncryptionSaltOffset();

    /**
     * @return string
     */
    public function getPrefix();
}

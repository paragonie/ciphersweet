<?php
namespace ParagonIE\CipherSweet\Contract;

use ParagonIE\CipherSweet\Backend\Key\AsymmetricPublicKey;
use ParagonIE\CipherSweet\Backend\Key\AsymmetricSecretKey;
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
     * @return string
     */
    public function encrypt($plaintext, SymmetricKey $key);

    /**
     * @param string $ciphertext
     * @param SymmetricKey $key
     * @return string
     */
    public function decrypt($ciphertext, SymmetricKey $key);

    /**
     * @param string $message
     * @param AsymmetricPublicKey $publicKey
     * @return string
     */
    public function publicEncrypt($message, AsymmetricPublicKey $publicKey);

    /**
     * @param string $message
     * @param AsymmetricSecretKey $secretKey
     *
     * @return string
     */
    public function privateDecrypt($message, AsymmetricSecretKey $secretKey);

    /**
     * @param string $message
     * @param AsymmetricSecretKey $secretKey
     *
     * @return string
     */
    public function sign($message, AsymmetricSecretKey $secretKey);

    /**
     * @param string $message
     * @param AsymmetricPublicKey $publicKey
     * @param string $signature
     * @return bool
     */
    public function verify($message, AsymmetricPublicKey $publicKey, $signature);

    /**
     * @param string $plaintext
     * @param SymmetricKey $key
     * @param int|null $outputLength
     *
     * @return string
     */
    public function blindIndexFast($plaintext, SymmetricKey $key, $outputLength = null);

    /**
     * @param string $plaintext
     * @param SymmetricKey $key
     * @param int|null $outputLength
     * @param array $config
     *
     * @return string
     */
    public function blindIndexSlow($plaintext, SymmetricKey $key, $outputLength = null, array $config = []);

    /**
     * @param string $tableName
     * @param string $fieldName
     * @param string $indexName
     * @return string
     */
    public function getIndexTypeColumn($tableName, $fieldName, $indexName);

    /**
     * @param AsymmetricSecretKey $secretKey
     * @return AsymmetricPublicKey
     */
    public function getPublicKeyFromSecretKey(AsymmetricSecretKey $secretKey);
}

<?php
namespace ParagonIE\CipherSweet;

use ParagonIE\CipherSweet\Backend\FIPSCrypto;
use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\Backend\ModernCrypto;
use ParagonIE\CipherSweet\Contract\BackendInterface;
use ParagonIE\CipherSweet\Contract\KeyProviderInterface;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;
use ParagonIE_Sodium_Compat as SodiumCompat;

/**
 * Class CipherSweet
 * @package ParagonIE\CipherSweet
 */
final class CipherSweet
{
    /**
     * @var BackendInterface $backend
     */
    private $backend;

    /**
     * @var KeyProviderInterface $keyProvider
     */
    private $keyProvider;

    /**
     * CipherSweet constructor.
     *
     * @param KeyProviderInterface $keyProvider
     * @param BackendInterface $backend
     */
    public function __construct(
        KeyProviderInterface $keyProvider,
        BackendInterface $backend
    ) {
        $this->keyProvider = $keyProvider;
        $this->backend = $backend;
    }

    /**
     * @return BackendInterface
     */
    public function getBackend()
    {
        return $this->backend;
    }

    /**
     * @param string $tableName
     * @param string $fieldName
     * @param string $indexName
     * @return string
     */
    public function getIndexTypeColumn(
        $tableName,
        $fieldName,
        $indexName
    ) {
        return $this->backend->getIndexTypeColumn(
            $tableName,
            $fieldName,
            $indexName
        );
    }

    /**
     * Get the root key for calculating blind index keys for a given
     * EncryptedField instance.
     *
     * Uses a 32 byte prefix for the HKDF "info" parameter, for domain
     * separation.
     *
     * @param string $tableName
     * @param string $fieldName
     *
     * @return SymmetricKey
     * @throws CryptoOperationException
     */
    public function getBlindIndexRootKey($tableName, $fieldName)
    {
        return new SymmetricKey(
            Util::HKDF(
                $this->keyProvider->getSymmetricKey(),
                $tableName,
                Constants::DS_BIDX . $fieldName
            )
        );
    }

    /**
     * Get the per-field encryption key.
     *
     * Uses a 32 byte prefix for the HKDF "info" parameter, for domain
     * separation.
     *
     * @param string $tableName
     * @param string $fieldName
     *
     * @return SymmetricKey
     * @throws CryptoOperationException
     */
    public function getFieldSymmetricKey($tableName, $fieldName)
    {
        return new SymmetricKey(
            Util::HKDF(
                $this->keyProvider->getSymmetricKey(),
                $tableName,
                Constants::DS_FENC . $fieldName
            )
        );
    }

    /**
     * Return the default backend for a given environment. Note that the
     * stability of the result of this static method should not be depended on.
     *
     * @return BackendInterface
     */
    public static function getDefaultBackend()
    {
        if (SodiumCompat::crypto_pwhash_is_available()) {
            if (PHP_VERSION_ID >= 70000 && \extension_loaded('sodium')) {
                return new ModernCrypto();
            }
            if (PHP_VERSION_ID >= 70000 && \extension_loaded('libsodium')) {
                // This is a little weird but OK
                return new ModernCrypto();
            }
            if (PHP_VERSION_ID < 70000 && \extension_loaded('libsodium')) {
                return new ModernCrypto();
            }
        }
        // FIPS mode will always work... but it only uses FIPS algorithms.
        return new FIPSCrypto();
    }
}

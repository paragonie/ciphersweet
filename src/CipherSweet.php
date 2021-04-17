<?php
namespace ParagonIE\CipherSweet;

use ParagonIE\CipherSweet\Backend\BoringCrypto;
use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\Contract\BackendInterface;
use ParagonIE\CipherSweet\Contract\KeyProviderInterface;
use ParagonIE\CipherSweet\Contract\MultiTenantAwareProviderInterface;
use ParagonIE\CipherSweet\Contract\MultiTenantSafeBackendInterface;
use ParagonIE\CipherSweet\Exception\CipherSweetException;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;

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
     * @param BackendInterface|null $backend
     */
    public function __construct(
        KeyProviderInterface $keyProvider,
        BackendInterface $backend = null
    ) {
        $this->keyProvider = $keyProvider;
        $this->backend = $backend ?: new BoringCrypto();
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
     * @throws \SodiumException
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
     *
     * @throws CipherSweetException
     * @throws CryptoOperationException
     */
    public function getFieldSymmetricKey($tableName, $fieldName)
    {
        if ($this->isMultiTenantSupported()) {
            return new SymmetricKey(
                Util::HKDF(
                    $this->getKeyProviderForActiveTenant()->getSymmetricKey(),
                    $tableName,
                    Constants::DS_FENC . $fieldName
                )
            );
        }

        return new SymmetricKey(
            Util::HKDF(
                $this->keyProvider->getSymmetricKey(),
                $tableName,
                Constants::DS_FENC . $fieldName
            )
        );
    }

    /**
     * Get the key provider for a given tenant
     *
     * @return KeyProviderInterface
     * @throws CipherSweetException
     */
    public function getKeyProviderForActiveTenant()
    {
        if (!($this->keyProvider instanceof MultiTenantAwareProviderInterface)) {
            throw new CipherSweetException('Your Key Provider is not multi-tenant aware');
        }
        /** @param MultiTenantAwareProviderInterface $kp */
        $kp = $this->keyProvider;
        return $kp->getActiveTenant();
    }

    /**
     * Get the key provider for a given tenant
     *
     * @param array-key $name
     * @return KeyProviderInterface
     * @throws CipherSweetException
     */
    public function getKeyProviderForTenant($name)
    {
        if (!($this->keyProvider instanceof MultiTenantAwareProviderInterface)) {
            throw new CipherSweetException('Your Key Provider is not multi-tenant aware');
        }
        /** @param MultiTenantAwareProviderInterface $kp */
        $kp = $this->keyProvider;
        return $kp->getTenant($name);
    }

    /**
     * @param array $row
     * @param string $tableName
     * @return string
     * @throws CipherSweetException
     */
    public function getTenantFromRow(array $row, $tableName = '')
    {
        /** @param MultiTenantAwareProviderInterface $kp */
        if ($this->keyProvider instanceof MultiTenantAwareProviderInterface) {
            $kp = $this->keyProvider;
            return $kp->getTenantFromRow($row, $tableName);
        }
        throw new CipherSweetException('Your Key Provider is not multi-tenant aware');
    }

    /**
     * @param string $name
     * @return void
     * @throws CipherSweetException
     */
    public function setActiveTenant($name)
    {
        /** @param MultiTenantAwareProviderInterface $kp */
        if ($this->keyProvider instanceof MultiTenantAwareProviderInterface) {
            $this->keyProvider->setActiveTenant($name);
            return;
        }
        throw new CipherSweetException('Your Key Provider is not multi-tenant aware');
    }

    /**
     * @param array $row
     * @param string $tableName
     * @return array
     * @throws CipherSweetException
     */
    public function injectTenantMetadata(array $row, $tableName = '')
    {
        if ($this->keyProvider instanceof MultiTenantAwareProviderInterface) {
            $kp = $this->keyProvider;
            return $kp->injectTenantMetadata($row, $tableName);
        }
        throw new CipherSweetException('Multi-tenant is not supported');
    }

    /**
     * @return bool
     */
    public function isMultiTenantSupported()
    {
        if (!($this->backend instanceof MultiTenantSafeBackendInterface)) {
            // Backend doesn't provide the cryptographic properties we need.
            return false;
        }

        if (!($this->keyProvider instanceof MultiTenantAwareProviderInterface)) {
            // KeyProvider doesn't understand the concept of multiple tenants.
            return false;
        }
        return true;
    }
}

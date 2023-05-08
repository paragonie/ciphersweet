<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet;

use ParagonIE\CipherSweet\Backend\{
    BoringCrypto,
    Key\SymmetricKey
};
use ParagonIE\CipherSweet\Contract\{
    BackendInterface,
    KeyProviderInterface,
    MultiTenantAwareProviderInterface,
    MultiTenantSafeBackendInterface
};
use ParagonIE\CipherSweet\Exception\{
    CipherSweetException,
    CryptoOperationException
};
use SodiumException;

/**
 * Class CipherSweet
 * @package ParagonIE\CipherSweet
 */
final class CipherSweet
{
    private BackendInterface $backend;
    private KeyProviderInterface $keyProvider;
    private bool $enableMultiTenantCountCheck = true;

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
    public function getBackend(): BackendInterface
    {
        return $this->backend;
    }

    /**
     * Obtain the Key Provider that was passed to the constructor.
     *
     * @return KeyProviderInterface
     */
    public function getKeyProvider(): KeyProviderInterface
    {
        return $this->keyProvider;
    }

    /**
     * @throws SodiumException
     */
    public function getIndexTypeColumn(
        string $tableName,
        string $fieldName,
        string $indexName
    ): string {
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
     */
    public function getBlindIndexRootKey(string $tableName, string $fieldName): SymmetricKey
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
    public function getFieldSymmetricKey(string $tableName, string $fieldName): SymmetricKey
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
     * Get a key for use with CipherSweet extensions
     *
     * @param string $extensionUniqueName
     * @param string ...$extra
     *
     * @return SymmetricKey
     *
     * @throws CipherSweetException
     * @throws CryptoOperationException
     */
    public function getExtensionKey(string $extensionUniqueName, string ...$extra): SymmetricKey
    {
        $info = Constants::DS_EXT . Util::pack([$extensionUniqueName, ...$extra]);

        if ($this->isMultiTenantSupported()) {
            return new SymmetricKey(
                Util::HKDF(
                    $this->getKeyProviderForActiveTenant()->getSymmetricKey(),
                    '',
                    $info
                )
            );
        }

        return new SymmetricKey(
            Util::HKDF(
                $this->keyProvider->getSymmetricKey(),
                '',
                $info
            )
        );
    }

    /**
     * Get the key provider for a given tenant
     *
     * @return KeyProviderInterface
     * @throws CipherSweetException
     */
    public function getKeyProviderForActiveTenant(): KeyProviderInterface
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
    public function getKeyProviderForTenant(string|int $name): KeyProviderInterface
    {
        if (!($this->keyProvider instanceof MultiTenantAwareProviderInterface)) {
            throw new CipherSweetException('Your Key Provider is not multi-tenant aware');
        }
        /** @param MultiTenantAwareProviderInterface $kp */
        $kp = $this->keyProvider;
        return $kp->getTenant($name);
    }

    /**
     * @return bool
     */
    public function getMultiTenantCountCheckEnabled(): bool
    {
        return $this->enableMultiTenantCountCheck;
    }

    /**
     * @param array $row
     * @param string $tableName
     * @return string|int
     *
     * @throws CipherSweetException
     */
    public function getTenantFromRow(array $row, string $tableName = ''): string|int
    {
        /** @param MultiTenantAwareProviderInterface $kp */
        if ($this->keyProvider instanceof MultiTenantAwareProviderInterface) {
            $kp = $this->keyProvider;
            return $kp->getTenantFromRow($row, $tableName);
        }
        throw new CipherSweetException('Your Key Provider is not multi-tenant aware');
    }

    /**
     * @param string|int $tenant
     * @return void
     * @throws CipherSweetException
     */
    public function setActiveTenant(string|int $tenant): void
    {
        /** @param MultiTenantAwareProviderInterface $kp */
        if ($this->keyProvider instanceof MultiTenantAwareProviderInterface) {
            $this->keyProvider->setActiveTenant($tenant);
            return;
        }
        throw new CipherSweetException('Your Key Provider is not multi-tenant aware');
    }

    /**
     * @param bool $value
     * @return self
     */
    public function setMultiTenantCountCheckEnabled(bool $value): self
    {
        $this->enableMultiTenantCountCheck = $value;
        return $this;
    }

    /**
     * @param array $row
     * @param string $tableName
     * @return array
     *
     * @throws CipherSweetException
     */
    public function injectTenantMetadata(array $row, string $tableName = ''): array
    {
        if ($this->keyProvider instanceof MultiTenantAwareProviderInterface) {
            $kp = $this->keyProvider;

            // This check is to prevent implementation mistakes with multi-tenant key providers.
            if ($this->enableMultiTenantCountCheck) {
                $injected = $kp->injectTenantMetadata($row, $tableName);
                if (count($injected) < count($row)) {
                    $message = 'Injecting tenant metadata should not decrease the size of the array. ';
                    $message .= 'Before: ' . count($row) . '. After: ' . count($injected) . '.';
                    throw new CipherSweetException($message);
                }
                return $injected;
            }

            // If the above check was disabled, we just return the result naively like before:
            return $kp->injectTenantMetadata($row, $tableName);
        }
        throw new CipherSweetException('Multi-tenant is not supported');
    }

    /**
     * @return bool
     */
    public function isMultiTenantSupported(): bool
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

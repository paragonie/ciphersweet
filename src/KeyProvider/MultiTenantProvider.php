<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\KeyProvider;

use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\Contract\{
    KeyProviderInterface,
    MultiTenantAwareProviderInterface
};
use ParagonIE\CipherSweet\Exception\CipherSweetException;

/**
 * Class MultiTenantProvider
 * @package ParagonIE\CipherSweet\KeyProvider
 */
class MultiTenantProvider implements KeyProviderInterface, MultiTenantAwareProviderInterface
{
    /** @var array<array-key, KeyProviderInterface> $tenants */
    protected array $tenants = [];

    /** @var array-key|null $active */
    protected string|int|null $active;

    /**
     * MultiTenantProvider constructor.
     *
     * @param array<array-key, KeyProviderInterface> $keyProviders
     * @param array-key|null $active
     */
    public function __construct(array $keyProviders, string|int|null $active = null)
    {
        foreach ($keyProviders as $name => $keyProvider) {
            $this->tenants[$name] = $keyProvider;
        }
        $this->active = $active;
    }

    /**
     * @param array-key $index
     * @param KeyProviderInterface $provider
     * @return static
     */
    public function addTenant(string|int $index, KeyProviderInterface $provider): static
    {
        $this->tenants[$index] = $provider;
        return $this;
    }

    /**
     * @param array-key $index
     * @return static
     */
    public function setActiveTenant(string|int $index): static
    {
        $this->active = $index;
        return $this;
    }

    /**
     * @param array-key $name
     * @return KeyProviderInterface
     * @throws CipherSweetException
     * @psalm-suppress PossiblyNullArrayOffset
     */
    public function getTenant(string|int $name): KeyProviderInterface
    {
        if (!\array_key_exists($name, $this->tenants)) {
            throw new CipherSweetException('Tenant does not exist');
        }
        return $this->tenants[$name];
    }

    /**
     * @return KeyProviderInterface
     * @throws CipherSweetException
     */
    public function getActiveTenant(): KeyProviderInterface
    {
        if (\is_null($this->active)) {
            throw new CipherSweetException('Active tenant not set');
        }
        if (!\array_key_exists($this->active, $this->tenants)) {
            throw new CipherSweetException('Tenant does not exist');
        }
        return $this->tenants[$this->active];
    }

    /**
     * @return SymmetricKey
     * @throws CipherSweetException
     */
    public function getSymmetricKey(): SymmetricKey
    {
        if (\is_null($this->active)) {
            throw new CipherSweetException('Active tenant not set');
        }
        return $this->getActiveTenant()->getSymmetricKey();
    }

    /**
     * OVERRIDE THIS in your own class!
     *
     * Given a row of data, determine which tenant should be selected.
     *
     * @param array $row
     * @param string $tableName
     * @return string|int
     *
     * @throws CipherSweetException
     */
    public function getTenantFromRow(array $row, string $tableName): string|int
    {
        if (!$this->active) {
            throw new CipherSweetException('This is not implemented. Please override in a child class.');
        }
        return $this->active;
    }

    /**
     * OVERRIDE THIS in your own class!
     *
     * @param array $row
     * @param string $tableName
     * @return array
     */
    public function injectTenantMetadata(array $row, string $tableName): array
    {
        return $row;
    }
}

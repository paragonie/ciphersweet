<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\Contract;

use ParagonIE\CipherSweet\Exception\CipherSweetException;

/**
 * Interface MultiTenantAwareProviderInterface
 * @package ParagonIE\CipherSweet\Contract
 */
interface MultiTenantAwareProviderInterface
{
    /**
     * @return KeyProviderInterface
     * @throws CipherSweetException
     */
    public function getActiveTenant(): KeyProviderInterface;

    /**
     * @param array-key $name
     * @return KeyProviderInterface
     * @throws CipherSweetException
     */
    public function getTenant(string|int $name): KeyProviderInterface;

    /**
     * @param array-key $index
     * @return self
     */
    public function setActiveTenant(string|int $index): self;

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
    public function getTenantFromRow(array $row, string $tableName): string|int;

    /**
     * @param array $row
     * @param string $tableName
     * @return array
     */
    public function injectTenantMetadata(array $row, string $tableName): array;
}

<?php
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
    public function getActiveTenant();

    /**
     * @param array-key $name
     * @return KeyProviderInterface
     * @throws CipherSweetException
     */
    public function getTenant($name);

    /**
     * @param array-key $index
     * @return self
     */
    public function setActiveTenant($index);

    /**
     * OVERRIDE THIS in your own class!
     *
     * Given a row of data, determine which tenant should be selected.
     *
     * @param array $row
     * @return string
     *
     * @throws CipherSweetException
     */
    public function getTenantFromRow(array $row);

    /**
     * @param array $row
     * @return array
     */
    public function injectTenantMetadata(array $row);
}

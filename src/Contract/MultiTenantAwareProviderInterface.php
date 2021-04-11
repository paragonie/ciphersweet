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
}

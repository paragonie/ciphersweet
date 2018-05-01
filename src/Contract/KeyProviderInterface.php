<?php
namespace ParagonIE\CipherSweet\Contract;

use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;

/**
 * Interface KeyProviderInterface
 * @package ParagonIE\CipherSweet\Contract
 */
interface KeyProviderInterface
{
    /**
     * @return BackendInterface
     */
    public function getBackend();

    /**
     * @return SymmetricKey
     */
    public function getSymmetricKey();
}

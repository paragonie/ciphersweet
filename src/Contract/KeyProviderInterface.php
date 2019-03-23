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
     * @return SymmetricKey
     */
    public function getSymmetricKey();
}

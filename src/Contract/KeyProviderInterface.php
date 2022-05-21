<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\Contract;

use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;

/**
 * Interface KeyProviderInterface
 * @package ParagonIE\CipherSweet\Contract
 */
interface KeyProviderInterface
{
    public function getSymmetricKey(): SymmetricKey;
}

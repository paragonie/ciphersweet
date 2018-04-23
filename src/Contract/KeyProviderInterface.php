<?php
namespace ParagonIE\CipherSweet\Contract;

use ParagonIE\CipherSweet\Backend\Key\AsymmetricPublicKey;
use ParagonIE\CipherSweet\Backend\Key\AsymmetricSecretKey;
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
     * @return AsymmetricPublicKey
     */
    public function getPublicKey();

    /**
     * @return SymmetricKey
     */
    public function getSymmetricKey();

    /**
     * @return AsymmetricSecretKey
     */
    public function getSecretKey();
}

<?php
namespace ParagonIE\CipherSweet\Backend\Key;

use ParagonIE\CipherSweet\Contract\BackendInterface;

/**
 * Class AsymmetricSecretKey
 * @package ParagonIE\CipherSweet\Backend\Key
 */
class AsymmetricSecretKey
{
    /**
     * @var BackendInterface $Backend
     */
    private $Backend;

    /**
     * @var string $keyMaterial
     */
    private $keyMaterial;

    /**
     * SymmetricKey constructor.
     *
     * @param BackendInterface $Backend
     * @param string $rawKeyMaterial
     */
    public function __construct(BackendInterface $Backend, $rawKeyMaterial)
    {
        $this->Backend = $Backend;
        $this->keyMaterial = $rawKeyMaterial;
    }

    /**
     * @return AsymmetricPublicKey
     */
    public function getPublicKey()
    {
        return $this->Backend->getPublicKeyFromSecretKey($this);
    }

    /**
     * @return string
     */
    public function getRawKey()
    {
        return $this->keyMaterial;
    }
}

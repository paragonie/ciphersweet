<?php
namespace ParagonIE\CipherSweet\Backend\Key;

use ParagonIE\CipherSweet\Contract\BackendInterface;

/**
 * Class AsymmetricPublicKey
 * @package ParagonIE\CipherSweet\Backend\Key
 */
class AsymmetricPublicKey
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
     * @return string
     */
    public function getRawKey()
    {
        return $this->keyMaterial;
    }
}

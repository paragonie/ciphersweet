<?php
namespace ParagonIE\CipherSweet\Backend\Key;

use ParagonIE\CipherSweet\Contract\BackendInterface;

/**
 * Class SymmetricKey
 * @package ParagonIE\CipherSweet\Backend\Key
 */
class SymmetricKey
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
        /** @psalm-suppress RedundantConditionGivenDocblockType */
        if (!\is_string($rawKeyMaterial)) {
            throw new \TypeError('String expected');
        }
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

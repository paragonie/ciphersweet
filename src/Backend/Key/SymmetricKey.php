<?php
namespace ParagonIE\CipherSweet\Backend\Key;

use ParagonIE\CipherSweet\Contract\BackendInterface;
use ParagonIE\CipherSweet\Util;

/**
 * Class SymmetricKey
 * @package ParagonIE\CipherSweet\Backend\Key
 */
class SymmetricKey
{
    /**
     * @var BackendInterface $Backend
     */
    private $backend;

    /**
     * @var string $keyMaterial
     */
    private $keyMaterial;

    /**
     * SymmetricKey constructor.
     *
     * @param BackendInterface $backend
     * @param string $rawKeyMaterial
     */
    public function __construct(BackendInterface $backend, $rawKeyMaterial)
    {
        /** @psalm-suppress RedundantConditionGivenDocblockType */
        if (!\is_string($rawKeyMaterial)) {
            throw new \TypeError('String expected');
        }
        $this->backend = $backend;
        $this->keyMaterial = $rawKeyMaterial;
    }

    /**
     * Attempt to wipe memory.
     *
     * @throws \SodiumException
     */
    public function __destruct()
    {
        Util::memzero($this->keyMaterial);
    }

    /**
     * @return string
     */
    public function getRawKey()
    {
        return $this->keyMaterial;
    }
}

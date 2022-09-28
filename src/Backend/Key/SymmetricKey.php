<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\Backend\Key;

use ParagonIE\CipherSweet\Util;

/**
 * Class SymmetricKey
 * @package ParagonIE\CipherSweet\Backend\Key
 */
class SymmetricKey
{
    public function __construct(
        private string $keyMaterial
    ) {}

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
    public function getRawKey(): string
    {
        return $this->keyMaterial;
    }
}

<?php
namespace ParagonIE\CipherSweet\Backend\Key;

use ParagonIE\CipherSweet\Contract\BackendInterface;
use ParagonIE\ConstantTime\Binary;

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
     */
    public function __destruct()
    {
        if (PHP_VERSION_ID >= 70200) {
            \sodium_memzero($this->keyMaterial);
        } elseif (PHP_VERSION_ID >= 70000 && \extension_loaded('sodium')) {
            \sodium_memzero($this->keyMaterial);
        } elseif (\extension_loaded('libsodium')) {
            \Sodium\memzero($this->keyMaterial);
        } else {
            // Worst-case scenario: Best-ditch effort to wipe memory
            $m = \str_repeat("\xff", Binary::safeStrlen($this->keyMaterial));
            $this->keyMaterial ^= ($this->keyMaterial ^ $m);
            unset($this->keyMaterial);
        }
    }

    /**
     * @return string
     */
    public function getRawKey()
    {
        return $this->keyMaterial;
    }
}

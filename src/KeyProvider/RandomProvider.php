<?php
namespace ParagonIE\CipherSweet\KeyProvider;

use ParagonIE\CipherSweet\Backend\FIPSCrypto;
use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\Backend\ModernCrypto;
use ParagonIE\CipherSweet\Contract\BackendInterface;
use ParagonIE\CipherSweet\Contract\KeyProviderInterface;

/**
 * Class RandomProvider
 *
 * This is mostly useful for initially key generation and/or unit testing.
 *
 * @package ParagonIE\CipherSweet\KeyProvider
 */
class RandomProvider implements KeyProviderInterface
{
    /**
     * @var BackendInterface
     */
    private $backend;

    /**
     * RandomProvider constructor.
     *
     * @param BackendInterface $backend
     */
    public function __construct(BackendInterface $backend)
    {
        $this->backend = $backend;
    }

    /**
     * @return BackendInterface
     */
    public function getBackend()
    {
        return $this->backend;
    }

    /**
     * @return SymmetricKey
     */
    public function getSymmetricKey()
    {
        if ($this->backend instanceof FIPSCrypto) {
            return new SymmetricKey(
                $this->backend,
                \random_bytes(32)
            );
        } elseif ($this->backend instanceof ModernCrypto) {
            return new SymmetricKey(
                $this->backend,
                \ParagonIE_Sodium_Compat::crypto_secretbox_keygen()
            );
        }
        throw new \TypeError('Invalid Backend provided');
    }
}
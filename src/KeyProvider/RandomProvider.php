<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\KeyProvider;

use ParagonIE\CipherSweet\Backend\{
    BoringCrypto,
    FIPSCrypto,
    ModernCrypto
};
use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
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
    private BackendInterface $backend;

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
     * @return SymmetricKey
     * @throws \Exception
     */
    public function getSymmetricKey(): SymmetricKey
    {
        if ($this->backend instanceof FIPSCrypto) {
            return new SymmetricKey(
                \random_bytes(32)
            );
        } elseif ($this->backend instanceof ModernCrypto) {
            return new SymmetricKey(
                \ParagonIE_Sodium_Compat::crypto_secretbox_keygen()
            );
        } elseif ($this->backend instanceof BoringCrypto) {
            return new SymmetricKey(
                \ParagonIE_Sodium_Compat::crypto_secretbox_keygen()
            );
        }
        throw new \TypeError('Invalid Backend provided');
    }

    /**
     * @return array
     */
    public function __debugInfo()
    {
        return [];
    }
}

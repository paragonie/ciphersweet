<?php
namespace ParagonIE\CipherSweet\KeyProvider;

use ParagonIE\CipherSweet\Backend\FIPSCrypto;
use ParagonIE\CipherSweet\Backend\Key\AsymmetricPublicKey;
use ParagonIE\CipherSweet\Backend\Key\AsymmetricSecretKey;
use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\Backend\ModernCrypto;
use ParagonIE\CipherSweet\Contract\BackendInterface;
use ParagonIE\CipherSweet\Contract\KeyProviderInterface;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;

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
     * @return AsymmetricPublicKey|void
     * @throws CryptoOperationException
     * @psalm-suppress ImplementedReturnTypeMismatch
     */
    public function getPublicKey()
    {
        throw new CryptoOperationException(
            'Randomly generating a public key is meaningless. Instead, ' .
            'generate a secret key and derive the public key from that.'
        );
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

    /**
     * @return AsymmetricSecretKey
     * @throws \SodiumException
     */
    public function getSecretKey()
    {
        if ($this->backend instanceof FIPSCrypto) {
            /** @var array<string, string> $keypair */
            $keypair = FIPSCrypto::getRsa()->createKey(2048);
            return new AsymmetricSecretKey(
                $this->backend,
                $keypair['privatekey']
            );
        } elseif ($this->backend instanceof ModernCrypto) {
            $keypair = \ParagonIE_Sodium_Compat::crypto_sign_keypair();
            return new AsymmetricSecretKey(
                $this->backend,
                \ParagonIE_Sodium_Compat::crypto_sign_secretkey($keypair)
            );
        }
        throw new \TypeError('Invalid Backend provided');
    }

}
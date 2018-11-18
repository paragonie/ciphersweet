<?php
namespace ParagonIE\CipherSweet\KeyProvider;

use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\Contract\BackendInterface;
use ParagonIE\CipherSweet\Contract\KeyProviderInterface;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;
use ParagonIE\CipherSweet\Util;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\ConstantTime\Hex;

/**
 * Class StringProvider
 * @package ParagonIE\CipherSweet\KeyProvider
 */
class StringProvider implements KeyProviderInterface
{
    /**
     * @var BackendInterface $backend
     */
    private $backend;

    /**
     * @var string $rootSymmetricKey
     */
    private $rootSymmetricKey;

    /**
     * StringProvider constructor.
     *
     * @param BackendInterface $backend
     * @param string $rawKey
     *
     * @throws CryptoOperationException
     */
    public function __construct(BackendInterface $backend, $rawKey = '')
    {
        $this->backend = $backend;
        if (Binary::safeStrlen($rawKey) === 64) {
            $this->rootSymmetricKey = Hex::decode($rawKey);
        } elseif (Binary::safeStrlen($rawKey) === 44) {
            $this->rootSymmetricKey = Base64UrlSafe::decode($rawKey);
        } elseif (Binary::safeStrlen($rawKey) === 32) {
            $this->rootSymmetricKey = $rawKey;
        } else {
            throw new CryptoOperationException('Invalid key size');
        }
    }

    /**
     * Attempt to wipe memory.
     *
     * @throws \SodiumException
     */
    public function __destruct()
    {
        Util::memzero($this->rootSymmetricKey);
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
        return new SymmetricKey($this->backend, $this->rootSymmetricKey);
    }

    /**
     * @return array
     */
    public function __debugInfo()
    {
        return [];
    }
}

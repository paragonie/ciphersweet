<?php

namespace ParagonIE\CipherSweet\KeyProvider;

use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\ConstantTime\Hex;
use ParagonIE\CipherSweet\Backend\Key\AsymmetricPublicKey;
use ParagonIE\CipherSweet\Backend\Key\AsymmetricSecretKey;
use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\Contract\BackendInterface;
use ParagonIE\CipherSweet\Contract\KeyProviderInterface;
use ParagonIE\CipherSweet\Exception\ArrayKeyException;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;

/**
 * Class ArrayProvider
 * @package ParagonIE\CipherSweet\KeyProvider
 */
class ArrayProvider implements KeyProviderInterface
{
    const INDEX_SYMMETRIC_KEY = 'symmetric-key';
    const INDEX_ASYMMETRIC_PUBLICKEY = 'asymmetric-public-key';
    const INDEX_ASYMMETRIC_SECRETKEY = 'asymmetric-secret-key';

    /**
     * @var BackendInterface
     */
    private $backend;

    /**
     * @var string
     */
    private $rootSymmetricKey;

    /**
     * @var string
     */
    private $publicKey;
    /**
     * @var string
     */
    private $secretKey;

    /**
     * ArrayProvider constructor.
     *
     * @param BackendInterface $backend
     * @param array<string, string> $config
     *
     * @throws ArrayKeyException
     * @throws CryptoOperationException
     */
    public function __construct(BackendInterface $backend, array $config = [])
    {
        if (!isset($config[self::INDEX_SYMMETRIC_KEY])) {
            throw new ArrayKeyException(
                'Expected key "' .
                    self::INDEX_SYMMETRIC_KEY .
                    '" to be defined on array.'
            );
        }
        $this->backend = $backend;

        /** @var string $rawKey */
        $rawKey = $config[self::INDEX_SYMMETRIC_KEY];
        if (Binary::safeStrlen($rawKey) === 64) {
            $this->rootSymmetricKey = Hex::decode($rawKey);
        } elseif (Binary::safeStrlen($rawKey) === 44) {
            $this->rootSymmetricKey = Base64UrlSafe::decode($rawKey);
        } elseif (Binary::safeStrlen($rawKey) === 32) {
            $this->rootSymmetricKey = $rawKey;
        } else {
            throw new CryptoOperationException('Invalid key size');
        }

        if (isset($config[self::INDEX_ASYMMETRIC_PUBLICKEY])) {
            $this->publicKey = (string) $config[self::INDEX_ASYMMETRIC_PUBLICKEY];
        }
        if (isset($config[self::INDEX_ASYMMETRIC_SECRETKEY])) {
            $this->secretKey = (string) $config[self::INDEX_ASYMMETRIC_SECRETKEY];
        }
    }

    /**
     * @return BackendInterface
     */
    public function getBackend()
    {
        return $this->backend;
    }

    /**
     * @return AsymmetricPublicKey
     */
    public function getPublicKey()
    {
        return new AsymmetricPublicKey($this->backend, $this->publicKey);
    }

    /**
     * @return SymmetricKey
     */
    public function getSymmetricKey()
    {
        return new SymmetricKey($this->backend, $this->rootSymmetricKey);
    }

    /**
     * @return AsymmetricSecretKey
     */
    public function getSecretKey()
    {
        return new AsymmetricSecretKey($this->backend, $this->secretKey);
    }
}
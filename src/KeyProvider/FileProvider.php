<?php
namespace ParagonIE\CipherSweet\KeyProvider;

use ParagonIE\CipherSweet\Backend\Key\AsymmetricPublicKey;
use ParagonIE\CipherSweet\Backend\Key\AsymmetricSecretKey;
use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\Contract\BackendInterface;
use ParagonIE\CipherSweet\Contract\KeyProviderInterface;
use ParagonIE\CipherSweet\Exception\KeyProviderException;

/**
 * Class FileProvider
 * @package ParagonIE\CipherSweet\KeyProvider
 */
class FileProvider implements KeyProviderInterface
{
    /**
     * @var BackendInterface $backend
     */
    protected $backend;

    /**
     * @var string|null $symmetricKeyPath
     */
    protected $symmetricKeyPath = null;

    /**
     * @var string|null $secretKeyPath
     */
    protected $secretKeyPath = null;

    /**
     * @var string|null  $publicKeyPath
     */
    protected $publicKeyPath = null;

    /**
     * FileProvider constructor.
     *
     * @param BackendInterface $backend
     * @param string|null $symmetricKeyPath
     * @param string|null $asymmetricSecretKeyPath
     * @param string|null $asymmetricPublicKeyPath
     */
    public function __construct(
        BackendInterface $backend,
        $symmetricKeyPath = null,
        $asymmetricSecretKeyPath = null,
        $asymmetricPublicKeyPath = null
    ) {
        $this->backend = $backend;
        $this->symmetricKeyPath = $symmetricKeyPath;
        $this->secretKeyPath = $asymmetricSecretKeyPath;
        $this->publicKeyPath = $asymmetricPublicKeyPath;
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
     * @throws KeyProviderException
     */
    public function getPublicKey()
    {
        if (\is_null($this->publicKeyPath)) {
            throw new KeyProviderException('Public key path was not provided');
        }
        $contents = \file_get_contents($this->publicKeyPath);
        if (!\is_string($contents)) {
            throw new KeyProviderException('Could not read public key from file.');
        }

        return new AsymmetricPublicKey($this->backend, $contents);
    }

    /**
     * @return SymmetricKey
     * @throws KeyProviderException
     */
    public function getSymmetricKey()
    {
        if (\is_null($this->symmetricKeyPath)) {
            throw new KeyProviderException('Symmetric key path was not provided');
        }
        $contents = \file_get_contents($this->symmetricKeyPath);
        if (!\is_string($contents)) {
            throw new KeyProviderException('Could not read symmetric key from file.');
        }

        return new SymmetricKey($this->backend, $contents);

    }

    /**
     * @return AsymmetricSecretKey
     * @throws KeyProviderException
     */
    public function getSecretKey()
    {
        if (\is_null($this->secretKeyPath)) {
            throw new KeyProviderException('Secret key path was not provided');
        }
        $contents = \file_get_contents($this->secretKeyPath);
        if (!\is_string($contents)) {
            throw new KeyProviderException('Could not read secret key from file.');
        }

        return new AsymmetricSecretKey($this->backend, $contents);
    }
}

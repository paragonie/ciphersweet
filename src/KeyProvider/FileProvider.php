<?php
namespace ParagonIE\CipherSweet\KeyProvider;

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
     * FileProvider constructor.
     *
     * @param BackendInterface $backend
     * @param string|null $symmetricKeyPath
     */
    public function __construct(
        BackendInterface $backend,
        $symmetricKeyPath = null
    ) {
        $this->backend = $backend;
        $this->symmetricKeyPath = $symmetricKeyPath;
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
}

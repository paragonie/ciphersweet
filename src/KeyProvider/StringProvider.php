<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\KeyProvider;

use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\Contract\KeyProviderInterface;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;
use ParagonIE\CipherSweet\Util;
use ParagonIE\ConstantTime\{
    Base64UrlSafe,
    Binary,
    Hex
};
use SodiumException;

/**
 * Class StringProvider
 * @package ParagonIE\CipherSweet\KeyProvider
 */
class StringProvider implements KeyProviderInterface
{
    /**
     * @var string $rootSymmetricKey
     */
    private string $rootSymmetricKey;

    /**
     * StringProvider constructor.
     *
     * @param string $rawKey
     *
     * @throws CryptoOperationException
     */
    public function __construct(
        #[\SensitiveParameter]
        string $rawKey = ''
    ) {
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
     * @throws SodiumException
     */
    public function __destruct()
    {
        Util::memzero($this->rootSymmetricKey);
    }

    /**
     * @return SymmetricKey
     */
    public function getSymmetricKey(): SymmetricKey
    {
        return new SymmetricKey($this->rootSymmetricKey);
    }

    /**
     * @return array
     */
    public function __debugInfo(): array
    {
        return [];
    }
}

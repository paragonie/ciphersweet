<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\KeyProvider;

use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\Contract\KeyProviderInterface;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;
use ParagonIE\CipherSweet\Util;
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
        $this->rootSymmetricKey = Util::convertSymmetricStringKeyToBinary($rawKey);
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

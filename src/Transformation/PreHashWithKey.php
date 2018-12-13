<?php
namespace ParagonIE\CipherSweet\Transformation;

use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;

/**
 * Class PreHashWithKey
 * @package ParagonIE\CipherSweet\Transformation
 */
class PreHashWithKey implements TransformationInterface
{
    /** @var string $algo */
    private $algo;

    /** @var SymmetricKey $key */
    private $key;

    /**
     * PreHashWithKey constructor.
     *
     * @param string $algo
     * @param SymmetricKey $key
     *
     * @throws CryptoOperationException
     */
    public function __construct($algo, SymmetricKey $key)
    {
        if (!\in_array($algo, \hash_algos(), true)) {
            if (\strtolower($algo) !== 'blake2b') {
                // BLAKE2b can be done by libsodium or sodium_compat
                throw new CryptoOperationException('Unknown hash function: ' . $algo);
            }
        }
        $this->algo = $algo;
        $this->key = $key;
    }

    /**
     * Returns the lowercase representation of the input string.
     * Returns a raw binary string.
     *
     * @param string $input
     * @return string
     * @throws \SodiumException
     */
    public function __invoke($input)
    {
        if ($this->algo === 'blake2b') {
            return sodium_crypto_generichash(
                $input,
                $this->key->getRawKey()
            );
        }
        return \hash_hmac(
            $this->algo,
            $input,
            $this->key->getRawKey(),
            true
        );
    }
}

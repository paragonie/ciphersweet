<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet;

use ParagonIE\CipherSweet\Contract\TransformationInterface;
use ParagonIE\CipherSweet\Exception\CipherSweetException;

class FastBlindIndex extends BlindIndex
{
    /**
     * FastBlindIndex constructor.
     *
     * @param string $name
     * @param array<int, TransformationInterface> $transformations
     * @param int $filterBits
     * @param bool $fastHash
     * @param array $hashConfig
     *
     * @throws CipherSweetException
     */
    public function __construct(
        string $name,
        array $transformations = [],
        int $filterBits = 256,
        bool $fastHash = true,
        array $hashConfig = []
    ) {
        if (!$fastHash) {
            throw new CipherSweetException("FastBlindIndex cannot be turned slow");
        }
        return parent::__construct($name, $transformations, $filterBits, $fastHash, $hashConfig);
    }
}

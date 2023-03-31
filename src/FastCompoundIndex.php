<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet;

use ParagonIE\CipherSweet\Exception\CipherSweetException;

class FastCompoundIndex extends CompoundIndex
{
    /**
     * FastCompoundIndex constructor.
     *
     * @param string $name
     * @param array<int, string> $columns
     * @param int $filterBits
     * @param bool $fastHash
     * @param array $hashConfig
     *
     * @throws CipherSweetException
     */
    public function __construct(
        string $name,
        array $columns = [],
        int $filterBits = 256,
        bool $fastHash = true,
        array $hashConfig = []
    ) {
        if (!$fastHash) {
            throw new CipherSweetException("FastCompoundIndex cannot be turned slow");
        }
        return parent::__construct(
            $name,
            $columns,
            $filterBits,
            $fastHash,
            $hashConfig
        );
    }
}

<?php

namespace ParagonIE\CipherSweet\Tests;

use ParagonIE\CipherSweet\Backend\FIPSCrypto;
use ParagonIE\CipherSweet\Backend\ModernCrypto;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\KeyProvider\ArrayProvider;
use ParagonIE\ConstantTime\Hex;

trait CreatesEngines
{
    /**
     * @param string|null $key
     * @return CipherSweet
     * @throws \ParagonIE\CipherSweet\Exception\ArrayKeyException
     * @throws \ParagonIE\CipherSweet\Exception\CryptoOperationException
     */
    final protected function createFipsEngine($key = null)
    {
        return new CipherSweet(
            new ArrayProvider([ArrayProvider::INDEX_SYMMETRIC_KEY => $key ? Hex::decode($key) : \random_bytes(32)]),
            new FIPSCrypto
        );
    }

    /**
     * @param string|null $key
     * @return CipherSweet
     * @throws \ParagonIE\CipherSweet\Exception\ArrayKeyException
     * @throws \ParagonIE\CipherSweet\Exception\CryptoOperationException
     */
    final protected function createModernEngine($key = null)
    {
        return new CipherSweet(
            new ArrayProvider([ArrayProvider::INDEX_SYMMETRIC_KEY => $key ? Hex::decode($key) : \random_bytes(32)]),
            new ModernCrypto
        );
    }
}

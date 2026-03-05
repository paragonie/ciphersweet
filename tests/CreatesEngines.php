<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\Tests;

use ParagonIE\CipherSweet\Backend\BoringCrypto;
use ParagonIE\CipherSweet\Backend\FIPSCrypto;
use ParagonIE\CipherSweet\Backend\ModernCrypto;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;
use ParagonIE\CipherSweet\KeyProvider\StringProvider;
use ParagonIE\ConstantTime\Hex;
use Random\RandomException;

trait CreatesEngines
{
    /**
     * @throws CryptoOperationException
     * @throws RandomException
     */
    final protected static function createFipsEngine($key = null): CipherSweet
    {
        return new CipherSweet(
            new StringProvider($key ? Hex::decode($key) : random_bytes(32)),
            new FIPSCrypto
        );
    }

    /**
     * @throws CryptoOperationException
     * @throws RandomException
     */
    final protected static function createModernEngine($key = null): CipherSweet
    {
        return new CipherSweet(
            new StringProvider($key ? Hex::decode($key) : random_bytes(32)),
            new ModernCrypto
        );
    }

    /**
     * @throws CryptoOperationException
     * @throws RandomException
     */
    final protected static function createBoringEngine($key = null): CipherSweet
    {
        return new CipherSweet(
            new StringProvider($key ? Hex::decode($key) : random_bytes(32)),
            new BoringCrypto
        );
    }
}

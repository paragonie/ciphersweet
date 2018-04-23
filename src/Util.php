<?php

namespace ParagonIE\CipherSweet;

use ParagonIE\ConstantTime\Binary;
use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;

/**
 * Class Util
 * @package ParagonIE\CipherSweet
 */
abstract class Util
{
    /**
     * Userland polfill for AES-256-CTR, using AES-256-ECB
     *
     * @param string $plaintext
     * @param string $key
     * @param string $nonce
     * @return string
     */
    public static function aes256ctr($plaintext, $key, $nonce)
    {
        if (empty($plaintext)) {
            return '';
        }
        $length = Binary::safeStrlen($plaintext);
        /** @var int $numBlocks */
        $numBlocks = (($length - 1) >> 4) + 1;
        $stream = '';
        for ($i = 0; $i < $numBlocks; ++$i) {
            $stream .= $nonce;
            $nonce = self::ctrNonceIncrease($nonce);
        }
        /** @var string $xor */
        $xor = \openssl_encrypt(
            $stream,
            'aes-256-ecb',
            $key,
            OPENSSL_RAW_DATA
        );
        return (string) (
            $plaintext ^ Binary::safeSubstr($xor, 0, $length)
        );
    }

    /**
     * Increase a counter nonce, starting with big-endian
     *
     * @param string $nonce
     * @return string
     */
    public static function ctrNonceIncrease($nonce)
    {
        $pieces = \unpack('C*', $nonce);
        $c = 0;
        ++$pieces[16];
        for ($i = 16; $i > 0; --$i) {
            $pieces[$i] += $c;
            $c = $pieces[$i] >> 8;
            $pieces[$i] &= 0xff;
        }
        \array_unshift($pieces, \str_repeat('C', 16));
        return \call_user_func_array('pack', $pieces);
    }

    /**
     * @param SymmetricKey $key
     * @param string|null $salt
     * @param string $info
     * @param int $length
     * @param string $hash
     *
     * @return string
     * @throws CryptoOperationException
     */
    public static function HKDF(
        SymmetricKey $key,
        $salt = null,
        $info = '',
        $length = 32,
        $hash = 'sha384'
    ) {
        static $nativeHKDF = null;
        if ($nativeHKDF === null) {
            $nativeHKDF = \is_callable('\\hash_hkdf');
        }
        /** @var string $ikm */
        $ikm = $key->getRawKey();

        if ($nativeHKDF) {
            /**
             * @psalm-suppress UndefinedFunction
             * This is wrapped in an is_callable() check.
             */
            return (string) \hash_hkdf($hash, $ikm, $length, $info, (string) $salt);
        }

        $digest_length = Binary::safeStrlen(
            \hash_hmac($hash, '', '', true)
        );

        // Sanity-check the desired output length.
        if (empty($length) || $length < 0 || $length > 255 * $digest_length) {
            throw new CryptoOperationException(
                'Bad output length requested of HKDF.'
            );
        }

        // "if [salt] not provided, is set to a string of HashLen zeroes."
        if (\is_null($salt)) {
            $salt = \str_repeat("\x00", $digest_length);
        }

        // HKDF-Extract:
        // PRK = HMAC-Hash(salt, IKM)
        // The salt is the HMAC key.
        $prk = \hash_hmac($hash, $ikm, $salt, true);

        // HKDF-Expand:
        // T(0) = ''
        $t          = '';
        $last_block = '';
        for ($block_index = 1; Binary::safeStrlen($t) < $length; ++$block_index) {
            // T(i) = HMAC-Hash(PRK, T(i-1) | info | 0x??)
            $last_block = \hash_hmac(
                $hash,
                $last_block . $info . \chr($block_index),
                $prk,
                true
            );
            // T = T(1) | T(2) | T(3) | ... | T(N)
            $t .= $last_block;
        }

        // ORM = first L octets of T
        /** @var string $orm */
        $orm = Binary::safeSubstr($t, 0, $length);
        return (string) $orm;
    }

    /**
     * Used for packing [table, field, index] names together in a way that
     * resists and/or prevents collisions caused by operator error.
     *
     * @param array<int, string> $pieces
     * @return string
     */
    public static function pack(array $pieces)
    {
        $output = \ParagonIE_Sodium_Core_Util::store32_le(\count($pieces));
        foreach ($pieces as $piece) {
            $output .= \ParagonIE_Sodium_Core_Util::store64_le(
                Binary::safeStrlen($piece)
            );
            $output .= $piece;
        }
        return $output;
    }
}

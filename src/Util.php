<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet;

use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\ConstantTime\Binary;
use ParagonIE_Sodium_Core_Util as SodiumUtil;
use ArrayAccess;
use SodiumException;
use TypeError;

/**
 * Class Util
 * @package ParagonIE\CipherSweet
 */
abstract class Util
{
    /**
     * Userland polyfill for AES-256-CTR, using AES-256-ECB
     */
    public static function aes256ctr(
        #[\SensitiveParameter]
        string $plaintext,
        #[\SensitiveParameter]
        string $key,
        #[\SensitiveParameter]
        string $nonce
    ): string {
        if (empty($plaintext)) {
            return '';
        }
        $length = Binary::safeStrlen($plaintext);
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
     * @throws SodiumException
     */
    public static function andMask(
        #[\SensitiveParameter]
        string $input,
        int $bits,
        bool $bitwiseLeft = false
    ): string {
        $bytes = $bits >> 3;
        $length = Binary::safeStrlen($input);
        if ($bytes >= $length) {
            $input .= \str_repeat("\0", ($bytes - $length) + 1);
        }
        $string = Binary::safeSubstr($input, 0, $bytes);
        $leftOver = ($bits - ($bytes << 3));
        if ($leftOver > 0) {
            $mask = (1 << $leftOver) - 1;
            if (!$bitwiseLeft) {
                // https://stackoverflow.com/a/2602885
                $mask = ($mask & 0xF0) >> 4 | ($mask & 0x0F) << 4;
                $mask = ($mask & 0xCC) >> 2 | ($mask & 0x33) << 2;
                $mask = ($mask & 0xAA) >> 1 | ($mask & 0x55) << 1;
            }
            $int = SodiumUtil::chrToInt($input[$bytes]);
            $string .= SodiumUtil::intToChr($int & $mask);
        }
        return $string;
    }

    /**
     * Convert a nullable boolean to a string with a length of 1.
     */
    public static function boolToChr(?bool $bool): string
    {
        if (\is_null($bool)) {
            $int = 0;
        } else {
            $int = $bool ? 2 : 1;
        }
        return \pack('C', $int);
    }

    /**
     * Convert a string with a length of 1 to a nullable boolean.
     */
    public static function chrToBool(string $string): ?bool
    {
        if (Binary::safeStrlen($string) !== 1) {
            throw new \OutOfRangeException(
                'String is not 1 length long'
            );
        }
        /** @var array<int, int> $unpacked */
        $unpacked = \unpack('C', $string);
        switch ($unpacked[1]) {
            case 0:
                return null;
            case 1:
                return false;
            case 2:
                return true;
        }
        throw new \InvalidArgumentException(
            'Internal integer is not 0, 1, or 2'
        );
    }

    /**
     * If a variable does not match a given type, throw a TypeError.
     *
     * @param mixed $mixedVar
     * @param string $type
     * @param int $argumentIndex
     * @throws TypeError
     * @throws SodiumException
     * @return void
     */
    public static function declareScalarType(
        mixed &$mixedVar = null,
        string $type = 'void',
        int $argumentIndex = 0
    ): void {
        if (func_num_args() === 0) {
            /* Tautology, by default */
            return;
        }
        if (func_num_args() === 1) {
            throw new TypeError('Declared void, but passed a variable');
        }
        $realType = strtolower(gettype($mixedVar));
        $type = strtolower($type);
        switch ($type) {
            case 'null':
                if ($mixedVar !== null) {
                    throw new TypeError('Argument ' . $argumentIndex . ' must be null, ' . $realType . ' given.');
                }
                break;
            case 'integer':
            case 'int':
                $allow = array('int', 'integer');
                if (!in_array($type, $allow)) {
                    throw new TypeError('Argument ' . $argumentIndex . ' must be an integer, ' . $realType . ' given.');
                }
                $mixedVar = (int) $mixedVar;
                break;
            case 'boolean':
            case 'bool':
                $allow = array('bool', 'boolean');
                if (!in_array($type, $allow)) {
                    throw new TypeError('Argument ' . $argumentIndex . ' must be a boolean, ' . $realType . ' given.');
                }
                $mixedVar = (bool) $mixedVar;
                break;
            case 'string':
                if (!is_string($mixedVar)) {
                    throw new TypeError('Argument ' . $argumentIndex . ' must be a string, ' . $realType . ' given.');
                }
                $mixedVar = (string) $mixedVar;
                break;
            case 'decimal':
            case 'double':
            case 'float':
                $allow = array('decimal', 'double', 'float');
                if (!in_array($type, $allow)) {
                    throw new TypeError('Argument ' . $argumentIndex . ' must be a float, ' . $realType . ' given.');
                }
                $mixedVar = (float) $mixedVar;
                break;
            case 'object':
                if (!is_object($mixedVar)) {
                    throw new TypeError('Argument ' . $argumentIndex . ' must be an object, ' . $realType . ' given.');
                }
                break;
            case 'array':
                if (!is_array($mixedVar)) {
                    if (is_object($mixedVar)) {
                        if ($mixedVar instanceof ArrayAccess) {
                            return;
                        }
                    }
                    throw new TypeError('Argument ' . $argumentIndex . ' must be an array, ' . $realType . ' given.');
                }
                break;
            default:
                throw new SodiumException('Unknown type (' . $realType .') does not match expect type (' . $type . ')');
        }
    }

    /**
     * @throws SodiumException
     */
    public static function floatToString(float $float): string
    {
        Util::declareScalarType($float, 'float');
        return \pack('e', $float);
    }

    /**
     * @throws \TypeError
     */
    public static function hashEquals(
        #[\SensitiveParameter]
        string $a,
        #[\SensitiveParameter]
        string $b
    ): bool {
        return \hash_equals($a, $b);
    }

    /**
     * @param int $int
     * @return string
     */
    public static function intToString(int $int): string
    {
        return SodiumUtil::store64_le($int);
    }

    /**
     * Increase a counter nonce, starting with the LSB (big-endian)
     *
     * @param string $nonce
     * @param int $amount
     * @return string
     */
    public static function ctrNonceIncrease(
        #[\SensitiveParameter]
        string $nonce,
        int $amount = 1
    ): string {
        /** @var array<int, int> $pieces */
        $pieces = \unpack('C*', $nonce);
        $c = 0;
        $pieces[16] += $amount;
        for ($i = 16; $i > 0; --$i) {
            $pieces[$i] += $c;
            $c = $pieces[$i] >> 8;
            $pieces[$i] &= 0xff;
        }
        \array_unshift($pieces, \str_repeat('C', 16));
        return (string) \call_user_func_array('pack', $pieces);
    }

    public static function HKDF(
        #[\SensitiveParameter]
        SymmetricKey $key,
        #[\SensitiveParameter]
        ?string $salt = '',
        #[\SensitiveParameter]
        string $info = '',
        int $length = 32,
        string $hash = 'sha384'
    ): string {
        return \hash_hkdf($hash, $key->getRawKey(), $length, $info, (string) $salt);
    }

    /**
     * @param string $string
     * @param-out null $string
     * @return void
     *
     * @throws SodiumException
     * @psalm-suppress ReferenceConstraintViolation
     * @psalm-suppress InvalidOperand
     * @psalm-suppress UndefinedFunction
     */
    public static function memzero(
        #[\SensitiveParameter]
        string &$string
    ): void
    {
        if (\extension_loaded('sodium')) {
            \sodium_memzero($string);
        } elseif (\extension_loaded('libsodium')) {
            \Sodium\memzero($string);
        } else {
            // Worst-case scenario: Best-ditch effort to wipe memory
            $string ^= $string;
            unset($string);
        }
    }

    /**
     * Used for packing [table, field, index] names together in a way that
     * resists and/or prevents collisions caused by operator error.
     *
     * @param array<int, string> $pieces
     * @return string
     */
    public static function pack(array $pieces): string
    {
        $output = SodiumUtil::store32_le(\count($pieces));
        foreach ($pieces as $piece) {
            $output .= SodiumUtil::store64_le(
                Binary::safeStrlen($piece)
            );
            $output .= $piece;
        }
        return $output;
    }

    /**
     * @throws SodiumException
     */
    public static function stringToInt(string $string): int
    {
        return SodiumUtil::load64_le($string);
    }

    /**
     * @throws SodiumException
     */
    public static function stringToFloat(string $string): float
    {
        Util::declareScalarType($string, 'string');
        /** @var array{1: float} $unpacked */
        $unpacked = \unpack('e', (string) $string);
        return (float) $unpacked[1];
    }
}

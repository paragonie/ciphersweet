<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet;

/**
 * Class Constants
 * @package ParagonIE\CipherSweet
 */
abstract class Constants
{
    /*
     * These domain separation constants has a hamming distance of 4 from each
     * other, for each byte.
     */
    const DS_BIDX = "\x7E\x7E\x7E\x7E\x7E\x7E\x7E\x7E\x7E\x7E\x7E\x7E\x7E\x7E\x7E\x7E\x7E\x7E\x7E\x7E\x7E\x7E\x7E\x7E\x7E\x7E\x7E\x7E\x7E\x7E\x7E\x7E";
    const DS_FENC = "\xB4\xB4\xB4\xB4\xB4\xB4\xB4\xB4\xB4\xB4\xB4\xB4\xB4\xB4\xB4\xB4\xB4\xB4\xB4\xB4\xB4\xB4\xB4\xB4\xB4\xB4\xB4\xB4\xB4\xB4\xB4\xB4";

    /*
     * Domain separation constant for JSON field key derivation.
     *
     * Calculated as: SHA256("json") xor SHA256("JSON")
     *
     * 02bd175f329720378ce83dd56a1b6b1f5291a60182d6c54b5e0d1e8d248a267a
     *                                 xor
     * db1a21a0bc2ef8fbe13ac4cf044e8c9116d29137d5ed8b916ab63dcb2d4290df
     *~----------------------------------------------------------------
     * d9a736ff8eb9d8cc6dd2f91a6e55e78e44433736573b4eda34bb234609c8b6a5
     */
    const DS_JSON = "\xD9\xA7\x36\xFF\x8E\xB9\xD8\xCC\x6D\xD2\xF9\x1A\x6E\x55\xE7\x8E\x44\x43\x37\x36\x57\x3B\x4E\xDA\x34\xBB\x23\x46\x09\xC8\xB6\xA5";

    const TYPE_JSON = 'json';
    const TYPE_BOOLEAN = 'bool';
    const TYPE_TEXT = 'string';
    const TYPE_INT = 'int';
    const TYPE_FLOAT = 'float';

    const COMPOUND_SPECIAL = 'special__compound__indexes';

    const FILE_TABLE = "special__file__encryption";
    const FILE_COLUMN = "special__file__ciphersweet";
    const DUMMY_SALT = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
}

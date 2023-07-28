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

    /*
     * Domain separation constant for CipherSweet extensions
     *
     * Calculated as:
     * SHA256("ciphersweet extensions") xor SHA256("CIPHERSWEET EXTENSIONS")
     *
     * 1ce46264e18a7cdc40ead6f379bc1e233d356c5a95f4c48fbd89c6076960338b
     *                                 xor
     * 98f0e454e75dddb6108c32294be2db4c2b664b0ad8da1aa072d7493dc0654866
     * ----------------------------------------------------------------
     * 8414863006d7a16a5066e4da325ec56f165327504d2ede2fcf5e8f3aa9057bed
     */
    const DS_EXT = "\x84\x14\x86\x30\x06\xd7\xa1\x6a\x50\x66\xe4\xda\x32\x5e\xc5\x6f\x16\x53\x27\x50\x4d\x2e\xde\x2f\xcf\x5e\x8f\x3a\xa9\x05\x7b\xed";

    const TYPE_JSON = 'json';
    const TYPE_BOOLEAN = 'bool';
    const TYPE_TEXT = 'string';
    const TYPE_INT = 'int';
    const TYPE_FLOAT = 'float';

    const TYPE_OPTIONAL_JSON = '?json';
    const TYPE_OPTIONAL_BOOLEAN = '?bool';
    const TYPE_OPTIONAL_TEXT = '?string';
    const TYPE_OPTIONAL_INT = '?int';
    const TYPE_OPTIONAL_FLOAT = '?float';

    // Lists of type constants for ease-of-inlining
    const TYPES_OPTIONAL = ['?json', '?bool', '?string', '?int', '?float'];
    const TYPES_BOOLEAN = ['?bool', 'bool'];
    const TYPES_JSON = ['?json', 'json'];

    const COMPOUND_SPECIAL = 'special__compound__indexes';

    const FILE_TABLE = "special__file__encryption";
    const FILE_COLUMN = "special__file__ciphersweet";
    const DUMMY_SALT = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
}

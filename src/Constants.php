<?php
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

    const TYPE_BOOLEAN = 'bool';
    const TYPE_TEXT = 'string';
    const TYPE_INT = 'int';
    const TYPE_FLOAT = 'float';

    const COMPOUND_SPECIAL = 'special__compound__indexes';
}

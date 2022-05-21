<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\KeyRotation;

use ParagonIE\CipherSweet\Contract\KeyRotationInterface;
use ParagonIE\CipherSweet\EncryptedField;
use ParagonIE\CipherSweet\Exception\{
    BlindIndexNotFoundException,
    InvalidCiphertextException
};
use ParagonIE\CipherSweet\Util;
use ParagonIE\ConstantTime\Binary;
use SodiumException;

/**
 * Class FieldRotator
 * @package ParagonIE\CipherSweet\KeyRotation
 */
class FieldRotator implements KeyRotationInterface
{
    /** @var EncryptedField $old */
    protected EncryptedField $old;

    /** @var EncryptedField $new */
    protected EncryptedField $new;

    /**
     * FIeldRotator constructor.
     * @param EncryptedField $old
     * @param EncryptedField $new
     */
    public function __construct(EncryptedField $old, EncryptedField $new)
    {
        $this->old = $old;
        $this->new = $new;
    }

    /**
     * @param string|array $ciphertext
     * @param string $aad
     * @return bool
     *
     * @throws InvalidCiphertextException
     */
    public function needsReEncrypt(string|array $ciphertext = '', string $aad = ''): bool
    {
        if (!\is_string($ciphertext)) {
            throw new InvalidCiphertextException('FieldRotator expects a string, not an array');
        }
        if (Binary::safeStrlen($ciphertext) < 5) {
            throw new InvalidCiphertextException('This message is not encrypted');
        }
        $pre = Binary::safeSubstr($ciphertext, 0, 5);
        if (!Util::hashEquals($pre, $this->new->getEngine()->getBackend()->getPrefix())) {
            // Header mismatch: True
            return true;
        }
        try {
            $this->new->decryptValue($ciphertext, $aad);
            return false;
        } catch (\Exception $ex) {
        }
        return true;
    }

    /**
     * @param array|string $values
     * @param string $oldAad
     * @param string $newAad
     * @return array
     *
     * @throws BlindIndexNotFoundException
     * @throws SodiumException
     */
    public function prepareForUpdate(
        array|string $values,
        string $oldAad = '',
        string $newAad = ''
    ): array {
        if (!\is_string($values)) {
            throw new \TypeError('FieldRotator expects a string');
        }
        $plaintext = $this->old->decryptValue($values, $oldAad);
        return $this->new->prepareForStorage($plaintext, $newAad);
    }
}

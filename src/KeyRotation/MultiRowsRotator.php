<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\KeyRotation;

use ParagonIE\CipherSweet\Contract\KeyRotationInterface;
use ParagonIE\CipherSweet\EncryptedMultiRows;
use ParagonIE\CipherSweet\Exception\{
    ArrayKeyException,
    CipherSweetException,
    CryptoOperationException,
    InvalidCiphertextException
};
use SodiumException;

/**
 * Class MultiRowsRotator
 * @package ParagonIE\CipherSweet\KeyRotation
 */
class MultiRowsRotator implements KeyRotationInterface
{
    /** @var EncryptedMultiRows $old */
    protected EncryptedMultiRows $old;

    /** @var EncryptedMultiRows $new */
    protected EncryptedMultiRows $new;

    /**
     * MultiRowsRotator constructor.
     * @param EncryptedMultiRows $old
     * @param EncryptedMultiRows $new
     */
    public function __construct(EncryptedMultiRows $old, EncryptedMultiRows $new)
    {
        $this->old = $old;
        $this->new = $new;
    }

    /**
     * @param string|array<string, array<string, string>> $ciphertext
     * @return bool
     * @throws InvalidCiphertextException
     */
    public function needsReEncrypt(array|string $ciphertext = ''): bool
    {
        if (!\is_array($ciphertext)) {
            throw new InvalidCiphertextException('MultiRowsRotator expects an array, not a string');
        }
        try {
            $this->new->decryptManyRows($ciphertext);
            return false;
        } catch (\Exception $ex) {
        }
        return true;
    }

    /**
     * @param string|array<string, array<string, string>> $values
     * @return array
     *
     * @throws ArrayKeyException
     * @throws CipherSweetException
     * @throws CryptoOperationException
     * @throws InvalidCiphertextException
     * @throws SodiumException
     */
    public function prepareForUpdate(array|string $values): array
    {
        if (!\is_array($values)) {
            throw new InvalidCiphertextException('MultiRowsRotator expects an array, not a string');
        }
        /** @var array<string, array<string, string|int|float|bool|null>> $decrypted */
        $decrypted = $this->old->decryptManyRows($values);
        return $this->new->prepareForStorage($decrypted);
    }
}

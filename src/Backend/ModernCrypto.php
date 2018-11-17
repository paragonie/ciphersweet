<?php
namespace ParagonIE\CipherSweet\Backend;

use ParagonIE\CipherSweet\Exception\CryptoOperationException;
use ParagonIE\CipherSweet\Util;
use ParagonIE\ConstantTime\Base32;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\CipherSweet\Contract\BackendInterface;
use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\Exception\InvalidCiphertextException;
use ParagonIE_Sodium_Compat as SodiumCompat;
use ParagonIE_Sodium_Core_Util as SodiumUtil;

/**
 * Class ModernCrypto
 *
 * Use modern cryptography (e.g. Curve25519, Chapoly)
 *
 * @package ParagonIE\CipherSweet\Backend
 */
class ModernCrypto implements BackendInterface
{
    const MAGIC_HEADER = "nacl:";
    const NONCE_SIZE = 24;

    /**
     * Encrypt a message using XChaCha20-Poly1305
     *
     * @param string $plaintext
     * @param SymmetricKey $key
     * @param string $aad       Additional authenticated data
     *
     * @return string
     *
     * @throws CryptoOperationException
     * @throws \SodiumException
     */
    public function encrypt($plaintext, SymmetricKey $key, $aad = '')
    {
        try {
            $nonce = \random_bytes(self::NONCE_SIZE);
        } catch (\Exception $ex) {
            throw new CryptoOperationException('CSPRNG failure', 0, $ex);
        }
        $ciphertext = SodiumCompat::crypto_aead_xchacha20poly1305_ietf_encrypt(
            $plaintext,
            $nonce . $aad,
            $nonce,
            $key->getRawKey()
        );
        return self::MAGIC_HEADER . Base64UrlSafe::encode($nonce . $ciphertext);
    }

    /**
     * Decrypt a message using XChaCha20-Poly1305
     *
     * @param string $ciphertext
     * @param SymmetricKey $key
     * @param string $aad       Additional authenticated data
     *
     * @return string
     * @throws InvalidCiphertextException
     * @throws \SodiumException
     */
    public function decrypt($ciphertext, SymmetricKey $key, $aad = '')
    {
        // Make sure we're using the correct version:
        $header = Binary::safeSubstr($ciphertext, 0, 5);
        if (!SodiumUtil::hashEquals($header, self::MAGIC_HEADER)) {
            throw new InvalidCiphertextException('Invalid ciphertext header.');
        }

        // Decompose the encrypted message into its constituent parts:
        $decoded = Base64UrlSafe::decode(Binary::safeSubstr($ciphertext, 5));
        if (Binary::safeStrlen($decoded) < (self::NONCE_SIZE + 16)) {
            throw new InvalidCiphertextException('Message is too short.');
        }
        $nonce = Binary::safeSubstr($decoded, 0, self::NONCE_SIZE);
        $encrypted = Binary::safeSubstr($decoded, self::NONCE_SIZE);

        return SodiumCompat::crypto_aead_xchacha20poly1305_ietf_decrypt(
            $encrypted,
            $nonce . $aad,
            $nonce,
            $key->getRawKey()
        );
    }

    /**
     * @param string $plaintext
     * @param SymmetricKey $key
     * @param int|null $bitLength
     *
     * @return string
     * @throws \SodiumException
     */
    public function blindIndexFast(
        $plaintext,
        SymmetricKey $key,
        $bitLength = null
    ) {
        if (\is_null($bitLength)) {
            $bitLength = 256;
        }
        if ($bitLength > 512) {
            throw new \SodiumException('Output length is too high');
        }
        if ($bitLength > 256) {
            $hashLength = $bitLength >> 3;
        } else {
            $hashLength = 32;
        }
        $hash = SodiumCompat::crypto_generichash(
            $plaintext,
            $key->getRawKey(),
            $hashLength
        );
        return Util::andMask($hash, $bitLength);
    }

    /**
     * @param string $plaintext
     * @param SymmetricKey $key
     * @param int|null $bitLength
     * @param array $config
     *
     * @return string
     * @throws \SodiumException
     */
    public function blindIndexSlow(
        $plaintext,
        SymmetricKey $key,
        $bitLength = null,
        array $config = []
    ) {
        if (!SodiumCompat::crypto_pwhash_is_available()) {
            throw new \SodiumException(
                'Not using the native libsodium bindings'
            );
        }
        $opsLimit = SodiumCompat::CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE;
        $memLimit = SodiumCompat::CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE;

        if (isset($config['opslimit'])) {
            if ($config['opslimit'] > $opsLimit) {
                $opsLimit = (int) $config['opslimit'];
            }
        }
        if (isset($config['memlimit'])) {
            if ($config['memlimit'] > $memLimit) {
                $memLimit = (int) $config['memlimit'];
            }
        }
        if (\is_null($bitLength)) {
            $bitLength = 256;
        }
        /** @var int $pwHashLength */
        $pwHashLength = $bitLength >> 3;
        if ($pwHashLength < 16) {
            $pwHashLength = 16;
        }
        if ($pwHashLength > 4294967295) {
            throw new \SodiumException('Output length is far too big');
        }

        $hash = SodiumCompat::crypto_pwhash(
            $pwHashLength,
            $plaintext,
            SodiumCompat::crypto_generichash($key->getRawKey(), '', 16),
            $opsLimit,
            $memLimit,
            SodiumCompat::CRYPTO_PWHASH_ALG_ARGON2ID13
        );
        return Util::andMask($hash, $bitLength);
    }

    /**
     * @param string $tableName
     * @param string $fieldName
     * @param string $indexName
     * @return string
     * @throws \SodiumException
     */
    public function getIndexTypeColumn($tableName, $fieldName, $indexName)
    {
        $hash = SodiumCompat::crypto_shorthash(
            Util::pack([$fieldName, $indexName]),
            SodiumCompat::crypto_generichash($tableName, '', 16)
        );
        return Base32::encodeUnpadded($hash);
    }
}

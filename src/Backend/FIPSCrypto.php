<?php
namespace ParagonIE\CipherSweet\Backend;

use ParagonIE\CipherSweet\Contract\BackendInterface;
use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;
use ParagonIE\CipherSweet\Exception\InvalidCiphertextException;
use ParagonIE\CipherSweet\Util;
use ParagonIE\ConstantTime\Base32;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;
use ParagonIE_Sodium_Core_Util as SodiumUtil;

/**
 * Class FIPSCrypto
 *
 * This only uses algorithms supported by FIPS-140-2.
 *
 * Please consult your FIPS compliance auditor before you claim that your use
 * of this library is FIPS 140-2 compliant.
 *
 * @ref https://csrc.nist.gov/CSRC/media//Publications/fips/140/2/final/documents/fips1402annexa.pdf
 * @ref https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
 * @ref https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf
 *
 * @package ParagonIE\CipherSweet\Backend
 */
class FIPSCrypto implements BackendInterface
{
    const MAGIC_HEADER = "fips:";
    const MAC_SIZE = 48;
    const SALT_SIZE = 32;
    const NONCE_SIZE = 16;

    /**
     * Encrypt a string using AES-256-CTR and HMAC-SHA-384, encrypt-then-MAC.
     * The AES and MAC keys are split from the provided key using HKDF and a
     * random salt, thereby allowing for keys to live longer before rotation.
     *
     * The HMAC-SHA-384 authentication tag covers the header, salt (for HKDF),
     * nonce (for AES-CTR), and ciphertext.
     *
     * @param string $plaintext
     * @param SymmetricKey $key
     * @param string $aad       Additional authenticated data
     *
     * @return string
     * @throws CryptoOperationException
     * @throws \SodiumException
     */
    public function encrypt($plaintext, SymmetricKey $key, $aad = '')
    {
        try {
            $hkdfSalt = \random_bytes(self::SALT_SIZE);
            $ctrNonce = \random_bytes(self::NONCE_SIZE);
        } catch (\Exception $ex) {
            throw new CryptoOperationException('CSPRNG failure', 0, $ex);
        }
        $encKey = Util::HKDF($key, $hkdfSalt, 'AES-256-CTR');
        $macKey = Util::HKDF($key, $hkdfSalt, 'HMAC-SHA-384');

        // Encrypt then MAC to avoid the Cryptographic Doom Principle:
        $ciphertext = self::aes256ctr($plaintext, $encKey, $ctrNonce);
        $mac = \hash_hmac(
            'sha384',
            Util::pack([self::MAGIC_HEADER, $hkdfSalt, $ctrNonce, $ciphertext]) . $aad,
            $macKey,
            true
        );
        Util::memzero($encKey);
        Util::memzero($macKey);

        return self::MAGIC_HEADER . Base64UrlSafe::encode(
            $hkdfSalt . $ctrNonce . $mac . $ciphertext
        );
    }

    /**
     * Verify the HMAC-SHA-384 authentication tag, then decrypt the ciphertext
     * using AES-256-CTR.
     *
     * @param string $ciphertext
     * @param SymmetricKey $key
     * @param string $aad       Additional authenticated data
     *
     * @return string
     * @throws CryptoOperationException
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
        if (Binary::safeStrlen($decoded) < (self::MAC_SIZE + self::NONCE_SIZE + self::SALT_SIZE)) {
            throw new InvalidCiphertextException('Message is too short.');
        }
        $hkdfSalt = Binary::safeSubstr($decoded, 0, self::SALT_SIZE);
        $ctrNonce = Binary::safeSubstr($decoded, self::SALT_SIZE, self::NONCE_SIZE);
        $mac = Binary::safeSubstr($decoded, self::SALT_SIZE + self::NONCE_SIZE, self::MAC_SIZE);
        $ciphertext = Binary::safeSubstr($decoded, self::SALT_SIZE + self::NONCE_SIZE + self::MAC_SIZE);

        // Split the keys using the packed HKDF salt:
        $encKey = Util::HKDF($key, $hkdfSalt, 'AES-256-CTR');
        $macKey = Util::HKDF($key, $hkdfSalt, 'HMAC-SHA-384');

        // Verify the MAC in constant-time:
        $recalc = \hash_hmac(
            'sha384',
            Util::pack([self::MAGIC_HEADER, $hkdfSalt, $ctrNonce, $ciphertext]) . $aad,
            $macKey,
            true
        );


        if (!SodiumUtil::hashEquals($recalc, $mac)) {
            throw new InvalidCiphertextException('Invalid MAC');
        }

        // If we're here, it's time to decrypt:
        $plaintext = self::aes256ctr($ciphertext, $encKey, $ctrNonce);
        Util::memzero($encKey);
        Util::memzero($macKey);
        return $plaintext;
    }

    /**
     * Perform a fast blind index. Ideal for high-entropy inputs.
     * Algorithm: PBKDF2-SHA384 with only 1 iteration.
     *
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
        $output = \hash_pbkdf2(
            'sha384',
            $plaintext,
            $key->getRawKey(),
            1,
            ($bitLength >> 3),
            true
        );
        return Util::andMask($output, $bitLength);
    }

    /**
     * Perform a slower Blind Index calculation.
     * Algorithm: PBKDF2-SHA384 with at least 50,000 iterations.
     *
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
        if (\is_null($bitLength)) {
            $bitLength = 256;
        }
        $iterations = 50000;
        if (isset($config['iterations'])) {
            if ($config['iterations'] > 50000) {
                $iterations = (int) $config['iterations'];
            }
        }
        $output = \hash_pbkdf2(
            'sha384',
            $plaintext,
            $key->getRawKey(),
            $iterations,
            ($bitLength >> 3),
            true
        );
        return Util::andMask($output, $bitLength);
    }

    /**
     * Calculate the "type" value for a blind index.
     *
     * @param string $tableName
     * @param string $fieldName
     * @param string $indexName
     * @return string
     */
    public function getIndexTypeColumn($tableName, $fieldName, $indexName)
    {
        $hash = \hash_hmac(
            'sha384',
            Util::pack([$fieldName, $indexName]),
            $tableName,
            true
        );
        return Base32::encodeUnpadded(Binary::safeSubstr($hash, 0, 8));
    }

    /**
     * Encrypt/decrypt AES-256-CTR.
     *
     * @param string $plaintext
     * @param string $key
     * @param string $nonce
     * @return string
     *
     * @throws CryptoOperationException
     */
    private static function aes256ctr($plaintext, $key, $nonce)
    {
        if (!\in_array('aes-256-ctr', \openssl_get_cipher_methods(), true)) {
            if (!\in_array('aes-256-ecb', \openssl_get_cipher_methods(), true)) {
                throw new CryptoOperationException(
                    'AES-256 not provided by OpenSSL'
                );
            }
            return Util::aes256ctr($plaintext, $key, $nonce);
        }
        $ciphertext = \openssl_encrypt(
            $plaintext,
            'aes-256-ctr',
            $key,
            OPENSSL_RAW_DATA,
            $nonce
        );
        if (!\is_string($ciphertext)) {
            throw new CryptoOperationException('OpenSSL failed us');
        }

        return $ciphertext;
    }

    /**
     * @return string
     */
    public function getPrefix()
    {
        return static::MAGIC_HEADER;
    }
}

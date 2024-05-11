<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\Backend;

use ParagonIE\CipherSweet\AAD;
use ParagonIE\CipherSweet\Constants;
use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\Contract\{
    BackendInterface,
    MultiTenantSafeBackendInterface
};
use ParagonIE\CipherSweet\Exception\{
    CryptoOperationException,
    InvalidCiphertextException
};
use ParagonIE\CipherSweet\Util;
use ParagonIE\ConstantTime\{
    Base32,
    Base64UrlSafe,
    Binary
};

/**
 * Class FIPSCrypto
 *
 * This only uses algorithms supported by FIPS 140-3.
 *
 * If you use a FIPS module with OpenSSL, we expect this backend to work.
 * If it doesn't, that is a bug.
 *
 * Please consult your FIPS compliance auditor before you claim that your use
 * of this library is FIPS 140-3 compliant.
 *
 * @ref https://csrc.nist.gov/CSRC/media//Publications/fips/140/2/final/documents/fips1402annexa.pdf
 * @ref https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
 * @ref https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf
 *
 * @package ParagonIE\CipherSweet\Backend
 */
class FIPSCrypto implements BackendInterface, MultiTenantSafeBackendInterface
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
    public function encrypt(
        #[\SensitiveParameter]
        string $plaintext,
        #[\SensitiveParameter]
        SymmetricKey $key,
        #[\SensitiveParameter]
        string $aad = ''
    ): string {
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
    public function decrypt(
        #[\SensitiveParameter]
        string $ciphertext,
        #[\SensitiveParameter]
        SymmetricKey $key,
        #[\SensitiveParameter]
        string $aad = ''
    ): string {
        // Make sure we're using the correct version:
        $header = Binary::safeSubstr($ciphertext, 0, 5);
        if (!Util::hashEquals($header, self::MAGIC_HEADER)) {
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


        if (!Util::hashEquals($recalc, $mac)) {
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
        #[\SensitiveParameter]
        string $plaintext,
        #[\SensitiveParameter]
        SymmetricKey $key,
        ?int $bitLength = null
    ): string {
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
        #[\SensitiveParameter]
        string $plaintext,
        #[\SensitiveParameter]
        SymmetricKey $key,
        ?int $bitLength = null,
        array $config = []
    ): string {
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
    public function getIndexTypeColumn(
        #[\SensitiveParameter]
        string $tableName,
        #[\SensitiveParameter]
        string $fieldName,
        #[\SensitiveParameter]
        string $indexName
    ): string {
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
    private static function aes256ctr(
        #[\SensitiveParameter]
        string $plaintext,
        #[\SensitiveParameter]
        string $key,
        #[\SensitiveParameter]
        string $nonce
    ): string {
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
     * @param string $password
     * @param string $salt
     * @return SymmetricKey
     */
    public function deriveKeyFromPassword(
        #[\SensitiveParameter]
        string $password,
        #[\SensitiveParameter]
        string $salt
    ): SymmetricKey {
        return new SymmetricKey(
            \hash_pbkdf2(
                'sha384',
                $password,
                $salt,
                100000,
                32,
                true
            )
        );
    }

    /**
     * @param resource $inputFP
     * @param resource $outputFP
     * @param SymmetricKey $key
     * @param int $chunkSize
     * @param ?AAD $aad
     * @return bool
     *
     * @throws CryptoOperationException
     * @throws \SodiumException
     */
    public function doStreamDecrypt(
        $inputFP,
        $outputFP,
        SymmetricKey $key,
        int $chunkSize = 8192,
        ?AAD $aad = null
    ): bool {
        \fseek($inputFP, 0, SEEK_SET);
        \fseek($outputFP, 0, SEEK_SET);
        $header = \fread($inputFP, 5);
        if (Binary::safeStrlen($header) < 5) {
            throw new CryptoOperationException('Input file is empty');
        }
        if (!Util::hashEquals((string) (static::MAGIC_HEADER), $header)) {
            throw new CryptoOperationException('Invalid cipher backend for this file');
        }
        $storedMAC = \fread($inputFP, 48);
        $salt = \fread($inputFP, 16);
        $hkdfSalt = \fread($inputFP, 32);
        $ctrNonce = \fread($inputFP, 16);

        $encKey = Util::HKDF($key, $hkdfSalt, 'AES-256-CTR');
        $macKey = Util::HKDF($key, $hkdfSalt, 'HMAC-SHA-384');

        // Initialize MAC state
        $hmac = \hash_init('sha384', HASH_HMAC, $macKey);
        \hash_update($hmac, (string) (static::MAGIC_HEADER));
        \hash_update($hmac, $salt);
        \hash_update($hmac, $hkdfSalt);
        \hash_update($hmac, $ctrNonce);
        // Include optional AAD
        if ($aad) {
            $aadCanon = $aad->canonicalize();
            \hash_update($hmac, $aadCanon);
            unset($aadCanon);
        }

        $pos = \ftell($inputFP);
        // MAC each chunk in memory to defend against race conditions
        $chunkMacs = [];
        $hmacInit = \hash_copy($hmac);
        do {
            $ciphertext = \fread($inputFP, $chunkSize);
            \hash_update($hmac, $ciphertext);
            $chunk = \hash_copy($hmac);
            $chunkMacs []= Binary::safeSubstr(\hash_final($chunk, true), 0, 16);
        } while (!\feof($inputFP));
        $calcMAC = \hash_final($hmac, true);

        // Did the final MAC validate? If so, we're good to decrypt.
        if (!Util::hashEquals($storedMAC, $calcMAC)) {
            throw new CryptoOperationException('Invalid authentication tag');
        }

        $hmac = \hash_copy($hmacInit);
        \fseek($inputFP, $pos, SEEK_SET);

        // We want to increase our CTR value by the number of blocks we used previously
        $ctrIncrease = ($chunkSize + 15) >> 4;
        do {
            $ciphertext = \fread($inputFP, $chunkSize);
            \hash_update($hmac, $ciphertext);

            // Guard against TOCTOU
            $chunk = \hash_copy($hmac);
            $storedChunk = \array_shift($chunkMacs);
            $thisChunk = Binary::safeSubstr(\hash_final($chunk, true), 0, 16);
            if (!Util::hashEquals($storedChunk, $thisChunk)) {
                throw new CryptoOperationException('Race condition');
            }

            $plaintext = self::aes256ctr($ciphertext, $encKey, $ctrNonce);
            \fwrite($outputFP, $plaintext);

            $ctrNonce = Util::ctrNonceIncrease($ctrNonce, $ctrIncrease);
        } while (!\feof($inputFP));

        if (!empty($chunkMacs)) {
            // Truncation attack against decryption after MAC validation
            throw new CryptoOperationException('Race condition');
        }
        \rewind($outputFP);
        return true;
    }

    /**
     * @param resource $inputFP
     * @param resource $outputFP
     * @param SymmetricKey $key
     * @param int $chunkSize
     * @param string $salt
     * @param ?AAD $aad
     * @return bool
     *
     * @throws CryptoOperationException
     */
    public function doStreamEncrypt(
        $inputFP,
        $outputFP,
        SymmetricKey $key,
        int $chunkSize = 8192,
        string $salt = Constants::DUMMY_SALT,
        ?AAD $aad = null
    ): bool {
        \fseek($inputFP, 0, SEEK_SET);
        \fseek($outputFP, 0, SEEK_SET);
        try {
            $hkdfSalt = \random_bytes(self::SALT_SIZE);
            $ctrNonce = \random_bytes(self::NONCE_SIZE);
        } catch (\Exception $ex) {
            throw new CryptoOperationException('CSPRNG failure', 0, $ex);
        }
        $encKey = Util::HKDF($key, $hkdfSalt, 'AES-256-CTR');
        $macKey = Util::HKDF($key, $hkdfSalt, 'HMAC-SHA-384');

        // Write the header, empty space for a MAC, salts, then nonce.
        \fwrite($outputFP, (string) (static::MAGIC_HEADER), 5);
        \fwrite($outputFP, str_repeat("\0", 48), 48);
        \fwrite($outputFP, $salt, 16);
        \fwrite($outputFP, $hkdfSalt, 32);
        \fwrite($outputFP, $ctrNonce, 16);

        // Init MAC state
        $hmac = \hash_init('sha384', HASH_HMAC, $macKey);
        \hash_update($hmac, (string) (static::MAGIC_HEADER));
        \hash_update($hmac, $salt);
        \hash_update($hmac, $hkdfSalt);
        \hash_update($hmac, $ctrNonce);

        // Include optional AAD
        if ($aad) {
            $aadCanon = $aad->canonicalize();
            \hash_update($hmac, $aadCanon);
            unset($aadCanon);
        }

        // We want to increase our CTR value by the number of blocks we used previously
        $ctrIncrease = ($chunkSize + 15) >> 4;
        do {
            $plaintext = \fread($inputFP, $chunkSize);
            $ciphertext = self::aes256ctr($plaintext, $encKey, $ctrNonce);
            \hash_update($hmac, $ciphertext);
            \fwrite($outputFP, $ciphertext);
            $ctrNonce = Util::ctrNonceIncrease($ctrNonce, $ctrIncrease);
        } while (!\feof($inputFP));

        $end = \ftell($outputFP);

        // Write the MAC at the beginning of the file.
        $mac = \hash_final($hmac, true);
        \fseek($outputFP, 5, SEEK_SET);
        \fwrite($outputFP, $mac, 48);
        \fseek($outputFP, $end, SEEK_SET);
        \rewind($outputFP);
        return true;
    }

    /**
     * @return int
     */
    public function getFileEncryptionSaltOffset(): int
    {
        return 53;
    }

    /**
     * @return string
     */
    public function getPrefix(): string
    {
        return (string) static::MAGIC_HEADER;
    }
}

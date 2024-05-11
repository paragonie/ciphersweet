<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\Backend;

use ParagonIE\CipherSweet\AAD;
use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\Constants;
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
use ParagonIE_Sodium_Compat as SodiumCompat;
use ParagonIE\Sodium\Core\ChaCha20;
use ParagonIE\Sodium\Core\HChaCha20;
use ParagonIE_Sodium_Core_Util as SodiumUtil;
use SodiumException;

/**
 * Class BoringCrypto
 *
 * This backend dispenses with the Poly1305 authenticator and instead uses BLAKE2b-MAC (B2MAC).
 *
 * @package ParagonIE\CipherSweet\Backend
 */
class BoringCrypto implements BackendInterface, MultiTenantSafeBackendInterface
{
    const MAGIC_HEADER = "brng:";
    const NONCE_SIZE = 24;
    const MAC_SIZE = 32;

    /**
     * @param SymmetricKey $key
     * @return SymmetricKey
     * @throws SodiumException
     */
    protected function getEncryptionKey(
        #[\SensitiveParameter]
        SymmetricKey $key
    ): SymmetricKey
    {
        return new SymmetricKey(
            SodiumCompat::crypto_generichash('message-encryption', $key->getRawKey(), 32)
        );
    }

    /**
     * @param SymmetricKey $key
     * @return SymmetricKey
     * @throws SodiumException
     */
    protected function getIntegrityKey(
        #[\SensitiveParameter] SymmetricKey $key
    ): SymmetricKey {
        return new SymmetricKey(
            SodiumCompat::crypto_generichash('message-integrity', $key->getRawKey(), 32)
        );
    }

    /**
     * Encrypt a message using XChaCha20-B2MAC
     *
     * @param string $plaintext
     * @param SymmetricKey $key
     * @param string $aad       Additional authenticated data
     *
     * @return string
     *
     * @throws CryptoOperationException
     * @throws SodiumException
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
            $nonce = \random_bytes(self::NONCE_SIZE);
        } catch (\Exception $ex) {
            throw new CryptoOperationException('CSPRNG failure', 0, $ex);
        }
        $ciphertext = \sodium_crypto_stream_xchacha20_xor(
            $plaintext,
            $nonce,
            $this->getEncryptionKey($key)->getRawKey()
        );
        $cipherLength = SodiumUtil::strlen($ciphertext);
        $aadLength = SodiumUtil::strlen($aad);
        // T := BLAKE2b-MAC (nonce || len(aad) || aad || len(C) || C)
        $mac = SodiumCompat::crypto_generichash(
            ((string) static::MAGIC_HEADER) . $nonce . $aadLength . $aad . $cipherLength . $ciphertext,
            $this->getIntegrityKey($key)->getRawKey(),
            self::MAC_SIZE
        );
        return (string) (self::MAGIC_HEADER) . Base64UrlSafe::encode($nonce . $mac . $ciphertext);
    }

    /**
     * Decrypt a message using XChaCha20-B2MAC
     *
     * @param string $ciphertext
     * @param SymmetricKey $key
     * @param string $aad       Additional authenticated data
     *
     * @return string
     * @throws InvalidCiphertextException
     * @throws SodiumException
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
        if (Binary::safeStrlen($decoded) < (self::NONCE_SIZE + self::MAC_SIZE)) {
            throw new InvalidCiphertextException('Message is too short.');
        }
        $nonce = Binary::safeSubstr($decoded, 0, self::NONCE_SIZE);
        $storedMac = Binary::safeSubstr($decoded, self::NONCE_SIZE, self::MAC_SIZE);
        $encrypted = Binary::safeSubstr($decoded, self::NONCE_SIZE + self::MAC_SIZE);

        // T := BLAKE2b-MAC ( len(aad) || aad || len(C) || C)
        $cipherLength = SodiumUtil::strlen($encrypted);
        $aadLength = SodiumUtil::strlen($aad);
        $calcMac = SodiumCompat::crypto_generichash(
            ((string) static::MAGIC_HEADER) . $nonce . $aadLength . $aad . $cipherLength . $encrypted,
            $this->getIntegrityKey($key)->getRawKey(),
            self::MAC_SIZE
        );
        if (!Util::hashEquals($calcMac, $storedMac)) {
            throw new \SodiumException("Invalid ciphertext");
        }

        return \sodium_crypto_stream_xchacha20_xor(
            $encrypted,
            $nonce,
            $this->getEncryptionKey($key)->getRawKey()
        );
    }

    /**
     * @param string $plaintext
     * @param SymmetricKey $key
     * @param int|null $bitLength
     *
     * @return string
     * @throws SodiumException
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
     * @throws SodiumException
     */
    public function blindIndexSlow(
        #[\SensitiveParameter]
        string $plaintext,
        #[\SensitiveParameter]
        SymmetricKey $key,
        ?int $bitLength = null,
        array $config = []
    ): string {
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

        $hash = @sodium_crypto_pwhash(
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
     * @throws SodiumException
     */
    public function getIndexTypeColumn(
        #[\SensitiveParameter]
        string $tableName,
        #[\SensitiveParameter]
        string $fieldName,
        #[\SensitiveParameter]
        string $indexName
    ): string {
        $hash = SodiumCompat::crypto_shorthash(
            Util::pack([$fieldName, $indexName]),
            SodiumCompat::crypto_generichash($tableName, '', 16)
        );
        return Base32::encodeUnpadded($hash);
    }

    /**
     * @param string $password
     * @param string $salt
     * @return SymmetricKey
     *
     * @throws SodiumException
     */
    public function deriveKeyFromPassword(
        #[\SensitiveParameter]
        string $password,
        #[\SensitiveParameter]
        string $salt
    ): SymmetricKey {
        return new SymmetricKey(
            SodiumCompat::crypto_pwhash(
                32,
                $password,
                $salt,
                SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
                SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
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
     * @throws SodiumException
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
        $adlen = 61; // 5 + 24 + 32

        $header = \fread($inputFP, 5);
        if (Binary::safeStrlen($header) < 5) {
            throw new CryptoOperationException('Input file is empty');
        }
        if (!Util::hashEquals((string) (static::MAGIC_HEADER), $header)) {
            throw new CryptoOperationException('Invalid cipher backend for this file');
        }
        $storedAuthTag = \fread($inputFP, 32);
        $salt = \fread($inputFP, 16);
        $nonce = \fread($inputFP, 24);

        // HChaCha20 step
        $subkey = HChaCha20::hChaCha20(
            SodiumUtil::substr($nonce, 0, 16),
            $this->getEncryptionKey($key)->getRawKey()
        );
        $nonceLast = "\x00\x00\x00\x00" . SodiumUtil::substr($nonce, 16, 8);
        $b2mac = SodiumCompat::crypto_generichash_init(
            $this->getIntegrityKey($key)->getRawKey(),
            self::MAC_SIZE
        );
        SodiumCompat::crypto_generichash_update($b2mac, (string) (static::MAGIC_HEADER) . $salt . $nonce);
        // Include optional AAD
        if ($aad) {
            $aadCanon = $aad->canonicalize();
            $adlen += Binary::safeStrlen($aadCanon);
            SodiumCompat::crypto_generichash_update($b2mac, $aadCanon);
            unset($aadCanon);
        }
        $pos = \ftell($inputFP);
        $chunkMacKey = $this->getIntegrityKey($this->getIntegrityKey($key))->getRawKey();

        $chunkMacs = [];
        $len = 0;
        $hash = SodiumCompat::crypto_generichash_init($chunkMacKey, 16);
        do {
            $ciphertext = \fread($inputFP, $chunkSize);
            $len += Binary::safeStrlen($ciphertext);
            SodiumCompat::crypto_generichash_update($b2mac, $ciphertext);
            SodiumCompat::crypto_generichash_update($hash, $ciphertext);
            $hashCopy = '' . $hash;
            $chunkMacs[] = SodiumCompat::crypto_generichash_final($hashCopy);
        } while (!\feof($inputFP));

        SodiumCompat::crypto_generichash_update($b2mac, SodiumUtil::store64_le($adlen));
        SodiumCompat::crypto_generichash_update($b2mac, SodiumUtil::store64_le($len));
        $authTag = SodiumCompat::crypto_generichash_final($b2mac, self::MAC_SIZE);

        if (!\hash_equals($storedAuthTag, $authTag)) {
            throw new CryptoOperationException('Invalid authentication tag');
        }

        \fseek($inputFP, $pos, SEEK_SET);
        $ctr = 1;
        $ctrIncrease = ($chunkSize + 63) >> 6;
        $hash = SodiumCompat::crypto_generichash_init($chunkMacKey, 16);
        do {
            $ciphertext = \fread($inputFP, $chunkSize);

            SodiumCompat::crypto_generichash_update($hash, $ciphertext);
            $hashCopy = '' . $hash;
            $chunk = SodiumCompat::crypto_generichash_final($hashCopy);
            $storedChunk = \array_shift($chunkMacs);
            if (!Util::hashEquals($storedChunk, $chunk)) {
                throw new CryptoOperationException('Race condition');
            }

            $plaintext = ChaCha20::ietfStreamXorIc(
                $ciphertext,
                $nonceLast,
                $subkey,
                SodiumUtil::store64_le($ctr)
            );
            \fwrite($outputFP, $plaintext);
            $ctr += $ctrIncrease;
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
     * @throws SodiumException
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
        $adlen = 61; // 5 + 24 + 32
        try {
            $nonce = \random_bytes(self::NONCE_SIZE);
        } catch (\Exception $ex) {
            throw new CryptoOperationException('CSPRNG failure', 0, $ex);
        };

        // HChaCha20 step
        $subkey = HChaCha20::hChaCha20(
            SodiumUtil::substr($nonce, 0, 16),
            $this->getEncryptionKey($key)->getRawKey()
        );
        $nonceLast = "\x00\x00\x00\x00" . SodiumUtil::substr($nonce, 16, 8);

        // Write the header, empty space for a MAC, salts, then nonce.
        \fwrite($outputFP, (string) static::MAGIC_HEADER, 5);
        \fwrite($outputFP, str_repeat("\0", 32), 32);
        \fwrite($outputFP, $salt, 16);
        \fwrite($outputFP, $nonce, 24);

        $b2mac = SodiumCompat::crypto_generichash_init(
            $this->getIntegrityKey($key)->getRawKey(),
            self::MAC_SIZE
        );
        SodiumCompat::crypto_generichash_update($b2mac, (string) (static::MAGIC_HEADER) . $salt . $nonce);
        // Include optional AAD
        if ($aad) {
            $aadCanon = $aad->canonicalize();
            $adlen += Binary::safeStrlen($aadCanon);
            SodiumCompat::crypto_generichash_update($b2mac, $aadCanon);
            unset($aadCanon);
        }

        $ctr = 1;
        $ctrIncrease = ($chunkSize + 63) >> 6;
        $len = 0;
        do {
            $plaintext = \fread($inputFP, $chunkSize);
            $len += Binary::safeStrlen($plaintext);
            $ciphertext = ChaCha20::ietfStreamXorIc(
                $plaintext,
                $nonceLast,
                $subkey,
                SodiumUtil::store64_le($ctr)
            );
            \fwrite($outputFP, $ciphertext);
            SodiumCompat::crypto_generichash_update($b2mac, $ciphertext);
            $ctr += $ctrIncrease;
        } while (!\feof($inputFP));
        $end = \ftell($outputFP);

        SodiumCompat::crypto_generichash_update($b2mac, SodiumUtil::store64_le($adlen));
        SodiumCompat::crypto_generichash_update($b2mac, SodiumUtil::store64_le($len));
        $authTag = SodiumCompat::crypto_generichash_final($b2mac, self::MAC_SIZE);

        // Write the Poly1305 auth tag at the beginning of the file
        \fseek($outputFP, 5, SEEK_SET);
        \fwrite($outputFP, $authTag, 32);
        \fseek($outputFP, $end, SEEK_SET);
        \rewind($outputFP);
        return true;
    }

    /**
     * @return int
     */
    public function getFileEncryptionSaltOffset(): int
    {
        return 37;
    }

    /**
     * @return string
     */
    public function getPrefix(): string
    {
        return (string) static::MAGIC_HEADER;
    }
}
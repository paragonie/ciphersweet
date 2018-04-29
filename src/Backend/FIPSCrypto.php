<?php
namespace ParagonIE\CipherSweet\Backend;

use ParagonIE\ConstantTime\Base32;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\CipherSweet\Backend\Key\AsymmetricPublicKey;
use ParagonIE\CipherSweet\Backend\Key\AsymmetricSecretKey;
use ParagonIE\CipherSweet\Contract\BackendInterface;
use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;
use ParagonIE\CipherSweet\Exception\InvalidCiphertextException;
use ParagonIE\CipherSweet\Util;
use ParagonIE_Sodium_Core_Util as SodiumUtil;
use phpseclib\Crypt\RSA;

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
     *
     * @return string
     * @throws CryptoOperationException
     */
    public function encrypt($plaintext, SymmetricKey $key)
    {
        $hkdfSalt = \random_bytes(self::SALT_SIZE);
        $ctrNonce = \random_bytes(self::NONCE_SIZE);
        $encKey = Util::HKDF($key, $hkdfSalt, 'AES-256-CTR');
        $macKey = Util::HKDF($key, $hkdfSalt, 'HMAC-SHA-384');

        // Encrypt then MAC to avoid the Cryptographic Doom Principle:
        $ciphertext = self::aes256ctr($plaintext, $encKey, $ctrNonce);
        $mac = \hash_hmac(
            'sha384',
            Util::pack([self::MAGIC_HEADER, $hkdfSalt, $ctrNonce, $ciphertext]),
            $macKey,
            true
        );

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
     *
     * @return string
     * @throws CryptoOperationException
     * @throws InvalidCiphertextException
     * @throws \SodiumException
     */
    public function decrypt($ciphertext, SymmetricKey $key)
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
            Util::pack([self::MAGIC_HEADER, $hkdfSalt, $ctrNonce, $ciphertext]),
            $macKey,
            true
        );


        if (!SodiumUtil::hashEquals($recalc, $mac)) {
            throw new InvalidCiphertextException('Invalid MAC');
        }

        // If we're here, it's time to decrypt:
        return self::aes256ctr($ciphertext, $encKey, $ctrNonce);
    }

    /**
     * Encrypt a message against an RSA public key, using KEM+DEM.
     *
     * KEM+DEM construction explained:
     *
     * 1. Generate a random 256-bit value.
     * 2. Encrypt the random key using the RSA public key.
     *    - Algorithm: RSAES-OAEP with MGF1+SHA384 and e = 65537
     * 3. Next, calculate the message key from the random key and its RSA
     *    ciphertext, using HMAC
     * 4. Encrypt the message (see: encrypt() above) with the message key
     *    (step 3).
     * 5. Send the outputs of Steps 2 and 4 together.
     *
     * KEM+DEM analysis:
     *
     * Only someone in possession of the correct RSA private key will be able
     * to recover the random 256-bit value (step 1), which is needed with the
     * public RSA ciphertext to calculate the message key (step 3).
     *
     * Any attempts to perform a chosen-ciphertext attack will result in an
     * unpredictably random AES key, which will fail to decrypt the message.
     *
     * This construction is an insurance policy in case RSAES-OAEP's security
     * proof doesn't hold up to advances in side-channel cryptanalysis.
     *
     * @param string $message
     * @param AsymmetricPublicKey $publicKey
     * @return string
     * @throws CryptoOperationException
     */
    public function publicEncrypt($message, AsymmetricPublicKey $publicKey)
    {
        // KEM+DEM Step 1:
        $randomKey = \random_bytes(32);

        // KEM+DEM Step 2:
        $rsa = self::getRsa();
        $rsa->loadKey($publicKey->getRawKey());
        /** @var string|bool $rsaCiphertext */
        $rsaCiphertext = $rsa->encrypt($randomKey);
        if (!\is_string($rsaCiphertext)) {
            throw new CryptoOperationException('Could not encrypt ephemeral key');
        }

        // KEM+DEM Step 3:
        $key256 = \hash_hmac('sha256', $rsaCiphertext, $randomKey, true);
        $ephemeral = new SymmetricKey($this, $key256);

        // KEM+DEM Step 4:
        $ciphertext = $this->encrypt($message, $ephemeral);

        // KEM+DEM Step 5:
        return $ciphertext . ':' . Base64UrlSafe::encode($rsaCiphertext);
    }

    /**
     * Decrypt a message against an RSA public key, using KEM+DEM.
     *
     * See publicEncrypt() above for an explanation of the KEM+DEM
     * construction.
     *
     * @param string $message
     * @param AsymmetricSecretKey $secretKey
     *
     * @return string
     * @throws CryptoOperationException
     * @throws InvalidCiphertextException
     * @throws \SodiumException
     */
    public function privateDecrypt($message, AsymmetricSecretKey $secretKey)
    {
        $pieces = explode(':', $message);
        if (\count($pieces) !== 3) {
            throw new InvalidCiphertextException(
                'Message truncated or invalid'
            );
        }
        $rsaCiphertext = Base64UrlSafe::decode($pieces[2]);
        $ciphertext = $pieces[0] . ':' . $pieces[1];

        $rsa = self::getRsa();
        $rsa->loadKey($secretKey->getRawKey());
        /** @var string|bool $randomKey */
        $randomKey = $rsa->decrypt($rsaCiphertext);
        if (!\is_string($randomKey)) {
            throw new CryptoOperationException(
                'Could not encrypt ephemeral key'
            );
        }

        // Redo KEM+DEM encryption step 3 to calculate the message key:
        $key256 = \hash_hmac('sha256', $rsaCiphertext, $randomKey, true);
        $ephemeral = new SymmetricKey($this, $key256);

        // Decrypt the message, using symmetric encryption:s
        return $this->decrypt($ciphertext, $ephemeral);
    }

    /**
     * Sign a message using RSASSA-PSS with SHA384 and MGF1+SHA384, e = 65537.
     *
     * @param string $message
     * @param AsymmetricSecretKey $secretKey
     *
     * @return string
     */
    public function sign($message, AsymmetricSecretKey $secretKey)
    {
        $rsa = self::getRsa();
        $rsa->loadKey($secretKey->getRawKey());
        return self::MAGIC_HEADER . Base64UrlSafe::encode($rsa->sign($message));
    }

    /**
     * Verify a message signature that was signed using RSASSA-PSS with SHA384
     * and MGF1+SHA384, e = 65537.
     *
     * @param string $message
     * @param AsymmetricPublicKey $publicKey
     * @param string $signature
     * @return bool
     *
     * @throws InvalidCiphertextException
     * @throws \SodiumException
     */
    public function verify($message, AsymmetricPublicKey $publicKey, $signature)
    {
        $header = Binary::safeSubstr($signature, 0, 5);
        if (!SodiumUtil::hashEquals($header, self::MAGIC_HEADER)) {
            throw new InvalidCiphertextException('Invalid signature header.');
        }
        $decoded = Base64UrlSafe::decode(Binary::safeSubstr($signature, 5));

        $rsa = self::getRsa();
        $rsa->loadKey($publicKey->getRawKey());
        return $rsa->verify($message, $decoded);
    }

    /**
     * Perform a fast blind index. Ideal for high-entropy inputs.
     * Algorithm: PBKDF2-SHA384 with only 1 iteration.
     *
     * @param string $plaintext
     * @param SymmetricKey $key
     * @param int|null $outputLength
     *
     * @return string
     */
    public function blindIndexFast(
        $plaintext,
        SymmetricKey $key,
        $outputLength = null
    ) {
        if (\is_null($outputLength)) {
            $outputLength = 32;
        }
        return \hash_pbkdf2(
            'sha384',
            $plaintext,
            $key->getRawKey(),
            1,
            $outputLength,
            true
        );
    }

    /**
     * Perform a slower Blind Index calculation.
     * Algorithm: PBKDF2-SHA384 with at least 50,000 iterations.
     *
     * @param string $plaintext
     * @param SymmetricKey $key
     * @param int|null $outputLength
     * @param array $config
     *
     * @return string
     */
    public function blindIndexSlow(
        $plaintext,
        SymmetricKey $key,
        $outputLength = null,
        array $config = []
    ) {
        if (\is_null($outputLength)) {
            $outputLength = 32;
        }
        $iterations = 50000;
        if (isset($config['iterations'])) {
            if ($config['iterations'] > 50000) {
                $iterations = (int) $config['iterations'];
            }
        }

        return \hash_pbkdf2(
            'sha384',
            $plaintext,
            $key->getRawKey(),
            $iterations,
            $outputLength,
            true
        );
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
        return \rtrim(Base32::encode(Binary::safeSubstr($hash, 0, 8)), '=');
    }

    /**
     * Get the RSA public key for a given RSA secret key.
     *
     * @param AsymmetricSecretKey $secretKey
     *
     * @return AsymmetricPublicKey
     */
    public function getPublicKeyFromSecretKey(AsymmetricSecretKey $secretKey)
    {
        $keyMaterial = $secretKey->getRawKey();
        $res = \openssl_pkey_get_private($keyMaterial);
        /** @var array<string, string> $pubkey */
        $pubkey = \openssl_pkey_get_details($res);
        $public = \rtrim(
            \str_replace("\n", "\r\n", $pubkey['key']),
            "\r\n"
        );
        return new AsymmetricPublicKey($this, $public);
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
     * Get the PHPSecLib RSA provider
     *
     * Hard-coded:
     *
     * - RSAES-OAEP with MGF1+SHA384, e = 65537
     * - RSASSA-PSS with MGF1+SHA384 and SHA384, e = 65537
     *
     * @return RSA
     */
    public static function getRsa()
    {
        $rsa = new RSA();
        $rsa->setHash('sha384');
        $rsa->setMGFHash('sha384');
        $rsa->setEncryptionMode(RSA::ENCRYPTION_OAEP);
        $rsa->setSignatureMode(RSA::SIGNATURE_PSS);
        return $rsa;
    }
}

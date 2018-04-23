<?php
namespace ParagonIE\CipherSweet\Backend;

use ParagonIE\CipherSweet\Util;
use ParagonIE\ConstantTime\Base32;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\CipherSweet\Backend\Key\AsymmetricPublicKey;
use ParagonIE\CipherSweet\Backend\Key\AsymmetricSecretKey;
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
     *
     * @return string
     * @throws \SodiumException
     */
    public function encrypt($plaintext, SymmetricKey $key)
    {
        $nonce = \random_bytes(self::NONCE_SIZE);
        $ciphertext = SodiumCompat::crypto_aead_xchacha20poly1305_ietf_encrypt(
            $plaintext,
            $nonce,
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
     *
     * @return string
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
        if (Binary::safeStrlen($decoded) < (self::NONCE_SIZE + 16)) {
            throw new InvalidCiphertextException('Message is too short.');
        }
        $nonce = Binary::safeSubstr($decoded, 0, self::NONCE_SIZE);
        $encrypted = Binary::safeSubstr($decoded, self::NONCE_SIZE);

        return SodiumCompat::crypto_aead_xchacha20poly1305_ietf_decrypt(
            $encrypted,
            $nonce,
            $nonce,
            $key->getRawKey()
        );
    }

    /**
     * Encrypt a message with the recipient's public key.
     *
     * 1. Generate a random X25519 keypair.
     * 2. Convert the recipient's Ed25519 public key into an X25519 public key,
     *    then do a key exchange.
     * 3. Encrypt the message, using the output of Step 2.
     *
     * @param string $message
     * @param AsymmetricPublicKey $publicKey
     *
     * @return string
     * @throws \SodiumException
     */
    public function publicEncrypt($message, AsymmetricPublicKey $publicKey)
    {
        $myKeypair = SodiumCompat::crypto_box_keypair();
        $mySecret = SodiumCompat::crypto_box_secretkey($myKeypair);
        $myPublic = SodiumCompat::crypto_box_publickey($myKeypair);
        $theirPublic = SodiumCompat::crypto_sign_ed25519_pk_to_curve25519(
            $publicKey->getRawKey()
        );

        $shared = new SymmetricKey(
            $this,
            SodiumCompat::crypto_kx(
                $mySecret,
                $theirPublic,
                $myPublic,
                $theirPublic
            )
        );

        $ciphertext = $this->encrypt($message, $shared);
        return $ciphertext . ':' . Base64UrlSafe::encode($myPublic);
    }

    /**
     * Decrypt a message using your secret key.
     *
     * @param string $message
     * @param AsymmetricSecretKey $secretKey
     *
     * @return string
     * @throws InvalidCiphertextException
     * @throws \SodiumException
     */
    public function privateDecrypt($message, AsymmetricSecretKey $secretKey)
    {
        $pieces = explode(':', $message);
        if (\count($pieces) !== 3) {
            throw new InvalidCiphertextException('Message truncated');
        }
        $theirPublic = Base64UrlSafe::decode($pieces[2]);
        $ciphertext = $pieces[0] . ':' . $pieces[1];

        $mySecret = SodiumCompat::crypto_sign_ed25519_sk_to_curve25519(
            $secretKey->getRawKey()
        );
        $myPublic = SodiumCompat::crypto_box_publickey_from_secretkey(
            $mySecret
        );

        $shared = new SymmetricKey(
            $this,
            SodiumCompat::crypto_kx(
                $mySecret,
                $theirPublic,
                $theirPublic,
                $myPublic
            )
        );

        return $this->decrypt($ciphertext, $shared);
    }

    /**
     * Sign a message using Ed25519.
     *
     * @param string $message
     * @param AsymmetricSecretKey $secretKey
     *
     * @return string
     * @throws \SodiumException
     */
    public function sign($message, AsymmetricSecretKey $secretKey)
    {
        $signature = SodiumCompat::crypto_sign_detached(
            $message,
            $secretKey->getRawKey()
        );
        return self::MAGIC_HEADER . Base64UrlSafe::encode($signature);
    }

    /**
     * Verify a message using Ed25519.
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
        if (!\ParagonIE_Sodium_Core_Util::hashEquals($header, self::MAGIC_HEADER)) {
            throw new InvalidCiphertextException('Invalid signature header.');
        }
        $decoded = Base64UrlSafe::decode(Binary::safeSubstr($signature, 5));

        return SodiumCompat::crypto_sign_verify_detached(
            $decoded,
            $message,
            $publicKey->getRawKey()
        );
    }

    /**
     * @param string $plaintext
     * @param SymmetricKey $key
     * @param int|null $outputLength
     *
     * @return string
     * @throws \SodiumException
     */
    public function blindIndexFast($plaintext, SymmetricKey $key, $outputLength = null)
    {
        $hash = SodiumCompat::crypto_generichash(
            $plaintext,
            $key->getRawKey()
        );
        return Binary::safeSubstr($hash, 0, $outputLength);
    }

    /**
     * @param string $plaintext
     * @param SymmetricKey $key
     * @param int|null $outputLength
     * @param array $config
     *
     * @return string
     * @throws \SodiumException
     */
    public function blindIndexSlow($plaintext, SymmetricKey $key, $outputLength = null, array $config = [])
    {
        if (!SodiumCompat::crypto_pwhash_is_available()) {
            throw new \SodiumException('Not using the native libsodium bindings');
        }
        $opsLimit = SodiumCompat::CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE;
        $memLimit = SodiumCompat::CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE;

        if (isset($config['opslimit'])) {
            if ($config['opslimit'] > SodiumCompat::CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE) {
                $opsLimit = (int) $config['opslimit'];
            }
        }
        if (isset($config['memlimit'])) {
            if ($config['memlimit'] > SodiumCompat::CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE) {
                $memLimit = (int) $config['memlimit'];
            }
        }
        /** @var int $pwHashLength */
        $pwHashLength = \is_null($outputLength) ? 16 : $outputLength;
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
        return Binary::safeSubstr($hash, 0, $outputLength);
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

    /**
     * @param AsymmetricSecretKey $secretKey
     * @return AsymmetricPublicKey
     */
    public function getPublicKeyFromSecretKey(AsymmetricSecretKey $secretKey)
    {
        return new AsymmetricPublicKey(
            $this,
            \sodium_crypto_sign_publickey_from_secretkey(
                $secretKey->getRawKey()
            )
        );
    }
}

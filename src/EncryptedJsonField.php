<?php
namespace ParagonIE\CipherSweet;

use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\Contract\BackendInterface;
use ParagonIE\CipherSweet\Exception\CipherSweetException;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;
use ParagonIE\CipherSweet\Exception\InvalidCiphertextException;
use ParagonIE\CipherSweet\Exception\JsonMapException;
use SodiumException;

class EncryptedJsonField
{
    use TypeEncodingTrait;

    /** @var BackendInterface $backend */
    private $backend;

    /** @var SymmetricKey $rootKey */
    private $rootKey;

    /** @var JsonFieldMap $fieldMap */
    private $fieldMap;

    public function __construct(
        BackendInterface $backend,
        SymmetricKey $rootKey,
        JsonFieldMap $fieldMap
    ) {
        $this->backend = $backend;
        $this->rootKey = $rootKey;
        $this->fieldMap = $fieldMap;
    }

    /**
     * @param array<array-key, string|int> $indices
     * @return self
     *
     * @throws JsonMapException
     */
    public function addBooleanField($indices)
    {
        if (is_string($indices) || is_int($indices)) {
            $indices = [$indices];
        }
        return $this->addField($indices, Constants::TYPE_BOOLEAN);
    }

    /**
     * @param array<array-key, string|int> $indices
     * @return self
     *
     * @throws JsonMapException
     */
    public function addFloatField($indices)
    {
        if (is_string($indices) || is_int($indices)) {
            $indices = [$indices];
        }
        return $this->addField($indices, Constants::TYPE_FLOAT);
    }

    /**
     * @param array<array-key, string|int> $indices
     * @return self
     *
     * @throws JsonMapException
     */
    public function addIntegerField($indices)
    {
        if (is_string($indices) || is_int($indices)) {
            $indices = [$indices];
        }
        return $this->addField($indices, Constants::TYPE_INT);
    }

    /**
     * @param array<array-key, string|int> $indices
     * @return self
     *
     * @throws JsonMapException
     */
    public function addTextField($indices)
    {
        if (is_string($indices) || is_int($indices)) {
            $indices = [$indices];
        }
        return $this->addField($indices, Constants::TYPE_TEXT);
    }

    /**
     * @param array<array-key, string|int> $indices
     * @param string $type
     * @return self
     *
     * @throws JsonMapException
     */
    public function addField(array $indices, $type)
    {
        $this->fieldMap->addField($indices, $type);
        return $this;
    }

    /**
     * @param string $encoded
     * @return array
     *
     * @throws CipherSweetException
     */
    public function decryptJson($encoded)
    {
        $field = json_decode($encoded, true);
        if (!is_array($field)) {
            throw new CipherSweetException("Could not decode JSON");
        }

        try {
            /**
             * @var array{flat: string, path: array, type: string} $mapped
             */
            foreach ($this->fieldMap->getMapping() as $mapped) {
                /** @var array<array-key, int|string> $path */
                $path = $mapped['path'];
                if (empty($path)) {
                    continue;
                }
                /** @var string $type */
                $type = $mapped['type'];
                $derivedKey = $this->deriveKey($mapped['flat']);
                $this->decryptInPlace($derivedKey, $field, $path, $type);
            }
            return $field;
        } catch (SodiumException $ex) {
            throw new InvalidCiphertextException("Decryption failed", 0, $ex);
        }
    }

    /**
     * @param array $field
     * @return string
     *
     * @throws CryptoOperationException
     * @throws SodiumException
     */
    public function encryptJson(array $field)
    {
        /**
         * @var array{flat: string, path: array, type: string} $mapped
         */
        foreach ($this->fieldMap->getMapping() as $mapped) {
            /** @var array<array-key, int|string> $path */
            $path = $mapped['path'];
            if (empty($path)) {
                continue;
            }
            /** @var string $type */
            $type = $mapped['type'];
            $derivedKey = $this->deriveKey($mapped['flat']);
            $this->encryptInPlace($derivedKey, $field, $path, $type);
        }
        return json_encode($field);
    }

    /**
     * @param string $flatPath
     * @return SymmetricKey
     * @throws CryptoOperationException
     */
    public function deriveKey($flatPath)
    {
        return new SymmetricKey(
            Util::HKDF(
                $this->rootKey,
                null,
                Constants::DS_JSON . $flatPath
            )
        );
    }

    /**
     * @param SymmetricKey $derivedKey
     * @param array<array-key, mixed|array> &$field
     * @param array<array-key, int|string> $path
     * @param string $type
     * @return void
     *
     * @throws SodiumException
     * @psalm-suppress InvalidArgument
     */
    public function decryptInPlace(
        SymmetricKey $derivedKey,
        array &$field,
        array $path,
        $type
    ) {
        // Walk down the path
        $curr = &$field;
        foreach ($path as $next) {
            if (!array_key_exists($next, $curr)) {
                return;
            }
            /** @var array<array-key, mixed|array>|null $curr */
            $curr =& $curr[$next];
        }
        if (is_null($curr)) {
            return;
        }
        $decrypted = $this->backend->decrypt($curr, $derivedKey);
        $curr = $this->convertFromString($decrypted, $type);
    }

    /**
     * @param SymmetricKey $derivedKey
     * @param array<array-key, mixed|array> &$field
     * @param array<array-key, int|string> $path
     * @param string $type
     * @return void
     *
     * @throws SodiumException
     * @psalm-suppress InvalidArgument
     */
    public function encryptInPlace(
        SymmetricKey $derivedKey,
        array &$field,
        array $path,
        $type
    ) {
        // Walk down the path
        $curr = &$field;
        foreach ($path as $next) {
            if (!array_key_exists($next, $curr)) {
                return;
            }

            /** @var array<array-key, mixed|array>|null $curr */
            $curr =& $curr[$next];
        }
        if (is_null($curr)) {
            return;
        }
        $curr = $this->backend->encrypt(
            $this->convertToString($curr, $type),
            $derivedKey
        );
    }
}

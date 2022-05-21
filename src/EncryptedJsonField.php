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

    /** @var JsonFieldMap $fieldMap */
    private $fieldMap;

    /** @var SymmetricKey $rootKey */
    private $rootKey;

    /** @var bool $strict */
    private $strict;

    /**
     * @param BackendInterface $backend
     * @param SymmetricKey $rootKey
     * @param JsonFieldMap $fieldMap
     * @param bool $strict
     */
    public function __construct(
        BackendInterface $backend,
        SymmetricKey $rootKey,
        JsonFieldMap $fieldMap,
        $strict = true
    ) {
        $this->backend = $backend;
        $this->rootKey = $rootKey;
        $this->fieldMap = $fieldMap;
        $this->strict = $strict;
    }

    /**
     * @param CipherSweet $engine
     * @param JsonFieldMap $fieldMap
     * @param string $tableName
     * @param string $fieldName
     * @param bool $strict
     * @return EncryptedJsonField
     *
     * @throws CipherSweetException
     * @throws CryptoOperationException
     */
    public static function create(
        CipherSweet $engine,
        JsonFieldMap $fieldMap,
        $tableName,
        $fieldName,
        $strict = true
    ) {
        return new self(
            $engine->getBackend(),
            $engine->getFieldSymmetricKey($tableName, $fieldName),
            $fieldMap,
            $strict
        );
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
     * @param string $aad
     * @return array
     *
     * @throws CipherSweetException
     */
    public function decryptJson($encoded, $aad = '')
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
                $this->decryptInPlace($derivedKey, $field, $path, $type, $aad);
            }
            return $field;
        } catch (SodiumException $ex) {
            throw new InvalidCiphertextException("Decryption failed", 0, $ex);
        }
    }

    /**
     * @param array $field
     * @param string $aad
     * @return string
     *
     * @throws CryptoOperationException
     * @throws SodiumException
     */
    public function encryptJson(array $field, $aad = '')
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
            $this->encryptInPlace($derivedKey, $field, $path, $type, $aad);
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
     * @param bool $bool
     * @return static
     */
    public function setStrictMode($bool = false)
    {
        $this->strict = !empty($bool);
        return $this;
    }

    /**
     * @param SymmetricKey $derivedKey
     * @param array<array-key, mixed|array> &$field
     * @param array<array-key, int|string> $path
     * @param string $type
     * @param string $aad
     * @return void
     *
     * @throws CipherSweetException
     * @throws SodiumException
     * @psalm-suppress InvalidArgument
     */
    protected function decryptInPlace(
        SymmetricKey $derivedKey,
        array &$field,
        array $path,
        $type,
        $aad = ''
    ) {
        // Walk down the path
        $curr = &$field;
        foreach ($path as $next) {
            if (!array_key_exists($next, $curr)) {
                $this->throwIfStrict(true);
                return;
            }
            /** @var array<array-key, mixed|array>|null $curr */
            $curr =& $curr[$next];
        }
        if (is_null($curr)) {
            return;
        }
        $decrypted = $this->backend->decrypt($curr, $derivedKey, $aad);
        $curr = $this->convertFromString($decrypted, $type);
    }

    /**
     * @param SymmetricKey $derivedKey
     * @param array<array-key, mixed|array> &$field
     * @param array<array-key, int|string> $path
     * @param string $type
     * @param string $aad
     * @return void
     *
     * @throws CipherSweetException
     * @throws SodiumException
     * @psalm-suppress InvalidArgument
     */
    protected function encryptInPlace(
        SymmetricKey $derivedKey,
        array &$field,
        array $path,
        $type,
        $aad = ''
    ) {
        // Walk down the path
        $curr = &$field;
        foreach ($path as $next) {
            if (!array_key_exists($next, $curr)) {
                $this->throwIfStrict();
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
            $derivedKey,
            $aad
        );
    }

    /**
     * @param bool $decrypting
     * @return void
     *
     * @throws CipherSweetException
     */
    private function throwIfStrict($decrypting = false)
    {
        if (!$this->strict) {
            /* NOP */
            return;
        }

        $pre = $decrypting ? 'de' : 'en';
        throw new CipherSweetException(
            "Required JSON field was missing on {$pre}cryptJSON() in strict mode"
        );
    }
}

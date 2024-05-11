<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet;

use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\Contract\BackendInterface;
use ParagonIE\CipherSweet\Exception\{
    CipherSweetException,
    CryptoOperationException,
    InvalidCiphertextException,
    JsonMapException
};
use SodiumException;

class EncryptedJsonField
{
    use TypeEncodingTrait;

    /** @var BackendInterface $backend */
    private BackendInterface $backend;

    /** @var JsonFieldMap $fieldMap */
    private JsonFieldMap $fieldMap;

    /** @var SymmetricKey $rootKey */
    private SymmetricKey $rootKey;

    /** @var bool $strict */
    private bool $strict;

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
        bool $strict = true
    ) {
        $this->backend = $backend;
        $this->rootKey = $rootKey;
        $this->fieldMap = $fieldMap;
        $this->strict = $strict;
    }

    /**
     * @throws CipherSweetException
     * @throws CryptoOperationException
     */
    public static function create(
        CipherSweet $engine,
        JsonFieldMap $fieldMap,
        string $tableName,
        string $fieldName,
        bool $strict = true
    ): self {
        return new self(
            $engine->getBackend(),
            $engine->getFieldSymmetricKey($tableName, $fieldName),
            $fieldMap,
            $strict
        );
    }

    /**
     * @param array<array-key, string|int>|int|string $indices
     * @return static
     *
     * @throws JsonMapException
     */
    public function addBooleanField(string|int|array $indices): static
    {
        if (!\is_array($indices)) {
            $indices = [$indices];
        }
        return $this->addField($indices, Constants::TYPE_BOOLEAN);
    }

    /**
     * @param array<array-key, string|int>|int|string $indices
     * @return static
     *
     * @throws JsonMapException
     */
    public function addFloatField(string|int|array $indices): static
    {
        if (!\is_array($indices)) {
            $indices = [$indices];
        }
        return $this->addField($indices, Constants::TYPE_FLOAT);
    }

    /**
     * @param array<array-key, string|int>|int|string $indices
     * @return static
     *
     * @throws JsonMapException
     */
    public function addIntegerField(string|int|array $indices): static
    {
        if (!\is_array($indices)) {
            $indices = [$indices];
        }
        return $this->addField($indices, Constants::TYPE_INT);
    }

    /**
     * @param array<array-key, string|int>|int|string $indices
     * @return static
     *
     * @throws JsonMapException
     */
    public function addTextField(string|int|array $indices): static
    {
        if (!\is_array($indices)) {
            $indices = [$indices];
        }
        return $this->addField($indices, Constants::TYPE_TEXT);
    }

    /**
     * @param array<array-key, string|int> $indices
     * @param string $type
     * @return static
     *
     * @throws JsonMapException
     */
    public function addField(array $indices, string $type): static
    {
        $this->fieldMap->addField($indices, $type);
        return $this;
    }

    /**
     * @throws CipherSweetException
     */
    public function decryptJson(string $encoded, string|AAD $aad = ''): array
    {
        $field = \json_decode($encoded, true);
        if (!\is_array($field)) {
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
     * @throws CipherSweetException
     * @throws SodiumException
     */
    public function encryptJson(array $field, string|AAD $aad = ''): string
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

    public function deriveKey(string $flatPath): SymmetricKey
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
    public function setStrictMode(bool $bool = false): static
    {
        $this->strict = $bool;
        return $this;
    }

    /**
     * @param SymmetricKey $derivedKey
     * @param array<array-key, mixed|array> &$field
     * @param array<array-key, int|string> $path
     * @param string $type
     * @param string|AAD $aad
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
        string $type,
        string|AAD $aad = ''
    ): void {
        // Walk down the path
        $curr = &$field;
        $depth = 0;
        foreach ($path as $next) {
            if (!\array_key_exists($next, $curr)) {
                $this->throwIfStrict($next, $depth, true);
                return;
            }
            /** @var array<array-key, mixed|array>|null $curr */
            $curr =& $curr[$next];
            ++$depth;
        }
        if (\is_null($curr)) {
            return;
        }
        $decrypted = $this->backend->decrypt($curr, $derivedKey, AAD::literal($aad)->canonicalize());
        $curr = $this->convertFromString($decrypted, $type);
    }

    /**
     * @param SymmetricKey $derivedKey
     * @param array<array-key, mixed|array> &$field
     * @param array<array-key, int|string> $path
     * @param string $type
     * @param string|AAD $aad
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
        string $type,
        string|AAD $aad = ''
    ): void {
        // Walk down the path
        $curr = &$field;
        $depth = 0;
        foreach ($path as $next) {
            if (!\array_key_exists($next, $curr)) {
                $this->throwIfStrict($next, $depth);
                return;
            }

            /** @var array<array-key, mixed|array>|null $curr */
            $curr =& $curr[$next];
            ++$depth;
        }
        if (\is_null($curr)) {
            return;
        }
        $curr = $this->backend->encrypt(
            $this->convertToString($curr, $type),
            $derivedKey,
            AAD::literal($aad)->canonicalize()
        );
    }

    /**
     * @param array-key $key
     * @param int $depth
     * @param bool $decrypting
     * @return void
     *
     * @throws CipherSweetException
     */
    private function throwIfStrict(string|int $key, int $depth, bool $decrypting = false): void
    {
        if (!$this->strict) {
            /* NOP */
            return;
        }

        $pre = $decrypting ? 'de' : 'en';
        throw new CipherSweetException(
            "Required JSON field {$key} was missing at depth {$depth} on {$pre}cryptJSON() in strict mode"
        );
    }
}

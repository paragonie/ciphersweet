<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet;

use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\Contract\BackendInterface;
use ParagonIE\CipherSweet\Exception\{
    BlindIndexNameCollisionException,
    BlindIndexNotFoundException,
    CipherSweetException,
    CryptoOperationException
};
use ParagonIE\ConstantTime\Hex;
use SodiumException;

/**
 * Class EncryptedField
 * @package ParagonIE\CipherSweet
 */
class EncryptedField
{
    /**
     * @var array<string, BlindIndex> $blindIndexes
     */
    protected array $blindIndexes = [];

    /**
     * @var CipherSweet $engine
     */
    protected CipherSweet $engine;

    /**
     * @var string $fieldName
     */
    protected string $fieldName = '';

    /**
     * @var bool $typedIndexes
     */
    protected bool $typedIndexes = false;

    /**
     * @var SymmetricKey $key
     */
    protected SymmetricKey $key;

    /**
     * @var string $tableName
     */
    protected string $tableName = '';

    /**
     * EncryptedField constructor.
     *
     * @throws CryptoOperationException
     * @throws CipherSweetException
     */
    public function __construct(
        CipherSweet $engine,
        #[\SensitiveParameter]
        string $tableName = '',
        #[\SensitiveParameter]
        string $fieldName = '',
        bool $useTypedIndexes = false
    ) {
        $this->engine = $engine;
        $this->tableName = $tableName;
        $this->fieldName = $fieldName;
        $this->key = $this->engine->getFieldSymmetricKey(
            $this->tableName,
            $this->fieldName
        );
        $this->typedIndexes = $useTypedIndexes;
    }

    /**
     * Only usable in multi-tenant setups.
     *
     * Sets the active tenant and re-derives the encryption key for this field.
     *
     * @throws CipherSweetException
     * @throws CryptoOperationException
     */
    public function setActiveTenant(
        #[\SensitiveParameter]
        string $tenantIndex
    ): static {
        if (!$this->engine->isMultiTenantSupported()) {
            throw new CipherSweetException('This is only available for multi-tenant-aware engines/providers.');
        }
        $this->engine->setActiveTenant($tenantIndex);
        $this->key = $this->engine->getFieldSymmetricKey(
            $this->tableName,
            $this->fieldName
        );
        return $this;
    }

    /**
     * Encrypt a value and calculate all of its blind indices in one go.
     *
     * @return array<int, string|array>
     *
     * @throws BlindIndexNotFoundException
     * @throws SodiumException
     */
    public function prepareForStorage(
        #[\SensitiveParameter]
        string $plaintext,
        #[\SensitiveParameter]
        string|AAD $aad = ''
    ): array {
        return [
            $this->encryptValue($plaintext, $aad),
            $this->getAllBlindIndexes($plaintext)
        ];
    }

    /**
     * Encrypt a single value, using the per-field symmetric key.
     *
     * @param string $plaintext
     * @param string|AAD $aad   Additional authenticated data
     * @return string
     */
    public function encryptValue(
        #[\SensitiveParameter]
        string $plaintext,
        #[\SensitiveParameter]
        string|AAD $aad = ''
    ): string {
        return $this
            ->engine
            ->getBackend()
            ->encrypt(
                $plaintext,
                $this->key,
                AAD::literal($aad)->canonicalize()
            );
    }

    /**
     * Decrypt a single value, using the per-field symmetric key.
     */
    public function decryptValue(
        #[\SensitiveParameter]
        string $ciphertext,
        #[\SensitiveParameter]
        string|AAD $aad = ''
    ): string {
        return $this
            ->engine
            ->getBackend()
            ->decrypt(
                $ciphertext,
                $this->key,
                AAD::literal($aad)->canonicalize()
            );
    }

    /**
     * Get all blind index values for a given plaintext.
     *
     * @return array<string, string|array>
     *
     * @throws BlindIndexNotFoundException
     * @throws SodiumException
     */
    public function getAllBlindIndexes(
        #[\SensitiveParameter]
        string $plaintext
    ): array {
        /** @var array<string, string|array> $output */
        $output = [];
        $key = $this->engine->getBlindIndexRootKey(
            $this->tableName,
            $this->fieldName
        );

        if ($this->typedIndexes) {
            /** @var BlindIndex $index */
            foreach ($this->blindIndexes as $name => $index) {
                $k = $this->engine->getIndexTypeColumn(
                    $this->tableName,
                    $this->fieldName,
                    $name
                );
                $output[$name] = [
                    'type' => $k,
                    'value' =>
                        Hex::encode(
                            $this->getBlindIndexRaw(
                                $plaintext,
                                $name,
                                $key
                            )
                        )
                ];
            }
        } else {
            /** @var BlindIndex $index */
            foreach ($this->blindIndexes as $name => $index) {
                $output[$name] = Hex::encode(
                    $this->getBlindIndexRaw(
                        $plaintext,
                        $name,
                        $key
                    )
                );
            }
        }
        return $output;
    }

    /**
     * Get a particular blind index of a given plaintext.
     *
     * @throws BlindIndexNotFoundException
     * @throws SodiumException
     */
    public function getBlindIndex(
        #[\SensitiveParameter]
        string $plaintext,
        #[\SensitiveParameter]
        string $name
    ): string|array {
        $key = $this->engine->getBlindIndexRootKey(
            $this->tableName,
            $this->fieldName
        );
        if ($this->typedIndexes) {
            $k = $this->engine->getIndexTypeColumn(
                $this->tableName,
                $this->fieldName,
                $name
            );
            return [
                'type' => $k,
                'value' =>
                    Hex::encode(
                        $this->getBlindIndexRaw(
                            $plaintext,
                            $name,
                            $key
                        )
                    )
            ];
        }
        return Hex::encode(
            $this->getBlindIndexRaw(
                $plaintext,
                $name,
                $key
            )
        );
    }

    /**
     * Internal: Get the raw blind index. Returns a raw binary string.
     *
     * @throws BlindIndexNotFoundException
     */
    protected function getBlindIndexRaw(
        #[\SensitiveParameter]
        string $plaintext,
        #[\SensitiveParameter]
        string $name,
        #[\SensitiveParameter]
        SymmetricKey $key = null
    ): string {
        if (!isset($this->blindIndexes[$name])) {
            throw new BlindIndexNotFoundException(
                'Blind index ' . $name . ' not found'
            );
        }
        if (!$key) {
            $key = $this->engine->getBlindIndexRootKey(
                $this->tableName,
                $this->fieldName
            );
        }

        $backend = $this->engine->getBackend();
        $subKey = new SymmetricKey(
            \hash_hmac(
                'sha256',
                Util::pack([$this->tableName, $this->fieldName, $name]),
                $key->getRawKey(),
                true
            )
        );

        /** @var BlindIndex $index */
        $index = $this->blindIndexes[$name];
        if ($index->getFastHash()) {
            return $backend->blindIndexFast(
                $index->getTransformed($plaintext),
                $subKey,
                $index->getFilterBitLength()
            );
        }
        return $backend->blindIndexSlow(
            $index->getTransformed($plaintext),
            $subKey,
            $index->getFilterBitLength(),
            $index->getHashConfig()
        );
    }

    /**
     * @return array<string, BlindIndex>
     */
    public function getBlindIndexObjects(): array
    {
        return $this->blindIndexes;
    }

    /**
     * Get the "type" of a specific blind index (by name).
     *
     * More specific than the getBlindIndexTypes() method.
     *
     * @throws SodiumException
     */
    public function getBlindIndexType(
        #[\SensitiveParameter]
        string $name
    ): string {
        return $this->engine->getIndexTypeColumn(
            $this->tableName,
            $this->fieldName,
            $name
        );
    }

    /**
     * Get a list of all the blind index "type"s, corresponding with their
     * index names.
     *
     * @return array<string, string>
     *
     * @throws SodiumException
     */
    public function getBlindIndexTypes(): array
    {
        $typeArray = [];
        foreach (\array_keys($this->blindIndexes) as $name) {
            $typeArray[$name] = $this->engine->getIndexTypeColumn(
                $this->tableName,
                $this->fieldName,
                $name
            );
        }
        return $typeArray;
    }

    /**
     * Add a blind index to this encrypted field.
     *
     * @throws BlindIndexNameCollisionException
     */
    public function addBlindIndex(BlindIndex $index, ?string $name = null): static
    {
        if (\is_null($name)) {
            $name = $index->getName();
        }
        if (isset($this->blindIndexes[$name])) {
            throw new BlindIndexNameCollisionException(
                'Index ' . $name . ' already defined'
            );
        }
        $this->blindIndexes[$name] = $index;
        return $this;
    }

    public function getFlatIndexes(): bool
    {
        return !$this->typedIndexes;
    }

    public function getTypedIndexes(): bool
    {
        return $this->typedIndexes;
    }

    public function getBackend(): BackendInterface
    {
        return $this->engine->getBackend();
    }

    /**
     * @return CipherSweet
     */
    public function getEngine(): CipherSweet
    {
        return $this->engine;
    }

    public function setFlatIndexes(bool $bool): static
    {
        $this->typedIndexes = !$bool;
        return $this;
    }

    public function setTypedIndexes(bool $bool): static
    {
        $this->typedIndexes = $bool;
        return $this;
    }
}

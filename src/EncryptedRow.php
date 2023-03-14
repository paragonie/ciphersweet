<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet;

use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\Contract\BackendInterface;
use ParagonIE\CipherSweet\Exception\{
    ArrayKeyException,
    BlindIndexNotFoundException,
    CipherSweetException,
    CryptoOperationException,
    EmptyFieldException,
    InvalidCiphertextException
};
use ParagonIE\ConstantTime\Hex;
use SodiumException;

/**
 * Class EncryptedRow
 * @package ParagonIE\CipherSweet
 */
class EncryptedRow
{
    use TypeEncodingTrait;

    /**
     * @var CipherSweet $engine
     */
    protected CipherSweet $engine;

    /**
     * @var array<string, string> $fieldsToEncrypt
     */
    protected array $fieldsToEncrypt = [];

    /**
     * @var array<string, JsonFieldMap> $jsonMaps
     */
    protected array $jsonMaps = [];

    /**
     * @var array<string, bool> $jsonStrict
     */
    protected array $jsonStrict = [];

    /**
     * @var array<string, string> $aadSourceField
     */
    protected array $aadSourceField = [];

    /**
     * @var array<string, array<string, BlindIndex>> $blindIndexes
     */
    protected array $blindIndexes = [];

    /**
     * @var bool $permitEmpty
     */
    protected bool $permitEmpty = false;

    /**
     * @var bool $typedIndexes
     */
    protected bool $typedIndexes = false;

    /**
     * @var array<string, CompoundIndex> $compoundIndexes
     */
    protected array $compoundIndexes = [];

    /**
     * @var string $tableName
     */
    protected string $tableName;

    /**
     * EncryptedFieldSet constructor.
     *
     * @param CipherSweet $engine
     * @param string $tableName
     * @param bool $useTypedIndexes
     */
    public function __construct(
        CipherSweet $engine,
        #[\SensitiveParameter]
        string $tableName,
        bool $useTypedIndexes = false
    ) {
        $this->engine = $engine;
        $this->tableName = $tableName;
        $this->typedIndexes = $useTypedIndexes;
    }

    /**
     * Define a field that will be encrypted.
     *
     * @param string $fieldName
     * @param string $type
     * @param string $aadSource Field name to source AAD from
     * @return static
     */
    public function addField(
        string $fieldName,
        string $type = Constants::TYPE_TEXT,
        string $aadSource = ''
    ): static {
        $this->fieldsToEncrypt[$fieldName] = $type;
        if ($aadSource) {
            $this->aadSourceField[$fieldName] = $aadSource;
        }
        return $this;
    }

    /**
     * Define a boolean field that will be encrypted. Nullable.
     *
     * @param string $fieldName
     * @param string $aadSource Field name to source AAD from
     * @return static
     */
    public function addBooleanField(string $fieldName, string $aadSource = ''): static
    {
        return $this->addField($fieldName, Constants::TYPE_BOOLEAN, $aadSource);
    }

    /**
     * Define a floating point number (decimal) field that will be encrypted.
     *
     * @param string $fieldName
     * @param string $aadSource Field name to source AAD from
     * @return static
     */
    public function addFloatField(string $fieldName, string $aadSource = ''): static
    {
        return $this->addField($fieldName, Constants::TYPE_FLOAT, $aadSource);
    }

    /**
     * Define an integer field that will be encrypted.
     *
     * @param string $fieldName
     * @param string $aadSource Field name to source AAD from
     * @return static
     */
    public function addIntegerField(string $fieldName, string $aadSource = ''): static
    {
        return $this->addField($fieldName, Constants::TYPE_INT, $aadSource);
    }

    /**
     * Define a JSON field that will be encrypted.
     *
     * @param string $fieldName
     * @param JsonFieldMap $fieldMap
     * @param string $aadSource Field name to source AAD from
     * @param bool $strict
     * @return static
     */
    public function addJsonField(
        string $fieldName,
        JsonFieldMap $fieldMap,
        string $aadSource = '',
        bool $strict = true
    ): static {
        $this->jsonMaps[$fieldName] = $fieldMap;
        $this->jsonStrict[$fieldName] = $strict;
        return $this->addField($fieldName, Constants::TYPE_JSON, $aadSource);
    }

    /**
     * Define a text field that will be encrypted.
     *
     * @param string $fieldName
     * @param string $aadSource Field name to source AAD from
     * @return static
     */
    public function addTextField(string $fieldName, string $aadSource = ''): static
    {
        return $this->addField($fieldName, Constants::TYPE_TEXT, $aadSource);
    }

    /**
     * Add a normal blind index to this EncryptedRow object.
     *
     * @param string $column
     * @param BlindIndex $index
     * @return static
     */
    public function addBlindIndex(string $column, BlindIndex $index): static
    {
        $this->blindIndexes[$column][$index->getName()] = $index;
        return $this;
    }

    /**
     * Add a compound blind index to this EncryptedRow object.
     *
     * @param CompoundIndex $index
     * @return static
     */
    public function addCompoundIndex(CompoundIndex $index): static
    {
        $this->compoundIndexes[$index->getName()] = $index;
        return $this;
    }

    /**
     * Create a compound blind index then add it to this EncryptedRow object.
     *
     * @param string $name
     * @param array<int, string> $columns
     * @param int $filterBits
     * @param bool $fastHash
     * @param array $hashConfig
     * @return CompoundIndex
     */
    public function createCompoundIndex(
        string $name,
        array $columns = [],
        int $filterBits = 256,
        bool $fastHash = false,
        array $hashConfig = []
    ): CompoundIndex {
        $index = new CompoundIndex(
            $name,
            $columns,
            $filterBits,
            $fastHash,
            $hashConfig
        );
        $this->addCompoundIndex($index);
        return $index;
    }

    /**
     * Calculate a blind index (or compound blind index) output for this row.
     *
     * @param string $indexName
     * @param array $row
     * @return array<string, string>|string
     *
     * @throws ArrayKeyException
     * @throws BlindIndexNotFoundException
     * @throws Exception\CryptoOperationException
     * @throws SodiumException
     */
    public function getBlindIndex(
        string $indexName,
        #[\SensitiveParameter]
        array $row
    ): string|array {
        foreach ($this->blindIndexes as $column => $blindIndexes) {
            if (isset($blindIndexes[$indexName])) {
                /** @var BlindIndex $blindIndex */
                $blindIndex = $blindIndexes[$indexName];
                return $this->calcBlindIndex(
                    $row,
                    $column,
                    $blindIndex
                );
            }
        }
        if (isset($this->compoundIndexes[$indexName])) {
            return $this->calcCompoundIndex($row, $this->compoundIndexes[$indexName]);
        }
        throw new BlindIndexNotFoundException();
    }

    /**
     * Get all of the blind indexes and compound indexes defined for this
     * object, calculated from the input array.
     *
     * @param array $row
     * @return array<string, array<string, string>|string>
     *
     * @throws ArrayKeyException
     * @throws Exception\CryptoOperationException
     * @throws SodiumException
     */
    public function getAllBlindIndexes(
        #[\SensitiveParameter]
        array $row
    ): array {
        /** @var array<string, array<string, string>|string> $return */
        $return = [];
        foreach ($this->blindIndexes as $column => $blindIndexes) {
            /** @var BlindIndex $blindIndex */
            foreach ($blindIndexes as $blindIndex) {
                $return[$blindIndex->getName()] = $this->calcBlindIndex(
                    $row,
                    $column,
                    $blindIndex
                );
            }
        }
        /**
         * @var string $name
         * @var CompoundIndex $compoundIndex
         */
        foreach ($this->compoundIndexes as $name => $compoundIndex) {
            $return[$name] = $this->calcCompoundIndex($row, $compoundIndex);
        }
        return $return;
    }

    /**
     * @param string $column
     * @return array<string, BlindIndex>
     */
    public function getBlindIndexObjectsForColumn(string $column): array
    {
        if (isset($this->blindIndexes[$column])) {
            return $this->blindIndexes[$column];
        }
        return [];
    }

    /**
     * Get the "type" of a specific blind index (by column and index name).
     *
     * @param string $column
     * @param string $name
     * @return string
     *
     * @throws SodiumException
     */
    public function getBlindIndexType(string $column, string $name): string
    {
        return $this->engine->getIndexTypeColumn(
            $this->tableName,
            $column,
            $name
        );
    }

    /**
     * Get the "type" of a specific compound index (by index name).
     *
     * @param string $name
     * @return string
     *
     * @throws SodiumException
     */
    public function getCompoundIndexType(string $name): string
    {
        return $this->engine->getIndexTypeColumn(
            $this->tableName,
            Constants::COMPOUND_SPECIAL,
            $name
        );
    }

    /**
     * @return array<string, CompoundIndex>
     */
    public function getCompoundIndexObjects(): array
    {
        return $this->compoundIndexes;
    }

    /**
     * @param string $name
     * @return JsonFieldMap
     *
     * @throws CipherSweetException
     */
    public function getJsonFieldMap(string $name): JsonFieldMap
    {
        if (!\array_key_exists($name, $this->fieldsToEncrypt)) {
            throw new CipherSweetException("Field does not exist: {$name}");
        }
        if ($this->fieldsToEncrypt[$name] !== Constants::TYPE_JSON) {
            throw new CipherSweetException("Field {$name} is not a JSON field");
        }
        if (!\array_key_exists($name, $this->jsonMaps)) {
            throw new CipherSweetException("JSON Map not found for field {$name}");
        }
        return $this->jsonMaps[$name];
    }

    /**
     * Decrypt any of the appropriate fields in the given array.
     *
     * If any columns are defined in this object to be decrypted, the value
     * will be decrypted in-place in the returned array.
     *
     * @param array<string, string> $row
     * @return array<string, string|int|float|bool|null|scalar[]>
     *
     * @throws CipherSweetException
     * @throws CryptoOperationException
     * @throws InvalidCiphertextException
     * @throws SodiumException
     *
     * @psalm-suppress InvalidReturnStatement
     */
    public function decryptRow(
        #[\SensitiveParameter]
        array $row
    ): array {
        /** @var array<string, string|int|float|bool|null|scalar[]> $return */
        $return = $row;
        $backend = $this->engine->getBackend();
        if ($this->engine->isMultiTenantSupported()) {
            $tenant = $this->engine->getTenantFromRow($row, $this->tableName);
            $this->engine->setActiveTenant($tenant);
        }
        foreach ($this->fieldsToEncrypt as $field => $type) {
            $key = $this->engine->getFieldSymmetricKey(
                $this->tableName,
                $field
            );
            if (!array_key_exists($field, $row)) {
                if (!$this->permitEmpty) {
                    throw new EmptyFieldException('Field is not defined in row: ' . $field);
                }
                continue;
            }
            if (\is_null($row[$field])) {
                $return[$field] = null;
                continue;
            }
            if (
                !empty($this->aadSourceField[$field])
                &&
                \array_key_exists($this->aadSourceField[$field], $row)
            ) {
                $aad = (string) $row[$this->aadSourceField[$field]];
            } else {
                $aad = '';
            }

            if ($type === Constants::TYPE_JSON && !empty($this->jsonMaps[$field])) {
                // JSON is a special case
                $jsonEncryptor = new EncryptedJsonField(
                    $backend,
                    $key,
                    $this->jsonMaps[$field],
                    $this->jsonStrict[$field]
                );
                $return[$field] = $jsonEncryptor->decryptJson($row[$field], $aad);
                continue;
            }
            $plaintext = $backend->decrypt($row[$field], $key, $aad);
            $return[$field] = $this->convertFromString($plaintext, $type);
        }
        return $return;
    }

    /**
     * Encrypt any of the appropriate fields in the given array.
     *
     * If any columns are defined in this object to be encrypted, the value
     * will be encrypted in-place in the returned array.
     *
     * @param array<string, string|int|float|bool|null> $row
     * @param bool|false $decode_json
     * @return array<string, string>
     *
     * @throws ArrayKeyException
     * @throws CryptoOperationException
     * @throws CipherSweetException
     * @throws SodiumException
     */
    public function encryptRow(
        #[\SensitiveParameter]
        array $row,
        bool $decode_json = false,
    ): array {
        /** @var array<string, string|int|float|bool|null|scalar[]> $return */
        $return = $row;
        $backend = $this->engine->getBackend();
        foreach ($this->fieldsToEncrypt as $field => $type) {
            if (!\array_key_exists($field, $row)) {
                throw new ArrayKeyException(
                    'Expected value for column ' .
                    $field .
                    ' on array, nothing given.'
                );
            }
            $key = $this->engine->getFieldSymmetricKey(
                $this->tableName,
                $field
            );
            if (
                !empty($this->aadSourceField[$field])
                &&
                \array_key_exists($this->aadSourceField[$field], $row)
            ) {
                $aad = (string) $row[$this->aadSourceField[$field]];
            } else {
                $aad = '';
            }
            if ($type === Constants::TYPE_JSON && !empty($this->jsonMaps[$field])) {
                // checks decode json option
                if ($decode_json) {
                    $row[$field] = $this->formatJson($row[$field]);
                }
                // JSON is a special case
                $jsonEncryptor = new EncryptedJsonField(
                    $backend,
                    $key,
                    $this->jsonMaps[$field],
                    $this->jsonStrict[$field]
                );
                /** @psalm-suppress InvalidArgument */
                $return[$field] = $jsonEncryptor->encryptJson($row[$field], $aad);
                continue;
            }
            $plaintext = $this->convertToString($row[$field], $type);
            $return[$field] = $backend->encrypt($plaintext, $key, $aad);
        }
        /** @var array<string, string> $return */
        if ($this->engine->isMultiTenantSupported()) {
            return $this->engine->injectTenantMetadata($return, $this->tableName);
        }
        return $return;
    }

    /**
     * Decoding json field
     *
     * @param string|null $field
     * @return array<object,empty>
     */
    public function formatJson(
        $field
    ): array {
        //decode json field then to take key from it to encrypt it
        $field = isset($field) ? (array)json_decode($field) : [];
        return $field;
    }

    /**
     * Process an entire row, which means:
     *
     * 1. If any columns are defined in this object to be encrypted, the value
     *    will be encrypted in-place in the first array.
     * 2. Blind indexes and compound indexes are calculated and stored in the
     *    second array.
     *
     * Calling encryptRow() and getAllBlindIndexes() is equivalent.
     *
     * @param array<string, int|float|string|bool|null> $row
     * @return array{0: array<string, string>, 1: array<string, array<string, string>|string>}
     *
     * @throws ArrayKeyException
     * @throws CipherSweetException
     * @throws CryptoOperationException
     * @throws SodiumException
     */
    public function prepareRowForStorage(
        #[\SensitiveParameter]
        array $row
    ): array {
        return [
            $this->encryptRow($row),
            $this->getAllBlindIndexes($row)
        ];
    }

    /**
     * Return a list of the fields in this row that will be encrypted.
     *
     * @return array<int, string>
     */
    public function listEncryptedFields(): array
    {
        return \array_keys($this->fieldsToEncrypt);
    }

    /**
     * Specify the Additional Authenticated Data source column for an encrypted
     * column.
     *
     * @param string $fieldName
     * @param string $aadSource
     * @return static
     */
    public function setAadSourceField(string $fieldName, string $aadSource): static
    {
        $this->aadSourceField[$fieldName] = $aadSource;
        return $this;
    }

    /**
     * Calculates the actual blind index on a given row.
     *
     * @param array $row
     * @param string $column
     * @param BlindIndex $index
     * @return array<string, string>|string
     *
     * @throws ArrayKeyException
     * @throws SodiumException
     */
    protected function calcBlindIndex(
        #[\SensitiveParameter]
        array $row,
        string $column,
        BlindIndex $index
    ): string|array {
        $name = $index->getName();
        $key = $this->engine->getBlindIndexRootKey(
            $this->tableName,
            $column
        );
        if ($this->typedIndexes) {
            $k = $this->engine->getIndexTypeColumn(
                $this->tableName,
                $column,
                $name
            );
            return [
                'type' => $k,
                'value' =>
                    Hex::encode(
                        $this->calcBlindIndexRaw(
                            $row,
                            $column,
                            $index,
                            $key
                        )
                    )
            ];
        }
        return Hex::encode(
            $this->calcBlindIndexRaw(
                $row,
                $column,
                $index,
                $key
            )
        );
    }

    /**
     * Call this to calculate a compound blind index on a given row.
     *
     * @param array $row
     * @param CompoundIndex $index
     * @return array<string, string>|string
     *
     * @throws CryptoOperationException
     * @throws SodiumException
     */
    protected function calcCompoundIndex(
        #[\SensitiveParameter]
        array $row,
        CompoundIndex $index
    ): string|array {
        $name = $index->getName();
        $key = $this->engine->getBlindIndexRootKey(
            $this->tableName,
            Constants::COMPOUND_SPECIAL
        );
        if ($this->typedIndexes) {
            $k = $this->engine->getIndexTypeColumn(
                $this->tableName,
                Constants::COMPOUND_SPECIAL,
                $name
            );
            return [
                'type' => $k,
                'value' =>
                    Hex::encode(
                        $this->calcCompoundIndexRaw(
                            $row,
                            $index,
                            $key
                        )
                    )
            ];
        }
        return Hex::encode(
            $this->calcCompoundIndexRaw(
                $row,
                $index,
                $key
            )
        );
    }

    /**
     * Calculates a blind index.
     *
     * @param array $row
     * @param string $column
     * @param BlindIndex $index
     * @param SymmetricKey|null $key
     *
     * @return string
     * @throws ArrayKeyException
     * @throws SodiumException
     */
    protected function calcBlindIndexRaw(
        #[\SensitiveParameter]
        array $row,
        string $column,
        BlindIndex $index,
        SymmetricKey $key = null
    ): string {
        if (!$key) {
            $key = $this->engine->getBlindIndexRootKey(
                $this->tableName,
                $column
            );
        }

        $backend = $this->engine->getBackend();
        $name = $index->getName();
        $subKey = new SymmetricKey(
            \hash_hmac(
                'sha256',
                Util::pack([$this->tableName, $column, $name]),
                $key->getRawKey(),
                true
            )
        );
        if (!\array_key_exists($column, $this->fieldsToEncrypt)) {
            throw new ArrayKeyException(
                'The field ' . $column . ' is not defined in this encrypted row.'
            );
        }
        /** @var string $fieldType */
        $fieldType = $this->fieldsToEncrypt[$column];

        /** @var string|bool|int|float|null $unconverted */
        $unconverted = $row[$column];

        $plaintext = $index->getTransformed(
            $this->convertToString($unconverted, $fieldType)
        );

        if ($index->getFastHash()) {
            return $backend->blindIndexFast(
                $plaintext,
                $subKey,
                $index->getFilterBitLength()
            );
        }
        return $backend->blindIndexSlow(
            $plaintext,
            $subKey,
            $index->getFilterBitLength(),
            $index->getHashConfig()
        );
    }

    /**
     * Calculates a compound blind index.
     *
     * @param array $row
     * @param CompoundIndex $index
     * @param SymmetricKey|null $key
     * @return string
     * @internal
     *
     * @throws \Exception
     * @throws Exception\CryptoOperationException
     */
    protected function calcCompoundIndexRaw(
        #[\SensitiveParameter]
        array $row,
        CompoundIndex $index,
        SymmetricKey $key = null
    ): string {
        if (!$key) {
            $key = $this->engine->getBlindIndexRootKey(
                $this->tableName,
                Constants::COMPOUND_SPECIAL
            );
        }

        $backend = $this->engine->getBackend();
        $name = $index->getName();
        $subKey = new SymmetricKey(
            \hash_hmac(
                'sha256',
                Util::pack([$this->tableName, Constants::COMPOUND_SPECIAL, $name]),
                $key->getRawKey(),
                true
            )
        );

        $plaintext = $index->getPacked($row);
        if ($index->getFastHash()) {
            return $backend->blindIndexFast(
                $plaintext,
                $subKey,
                $index->getFilterBitLength()
            );
        }
        return $backend->blindIndexSlow(
            $plaintext,
            $subKey,
            $index->getFilterBitLength(),
            $index->getHashConfig()
        );
    }

    /**
     * @return BackendInterface
     */
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

    /**
     * @return bool
     */
    public function getFlatIndexes(): bool
    {
        return !$this->typedIndexes;
    }

    /**
     * @param bool $bool
     * @return static
     */
    public function setFlatIndexes(bool $bool): static
    {
        $this->typedIndexes = !$bool;
        return $this;
    }

    /**
     * @return bool
     */
    public function getPermitEmpty(): bool
    {
        return $this->permitEmpty;
    }

    /**
     * @param bool $permitted
     * @return $this
     */
    public function setPermitEmpty(bool $permitted): static
    {
        $this->permitEmpty = $permitted;
        return $this;
    }

    /**
     * @return bool
     */
    public function getTypedIndexes(): bool
    {
        return $this->typedIndexes;
    }

    /**
     * @param bool $bool
     * @return static
     */
    public function setTypedIndexes(bool $bool): static
    {
        $this->typedIndexes = $bool;
        return $this;
    }
}

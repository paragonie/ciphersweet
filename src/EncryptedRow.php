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
    InvalidAADException,
    InvalidCiphertextException
};
use ParagonIE\ConstantTime\Hex;
use SodiumException;
use TypeError;
use function
    array_key_exists,
    in_array,
    is_null,
    is_scalar;

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
     * @var array<string, AAD> $aadSourceField
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
     * @var ?string $primaryKeyColumnName
     */
    protected ?string $primaryKeyColumnName;

    /**
     * EncryptedFieldSet constructor.
     *
     * @param CipherSweet $engine
     * @param string $tableName
     * @param bool $useTypedIndexes
     * @param ?string $primaryKeyColumnName
     */
    public function __construct(
        CipherSweet $engine,
        #[\SensitiveParameter]
        string $tableName,
        bool $useTypedIndexes = false,
        ?string $primaryKeyColumnName = null
    ) {
        $this->engine = $engine;
        $this->tableName = $tableName;
        $this->typedIndexes = $useTypedIndexes;
        $this->primaryKeyColumnName = $primaryKeyColumnName;
    }

    /**
     * Define a field that will be encrypted.
     *
     * @param string $fieldName
     * @param string $type
     * @param string|AAD $aadSource Field name to source AAD from
     * @return static
     */
    public function addField(
        string $fieldName,
        string $type = Constants::TYPE_TEXT,
        string|AAD $aadSource = '',
        bool $autoBindContext = false
    ): static {
        $this->fieldsToEncrypt[$fieldName] = $type;
        // If we set a primary key column name, we bind it to that field's value:
        if ($autoBindContext) {
            if (!is_null($this->primaryKeyColumnName)) {
                $aadSource = AAD::field($aadSource)
                    ->merge(AAD::field($this->primaryKeyColumnName));
            }
            $this->aadSourceField[$fieldName] = AAD::field($aadSource);
        } elseif ($aadSource) {
            $this->aadSourceField[$fieldName] = AAD::field($aadSource);
        }
        return $this;
    }

    /**
     * Define a boolean field that will be encrypted. Nullable.
     *
     * @param string $fieldName
     * @param string|AAD $aadSource Field name to source AAD from
     * @return static
     */
    public function addBooleanField(string $fieldName, string|AAD $aadSource = ''): static
    {
        return $this->addField($fieldName, Constants::TYPE_BOOLEAN, $aadSource);
    }

    /**
     * Define a floating point number (decimal) field that will be encrypted.
     *
     * @param string $fieldName
     * @param string|AAD $aadSource Field name to source AAD from
     * @return static
     */
    public function addFloatField(string $fieldName, string|AAD $aadSource = ''): static
    {
        return $this->addField($fieldName, Constants::TYPE_FLOAT, $aadSource);
    }

    /**
     * Define an integer field that will be encrypted.
     *
     * @param string $fieldName
     * @param string|AAD $aadSource Field name to source AAD from
     * @return static
     */
    public function addIntegerField(string $fieldName, string|AAD $aadSource = ''): static
    {
        return $this->addField($fieldName, Constants::TYPE_INT, $aadSource);
    }

    /**
     * Define a boolean field that will be encrypted. Permits NULL.
     *
     * @param string $fieldName
     * @param string|AAD $aadSource Field name to source AAD from
     * @return static
     */
    public function addOptionalBooleanField(string $fieldName, string|AAD $aadSource = ''): static
    {
        return $this->addField($fieldName, Constants::TYPE_OPTIONAL_BOOLEAN, $aadSource);
    }

    /**
     * Define a floating point number (decimal) field that will be encrypted. Permits NULL.
     *
     * @param string $fieldName
     * @param string|AAD $aadSource Field name to source AAD from
     * @return static
     */
    public function addOptionalFloatField(string $fieldName, string|AAD $aadSource = ''): static
    {
        return $this->addField($fieldName, Constants::TYPE_OPTIONAL_FLOAT, $aadSource);
    }

    /**
     * Define an integer field that will be encrypted. Permits NULL.
     *
     * @param string $fieldName
     * @param string|AAD $aadSource Field name to source AAD from
     * @return static
     */
    public function addOptionalIntegerField(string $fieldName, string|AAD $aadSource = ''): static
    {
        return $this->addField($fieldName, Constants::TYPE_OPTIONAL_INT, $aadSource);
    }

    /**
     * Define an integer field that will be encrypted. Permits NULL.
     *
     * @param string $fieldName
     * @param string|AAD $aadSource Field name to source AAD from
     * @return static
     */
    public function addOptionalTextField(string $fieldName, string|AAD $aadSource = ''): static
    {
        return $this->addField($fieldName, Constants::TYPE_OPTIONAL_TEXT, $aadSource);
    }

    /**
     * Define a JSON field that will be encrypted. Permits NULL.
     *
     * @param string $fieldName
     * @param JsonFieldMap $fieldMap
     * @param string|AAD $aadSource Field name to source AAD from
     * @param bool $strict
     * @return static
     */
    public function addNullableJsonField(
        string $fieldName,
        JsonFieldMap $fieldMap,
        string|AAD $aadSource = '',
        bool $strict = true
    ): static {
        $this->jsonMaps[$fieldName] = $fieldMap;
        $this->jsonStrict[$fieldName] = $strict;
        return $this->addField($fieldName, Constants::TYPE_OPTIONAL_JSON, $aadSource);
    }

    /**
     * Define a JSON field that will be encrypted.
     *
     * @param string $fieldName
     * @param JsonFieldMap $fieldMap
     * @param string|AAD $aadSource Field name to source AAD from
     * @param bool $strict
     * @return static
     */
    public function addJsonField(
        string $fieldName,
        JsonFieldMap $fieldMap,
        string|AAD $aadSource = '',
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
     * @param string|AAD $aadSource Field name to source AAD from
     * @return static
     */
    public function addTextField(string $fieldName, string|AAD $aadSource = ''): static
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
     * Create a fast compound blind index then add it to this EncryptedRow object.
     *
     * @param string $name
     * @param array<int, string> $columns
     * @param int $filterBits
     * @param array $hashConfig
     * @return CompoundIndex
     *
     * @throws CipherSweetException
     */
    public function createFastCompoundIndex(
        string $name,
        array $columns = [],
        int $filterBits = 256,
        array $hashConfig = []
    ): CompoundIndex {
        $index = new FastCompoundIndex(
            $name,
            $columns,
            $filterBits,
            true,
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
        $this->throwIfPrimaryKeyMisconfigured($row);
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
            // Support for nullable types
            if (in_array($type, Constants::TYPES_OPTIONAL, true)) {
                if (is_null($row[$field])) {
                    $return[$field] = null;
                    continue;
                }
            }
            // Encrypted booleans will be scalar values as ciphertext
            if (!is_scalar($row[$field])) {
                if (is_null($row[$field])) {
                    $this->fieldNotOptional($field, $type);
                }
                throw new TypeError('Invalid type for ' . $field);
            }
            $aad = $this->canonicalizeAADForField($field, $row);
            if (in_array($type, Constants::TYPES_JSON, true) && !empty($this->jsonMaps[$field])) {
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
     * @param array<string, scalar|scalar[]|null> $row
     * @return array<string, string>
     *
     * @throws ArrayKeyException
     * @throws CryptoOperationException
     * @throws CipherSweetException
     * @throws SodiumException
     */
    public function encryptRow(
        #[\SensitiveParameter]
        array $row
    ): array {
        $this->throwIfPrimaryKeyMisconfigured($row);
        /** @var array<string, string|int|float|bool|null|scalar[]> $return */
        $return = $row;
        $backend = $this->engine->getBackend();
        foreach ($this->fieldsToEncrypt as $field => $type) {
            if (!array_key_exists($field, $row)) {
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
            $aad = $this->canonicalizeAADForField($field, $row);
            if (in_array($type, Constants::TYPES_JSON, true) && !empty($this->jsonMaps[$field])) {
                // JSON is a special case
                $jsonEncryptor = new EncryptedJsonField(
                    $backend,
                    $key,
                    $this->jsonMaps[$field],
                    $this->jsonStrict[$field]
                );
                $return[$field] = $jsonEncryptor->encryptJson($this->coaxToArray($row[$field]), $aad);
                continue;
            }

            // Support nullable types
            if (in_array($type, Constants::TYPES_OPTIONAL, true)) {
                if (is_null($row[$field])) {
                    continue;
                }
            }

            // Boolean always supported NULL as a value to encrypt
            if (in_array($type, Constants::TYPES_BOOLEAN, true) && is_null($row[$field])) {
                $plaintext = $this->convertToString($row[$field], Constants::TYPE_BOOLEAN);
                $return[$field] = $backend->encrypt($plaintext, $key, $aad);
                continue;
            }

            // All others must be scalar
            if (!is_scalar($row[$field])) {
                // NULL is not permitted.
                if (is_null($row[$field])) {
                    $this->fieldNotOptional($field, $type);
                }
                throw new TypeError('Invalid type for ' . $field);
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
     * @param string|AAD $aadSource
     * @return static
     */
    public function setAadSourceField(string $fieldName, string|AAD $aadSource): static
    {
        $this->aadSourceField[$fieldName] = AAD::field($aadSource);
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
     * Get the AAD source for a given field.
     *
     * Returns an AAD object or the column name.
     *
     * @param string $fieldName
     * @return AAD|string
     *
     * @throws CipherSweetException
     */
    public function getAADSource(string $fieldName): AAD|string
    {
        if (!array_key_exists($fieldName, $this->aadSourceField)) {
            throw new CipherSweetException('Source field not found for field: ' . $fieldName);
        }
        return $this->aadSourceField[$fieldName];
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
     * @param ?string $columnName
     * @return self
     */
    public function setPrimaryKeyColumnName(?string $columnName = null): self
    {
        $this->primaryKeyColumnName = $columnName;
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

    /**
     * @param mixed $input
     * @return array
     */
    protected function coaxToArray(mixed $input): array
    {
        if (is_array($input)) {
            return $input;
        }
        if (is_null($input)) {
            return [];
        }
        if (is_object($input)) {
            /** psalm-suppress PossiblyInvalidCast */
            return (array) $input;
        }
        if (is_string($input)) {
            return json_decode($input, true);
        }
        throw new TypeError("Cannot coax to array: " . gettype($input));
    }

    /**
     * New exception message to make it clear this is a deliberate behavior, not a bug.
     *
     * Instead of, like, Constants::TYPE_TEXT, if you want to accept null parameters, you need to
     * use something like Constants::TYPE_OPTIONAL_TEXT.
     *
     * If you don't tell CipherSweet that NULL is an acceptable return type, it doesn't tolerate
     * NULL. To do this, you must change the declaration.
     *
     * This switch block tries to point the user of this library towards the correct constant to use
     * for this field, in order to populate the correct error message.
     */
    protected function fieldNotOptional(string $field, string $type): void
    {
        switch ($type) {
            case Constants::TYPE_JSON:
                $oldConst = 'Constants::TYPE_JSON';
                $newConst = 'Constants::TYPE_OPTIONAL_JSON';
                break;
            case Constants::TYPE_BOOLEAN:
                $oldConst = 'Constants::TYPE_BOOLEAN';
                $newConst = 'Constants::TYPE_OPTIONAL_BOOLEAN';
                break;
            case Constants::TYPE_TEXT:
                $oldConst = 'Constants::TYPE_TEXT';
                $newConst = 'Constants::TYPE_OPTIONAL_TEXT';
                break;
            case Constants::TYPE_FLOAT:
                $oldConst = 'Constants::TYPE_FLOAT';
                $newConst = 'Constants::TYPE_OPTIONAL_FLOAT';
                break;
            case Constants::TYPE_INT:
                $oldConst = 'Constants::TYPE_INT';
                $newConst = 'Constants::TYPE_OPTIONAL_INT';
                break;
            default:
                $oldConst = $type;
                $newConst = '?' . $type;
        }
        throw new TypeError(
            'Received a NULL value for ' . $field . ', which has a non-optional type. ' .
            'To fix this, try changing the type declaration from ' . $oldConst . ' to ' . $newConst . '.'
        );
    }

    /**
     * Canonicalize the AAD as a string OR return an empty string.
     *
     * @param string $field
     * @param array $row
     * @return string
     * @throws InvalidAADException
     */
    protected function canonicalizeAADForField(string $field, array $row): string
    {
        if (empty($this->aadSourceField[$field])) {
            return '';
        }
        if (is_string($this->aadSourceField[$field])) {
            return $this->aadSourceField[$field];;
        }
        if (array_intersect(
            array_keys($this->fieldsToEncrypt),
            $this->aadSourceField[$field]->getFieldNames()
        )) {
            throw new InvalidAADException('Cannot use encrypted field as AAD - field: ' . $field);
        }
        return $this->aadSourceField[$field]->canonicalize($row);
    }

    /**
     * This method throws an exception if the object is misconfigured in a way that would
     * allow accidental loss of data.
     *
     * i.e. You cannot encrypt the primary key and still bind other fields to it
     * Additionally, you cannot bind other fields to it, if you didn't set it.
     *
     * @throws CipherSweetException
     */
    protected function throwIfPrimaryKeyMisconfigured(
        #[\SensitiveParameter]
        array $row
    ): void {
        if (is_null($this->primaryKeyColumnName)) {
            // Nothing to do here!
            return;
        }
        if (!array_key_exists($this->primaryKeyColumnName, $row)) {
            throw new CipherSweetException(
                'EncryptedRow is configured with a primary key name, so it must be pre-populated on inserts'
            );
        }
        if (in_array($this->primaryKeyColumnName, $this->fieldsToEncrypt, true)) {
            throw new CipherSweetException(
                'Primary key must bot be encrypted'
            );
        }
    }
}

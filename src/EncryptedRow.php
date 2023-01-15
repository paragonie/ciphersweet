<?php
namespace ParagonIE\CipherSweet;

use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\Contract\BackendInterface;
use ParagonIE\CipherSweet\Exception\ArrayKeyException;
use ParagonIE\CipherSweet\Exception\BlindIndexNotFoundException;
use ParagonIE\CipherSweet\Exception\CipherSweetException;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;
use ParagonIE\CipherSweet\Exception\EmptyFieldException;
use ParagonIE\CipherSweet\Exception\InvalidCiphertextException;
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
    protected $engine;

    /**
     * @var array<string, string> $fieldsToEncrypt
     */
    protected $fieldsToEncrypt = [];

    /**
     * @var array<string, JsonFieldMap> $jsonMaps
     */
    protected $jsonMaps = [];

    /**
     * @var array<string, bool> $jsonStrict
     */
    protected $jsonStrict = [];

    /**
     * @var array<string, string> $aadSourceField
     */
    protected $aadSourceField = [];

    /**
     * @var array<string, array<string, BlindIndex>> $blindIndexes
     */
    protected $blindIndexes = [];

    /**
     * @var bool $permitEmpty
     */
    protected $permitEmpty = false;

    /**
     * @var bool $typedIndexes
     */
    protected $typedIndexes = false;

    /**
     * @var array<string, CompoundIndex> $compoundIndexes
     */
    protected $compoundIndexes = [];

    /**
     * @var string $tableName
     */
    protected $tableName;

    /**
     * EncryptedFieldSet constructor.
     *
     * @param CipherSweet $engine
     * @param string $tableName
     * @param bool $useTypedIndexes
     */
    public function __construct(CipherSweet $engine, $tableName, $useTypedIndexes = false)
    {
        $this->engine = $engine;
        $this->tableName = $tableName;
        $this->typedIndexes = !$useTypedIndexes;
    }

    /**
     * Define a field that will be encrypted.
     *
     * @param string $fieldName
     * @param string $type
     * @param string $aadSource Field name to source AAD from
     * @return self
     */
    public function addField($fieldName, $type = Constants::TYPE_TEXT, $aadSource = '')
    {
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
     * @return self
     */
    public function addBooleanField($fieldName, $aadSource = '')
    {
        return $this->addField($fieldName, Constants::TYPE_BOOLEAN, $aadSource);
    }

    /**
     * Define a floating point number (decimal) field that will be encrypted.
     *
     * @param string $fieldName
     * @param string $aadSource Field name to source AAD from
     * @return self
     */
    public function addFloatField($fieldName, $aadSource = '')
    {
        return $this->addField($fieldName, Constants::TYPE_FLOAT, $aadSource);
    }

    /**
     * Define an integer field that will be encrypted.
     *
     * @param string $fieldName
     * @param string $aadSource Field name to source AAD from
     * @return self
     */
    public function addIntegerField($fieldName, $aadSource = '')
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
     * @return self
     */
    public function addJsonField($fieldName, JsonFieldMap $fieldMap, $aadSource = '', $strict = true)
    {
        $this->jsonMaps[$fieldName] = $fieldMap;
        $this->jsonStrict[$fieldName] = $strict;
        return $this->addField($fieldName, Constants::TYPE_JSON, $aadSource);
    }

    /**
     * Define a text field that will be encrypted.
     *
     * @param string $fieldName
     * @param string $aadSource Field name to source AAD from
     * @return self
     */
    public function addTextField($fieldName, $aadSource = '')
    {
        return $this->addField($fieldName, Constants::TYPE_TEXT, $aadSource);
    }

    /**
     * Add a normal blind index to this EncryptedRow object.
     *
     * @param string $column
     * @param BlindIndex $index
     * @return self
     */
    public function addBlindIndex($column, BlindIndex $index)
    {
        $this->blindIndexes[$column][$index->getName()] = $index;
        return $this;
    }

    /**
     * Add a compound blind index to this EncryptedRow object.
     *
     * @param CompoundIndex $index
     * @return self
     */
    public function addCompoundIndex(CompoundIndex $index)
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
        $name,
        array $columns = [],
        $filterBits = 256,
        $fastHash = false,
        array $hashConfig = []
    ) {
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
    public function getBlindIndex($indexName, array $row)
    {
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
    public function getAllBlindIndexes(array $row)
    {
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
    public function getBlindIndexObjectsForColumn($column)
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
     * @throws SodiumException
     */
    public function getBlindIndexType($column, $name)
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
     * @throws SodiumException
     */
    public function getCompoundIndexType($name)
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
    public function getCompoundIndexObjects()
    {
        return $this->compoundIndexes;
    }

    /**
     * @param string $name
     * @return JsonFieldMap
     *
     * @throws CipherSweetException
     */
    public function getJsonFieldMap($name)
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
    public function decryptRow(array $row)
    {
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
                    throw new EmptyFieldException('Field not defined in row: ' . $field);
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
     *
     * @return array<string, string>
     * @throws ArrayKeyException
     * @throws CryptoOperationException
     * @throws CipherSweetException
     * @throws SodiumException
     */
    public function encryptRow(array $row)
    {
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
    public function prepareRowForStorage(array $row)
    {
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
    public function listEncryptedFields()
    {
        return \array_keys($this->fieldsToEncrypt);
    }

    /**
     * Specify the Additional Authenticated Data source column for an encrypted
     * column.
     *
     * @param string $fieldName
     * @param string $aadSource
     * @return self
     */
    public function setAadSourceField($fieldName, $aadSource)
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
     * @throws Exception\CryptoOperationException
     * @throws SodiumException
     */
    protected function calcBlindIndex(array $row, $column, BlindIndex $index)
    {
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
     *
     * @return array<string, string>|string
     * @throws CryptoOperationException
     * @throws SodiumException
     */
    protected function calcCompoundIndex(array $row, CompoundIndex $index)
    {
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
     * @throws Exception\CryptoOperationException
     * @throws ArrayKeyException
     * @throws SodiumException
     */
    protected function calcBlindIndexRaw(
        array $row,
        $column,
        BlindIndex $index,
        SymmetricKey $key = null
    ) {
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
        array $row,
        CompoundIndex $index,
        SymmetricKey $key = null
    ) {
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

        /** @var string $plaintext */
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
    public function getBackend()
    {
        return $this->engine->getBackend();
    }

    /**
     * @return CipherSweet
     */
    public function getEngine()
    {
        return $this->engine;
    }

    /**
     * @return bool
     */
    public function getFlatIndexes()
    {
        return !$this->typedIndexes;
    }

    /**
     * @param bool $bool
     * @return self
     */
    public function setFlatIndexes($bool)
    {
        $this->typedIndexes = !$bool;
        return $this;
    }

    /**
     * @return bool
     */
    public function getPermitEmpty()
    {
        return $this->permitEmpty;
    }

    /**
     * @param $permitted
     * @return static
     */
    public function setPermitEmpty($permitted)
    {
        $this->permitEmpty = !empty($permitted);
        return $this;
    }

    /**
     * @return bool
     */
    public function getTypedIndexes()
    {
        return $this->typedIndexes;
    }

    /**
     * @param bool $bool
     * @return self
     */
    public function setTypedIndexes($bool)
    {
        $this->typedIndexes = $bool;
        return $this;
    }
}

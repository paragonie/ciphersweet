<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet;

use ParagonIE\CipherSweet\Contract\BackendInterface;
use ParagonIE\CipherSweet\Exception\{
    ArrayKeyException,
    BlindIndexNotFoundException,
    CipherSweetException,
    CryptoOperationException
};
use SodiumException;

/**
 * Class EncryptedMultiRows
 * @package ParagonIE\CipherSweet
 */
class EncryptedMultiRows
{
    /**
     * @var CipherSweet $engine
     */
    protected CipherSweet $engine;

    /**
     * @var bool $typedIndexes
     */
    protected bool $typedIndexes;

    /**
     * @var array<string, EncryptedRow> $tables
     */
    protected array $tables = [];

    /**
     * @var bool|null $permitEmpty
     */
    protected ?bool $permitEmpty = null;

    /**
     * @var bool $autoBindContext
     */
    protected bool $autoBindContext = false;

    /**
     * EncryptedFieldSet constructor.
     *
     * @param CipherSweet $engine
     * @param bool $useTypedIndexes
     */
    public function __construct(
        CipherSweet $engine,
        bool $useTypedIndexes = false,
        bool $autoBindContext = false
    ) {
        $this->engine = $engine;
        $this->typedIndexes = $useTypedIndexes;
        $this->autoBindContext = $autoBindContext;
    }

    /**
     * Add a table to the list of tables we process.
     *
     * @throws CipherSweetException
     */
    public function addTable(string $tableName): static
    {
        if (\array_key_exists($tableName, $this->tables)) {
            throw new CipherSweetException('Table already exists');
        }
        $this->tables[$tableName] = new EncryptedRow($this->engine, $tableName);
        return $this;
    }

    /**
     * Mark a field to be encrypted.
     *
     * @throws CipherSweetException
     */
    public function addField(
        string $tableName,
        string $fieldName,
        string $type = Constants::TYPE_TEXT,
        string|AAD $aadSource = ''
    ): static {
        if ($this->autoBindContext) {
            // We automatically bind every field to the table and column name
            if (empty($aadSource)) {
                $aadSource = new AAD();
            }
            $aadSource = AAD::field($aadSource)
                ->merge(AAD::literal('table=' . $tableName . ';field=' . $fieldName));
        }
        $this->getEncryptedRowObjectForTable($tableName)
            ->addField($fieldName, $type, $aadSource, $this->autoBindContext);
        return $this;
    }

    /**
     * Mark a column to be encrypted as boolean input.
     *
     * @throws CipherSweetException
     */
    public function addBooleanField(
        string $tableName,
        string $fieldName,
        string|AAD $aadSource = ''
    ): static {
        return $this->addField(
            $tableName,
            $fieldName,
            Constants::TYPE_BOOLEAN,
            $aadSource
        );
    }

    /**
     * Mark a column to be encrypted as floating point input.
     *
     * @throws CipherSweetException
     */
    public function addFloatField(
        string $tableName,
        string $fieldName,
        string|AAD $aadSource = ''
    ): static {
        return $this->addField(
            $tableName,
            $fieldName,
            Constants::TYPE_FLOAT,
            $aadSource
        );
    }

    /**
     * Mark a column to be encrypted as integer input.
     *
     * @throws CipherSweetException
     */
    public function addIntegerField(
        string $tableName,
        string $fieldName,
        string|AAD $aadSource = ''
    ): static {
        return $this->addField(
            $tableName,
            $fieldName,
            Constants::TYPE_INT,
            $aadSource
        );
    }

    /**
     * Mark a column to be encryption as a JSON blob.
     *
     * @throws CipherSweetException
     */
    public function addJsonField(
        string $tableName,
        string $fieldName,
        JsonFieldMap $fieldMap,
        string|AAD $aadSource = '',
        bool $strict = true
    ): static {
        $this->getEncryptedRowObjectForTable($tableName)
            ->addJsonField($fieldName, $fieldMap, $aadSource, $strict);
        return $this;
    }

    /**
     * Mark a column to be encrypted as text input.
     *
     * @throws CipherSweetException
     */
    public function addTextField(
        string $tableName,
        string $fieldName,
        string|AAD $aadSource = ''
    ): static {
        return $this->addField(
            $tableName,
            $fieldName,
            Constants::TYPE_TEXT,
            $aadSource
        );
    }


    /**
     * Mark a column to be encrypted as boolean input. Permits NULL.
     *
     * @throws CipherSweetException
     */
    public function addOptionalBooleanField(
        string $tableName,
        string $fieldName,
        string|AAD $aadSource = ''
    ): static {
        return $this->addField(
            $tableName,
            $fieldName,
            Constants::TYPE_OPTIONAL_BOOLEAN,
            $aadSource
        );
    }

    /**
     * Mark a column to be encrypted as floating point input. Permits NULL.
     *
     * @throws CipherSweetException
     */
    public function addOptionalFloatField(
        string $tableName,
        string $fieldName,
        string|AAD $aadSource = ''
    ): static {
        return $this->addField(
            $tableName,
            $fieldName,
            Constants::TYPE_OPTIONAL_FLOAT,
            $aadSource
        );
    }

    /**
     * Mark a column to be encrypted as integer input. Permits NULL.
     *
     * @throws CipherSweetException
     */
    public function addOptionalIntegerField(
        string $tableName,
        string $fieldName,
        string|AAD $aadSource = ''
    ): static {
        return $this->addField(
            $tableName,
            $fieldName,
            Constants::TYPE_OPTIONAL_INT,
            $aadSource
        );
    }

    /**
     * Mark a column to be encryption as a JSON blob. Permits NULL.
     *
     * @throws CipherSweetException
     */
    public function addOptionalJsonField(
        string $tableName,
        string $fieldName,
        JsonFieldMap $fieldMap,
        string|AAD $aadSource = '',
        bool $strict = true
    ): static {
        $this->getEncryptedRowObjectForTable($tableName)
            ->addNullableJsonField($fieldName, $fieldMap, $aadSource, $strict);
        return $this;
    }

    /**
     * Mark a column to be encrypted as text input. Permits NULL.
     *
     * @throws CipherSweetException
     */
    public function addOptionalTextField(
        string $tableName,
        string $fieldName,
        string|AAD $aadSource = ''
    ): static {
        return $this->addField(
            $tableName,
            $fieldName,
            Constants::TYPE_OPTIONAL_TEXT,
            $aadSource
        );
    }

    /**
     * Add a blind index to a specific table.
     * @throws CipherSweetException
     */
    public function addBlindIndex(string $tableName, string $column, BlindIndex $index): static
    {
        $this->getEncryptedRowObjectForTable($tableName)
            ->addBlindIndex($column, $index);
        return $this;
    }

    /**
     * Add a CompoundIndex to a specific table.
     *
     * @throws CipherSweetException
     */
    public function addCompoundIndex(string $tableName, CompoundIndex $index): static
    {
        $this->getEncryptedRowObjectForTable($tableName)
            ->addCompoundIndex($index);
        return $this;
    }

    /**
     * Create a compound index. See EncryptedRow::createCompoundIndex().
     *
     * @throws CipherSweetException
     */
    public function createCompoundIndex(
        string $tableName,
        string $name,
        array $columns = [],
        int $filterBits = 256,
        bool $fastHash = false,
        array $hashConfig = []
    ): CompoundIndex {
        return $this->getEncryptedRowObjectForTable($tableName)
            ->createCompoundIndex(
                $name,
                $columns,
                $filterBits,
                $fastHash,
                $hashConfig
            );
    }

    /**
     * Create a compound index. See EncryptedRow::createCompoundIndex().
     *
     * @throws CipherSweetException
     */
    public function createFastCompoundIndex(
        string $tableName,
        string $name,
        array $columns = [],
        int $filterBits = 256,
        array $hashConfig = []
    ): CompoundIndex {
        return $this->getEncryptedRowObjectForTable($tableName)
            ->createFastCompoundIndex(
                $name,
                $columns,
                $filterBits,
                $hashConfig
            );
    }

    /**
     * Decrypt encrypted records from a database result set.
     * $rows should be formatted as follows:
     *
     * [
     *   "table_name" => [
     *     "column_name" => "value",
     *     "column2" => 0.123,
     *   ],
     *   "table2" => [...],
     *   ...
     * ]
     *
     * @param array<string, array<string, string>> $rows
     * @return array<string, array<string, string|int|float|bool|null>>
     *
     * @throws CryptoOperationException
     * @throws SodiumException
     * @throws CipherSweetException
     */
    public function decryptManyRows(
        #[\SensitiveParameter]
        array $rows
    ): array {
        foreach (\array_keys($this->tables) as $table) {
            if (isset($rows[$table])) {
                /** @var array<string, string> $row */
                $row = $rows[$table];
                $rows[$table] = $this
                    ->getEncryptedRowObjectForTable($table)
                    ->decryptRow($row);
            }
        }
        /** @var array<string, array<string, string|int|float|bool|null>> $rows */
        return $rows;
    }

    /**
     * Process many rows of data, encrypting anything that was added to this object.
     * $rows should be formatted as follows:
     *
     * [
     *   "table_name" => [
     *     "column_name" => "value",
     *     "column2" => 0.123,
     *   ],
     *   "table2" => [...],
     *   ...
     * ]
     *
     * @param array<string, array<string, string|int|float|bool|null>> $rows
     * @return array<string, array<string, string>>
     *
     * @throws ArrayKeyException
     * @throws CryptoOperationException
     * @throws SodiumException
     * @throws CipherSweetException
     */
    public function encryptManyRows(
        #[\SensitiveParameter]
        array $rows
    ): array {
        foreach (\array_keys($this->tables) as $table) {
            if (isset($rows[$table])) {
                /** @var array<string, string> $row */
                $row = $rows[$table];
                $rows[$table] = $this
                    ->getEncryptedRowObjectForTable($table)
                    ->encryptRow($row);
            }
        }
        /** @var array<string, array<string, string>> $rows */
        return $rows;
    }

    /**
     * Get a specific blind index output (for a given table and index)
     *
     * @return array<string, string>|string
     *
     * @throws ArrayKeyException
     * @throws BlindIndexNotFoundException
     * @throws CryptoOperationException
     * @throws SodiumException
     * @throws CipherSweetException
     */
    public function getBlindIndex(
        string $tableName,
        string $indexName,
        #[\SensitiveParameter]
        array $row
    ): string|array {
        return $this->getEncryptedRowObjectForTable($tableName)
            ->getBlindIndex($indexName, $row);
    }

    /**
     * Get all of the blind indexes for a given table.
     *
     * @param string $tableName
     * @param array $row
     * @return array<string, array<string, string>|string>
     *
     * @throws ArrayKeyException
     * @throws CryptoOperationException
     * @throws SodiumException
     * @throws CipherSweetException
     */
    public function getBlindIndexesForTable(
        string $tableName,
        #[\SensitiveParameter]
        array $row
    ): array {
        return $this->getEncryptedRowObjectForTable($tableName)
            ->getAllBlindIndexes($row);
    }

    /**
     * Get all blind indexes for the tables in this multi-table result set.
     * $rows should be formatted as follows:
     *
     * [
     *   "table_name" => [
     *     "column_name" => "value",
     *     "column2" => 0.123,
     *   ],
     *   "table2" => [...],
     *   ...
     * ]
     *
     * @param array<string, array> $rows
     * @return array<string, array<string, array<string, string>|string>>
     *
     * @throws ArrayKeyException
     * @throws Exception\CryptoOperationException
     * @throws SodiumException
     * @throws CipherSweetException
     */
    public function getAllBlindIndexes(
        #[\SensitiveParameter]
        array $rows
    ): array {
        /** @var array<string, array<string, array<string, string>|string>> $tables */
        $tables = [];
        foreach (\array_keys($this->tables) as $table) {
            if (isset($rows[$table])) {
                $tables[$table] = $this
                    ->getEncryptedRowObjectForTable($table)
                    ->getAllBlindIndexes($rows[$table]);
            }
        }
        return $tables;
    }

    /**
     * Get the "type" of a specific blind index (by table, column, and index name).
     *
     * @throws SodiumException
     * @throws CipherSweetException
     */
    public function getBlindIndexType(string $table, string $column, string $name): string
    {
        return $this->getEncryptedRowObjectForTable($table)
            ->getBlindIndexType(
                $column,
                $name
            );
    }

    /**
     * Get the "type" of a specific compound index (by table and index name).
     *
     * @throws SodiumException
     * @throws CipherSweetException
     */
    public function getCompoundIndexType(string $table, string $name): string
    {
        return $this->getEncryptedRowObjectForTable($table)
            ->getCompoundIndexType($name);
    }

    /**
     * Get the EncryptedRow instance for the given table in this multi-row
     * abstraction layer.
     *
     * @param string $tableName
     * @return EncryptedRow
     * @throws CipherSweetException
     */
    public function getEncryptedRowObjectForTable(string $tableName = ''): EncryptedRow
    {
        if (!\array_key_exists($tableName, $this->tables)) {
            $this->addTable($tableName);
        }
        /** @var EncryptedRow $encryptedRow */
        $encryptedRow = $this->tables[$tableName];
        $encryptedRow->setTypedIndexes($this->typedIndexes);
        if (!is_null($this->permitEmpty)) {
            $encryptedRow->setPermitEmpty($this->permitEmpty);
        }
        return $encryptedRow;
    }

    /**
     * @return array<int, string>
     */
    public function listTables(): array
    {
        return \array_keys($this->tables);
    }

    /**
     * @param bool $autoBindContext
     * @return self
     */
    public function setAutoBindContext(bool $autoBindContext = false): self
    {
        $this->autoBindContext = $autoBindContext;
        return $this;
    }

    /**
     * @throws CipherSweetException
     */
    public function setPrimaryKeyColumnName(string $tableName, ?string $columnName): self
    {
        $this->getEncryptedRowObjectForTable($tableName)
            ->setPrimaryKeyColumnName($columnName);
        return $this;
    }

    /**
     * @throws CipherSweetException
     */
    public function setAadSourceField(string $tableName, string $fieldName, string|AAD $aadSource): static
    {
        $this->getEncryptedRowObjectForTable($tableName)
            ->setAadSourceField($fieldName, $aadSource);
        return $this;
    }

    /**
     * A multi-row implementation of the other prepareForStorage() APIs.
     * $rows should be formatted as follows:
     *
     * [
     *   "table_name" => [
     *     "column_name" => "value",
     *     "column2" => 0.123,
     *   ],
     *   "table2" => [...],
     *   ...
     * ]
     *
     * @param array<string, array<string, string|int|float|bool|null>> $rows
     * @return array{0:array<string, array<string, string>>, 1:array<string, array<string, array<string, string>|string>>}
     *
     * @throws ArrayKeyException
     * @throws CryptoOperationException
     * @throws SodiumException
     * @throws CipherSweetException
     */
    public function prepareForStorage(
        #[\SensitiveParameter]
        array $rows
    ): array {
        $indexes = [];
        $tables = [];
        foreach (\array_keys($this->tables) as $table) {
            if (isset($rows[$table])) {
                /** @var array<string, string|int|float|bool|null> $row */
                $row = $rows[$table];
                $tables[$table] = $this
                    ->getEncryptedRowObjectForTable($table)
                    ->encryptRow($row);
                $indexes[$table] = $this
                    ->getEncryptedRowObjectForTable($table)
                    ->setTypedIndexes($this->typedIndexes)
                    ->getAllBlindIndexes($row);
            }
        }
        return [$tables, $indexes];
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

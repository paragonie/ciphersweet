<?php
namespace ParagonIE\CipherSweet;

use ParagonIE\CipherSweet\Exception\ArrayKeyException;
use ParagonIE\CipherSweet\Exception\BlindIndexNotFoundException;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;

/**
 * Class EncryptedMultiRows
 * @package ParagonIE\CipherSweet
 */
class EncryptedMultiRows
{
    /**
     * @var CipherSweet $engine
     */
    protected $engine;

    /**
     * @var array<string, EncryptedRow> $tables
     */
    protected $tables = [];

    /**
     * EncryptedFieldSet constructor.
     *
     * @param CipherSweet $engine
     */
    public function __construct(CipherSweet $engine)
    {
        $this->engine = $engine;
    }

    /**
     * Add a table to the list of tables we process.
     *
     * @param string $tableName
     * @return self
     */
    public function addTable($tableName)
    {
        $this->tables[$tableName] = new EncryptedRow($this->engine, $tableName);
        return $this;
    }

    /**
     * Mark a field to be encrypted.
     *
     * @param string $tableName
     * @param string $fieldName
     * @param string $type
     * @return $this
     */
    public function addField($tableName, $fieldName, $type = Constants::TYPE_TEXT)
    {
        $this->getEncryptedRowObjectForTable($tableName)
            ->addField($fieldName, $type);
        return $this;
    }

    /**
     * Mark a column to be encrypted as boolean input.
     *
     * @param string $tableName
     * @param string $fieldName
     * @return self
     */
    public function addBooleanField($tableName, $fieldName)
    {
        return $this->addField($tableName, $fieldName, Constants::TYPE_BOOLEAN);
    }

    /**
     * Mark a column to be encrypted as floating point input.
     *
     * @param string $tableName
     * @param string $fieldName
     * @return self
     */
    public function addFloatField($tableName, $fieldName)
    {
        return $this->addField($tableName, $fieldName, Constants::TYPE_FLOAT);
    }

    /**
     * Mark a column to be encrypted as integer input.
     *
     * @param string $tableName
     * @param string $fieldName
     * @return self
     */
    public function addIntegerField($tableName, $fieldName)
    {
        return $this->addField($tableName, $fieldName, Constants::TYPE_INT);
    }

    /**
     * Mark a column to be encrypted as text input.
     *
     * @param string $tableName
     * @param string $fieldName
     * @return self
     */
    public function addTextField($tableName, $fieldName)
    {
        return $this->addField($tableName, $fieldName, Constants::TYPE_TEXT);
    }

    /**
     * Add a blind index to a specific table.
     *
     * @param string $tableName
     * @param string $column
     * @param BlindIndex $index
     * @return self
     */
    public function addBlindIndex($tableName, $column, BlindIndex $index)
    {
        $this->getEncryptedRowObjectForTable($tableName)
            ->addBlindIndex($column, $index);
        return $this;
    }

    /**
     * Add a CompoundIndex to a specific table.
     *
     * @param string $tableName
     * @param CompoundIndex $index
     * @return self
     */
    public function addCompoundIndex($tableName,CompoundIndex $index)
    {
        $this->getEncryptedRowObjectForTable($tableName)
            ->addCompoundIndex($index);
        return $this;
    }

    /**
     * Create a compound index. See EncryptedRow::createCompoundIndex().
     *
     * @param string $tableName
     * @param string $name
     * @param array<int, string> $columns
     * @param int $filterBits
     * @param bool $fastHash
     * @param array $hashConfig
     * @return CompoundIndex
     */
    public function createCompoundIndex(
        $tableName,
        $name,
        array $columns = [],
        $filterBits = 256,
        $fastHash = false,
        array $hashConfig = []
    ) {
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
     * @throws \SodiumException
     */
    public function decryptManyRows(array $rows)
    {
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
     * @throws \SodiumException
     */
    public function encryptManyRows(array $rows)
    {
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
     * @param string $tableName
     * @param string $indexName
     * @param array $row
     * @return array<string, string>
     *
     * @throws ArrayKeyException
     * @throws BlindIndexNotFoundException
     * @throws CryptoOperationException
     * @throws \SodiumException
     */
    public function getBlindIndex($tableName, $indexName, array $row)
    {
        return $this->getEncryptedRowObjectForTable($tableName)
            ->getBlindIndex($indexName, $row);
    }

    /**
     * Get all of the blind indexes for a given table.
     *
     * @param string $tableName
     * @param array $row
     * @return array<string, array<string, string>>
     *
     * @throws ArrayKeyException
     * @throws CryptoOperationException
     * @throws \SodiumException
     */
    public function getBlindIndexesForTable($tableName, array $row)
    {
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
     * @return array<string, array<string, array<string, string>>>
     *
     * @throws ArrayKeyException
     * @throws Exception\CryptoOperationException
     * @throws \SodiumException
     */
    public function getAllBlindIndexes(array $rows)
    {
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
     * Get the EncryptedRow instance for the given table in this multi-row
     * abstraction layer.
     *
     * @param string $tableName
     * @return EncryptedRow
     */
    public function getEncryptedRowObjectForTable($tableName = '')
    {
        if (!\array_key_exists($tableName, $this->tables)) {
            $this->addTable($tableName);
        }
        /** @var EncryptedRow $encryptedRow */
        $encryptedRow = $this->tables[$tableName];
        return $encryptedRow;
    }

    /**
     * @return array<int, string>
     */
    public function listTables()
    {
        return \array_keys($this->tables);
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
     * @return array{0:array<string, array<string, string>>, 1:array<string, array<string, array<string, string>>>}
     *
     * @throws ArrayKeyException
     * @throws CryptoOperationException
     * @throws \SodiumException
     */
    public function prepareForStorage(array $rows)
    {
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
                    ->getAllBlindIndexes($row);
            }
        }
        return [$tables, $indexes];
    }
}

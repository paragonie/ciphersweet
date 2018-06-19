<?php
namespace ParagonIE\CipherSweet;

use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\Exception\ArrayKeyException;
use ParagonIE\ConstantTime\Hex;

/**
 * Class EncryptedRow
 * @package ParagonIE\CipherSweet
 */
class EncryptedRow
{
    const TYPE_BOOLEAN = 'bool';
    const TYPE_TEXT = 'string';
    const TYPE_INT = 'int';
    const TYPE_FLOAT = 'float';

    const COMPOUND_SPECIAL = 'special__compound__indexes';

    /**
     * @var CipherSweet $engine
     */
    protected $engine;

    /**
     * @var array<string, string> $fieldsToEncrypt
     */
    protected $fieldsToEncrypt = [];

    /**
     * @var array<string, array<string, BlindIndex>> $blindIndexes
     */
    protected $blindIndexes = [];

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
     */
    public function __construct(CipherSweet $engine, $tableName)
    {
        $this->engine = $engine;
        $this->tableName = $tableName;
    }

    /**
     * @param string $fieldName
     * @param string $type
     * @return self
     */
    public function addField($fieldName, $type = self::TYPE_TEXT)
    {
        $this->fieldsToEncrypt[$fieldName] = $type;
        return $this;
    }

    /**
     * @param string $fieldName
     * @return self
     */
    public function addBooleanField($fieldName)
    {
        return $this->addField($fieldName, self::TYPE_BOOLEAN);
    }

    /**
     * @param string $fieldName
     * @return self
     */
    public function addFloatField($fieldName)
    {
        return $this->addField($fieldName, self::TYPE_FLOAT);
    }

    /**
     * @param string $fieldName
     * @return self
     */
    public function addIntegerField($fieldName)
    {
        return $this->addField($fieldName, self::TYPE_INT);
    }

    /**
     * @param string $fieldName
     * @return self
     */
    public function addTextField($fieldName)
    {
        return $this->addField($fieldName, self::TYPE_TEXT);
    }

    /**
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
     * @param CompoundIndex $index
     * @return self
     */
    public function addCompoundIndex(CompoundIndex $index)
    {
        $this->compoundIndexes[$index->getName()] = $index;
        return $this;
    }

    /**
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
     * @param array $row
     * @param string $column
     * @param BlindIndex $index
     * @return array<string, string>
     *
     * @throws ArrayKeyException
     * @throws Exception\CryptoOperationException
     * @throws \SodiumException
     */
    public function calcBlindIndex(array $row, $column, BlindIndex $index)
    {
        $name = $index->getName();
        $key = $this->engine->getBlindIndexRootKey(
            $this->tableName,
            $column
        );

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

    /**
     * @param array $row
     * @param CompoundIndex $index
     *
     * @return array<string, string>
     * @throws Exception\CryptoOperationException
     */
    public function calcCompoundIndex(array $row, CompoundIndex $index)
    {
        $name = $index->getName();
        $key = $this->engine->getBlindIndexRootKey(
            $this->tableName,
            self::COMPOUND_SPECIAL
        );

        $k = $this->engine->getIndexTypeColumn(
            $this->tableName,
            self::COMPOUND_SPECIAL,
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

    /**
     * @param array $row
     * @param string $column
     * @param BlindIndex $index
     * @param SymmetricKey|null $key
     *
     * @return string
     * @throws Exception\CryptoOperationException
     * @throws ArrayKeyException
     * @throws \SodiumException
     */
    public function calcBlindIndexRaw(
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
        /** @var string $name */
        $name = $index->getName();

        /** @var SymmetricKey $subKey */
        $subKey = new SymmetricKey(
            $backend,
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

        /** @var string $plaintext */
        $plaintext = $this->convertToString($unconverted, $fieldType);

        /** @var BlindIndex $index */
        $index = $this->blindIndexes[$column][$name];
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
     * @param array $row
     * @param CompoundIndex $index
     * @param SymmetricKey|null $key
     * @return string
     *
     * @throws \Exception
     * @throws Exception\CryptoOperationException
     */
    public function calcCompoundIndexRaw(
        array $row,
        CompoundIndex $index,
        SymmetricKey $key = null
    ) {
        if (!$key) {
            $key = $this->engine->getBlindIndexRootKey(
                $this->tableName,
                self::COMPOUND_SPECIAL
            );
        }

        $backend = $this->engine->getBackend();
        /** @var string $name */
        $name = $index->getName();

        /** @var SymmetricKey $subKey */
        $subKey = new SymmetricKey(
            $backend,
            \hash_hmac(
                'sha256',
                Util::pack([$this->tableName, self::COMPOUND_SPECIAL, $name]),
                $key->getRawKey(),
                true
            )
        );

        /** @var string $plaintext */
        $plaintext = $index->getPacked($row);

        /** @var CompoundIndex $index */
        $index = $this->compoundIndexes[$name];

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
     * @param array $row
     * @return array<int, array<string, string>>
     *
     * @throws ArrayKeyException
     * @throws Exception\CryptoOperationException
     * @throws \SodiumException
     */
    public function getAllBlindIndexes(array $row)
    {
        $return = [];
        foreach ($this->blindIndexes as $column => $blindIndexes) {
            foreach ($blindIndexes as $blindIndex) {
                $return[] = $this->calcBlindIndex($row, $column, $blindIndex);
            }
        }
        foreach ($this->compoundIndexes as $name => $compoundIndex) {
            $return[] = $this->calcCompoundIndex($row, $compoundIndex);
        }
        return $return;
    }

    /**
     * @param array<string, string> $row
     * @return array<string, string|int|float|bool|null>
     * @throws Exception\CryptoOperationException
     * @throws \SodiumException
     */
    public function decryptRow(array $row)
    {
        $return = $row;
        foreach ($this->fieldsToEncrypt as $field => $type) {
            $key = $this->engine->getFieldSymmetricKey(
                $this->tableName,
                $field
            );
            $plaintext = $this
                ->engine
                ->getBackend()
                ->decrypt($row[$field], $key);
            $return[$field] = $this->convertFromString($plaintext, $type);
        }
        return $return;
    }

    /**
     * @param array<string, string|int|float|bool|null> $row
     *
     * @return array<string, string>
     * @throws ArrayKeyException
     * @throws Exception\CryptoOperationException
     * @throws \SodiumException
     */
    public function encryptRow(array $row)
    {
        $return = $row;
        foreach ($this->fieldsToEncrypt as $field => $type) {
            if (!\array_key_exists($field, $row)) {
                throw new ArrayKeyException(
                    'Expected value for column ' . $field. ' on array, nothing given.'
                );
            }
            /** @var string $plaintext */
            $plaintext = $this->convertToString($row[$field], $type);
            $key = $this->engine->getFieldSymmetricKey(
                $this->tableName,
                $field
            );
            $return[$field] = $this
                ->engine
                ->getBackend()
                ->encrypt($plaintext, $key);
        }
        /** @var array<string, string> $return */
        return $return;
    }

    /**
     * @param string $data
     * @param string $type
     * @return int|string|float|bool|null
     * @throws \SodiumException
     */
    protected function convertFromString($data, $type)
    {
        switch ($type) {
            case self::TYPE_BOOLEAN:
                return Util::chrToBool($data);
            case self::TYPE_FLOAT:
                return Util::stringToFloat($data);
            case self::TYPE_INT:
                return Util::stringToInt($data);
            default:
                return (string) $data;
        }
    }
    /**
     * @param int|string|float|bool|null $data
     * @param string $type
     * @return string
     * @throws \SodiumException
     */
    protected function convertToString($data, $type)
    {
        switch ($type) {
            case self::TYPE_BOOLEAN:
                if (!\is_null($data) && !\is_bool($data)) {
                    $data = !empty($data);
                }
                return Util::boolToChr($data);
            case self::TYPE_FLOAT:
                if (!\is_float($data)) {
                    throw new \TypeError('Expected a float');
                }
                return Util::floatToString($data);
            case self::TYPE_INT:
                if (!\is_int($data)) {
                    throw new \TypeError('Expected an integer');
                }
                return Util::intToString($data);
            default:
                return (string) $data;
        }
    }

    /**
     * @param array<string, int|float|string|bool|null> $row
     * @return array{0: array<string, string>, 1: array<int, array<string, string>>}
     *
     * @throws ArrayKeyException
     * @throws Exception\CryptoOperationException
     * @throws \SodiumException
     */
    public function prepareRowForStorage(array $row)
    {
        return [
            $this->encryptRow($row),
            $this->getAllBlindIndexes($row)
        ];
    }
}

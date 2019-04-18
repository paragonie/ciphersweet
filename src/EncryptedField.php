<?php
namespace ParagonIE\CipherSweet;

use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\Contract\BackendInterface;
use ParagonIE\CipherSweet\Exception\BlindIndexNameCollisionException;
use ParagonIE\CipherSweet\Exception\BlindIndexNotFoundException;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;
use ParagonIE\ConstantTime\Hex;

/**
 * Class EncryptedField
 * @package ParagonIE\CipherSweet
 */
class EncryptedField
{
    /**
     * @var array<string, BlindIndex> $blindIndexes
     */
    protected $blindIndexes = [];

    /**
     * @var CipherSweet $engine
     */
    protected $engine;

    /**
     * @var string $fieldName
     */
    protected $fieldName = '';

    /**
     * @var bool $flatIndexes
     */
    protected $flatIndexes = false;

    /**
     * @var SymmetricKey $key
     */
    protected $key;

    /**
     * @var string $tableName
     */
    protected $tableName = '';

    /**
     * EncryptedField constructor.
     *
     * @param CipherSweet $engine
     * @param string $tableName
     * @param string $fieldName
     * @param bool $useFlatIndexes
     *
     * @throws CryptoOperationException
     */
    public function __construct(CipherSweet $engine, $tableName = '', $fieldName = '', $useFlatIndexes = false)
    {
        $this->engine = $engine;
        $this->tableName = $tableName;
        $this->fieldName = $fieldName;
        $this->key = $this->engine->getFieldSymmetricKey(
            $this->tableName,
            $this->fieldName
        );
        $this->flatIndexes = $useFlatIndexes;
    }

    /**
     * Encrypt a value and calculate all of its blind indices in one go.
     *
     * @param string $plaintext
     * @param string $aad               Additional authenticated data
     * @return array<int, string|array>
     *
     * @throws BlindIndexNotFoundException
     * @throws CryptoOperationException
     */
    public function prepareForStorage($plaintext, $aad = '')
    {
        return [
            $this->encryptValue($plaintext, $aad),
            $this->getAllBlindIndexes($plaintext)
        ];
    }

    /**
     * Encrypt a single value, using the per-field symmetric key.
     *
     * @param string $plaintext
     * @param string $aad       Additional authenticated data
     * @return string
     */
    public function encryptValue($plaintext, $aad = '')
    {
        return $this
            ->engine
            ->getBackend()
            ->encrypt(
                $plaintext,
                $this->key,
                $aad
            );
    }

    /**
     * Decrypt a single value, using the per-field symmetric key.
     *
     * @param string $ciphertext
     * @param string $aad       Additional authenticated data
     * @return string
     */
    public function decryptValue($ciphertext, $aad = '')
    {
        return $this
            ->engine
            ->getBackend()
            ->decrypt(
                $ciphertext,
                $this->key,
                $aad
            );
    }

    /**
     * Get all blind index values for a given plaintext.
     *
     * @param string $plaintext
     * @return array<string, string|array>
     *
     * @throws BlindIndexNotFoundException
     * @throws CryptoOperationException
     */
    public function getAllBlindIndexes($plaintext)
    {
        $output = [];
        $key = $this->engine->getBlindIndexRootKey(
            $this->tableName,
            $this->fieldName
        );

        /** @var BlindIndex $index */
        foreach ($this->blindIndexes as $name => $index) {
            if ($this->flatIndexes) {
                $output[$name] = Hex::encode(
                    $this->getBlindIndexRaw(
                        $plaintext,
                        $name,
                        $key
                    )
                );
                continue;
            }
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
        return $output;
    }

    /**
     * Get a particular blind index of a given plaintext.
     *
     * @param string $plaintext
     * @param string $name
     * @return array|string
     *
     * @throws BlindIndexNotFoundException
     * @throws CryptoOperationException
     */
    public function getBlindIndex($plaintext, $name)
    {
        $key = $this->engine->getBlindIndexRootKey(
            $this->tableName,
            $this->fieldName
        );
        if ($this->flatIndexes) {
            return Hex::encode(
                $this->getBlindIndexRaw(
                    $plaintext,
                    $name,
                    $key
                )
            );
        }

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

    /**
     * Internal: Get the raw blind index. Returns a raw binary string.
     *
     * @param string $plaintext
     * @param string $name
     * @param SymmetricKey|null $key
     * @return string
     *
     * @throws BlindIndexNotFoundException
     * @throws CryptoOperationException
     */
    protected function getBlindIndexRaw(
        $plaintext,
        $name,
        SymmetricKey $key = null
    ) {
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
            $backend,
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
    public function getBlindIndexObjects()
    {
        return $this->blindIndexes;
    }

    /**
     * Get the "type" of a specific blind index (by name).
     *
     * More specific than the getBlindIndexTypes() method.
     *
     * @param string $name
     * @return string
     */
    public function getBlindIndexType($name)
    {
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
     */
    public function getBlindIndexTypes()
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
     * @param BlindIndex $index
     * @param string|null $name
     * @return self
     * @throws BlindIndexNameCollisionException
     */
    public function addBlindIndex(BlindIndex $index, $name = null)
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

    /**
     * @return bool
     */
    public function getFlatIndexes()
    {
        return $this->flatIndexes;
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
     * @param bool $bool
     * @return self
     */
    public function setFlatIndexes($bool)
    {
        $this->flatIndexes = $bool;
        return $this;
    }
}

<?php
namespace ParagonIE\CipherSweet;

use ParagonIE\CipherSweet\Exception\CipherSweetException;
use ParagonIE\CipherSweet\Exception\JsonMapException;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\ConstantTime\Hex;

class JsonFieldMap
{
    /** @var array<string, string> */
    private $fields = [];

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
        $path = $this->flattenPath($indices);
        $this->fields[$path] = $type;
        return $this;
    }

    /**
     * @param array<array-key, string|int> $indices
     * @return string
     *
     * @throws JsonMapException
     */
    protected function flattenPath(array $indices)
    {
        $pieces = [];
        foreach ($indices as $index) {
            if (is_int($index)) {
                $pieces []= '#' . Hex::encode(pack('J', $index));
            } elseif (is_string($index)) {
                $pieces []= '$' . Hex::encode($index);
            } else {
                throw new JsonMapException('Invalid type');
            }
        }
        return implode('.', $pieces);
    }

    /**
     * @param string $flattened
     * @return array<array-key, string|int>
     *
     * @throws CipherSweetException
     */
    protected function unflattenPath($flattened)
    {
        $pieces = explode('.', $flattened);
        $path = [];
        foreach ($pieces as $piece) {
            $decoded = Hex::decode(Binary::safeSubstr($piece, 1));
            if ($piece[0] === '#') {
                $unpack = unpack('J', $decoded);
                $path[] = $unpack[1];
            } elseif ($piece[0] === '$') {
                $path[] = $decoded;
            } else {
                throw new CipherSweetException("Unknown path type: {$piece[0]}");
            }
        }
        return $path;
    }

    /**
     * @return array
     *
     * @throws CipherSweetException
     */
    public function getMapping()
    {
        $mapping = [];
        foreach ($this->fields as $field => $type) {
            $mapping []= [
                'flat' => $field,
                'path' => $this->unflattenPath($field),
                'type' => $type
            ];
        }
        return $mapping;
    }
}

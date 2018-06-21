<?php
namespace ParagonIE\CipherSweet;

use ParagonIE\CipherSweet\Contract\TransformationInterface;
use ParagonIE\CipherSweet\Transformation\Compound;

/**
 * Class CompoundIndex
 * @package ParagonIE\CipherSweet
 */
class CompoundIndex
{
    /**
     * @var array<int, string> $columns
     */
    protected $columns;

    /**
     * @var bool $fastHash
     */
    protected $fastHash;

    /**
     * @var array $hashConfig
     */
    protected $hashConfig;

    /**
     * @var string $name
     */
    protected $name;

    /**
     * @var int $outputLength
     */
    protected $filterBits = 256;

    /**
     * @var array<string, array<int, TransformationInterface>>
     */
    protected $columnTransforms = [];

    /**
     * @var Compound
     */
    private static $compounder;

    /**
     * CompoundIndex constructor.
     *
     * @param string $name
     * @param array<int, string> $columns
     * @param int $filterBits
     * @param bool $fastHash
     * @param array $hashConfig
     */
    public function __construct(
        $name,
        array $columns = [],
        $filterBits = 256,
        $fastHash = false,
        array $hashConfig = []
    ) {
        $this->name = $name;
        $this->columns = $columns;
        $this->filterBits = $filterBits;
        $this->fastHash = $fastHash;
        $this->hashConfig = $hashConfig;
    }

    /**
     * @return Compound
     */
    public static function getCompounder()
    {
        if (!self::$compounder) {
            self::$compounder = new Compound();
        }
        return self::$compounder;
    }

    /**
     * @param string $column
     * @param TransformationInterface $tf
     * @return self
     */
    public function addTransform($column, TransformationInterface $tf)
    {
        $this->columnTransforms[$column][] = $tf;
        return $this;
    }

    /**
     * @return array<int, string>
     */
    public function getColumns()
    {
        return $this->columns;
    }

    /**
     * @return string
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * @return bool
     */
    public function getFastHash()
    {
        return $this->fastHash;
    }

    /**
     * @return int
     */
    public function getFilterBitLength()
    {
        return $this->filterBits;
    }

    /**
     * @return array
     */
    public function getHashConfig()
    {
        return $this->hashConfig;
    }

    /**
     * @param string $column
     * @return array<int, TransformationInterface>
     */
    public function getTransforms($column)
    {
        if (!\array_key_exists($column, $this->columns)) {
            return [];
        }
        return $this->columnTransforms[$column];
    }

    /**
     * Get a packed plaintext for use in creating a compound blind index
     * This is a one-way transformation meant to be distinct from other inputs
     * Not all elements of the row will be used.
     *
     * @param array $row
     *
     * @return string
     * @throws \Exception
     */
    public function getPacked(array $row)
    {
        /** @var array<int, string> $pieces */
        $pieces = [];
        /** @var string $col */
        foreach ($this->columns as $col) {
            if (!\array_key_exists($col, $row)) {
                continue;
            }
            /** @var string $piece */
            $piece = $row[$col];
            if (!empty($this->columnTransforms[$col])) {
                foreach ($this->columnTransforms[$col] as $tf) {
                    if ($tf instanceof TransformationInterface) {
                        /** @var string $piece */
                        $piece = $tf($piece);
                    }
                }
            }
            $pieces[$col] = $piece;
        }
        $compounder = self::getCompounder();
        return (string) $compounder($pieces);
    }
}

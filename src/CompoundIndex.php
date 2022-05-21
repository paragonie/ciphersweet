<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet;

use ParagonIE\CipherSweet\Contract\{
    RowTransformationInterface,
    TransformationInterface
};
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
    protected array $columns;

    protected bool $fastHash;

    protected array $hashConfig;

    protected string $name;

    protected int $filterBits = 256;

    /**
     * @var array<string, array<int, TransformationInterface>>
     */
    protected array $columnTransforms = [];

    /**
     * @var array<int, RowTransformationInterface>
     */
    protected array $rowTransforms = [];

    private static ?Compound $compounder = null;

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
        string $name,
        array $columns = [],
        int $filterBits = 256,
        bool $fastHash = false,
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
    public static function getCompounder(): Compound
    {
        if (is_null(self::$compounder)) {
            self::$compounder = new Compound();
        }
        return self::$compounder;
    }

    public function addTransform(string $column, TransformationInterface $tf): static
    {
        $this->columnTransforms[$column][] = $tf;
        return $this;
    }

    /**
     * Add a Row-Level Transform. This replaces the Compounder.
     */
    public function addRowTransform(RowTransformationInterface $tf): static
    {
        $this->rowTransforms[] = $tf;
        return $this;
    }

    /**
     * @return array<int, string>
     */
    public function getColumns(): array
    {
        return $this->columns;
    }

    /**
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * @return bool
     */
    public function getFastHash(): bool
    {
        return $this->fastHash;
    }

    /**
     * @return int
     */
    public function getFilterBitLength(): int
    {
        return $this->filterBits;
    }

    /**
     * @return array
     */
    public function getHashConfig(): array
    {
        return $this->hashConfig;
    }

    /**
     * @param string $column
     * @return array<int, TransformationInterface>
     */
    public function getTransforms(string $column): array
    {
        if (!\array_key_exists($column, $this->columns)) {
            return [];
        }
        return $this->columnTransforms[$column];
    }

    /**
     * @return array<int, RowTransformationInterface>
     */
    public function getRowTransforms(): array
    {
        return $this->rowTransforms;
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
    public function getPacked(array $row): string
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

        // If we define our own RowTransforms, we use them.
        if (!empty($this->rowTransforms)) {
            foreach ($this->rowTransforms as $tf) {
                if ($tf instanceof RowTransformationInterface) {
                    /** @var array|string $pieces */
                    $pieces = $tf($pieces);
                }
            }
        }

        // If we ended up with a string (i.e. from RowTransforms),
        // just return that. We're done.
        if (\is_string($pieces)) {
            return $pieces;
        }

        // Use the default Compound transformation to flatten the array
        // containing the pieces.
        $compounder = self::getCompounder();
        return (string) $compounder($pieces);
    }
}

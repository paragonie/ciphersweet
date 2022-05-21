<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet;

use ParagonIE\CipherSweet\Contract\TransformationInterface;

/**
 * Class BlindIndex
 * @package ParagonIE\CipherSweet
 */
class BlindIndex
{
    protected bool $fastHash;

    protected array $hashConfig;

    protected string $name;

    protected int $filterBits = 256;

    /**
     * @var array<int, TransformationInterface> $transformations
     */
    protected array $transformations;

    /**
     * BlindIndex constructor.
     *
     * @param string $name
     * @param array<int, TransformationInterface> $transformations
     * @param int $filterBits
     * @param bool $fastHash
     * @param array $hashConfig
     */
    public function __construct(
        string $name,
        array $transformations = [],
        int $filterBits = 256,
        bool $fastHash = false,
        array $hashConfig = []
    ) {
        $this->name = $name;
        $this->transformations = $transformations;
        $this->filterBits = $filterBits;
        $this->fastHash = $fastHash;
        $this->hashConfig = $hashConfig;
    }

    /**
     * @param TransformationInterface $tf
     * @return static
     */
    public function addTransformation(TransformationInterface $tf): static
    {
        $this->transformations[] = $tf;
        return $this;
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
     * @return array
     */
    public function getHashConfig(): array
    {
        return $this->hashConfig;
    }

    /**
     * @return int
     */
    public function getFilterBitLength(): int
    {
        return $this->filterBits;
    }

    /**
     * @param string $input
     * @return string
     */
    public function getTransformed(string $input): string
    {
        if (empty($this->transformations)) {
            return $input;
        }
        $output = $input;
        foreach ($this->transformations as $tf) {
            if ($tf instanceof TransformationInterface) {
                /** @var string $output */
                $output = $tf($output);
            }
        }
        return $output;
    }
}

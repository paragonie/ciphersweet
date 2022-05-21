<?php
namespace ParagonIE\CipherSweet;

use ParagonIE\CipherSweet\Contract\TransformationInterface;

/**
 * Class BlindIndex
 * @package ParagonIE\CipherSweet
 */
class BlindIndex
{
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
     * @var array<int, TransformationInterface> $transformations
     */
    protected $transformations;

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
        $name,
        array $transformations = [],
        $filterBits = 256,
        $fastHash = false,
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
     * @return self
     */
    public function addTransformation(TransformationInterface $tf)
    {
        $this->transformations[] = $tf;
        return $this;
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
     * @return array
     */
    public function getHashConfig()
    {
        return $this->hashConfig;
    }

    /**
     * @return int
     */
    public function getFilterBitLength()
    {
        return $this->filterBits;
    }

    /**
     * @param string $input
     * @return string
     */
    public function getTransformed($input)
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

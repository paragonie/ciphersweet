<?php
namespace ParagonIE\CipherSweet\Planner;

use ParagonIE\CipherSweet\BlindIndex;
use ParagonIE\CipherSweet\EncryptedField;
use ParagonIE\CipherSweet\Exception\PlannerException;

/**
 * Class Planner
 * @package ParagonIE\CipherSweet
 */
class FieldIndexPlanner
{
    /** @var int $population */
    protected $population = 0;

    /** @var array<string, array<string, int>> $indexes */
    protected $indexes = [];

    /**
     * Create a predictor from an EncryptedField.
     *
     * Attempts to parse the bit lengths of the existing fields. Note that this
     * may be slightly inaccurate with respect to the input domains of each
     * existing index. We default to "infinity" (PHP_INT_MAX bits) in our
     * estimates for K_i when populating from an object, but L_i is accurate.
     *
     * @param EncryptedField $field
     * @return self
     */
    public static function fromEncryptedField(EncryptedField $field)
    {
        $self = new static();
        /**
         * @var string $name
         * @var BlindIndex $object
         */
        foreach ($field->getBlindIndexObjects() as $name => $object) {
            $self->addExistingIndex($name, $object->getFilterBitLength(), PHP_INT_MAX);
        }
        return $self;
    }

    /**
     * @param string $name,
     * @param int $L
     * @param int $K
     * @return self
     */
    public function addExistingIndex($name, $L, $K)
    {
        $this->indexes[$name] = ['L' => $L, 'K' => $K];
        return $this;
    }

    /**
     * @return float
     */
    public function getCoincidenceCount()
    {
        $indexes = \array_values($this->indexes);
        return $this->coincidenceCounter($indexes, $this->population);
    }

    /**
     * @param int $extraFieldPopulationBits
     * @return array<string, int>
     *
     * @throws PlannerException
     */
    public function recommend($extraFieldPopulationBits = PHP_INT_MAX)
    {
        if ($this->population < 1) {
            throw new PlannerException('An empty population is not useful for estimates');
        }
        $existing = \array_values($this->indexes);
        $recommend = ['min' => null, 'max' => null];
        $sqrtR = \sqrt($this->population);

        /**
         * Calculate the boundary condition.
         *
         * We want at least 2, but if the population never allows less than e.g. 4 coincidences,
         * our maximum recommendation should be the lowest value that reaches this boundary.
         */
        $tmp = $existing;
        $tmp[] = ['L' => 257, 'K' => $extraFieldPopulationBits];
        /** @var float $boundary */
        $boundary = max(2, $this->coincidenceCounter($tmp, $this->population));

        // Brute force approach:
        for ($l = 256; $l >= 1; --$l) {
            $tmp = $existing;
            $tmp[] = ['L' => $l, 'K' => $extraFieldPopulationBits];
            $coincidences = $this->coincidenceCounter($tmp, $this->population);
            if (is_null($recommend['max']) && $coincidences > $boundary) {
                $recommend['max'] = $l + 1;
            }
            if ($coincidences >= 2 && $coincidences <= $sqrtR) {
                $recommend['min'] = $l;
            }
        }

        if (is_null($recommend['min'])) {
            $recommend['min'] = 1;
        }
        if (is_null($recommend['max'])) {
            throw new PlannerException('There is no safe upper bound');
        }

        // This will probably never happen, but...
        if ($recommend['min'] > $recommend['max']) {
            // ...the minimum should be lowered if it exceeds the maximum.
            $recommend['min'] = $recommend['max'];
        }
        return $recommend;
    }

    /**
     * @param int $extraFieldPopulationBits
     * @return int
     *
     * @throws PlannerException
     */
    public function recommendLow($extraFieldPopulationBits = PHP_INT_MAX)
    {
        /** @var array<string, int> $recommend */
        $recommend = $this->recommend($extraFieldPopulationBits);
        return $recommend['min'];
    }

    /**
     * @param int $extraFieldPopulationBits
     * @return int
     *
     * @throws PlannerException
     */
    public function recommendHigh($extraFieldPopulationBits = PHP_INT_MAX)
    {
        /** @var array<string, int> $recommend */
        $recommend = $this->recommend($extraFieldPopulationBits);
        return $recommend['max'];
    }

    /**
     * @param int $int
     * @return self
     */
    public function setEstimatedPopulation($int)
    {
        $this->population = $int;
        return $this;
    }

    /**
     * @param int $int
     * @return self
     */
    public function withPopulation($int)
    {
        /** @var self $clone */
        $clone = clone $this;
        return $clone->setEstimatedPopulation($int);
    }

    /**
     * @param array $indexes
     * @param int $R
     * @return float
     */
    protected function coincidenceCounter(array $indexes, $R)
    {
        /** @var int|float $exponent */
        $exponent = 0;
        $count = count($indexes);
        for ($i = 0; $i < $count; ++$i) {
            /** @var array<string, int|float> $index */
            $index = $indexes[$i];
            $exponent += min($index['L'], $index['K']);
        }
        return (float) max(1, $R) / pow(2, $exponent);
    }
}

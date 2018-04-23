<?php
namespace ParagonIE\CipherSweet\Contract;

/**
 * Interface TransformationInterface
 * @package ParagonIE\CipherSweet\Contract
 */
interface TransformationInterface
{
    /**
     * @param string $input
     * @return string
     */
    public function __invoke($input);
}

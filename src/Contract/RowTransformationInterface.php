<?php
namespace ParagonIE\CipherSweet\Contract;

/**
 * Interface RowTransformationInterface
 * @package ParagonIE\CipherSweet\Contract
 */
interface RowTransformationInterface extends TransformationInterface
{
    /**
     * @param array $input
     * @param int $layer
     *
     * @return array|string
     * @throws \Exception
     */
    public function processArray(array $input, $layer = 0);
}

<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\Contract;

/**
 * Interface TransformationInterface
 * @package ParagonIE\CipherSweet\Contract
 */
interface TransformationInterface
{
    /**
     * Implementations can define their own prototypes, but
     * this should almost always operate on a string, and must
     * always return a string.
     *
     * @param mixed $input
     * @return string
     */
    public function __invoke(
        #[\SensitiveParameter]
        mixed $input
    ): string;
}

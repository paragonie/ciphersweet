<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\Transformation;

use ParagonIE\CipherSweet\Contract\RowTransformationInterface;
use ParagonIE\ConstantTime\{
    Base64UrlSafe,
    Binary,
    Hex
};
use ParagonIE_Sodium_Core_Util as SodiumUtil;

/**
 * Class Compound
 * @package ParagonIE\CipherSweet\Transformation
 */
class Compound implements RowTransformationInterface
{
    /**
     * @param mixed $input
     *
     * @return string
     * @throws \Exception
     */
    public function __invoke(
        #[\SensitiveParameter]
        mixed $input
    ): string {
        if (!\is_array($input)) {
            throw new \TypeError('Compound Transformation expects an array');
        }
        return (string) \json_encode($this->processArray($input));
    }

    /**
     * @param string $string
     * @return string
     */
    public function packString(
        #[\SensitiveParameter]
        string $string
    ): string {
        $len = Binary::safeStrlen($string);
        $l = Hex::encode(SodiumUtil::store64_le($len));
        return $l . Base64UrlSafe::encode($string);
    }

    /**
     * @param array $input
     * @param int $layer
     *
     * @return array|string
     * @throws \Exception
     */
    public function processArray(array $input, int $layer = 0): array|string
    {
        if ($layer > 255) {
            throw new \Exception('Too much recursion');
        }

        $array = [];
        /**
         * @var string|int $key
         * @var array|string|int|bool|null|float $value
         */
        foreach ($input as $key => $value) {
            if (\is_array($value)) {
                $array[$key] = $this->processArray($value, $layer + 1);
                continue;
            }
            if (\is_float($value)) {
                $array[$key] = $this->packString((string) $value);
                continue;
            }
            if (\is_string($value)) {
                $array[$key] = $this->packString($value);
                continue;
            }
            $array[$key] = $value;
        }

        return $array;
    }
}

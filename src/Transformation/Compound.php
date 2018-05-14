<?php
namespace ParagonIE\CipherSweet\Transformation;


use ParagonIE\CipherSweet\Contract\TransformationInterface;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\ConstantTime\Hex;
use ParagonIE_Sodium_Core_Util as SodiumUtil;

class Compound implements TransformationInterface
{
    /**
     * @param mixed $input
     *
     * @return string
     * @throws \Exception
     */
    public function __invoke($input)
    {
        if (!\is_array($input)) {
            throw new \TypeError('Compound Transformation expects an array');
        }
        return (string) $this->processArray($input);
    }

    /**
     * @param string $string
     * @return string
     */
    public function packString($string)
    {
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
    public function processArray(array $input, $layer = 0)
    {
        if ($layer > 255) {
            throw new \Exception('Too much recursion');
        }

        $array = [];
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

        if ($layer === 0) {
            return \json_encode($array);
        } else {
            return $array;
        }
    }
}

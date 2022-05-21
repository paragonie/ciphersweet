<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\Tests;

use ParagonIE\CipherSweet\Util;
use ParagonIE\ConstantTime\Hex;
use PHPUnit\Framework\TestCase;

/**
 * Class UtilTest
 * @package ParagonIE\CipherSweet\Tests
 */
class UtilTest extends TestCase
{
    public function testAes256Ctr()
    {
        $key = \random_bytes(32);
        $nonce = \random_bytes(16);
        for ($i = 0; $i < 10; ++$i) {
            $message = \random_bytes(16 << $i);
            $expected = \openssl_encrypt(
                $message,
                'aes-256-ctr',
                $key,
                OPENSSL_RAW_DATA,
                $nonce
            );
            $actual = Util::aes256ctr($message, $key, $nonce);
            $this->assertSame(
                Hex::encode($expected),
                Hex::encode($actual)
            );
        }
    }

    /**
     * @ref https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
     *
     * Key
     * 603deb1015ca71be2b73aef0857d7781
     * 1f352c073b6108d72d9810a30914dff4
     *
     * Init. Counter
     * f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
     *
     * Block #1
     * Plaintext  6bc1bee22e409f96e93d7e117393172a
     * Ciphertext 601ec313775789a5b7a7f504bbf3d228
     *
     * Block #2
     * Plaintext  ae2d8a571e03ac9c9eb76fac45af8e51
     * Ciphertext f443e3ca4d62b59aca84e990cacaf5c5
     *
     * Block #3
     * Plaintext  30c81c46a35ce411e5fbc1191a0a52ef
     * Ciphertext 2b0930daa23de94ce87017ba2d84988d
     *
     * Block #4
     * Plaintext  f69f2445df4f9b17ad2b417be66c3710
     * Ciphertext dfc9c58db67aada613c2dd08457941a6
     *
     */
    public function testPolyfillAes256CtrTestVectors()
    {
        $key = Hex::decode('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4');
        $nonce = Hex::decode('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
        $plaintext = Hex::decode(
            "6bc1bee22e409f96e93d7e117393172a" .
            "ae2d8a571e03ac9c9eb76fac45af8e51" .
            "30c81c46a35ce411e5fbc1191a0a52ef" .
            "f69f2445df4f9b17ad2b417be66c3710"
        );
        $expected = "601ec313775789a5b7a7f504bbf3d228" .
            "f443e3ca4d62b59aca84e990cacaf5c5" .
            "2b0930daa23de94ce87017ba2d84988d" .
            "dfc9c58db67aada613c2dd08457941a6";

        $ciphertext = Util::aes256Ctr($plaintext, $key, $nonce);
        $this->assertSame(
            $expected,
            Hex::encode($ciphertext),
            'Test Vector from NIST SP 800-38A, F.5.5 CTR-AES256.Encrypt'
        );
    }

    /**
     * @throws \SodiumException
     */
    public function testBitMask()
    {
        $testCases = [
            ['ff', 4, 'f0', '0f'],
            ['ff', 9, 'ff00', 'ff00'],
            ['ffffffff', 16, 'ffff', 'ffff'],
            ['ffffffff', 17, 'ffff80', 'ffff01'],
            ['ffffffff', 18, 'ffffc0', 'ffff03'],
            ['ffffffff', 19, 'ffffe0', 'ffff07'],
            ['ffffffff', 20, 'fffff0', 'ffff0f'],
            ['ffffffff', 21, 'fffff8', 'ffff1f' ],
            ['ffffffff', 22, 'fffffc', 'ffff3f'],
            ['ffffffff', 23, 'fffffe', 'ffff7f'],
            ['ffffffff', 24, 'ffffff', 'ffffff'],
            ['ffffffff', 32, 'ffffffff', 'ffffffff'],
            ['ffffffff', 64, 'ffffffff00000000', 'ffffffff00000000'],
            ['55f6778c', 11, '55e0', '5506'],
            ['55f6778c', 12, '55f0', '5506'],
            ['55f6778c', 13, '55f0', '5516'],
            ['55f6778c', 14, '55f4', '5536'],
            ['55f6778c', 15, '55f6', '5576'],
            ['55f6778c', 16, '55f6', '55f6'],
            ['55f6778c', 17, '55f600', '55f601'],
            ['55f6778c', 32, '55f6778c', '55f6778c']
        ];
        foreach ($testCases as $testCase) {
            list ($input, $size, $output, $outputRight) = $testCase;
            $this->assertSame(
                $output,
                Hex::encode(
                    Util::andMask(Hex::decode($input), $size)
                )
            );
            $this->assertSame(
                $outputRight,
                Hex::encode(
                    Util::andMask(Hex::decode($input), $size, true)
                )
            );
        }
    }

    /**
     * @covers Util::chrToBool()
     * @covers Util::boolToChr()
     */
    public function testBoolToChr()
    {
        $this->assertSame("\x02", Util::boolToChr(true));
        $this->assertSame("\x01", Util::boolToChr(false));
        $this->assertSame("\x00", Util::boolToChr(null));

        try {
            Util::boolToChr(1);
            $this->fail('Invalid type was accepted');
        } catch (\TypeError $ex) {
        }
        try {
            Util::boolToChr(0);
            $this->fail('Invalid type was accepted');
        } catch (\TypeError $ex) {
        }
        try {
            Util::boolToChr('');
            $this->fail('Invalid type was accepted');
        } catch (\TypeError $ex) {
        }

        $this->assertSame(null, Util::chrToBool(Util::boolToChr(null)));
        $this->assertSame(false, Util::chrToBool(Util::boolToChr(false)));
        $this->assertSame(true, Util::chrToBool(Util::boolToChr(true)));
        try {
            Util::chrToBool('');
            $this->fail('Invalid length was accepted');
        } catch (\OutOfRangeException $ex) {
        }
        try {
            Util::chrToBool("\x03");
            $this->fail('Invalid argument was accepted');
        } catch (\InvalidArgumentException $ex) {
        }
    }

    /**
     * @throws \Exception
     * @throws \SodiumException
     */
    public function testFloatConversion()
    {
        $float = M_PI;

        $this->assertEquals(
            \number_format($float, 15),
            \number_format(Util::stringToFloat(Util::floatToString($float)), 15)
        );

        // for ($i = 0; $i < 10000; ++$i) {
        $left = (float) \random_int(1, PHP_INT_MAX - 1);
        $right = (float) \random_int(2, PHP_INT_MAX >> 4);
        $float = $left / $right;

        $this->assertEquals(
            \number_format($float, 9),
            \number_format(Util::stringToFloat(Util::floatToString($float)), 9),
            '[' . $left . ', ' . $right . '] division'
        );
        // }
    }

    /**
     * @throws \Exception
     * @throws \SodiumException
     */
    public function testIntConversion()
    {
        $int = \random_int(1, PHP_INT_MAX - 1);
        $this->assertSame(
            $int,
            Util::stringToInt(Util::intToString($int))
        );
    }

    public function testCtrNonceIncrease()
    {
        $testCases = [
            [
                '00000000000000000000000000000001',
                '00000000000000000000000000000000'
            ],
            [
                '00000000000000000000000000000100',
                '000000000000000000000000000000ff'
            ],
            [
                '0000000000000000000000000000ff00',
                '0000000000000000000000000000feff'
            ],
            [
                '00000000000000000000000000000000',
                'ffffffffffffffffffffffffffffffff'
            ]
        ];
        foreach ($testCases as $testCase) {
            list ($output, $input) = $testCase;
            $this->assertSame(
                $output,
                Hex::encode(Util::ctrNonceIncrease(Hex::decode($input)))
            );
        }
    }
}
